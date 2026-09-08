"""TOOL 3 — geolocate_ip with multi-source cross-validation.

Anti-fake-pinpoint design (this is the differentiator vs. "one GeoIP site"):
  * Query up to three sources: ip-api.com, ipinfo.io, and an *offline* MaxMind
    GeoLite2 mmdb if the user has one (the only source that works air-gapped).
  * Sources are cross-checked pairwise by haversine distance and country agreement.
  * The output is a **consensus cell + confidence radius**, never a "precise pin":
    agreement ≤50 km → tight-ish, ≤250 km → wide, >250 km → CONFLICT (confidence
    is slashed and the city string says "disputed").
  * The final confidence is *capped by the origin provenance* (an IP that came from
    a phishing-URL fallback cannot inherit 80% "we know where the sender is").
Every per-source failure is recorded as data (`ok: false, raw_error`), because
"honest gaps" is what makes the confidence number mean something.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

from ..models import GeoConsensus, GeoPoint, RiskSignal
from ..net import classify_ip, haversine_km, http_json, is_traceable
from ..risk import ORIGIN_CONFIDENCE_CEILING
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "ip": {"type": "string", "description": "optional IPv4 to locate (defaults to the resolved origin/infra IP)"},
        "sources": {"type": "string", "description": "optional comma-list restricting sources: ip-api,ipinfo,maxmind_offline"},
    },
}


@register(timeout_override=14.0)
@tool_meta(name="geolocate_ip", parameters=PARAMS,
           llm_hint="Use after resolve_origin. If confidence is low or status is 'unrecovered', you MUST say so (rule 5) — never invent a location.")
def tool_geolocate_ip(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Cross-validate 2–3 GeoIP sources for an IP and return a consensus + confidence radius."""
    signals: list[RiskSignal] = []
    origin = dict(ctx.state.get("origin") or {})
    wanted = (args.get("ip") or "").strip()

    targets: list[dict[str, Any]] = []
    if wanted:
        try:
            ipaddress.ip_address(wanted)
        except ValueError:
            return ToolResult(tool="geolocate_ip", ok=False, error=f"'{wanted}' is not an IP address",
                              summary="invalid ip argument", skipped=True)
        targets.append({"ip": wanted, "role": "operator_supplied", "ceiling": 70.0})
    else:
        if origin.get("ip"):
            targets.append({"ip": origin["ip"], "role": f"origin:{origin.get('source_kind', '')}",
                            "ceiling": ORIGIN_CONFIDENCE_CEILING.get(origin.get("source_kind", ""), 60.0)})
        for infra in (ctx.state.get("phishing_infra") or [])[:2]:
            if infra["ip"] not in [t["ip"] for t in targets]:
                targets.append({"ip": infra["ip"], "role": "phishing_infrastructure",
                                "ceiling": ORIGIN_CONFIDENCE_CEILING["phishing_infrastructure"]})

    if not targets:
        if ctx.state.get("geoloc_no_op_done"):
            return ToolResult(tool="geolocate_ip", ok=True, skipped=True,
                              summary="still nothing traceable to locate (deduplicated)",
                              data={"note": "dedup"})
        ctx.state["geoloc_no_op_done"] = True
        return ToolResult(
            tool="geolocate_ip", ok=True, skipped=True,
            summary="no traceable IP — geolocation reported as UNKNOWN (not guessed)",
            data={"note": "resolve_origin returned status=unrecovered and no resolvable linked infrastructure",
                  "geolocations": []},
            signals=[RiskSignal("origin_unrecovered", 1, 30,
                                explanation="no IP available to geolocate; location reported as unknown with low confidence",
                                source="geolocate_ip")],
        )

    located = set(ctx.state.get("geolocated_ips") or [])
    if not wanted and targets and all(t["ip"] in located for t in targets):
        return ToolResult(tool="geolocate_ip", ok=True, skipped=True,
                          summary="all candidate IPs already geolocated in an earlier pass — deduplicated",
                          data={"note": "dedup", "targets": list(located)})
    only = {s.strip() for s in (args.get("sources") or "").split(",") if s.strip()}
    results: list[dict[str, Any]] = []
    primary: Optional[dict[str, Any]] = None

    for target in targets:
        ip = target["ip"]
        kind = classify_ip(ip)
        # With --geoip-allow-private (demo corpus), loopback/RFC5737 addresses ARE
        # locatable — the mock/override GeoIP server holds fixtures for them, which
        # is how the offline demo shows the full multi-source path.
        demo_allowed = ctx.cfg.geoip_allow_private and ctx.cfg.geo_base_url_override
        if not is_traceable(ip, allow_private=ctx.cfg.geoip_allow_private) and not demo_allowed:
            note = (f"{ip} is {kind} — GeoIP answers for it are meaningless; skipping live lookups "
                    f"(enable --geoip-allow-private only for the bundled demo corpus)")
            results.append({"ip": ip, "role": target["role"], "consensus": GeoConsensus(
                ip=ip, notes=[note], summary=f"{ip} — non-routable ({kind}), NOT located", confidence=0.0).as_dict(),
                "skipped_reason": note})
            continue
        points = _query_sources(ctx, ip, only)
        consensus = build_consensus(ip, points, ceiling=target["ceiling"])
        results.append({"ip": ip, "role": target["role"], "points": [p.as_dict() for p in points],
                        "consensus": consensus.as_dict()})
        if primary is None and target["role"].startswith("origin"):
            primary = results[-1]
    if primary is None:
        primary = results[0]

    cons = primary["consensus"]
    ctx.state["geolocate"] = {"primary": primary, "all": results}
    ctx.state["geolocated_ips"] = sorted(located | {t["ip"] for t in targets})

    # NOTE: geolocation itself is *context*, not a risk factor — a phishing email
    # traced to a hosting DC is not riskier than one traced to a ISP simply because
    # the location is precise. Only *disagreement* is worth a (small) penalty note.
    if "CONFLICT" in " ".join(cons.get("notes", [])):
        signals.append(RiskSignal("tool_timeout", 1, 20,
                                  explanation="GeoIP sources disagree on this address — location treated as disputed, confidence reduced",
                                  source="geolocate_ip"))

    summary = f"primary {primary['ip']} → {cons['summary']} (confidence {cons['confidence']:.0f}%, ceiling {targets[0]['ceiling']:.0f}%)"
    return ToolResult(tool="geolocate_ip", ok=True, summary=summary,
                      data={"targets": results, "primary": primary, "origin_source_kind": origin.get("source_kind", "n/a")},
                      signals=signals)


# ─────────────────────────────────────────────────────────────────────────────
def _query_sources(ctx: ToolContext, ip: str, only: set[str]) -> list[GeoPoint]:
    cfg = ctx.cfg
    points: list[GeoPoint] = []
    if not only or "ip-api" in only:
        points.append(_ip_api(cfg, ip))
    if not only or "ipinfo" in only:
        points.append(_ipinfo(cfg, ip))
    if not only or "maxmind_offline" in only:
        points.append(_maxmind(ctx, ip))
    return points


def _ip_api(cfg: Any, ip: str) -> GeoPoint:
    """ip-api.com free tier: HTTP only (HTTPS needs a paid key). 45 req/min, no key.
    `status: fail` is a *valid* answer, recorded as ok=False with the reason."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,as,org,query,proximity&lang=en"
    r = http_json(url, timeout=cfg.http_timeout_s, offline=not cfg.geo_http_allowed,
                  base_override=cfg.geo_base_url_override)
    p = GeoPoint(source="ip-api", raw_error=r.get("error", ""))
    if not r.get("ok"):
        p.raw_error = r.get("error", "request failed")
        return p
    d = r.get("data") or {}
    if d.get("status") != "success":
        p.raw_error = f"api status={d.get('status')} {d.get('message', '')}"
        return p
    p.ok = True
    p.country, p.country_code = d.get("country", ""), (d.get("countryCode") or "").upper()
    p.region, p.city = d.get("regionName", ""), d.get("city", "")
    p.lat, p.lon = d.get("lat"), d.get("lon")
    p.timezone, p.asn, p.org = d.get("timezone", ""), d.get("as", ""), d.get("org", "")
    prox = d.get("proximity") or {}
    if isinstance(prox, dict) and prox.get("accuracyRadius"):
        p.accuracy_km = float(prox["accuracyRadius"])
    return p


def _ipinfo(cfg: Any, ip: str) -> GeoPoint:
    """ipinfo.io free tier: 50k req/month, no token needed over HTTP; token via env
    if the operator has one (and the token is never logged)."""
    headers = {}
    url = f"https://ipinfo.io/{ip}/json"
    if cfg.ipinfo_token:
        headers["Authorization"] = f"Bearer {cfg.ipinfo_token}"
    r = http_json(url, headers=headers, timeout=cfg.http_timeout_s, offline=not cfg.geo_http_allowed,
                  base_override=cfg.geo_base_url_override)
    p = GeoPoint(source="ipinfo", raw_error=r.get("error", ""))
    if not r.get("ok"):
        p.raw_error = r.get("error", "request failed")
        return p
    d = r.get("data") or {}
    if d.get("bogon"):
        p.raw_error = "ipinfo: bogon/non-routable"
        return p
    if not d.get("ip"):
        p.raw_error = "ipinfo: no record"
        return p
    p.ok = True
    p.country = d.get("country", "")
    p.country_code = (d.get("country") or "").upper()
    p.region, p.city = d.get("region", ""), d.get("city", "")
    loc = (d.get("loc") or "").split(",")
    if len(loc) == 2:
        try:
            p.lat, p.lon = float(loc[0]), float(loc[1])
        except ValueError:
            pass
    p.timezone = d.get("timezone", "")
    p.org = d.get("org", "")
    if d.get("privacy"):
        p.accuracy_km = None  # ipinfo privacy flags kept in raw digest if needed
    return p


def _maxmind(ctx: ToolContext, ip: str) -> GeoPoint:
    """Offline GeoLite2 (maxminddb). The only source that answers with zero network
    — and our tie-breaker when the two HTTP sources disagree."""
    p = GeoPoint(source="maxmind_offline")
    from pathlib import Path

    path = Path(ctx.cfg.geoip_mmdb_path)
    if not path.exists():
        p.raw_error = f"GeoLite2 mmdb not found at {path} (optional 3rd source)"
        return p
    try:
        import maxminddb  # type: ignore
    except ImportError:
        p.raw_error = "python package 'maxminddb' not installed (optional)"
        return p
    try:
        with maxminddb.open_database(str(path), mode=12) as db:  # MODE_READER
            rec = db.get(ip) or {}
        loc = rec.get("location") or {}
        p.ok = True
        c = (rec.get("country") or {}).get("iso_code", "")
        p.country = (rec.get("country") or {}).get("names", {}).get("en", c)
        p.country_code = c.upper()
        subs = rec.get("subdivisions") or []
        p.region = (subs[0].get("names", {}) or {}).get("en", "") if subs else ""
        p.city = (rec.get("city") or {}).get("names", {}).get("en", "")
        p.lat, p.lon = loc.get("latitude"), loc.get("longitude")
        acc = loc.get("accuracy_radius")
        p.accuracy_km = float(acc) if acc else None
        p.timezone = loc.get("time_zone", "")
    except Exception as exc:  # noqa: BLE001
        p.raw_error = f"{type(exc).__name__}: {exc}"
    return p


# ─────────────────────────────────────────────────────────────────────────────
def build_consensus(ip: str, points: list[GeoPoint], *, ceiling: float = 100.0) -> GeoConsensus:
    """Pure + unit-tested. Turns N source answers into (location, radius, confidence)."""
    good = [p for p in points if p.ok and p.lat is not None and p.lon is not None]
    c = GeoConsensus(ip=ip)
    c.points = [p.as_dict() for p in points]
    if not good:
        reasons = {p.source: (p.raw_error or "no coordinates") for p in points}
        c.summary = f"{ip}: unknown — no usable GeoIP answer"
        c.notes.append("no source returned coordinates; reported as unknown, not guessed")
        c.confidence = round(min(ceiling, 6.0), 1)
        c.radius_km = 5000.0
        c.points = [reasons]
        return c

    # pairwise agreement
    dists = [haversine_km(a.lat, a.lon, b.lat, b.lon) for i, a in enumerate(good) for b in good[i + 1:]]
    max_dist = max(dists) if dists else 0.0
    countries = {p.country_code for p in good if p.country_code}
    country_conflict = len(countries) > 1

    c.lat = sum(p.lat for p in good) / len(good)          # type: ignore[arg-type]
    c.lon = sum(p.lon for p in good) / len(good)          # type: ignore[arg-type]
    c.agreeing_sources = [p.source for p in good]
    base = max(15.0, min(1500.0, max_dist + 40.0)) if len(good) > 1 else 350.0
    if len(good) == 1:
        c.notes.append("single-source answer — reported with a deliberately wide radius")
    if country_conflict:
        base *= 3.0
        c.notes.append(f"CONFLICT: sources disagree on country {sorted(countries)}")
    c.radius_km = round(base, 1)

    agree_score = 100.0 if len(good) > 1 else 62.0
    if len(good) > 1:
        if max_dist <= 50:
            agree_score = 100.0
        elif max_dist <= 250:
            agree_score = 78.0
        elif max_dist <= 1000:
            agree_score = 50.0
        else:
            agree_score = 22.0
    if country_conflict:
        agree_score = min(agree_score, 30.0)
    # accuracy metadata bonus/penalty
    accs = [p.accuracy_km for p in good if p.accuracy_km]
    if accs:
        agree_score = 0.7 * agree_score + 0.3 * max(0.0, 100.0 - min(100.0, (sum(accs) / len(accs)) / 3.0))

    c.confidence = round(max(5.0, min(ceiling, agree_score * min(1.0, 0.72 + 0.14 * len(good))))
                         , 1)
    first = good[0]
    c.country = first.country
    c.country_code = "/".join(sorted(countries)) if countries else ""
    c.region = next((p.region for p in good if p.region), "")
    c.city = next((p.city for p in good if p.city), "")
    if len({p.city for p in good if p.city}) > 1:
        c.city = " / ".join(sorted({p.city for p in good if p.city})) + (" (disputed)" if max_dist > 250 else "")
    asn = next((p.org for p in good if p.org), "")
    label_city = c.city or c.region or "region unknown"
    c.summary = (f"≈ {label_city}, {c.country_code or '?'} · radius ±{c.radius_km:.0f} km · "
                 f"confidence {c.confidence:.0f}% · {asn}" if asn else
                 f"≈ {label_city}, {c.country_code or '?'} · radius ±{c.radius_km:.0f} km · confidence {c.confidence:.0f}%")
    if not country_conflict and len(good) > 1:
        c.notes.append(f"{len(good)} independent sources agree within {max_dist:.0f} km")
    return c
