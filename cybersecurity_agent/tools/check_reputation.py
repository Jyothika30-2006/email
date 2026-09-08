"""TOOL 6 — check_reputation: IP / domain / file-hash reputation.

Free tiers only, and *absence is recorded as absence*:
  * AbuseIPDB (1000 req/day, key required)   → abuse_confidence, reports, whitelisted
  * VirusTotal v3 (4 req/min, key required)  → detection ratios for URLs, domains,
    IP addresses and SHA-256 file hashes
  * Spamhaus CSS (no key, DNS only)          → SBL blocklist hits for the origin IP
No keys / no egress → the tool returns `skipped` entries (weight 0 → it does not
change the risk score) and the report says plainly which dimensions were unobserved.
That's deliberate: "we could not check" must never look like "we checked, it was clean".
"""
from __future__ import annotations

import base64
from typing import Any

from ..models import ReputationHit, RiskSignal
from ..net import dns_a, http_json
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "include": {"type": "string", "description": "comma list of ip,domain,file_hash (default all)"},
        "url_probe": {"type": "boolean", "description": "also submit link URLs to VT (uses quota — 1 URL = 1 request)"},
    },
}
VT = "https://www.virustotal.com/api/v3"


@register(timeout_override=13.0)
@tool_meta(name="check_reputation", parameters=PARAMS,
           llm_hint="If this tool reports 'skipped (no API key)', say the reputation dimension was NOT observed instead of implying cleanliness.")
def tool_check_reputation(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Query AbuseIPDB / VirusTotal / Spamhaus for the email's IPs, domains and attachment hashes."""
    done_targets = set(ctx.state.get("reputation_checked") or [])
    include = {i.strip() for i in (args.get("include") or "ip,domain,file_hash").split(",")}
    origin = dict(ctx.state.get("origin") or {})
    infra = ctx.state.get("phishing_infra") or []
    domains = list(ctx.state.get("url_hosts") or [])
    hits: list[dict[str, Any]] = []
    signals: list[RiskSignal] = []
    offline_note = "offline mode" if ctx.cfg.offline else ""

    ips = []
    for ip in [origin.get("ip")] + [d.get("ip") for d in infra]:
        if ip and ip not in ips:
            ips.append(ip)

    # ── IP reputation ───────────────────────────────────────────────────────
    if "ip" in include:
        for ip in ips[:3]:
            hit = _abuseipdb(ctx, ip, offline_note)
            hits.append(hit.as_dict())
            if hit.ok and (hit.abuse_confidence or 0) >= 50:
                signals.append(RiskSignal("abuse_reports", 1, min(100, 40 + (hit.abuse_confidence or 0) * 0.6),
                                          explanation=f"AbuseIPDB: {ip} has abuse confidence {hit.abuse_confidence}% ({hit.note})",
                                          source="check_reputation"))
            spf_hit = _spamhaus_sbl(ctx, ip)
            hits.append(spf_hit.as_dict())
            if spf_hit.ok and spf_hit.malicious:
                signals.append(RiskSignal("abuse_reports", 1, 70,
                                          explanation=f"{ip} listed on {spf_hit.categories[0]} — known spam/botnet source",
                                          source="check_reputation"))

    # ── domain reputation ───────────────────────────────────────────────────
    if "domain" in include:
        for dom in domains[:4]:
            hit = _vt_domain(ctx, dom, offline_note)
            hits.append(hit.as_dict())
            if hit.ok and hit.malicious:
                signals.append(RiskSignal("av_detections", 1, min(100, 40 + 4 * hit.malicious),
                                          explanation=f"VirusTotal: {hit.malicious}/{hit.total} engines flag domain {dom}",
                                          source="check_reputation"))
            elif hit.ok and not hit.malicious and hit.total:
                signals.append(RiskSignal("safe_domain_reputation", -1, 60,
                                          explanation=f"VirusTotal: {dom} not flagged by any of {hit.total} engines (URLs pointing at it are weaker phishing evidence)",
                                          source="check_reputation"))

    # ── file-hash reputation (hashes come from evidence manifest) ───────────
    if "file_hash" in include:
        for name, sha in sorted(ctx.evidence_hashes.items()):
            if name == "source" or len(sha) != 64:
                continue
            hit = _vt_file(ctx, sha, offline_note)
            hit.target = f"{name}#{sha[:12]}"
            hits.append(hit.as_dict())
            if hit.ok and hit.malicious:
                signals.append(RiskSignal("known_malware_hash", 1, 100,
                                          explanation=f"VirusTotal: SHA-256 {sha[:16]}… of attachment “{name}” is a KNOWN malware hash ({hit.malicious}/{hit.total} engines)",
                                          source="check_reputation"))
            elif hit.ok and not hit.malicious:
                signals.append(RiskSignal("av_clean", -1, 40,
                                          explanation=f"attachment “{name}” hash not in VirusTotal's corpus (absence of detections ≠ clean)",
                                          source="check_reputation"))

    new_targets = {str(h["target"]) for h in hits}
    if done_targets and new_targets and not (new_targets - done_targets):
        return ToolResult(tool="check_reputation", ok=True, skipped=True,
                          summary="all IPs/domains/hashes already reputation-checked in an earlier pass — deduplicated",
                          data={"note": "dedup", "hits": ctx.state.get("reputation") or []})
    ctx.state["reputation_checked"] = sorted(done_targets | new_targets)
    skipped = [h for h in hits if h["source"].startswith(("skipped", "virustotal:skipped", "abuseipdb:skipped"))]
    summary = (f"{len([h for h in hits if h['ok']])}/{len(hits)} reputation checks returned data"
               + (f"; {len(skipped)} skipped ({offline_note or 'no API keys configured'}) — those dimensions are UNOBSERVED, not clean" if skipped else ""))
    ctx.state["reputation"] = hits
    return ToolResult(tool="check_reputation", ok=True, summary=summary,
                      data={"hits": hits, "checked_ips": ips[:3], "checked_domains": domains[:4],
                            "keys_present": {"virustotal": bool(ctx.cfg.virustotal_api_key),
                                             "abuseipdb": bool(ctx.cfg.abuseipdb_api_key)}},
                      signals=signals)


# ─────────────────────────────────────────────────────────────────────────────
def _abuseipdb(ctx: ToolContext, ip: str, offline_note: str) -> ReputationHit:
    if not ctx.cfg.abuseipdb_api_key:
        return ReputationHit(source="abuseipdb", target=ip, ok=False,
                             note="skipped (no API key — free tier: https://www.abuseipdb.com/account/api)")
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    r = http_json(url, headers={"Key": ctx.cfg.abuseipdb_api_key, "Accept": "application/json"},
                  timeout=8.0, offline=ctx.cfg.offline, base_override=ctx.cfg.reputation_base_url_override)
    if not r.get("ok"):
        return ReputationHit(source="abuseipdb", target=ip, ok=False, note=(offline_note or r.get("error", "request failed"))[:160])
    d = ((r.get("data") or {}).get("data") or {})
    cats = [c.get("name", "") for c in (d.get("usageCategories") or [])][:4]
    return ReputationHit(source="abuseipdb", target=ip, ok=True,
                          abuse_confidence=int(d.get("abuseConfidenceScore") or 0),
                          total=int(d.get("totalReports") or 0), categories=cats,
                          last_seen=str(d.get("lastReportedAt") or ""),
                          note=f"country={d.get('countryCode', '?')} isp={str(d.get('isp', ''))[:40]}")


def _vt_domain(ctx: ToolContext, domain: str, offline_note: str) -> ReputationHit:
    if not ctx.cfg.virustotal_api_key:
        return ReputationHit(source="virustotal", target=domain, ok=False,
                             note="skipped (no API key — free tier: 4 requests/min)")
    b32 = base64.urlsafe_b64encode(domain.encode()).decode().rstrip("=")
    url = f"{VT}/domains/{b32}?domains_it_resolved_to=0"
    r = http_json(url, headers={"x-apikey": ctx.cfg.virustotal_api_key}, timeout=8.0,
                  offline=ctx.cfg.offline, base_override=ctx.cfg.reputation_base_url_override)
    if not r.get("ok"):
        return ReputationHit(source="virustotal", target=domain, ok=False, note=(offline_note or r.get("error", ""))[:160])
    attrs = ((r.get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(v or 0) for v in stats.values()) or 0
    cats = list((attrs.get("categories") or {}).values())[:4]
    return ReputationHit(source="virustotal", target=domain, ok=True,
                         malicious=int(stats.get("malicious") or 0), total=total,
                         categories=cats, last_seen=str(attrs.get("last_modification_date") or ""),
                         note=f"reputation={attrs.get('reputation', '')}")


def _vt_file(ctx: ToolContext, sha: str, offline_note: str) -> ReputationHit:
    if not ctx.cfg.virustotal_api_key:
        return ReputationHit(source="virustotal", target=sha[:16], ok=False,
                             note="skipped (no API key)")
    url = f"{VT}/files/{sha}"
    r = http_json(url, headers={"x-apikey": ctx.cfg.virustotal_api_key}, timeout=8.0,
                  offline=ctx.cfg.offline, base_override=ctx.cfg.reputation_base_url_override)
    if not r.get("ok"):
        return ReputationHit(source="virustotal", target=sha[:16], ok=False, note=(offline_note or r.get("error", ""))[:160])
    attrs = ((r.get("data") or {}).get("attributes") or {})
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(v or 0) for v in stats.values())
    return ReputationHit(source="virustotal", target=sha[:16], ok=True,
                         malicious=int(stats.get("malicious") or 0), total=total,
                         categories=[str(attrs.get("popular_threat_classification") or "")][:1],
                         note=f"names={attrs.get('names', [])[:3]}" if attrs.get("names") else f"positives={attrs.get('total_votes')}")


def _spamhaus_sbl(ctx: ToolContext, ip: str) -> ReputationHit:
    """Keyless DNSBL cross-check (works in most networks even without HTTP egress).
    Any 127.0.0.x answer means 'listed'; the last octet is a return code whose exact
    meaning varies by list, so we report the code instead of over-interpreting it."""
    rev = ".".join(ip.split(".")[::-1])
    ips, err = dns_a(f"{rev}.zen.spamhaus.org", timeout=2.5)
    if err == "NXDOMAIN" or (not ips and err in {"", "NODATA"}):
        return ReputationHit(source="spamhaus_css", target=ip, ok=True, malicious=0, note="not listed on SBL (NXDOMAIN)")
    if not ips:
        return ReputationHit(source="spamhaus_css", target=ip, ok=False, note=f"DNSBL lookup failed: {err or 'no answer'}")
    return ReputationHit(source="spamhaus_css", target=ip, ok=True, malicious=1,
                         categories=[f"zen.spamhaus.org return {a}" for a in ips[:3]],
                         note="listed — Spamhaus return-code semantics vary by list; verify before acting")
