"""TOOL 2 — resolve_origin: the Gmail/webmail-hides-the-sender-IP logic.

Layered fallback (README §2), each layer with a *documented* confidence ceiling:

  1. Walk every Received: hop bottom→top. A hop from a NON-provider network that
     carries a public IP is the best thing we can claim: "the machine that handed
     the message to the receiving/open MTA" (sender machine, or an open relay —
     we do not promise which).
  2. `Authentication-Results … client-ip=` / `Received-SPF: … client-ip=` — this
     is the IP that actually authenticated against the provider, i.e. the real
     *connecting client*, and it frequently survives even when the top Received:
     header was rewritten.
  3. If both only ever point at provider relay infrastructure → the personal IP is
     genuinely UNRECOVERABLE. We say so in the output (`status: unrecovered`) and
     degrade to:
        (a) phishing-infrastructure trace (resolve the lure server's IP),
        (b) Message-ID internal-hostname leak (+rDNS),
        (c) Date-header timezone offset (soft hint only),
        (d)/(e) handled by the reply-draft + style tools, flagged as available.
  4. Confidence is capped by the weakest link: geolocation of a fallback IP never
     inherits "we know the sender" semantics.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from ..evidence.eml import registrable_domain, relay_org_for, tz_hint
from ..models import OriginFinding, RiskSignal
from ..net import (classify_ip, dns_a, is_traceable, provider_network_for, reverse_dns)
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "prefer": {
            "type": "string",
            "enum": ["auto", "origin", "infrastructure"],
            "description": "auto = sender-first then fallbacks; infrastructure = only trace the linked lure server",
        },
        "skip_rdns": {"type": "boolean", "description": "disable the Message-ID reverse-DNS fallback (air-gap/time saving)"},
    },
}


@register(timeout_override=14.0)   # SAFETY #5: multiple bounded DNS lookups, but the
                                   # whole tool stays *inside* the 15s cap (4 hosts × 3s).
@tool_meta(name="resolve_origin", parameters=PARAMS,
           llm_hint="Run after parse_headers. Returns origin_source_kind + confidence ceiling; if unrecovered, explain the fallback you will rely on (rule 5).")
def tool_resolve_origin(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Resolve the true sending IP (or the best fallback) from parsed header data."""
    parsed = ctx.parsed
    prefer = (args.get("prefer") or "auto").lower()
    skip_rdns = bool(args.get("skip_rdns"))
    allow_private = ctx.cfg.geoip_allow_private
    signals: list[RiskSignal] = []

    hops = list(parsed.hops)
    candidates: list[dict[str, Any]] = []
    origin_ip: Optional[str] = None
    origin_hop: Optional[int] = None
    skipped: list[str] = []
    provider_edge = ""   # set if the only client-ip we ever see belongs to a webmail provider

    # ── 1. hop walk, oldest → newest ──────────────────────────────────────
    for hop in hops:
        if not hop.ip:
            skipped.append(f"hop#{hop.sequence}: no IP in '{hop.from_host or hop.by_host or '?'}'")
            continue
        kind = classify_ip(hop.ip)
        traceable = is_traceable(hop.ip, allow_private=allow_private)
        if hop.is_webmail_relay:
            skipped.append(f"hop#{hop.sequence}: {hop.relay_org} relay IP {hop.ip} (skipped — not the sender)")
            candidates.append({"hop": hop.sequence, "ip": hop.ip, "role": "provider_relay", "org": hop.relay_org, "usable": False})
            continue
        if kind in {"loopback", "private", "link_local", "multicast", "reserved"} and not allow_private:
            skipped.append(f"hop#{hop.sequence}: non-routable {kind} IP {hop.ip} (internal hop, not an origin)")
            candidates.append({"hop": hop.sequence, "ip": hop.ip, "role": kind, "usable": False})
            continue
        if not traceable:
            skipped.append(f"hop#{hop.sequence}: {kind} IP {hop.ip} is not GeoIP-traceable")
            candidates.append({"hop": hop.sequence, "ip": hop.ip, "role": kind, "usable": False})
            continue
        candidates.append({"hop": hop.sequence, "ip": hop.ip, "role": "sender_machine_or_open_relay", "usable": True,
                           "host": hop.by_host or hop.from_host})
        if origin_ip is None:
            origin_ip, origin_hop = hop.ip, hop.sequence

    # ── 2. SPF / Authentication-Results client-ip= ───────────────────────
    # Preference rule: when the oldest hop with an IP is a host in the *sender's own*
    # domain (attacker-controlled, trivially forgeable — they write their own
    # Received: lines), prefer the IP that actually authenticated (client-ip=): that
    # was stamped by a third-party receiver and is far harder to fake. When the
    # receiver is a webmail provider (Google/Microsoft) the client-ip IS the
    # connecting machine, so we still surface it — but under spf_client_ip semantics.
    spf_client_ips: list[dict[str, Any]] = []
    for rec in list(parsed.auth_results) + list(parsed.received_spf):
        ip = rec.get("client_ip")
        if ip and ip not in {c["ip"] for c in spf_client_ips}:
            spf_client_ips.append({"ip": ip, "from": rec.get("raw", "")[:120], "key": rec.get("client_ip_key", "client-ip")})
    spf_only_relay = False
    provider_edge = provider_network_for(spf_client_ips[0]["ip"]) if spf_client_ips else ""
    all_hops_relay = bool(hops) and all(h.is_webmail_relay for h in hops if h.ip)
    from_from_domain = registrable_domain((parsed.envelope.get("from", "").rsplit("@", 1)[-1] or "").strip(">"))
    if origin_ip and spf_client_ips:
        client_ip = spf_client_ips[0]["ip"]
        if (classify_ip(client_ip) == "public" or is_traceable(client_ip, allow_private=allow_private)) and client_ip != origin_ip:
            origin_host_domain = registrable_domain((hops[0].from_host or hops[0].by_host or "")) if hops else ""
            if origin_host_domain and (origin_host_domain == from_from_domain or origin_host_domain.endswith("." + from_from_domain)):
                origin_ip = client_ip
                origin_hop = None
                for c in candidates:
                    c["preferred_note"] = "lowest hop was in the sender's own domain (self-written, forgeable) → preferring the authenticating client-ip="
    if origin_ip is None and spf_client_ips:
        first = spf_client_ips[0]["ip"]
        relay_org = relay_org_for(*[h.by_host for h in hops], *[h.from_host for h in hops])
        provider_edge = provider_network_for(first)
        _ = provider_edge
        ip_hops = [h for h in hops if h.ip]
        all_hops_relay = bool(ip_hops) and all(h.is_webmail_relay for h in ip_hops)
        if provider_edge and all_hops_relay:
            # THE brief's core case — pure webmail compose. The client-ip= that
            # authenticated is the provider's own edge network (Google/Microsoft
            # space), so it can only ever tell us *which provider* handled the
            # message. We refuse to treat it as the sender's address, record it as
            # context, and continue to the fallback ladder (3a/3b/3c) instead.
            candidates.append({"hop": None, "ip": first, "role": "provider_edge", "usable": False,
                               "org": provider_edge, "note": "context only — not attributable to the sender"})
            origin_ip = None
        elif classify_ip(first) == "public" or is_traceable(first, allow_private=allow_private):
            origin_ip, origin_hop = first, None
            if hops and all(h.is_webmail_relay for h in hops if h.ip):
                # client-ip is real but its *network location* is all we can geolocate:
                # the composing client's egress, not a home line attribution guarantee.
                spf_only_relay = True
                candidates.append({"hop": None, "ip": first, "role": "connecting_client_via_spf", "usable": True,
                                   "org": relay_org})
                signals.append(RiskSignal("origin_webmail_relay", 1, 42,
                                          explanation=f"From-domain sends via {relay_org or 'a webmail provider'}; the only IP retained is the client-ip "
                                                      f"from authentication headers ({first}) — that is the *connecting machine*, not a guaranteed home line",
                                          source="resolve_origin"))
        else:
            candidates.append({"hop": None, "ip": first, "role": "spf_client_ip_nontraceable", "usable": False})

    # ── 3. genuinely unrecoverable?  ─────────────────────────────────────
    from_sender: list[dict[str, Any]] = []
    infra: list[dict[str, Any]] = []
    messageid_notes: list[str] = []
    rdns_host = ""

    finding = OriginFinding(notes=skipped[:8], candidates=candidates)

    if origin_ip:
        finding.source_kind = "spf_client_ip" if spf_only_relay or origin_hop is None else "received_hop"
        finding.status = "resolved" if not spf_only_relay else "fallback"
        finding.ip = origin_ip
        finding.ip_role = "sender_machine_or_open_relay"
        finding.hop_sequence = origin_hop
        finding.confidence = 78.0 if finding.source_kind == "spf_client_ip" else 82.0
        finding.notes = (finding.notes or []) + [
            f"origin taken from {'Authentication-Results/Received-SPF client-ip=' if origin_hop is None else f'Received hop #{origin_hop} (oldest usable)'}",
            "an 'open proxy/VPN/relay' is indistinguishable from a laptop here — flagged, not assumed",
        ]
        signals.append(RiskSignal("origin_direct_host", -1, 40,
                                  explanation=f"sender-side IP {origin_ip} recovered from headers — real traceable network, not just a relay",
                                  source="resolve_origin"))
    elif prefer in {"auto", "infrastructure"}:
        # (a) trace the phishing infrastructure instead
        infra = _trace_urls(ctx, allow_private=allow_private)
        if provider_edge and not infra:
            # nothing at all: not even a lure link to trace
            finding.source_kind = "unrecovered"
            finding.status = "unrecovered"
            finding.confidence = 0.0
            finding.fallbacks_used.append(f"provider_edge_context({provider_edge})")
            finding.notes.append(
                f"only {provider_edge} relay/edge IPs present (74.125.0.0/16-class space) — the composing device's address is "
                f"NOT in this message; geolocating the relay tells you where {provider_edge} peered, not where the sender was")
            signals.append(RiskSignal("origin_webmail_relay", 1, 60,
                                      explanation=f"sender sent via {provider_edge} webmail with no client IP retained anywhere → origin UNRECOVERABLE by design; confidence lowered (rule 5)",
                                      source="resolve_origin"))
            finding.ip, finding.ip_role = spf_client_ips[0]["ip"], "provider_edge"
            finding.status, finding.confidence = "degraded", 12.0
            finding.source_kind = "webmail_relay_only"
        elif infra:
            finding.source_kind = "phishing_infrastructure"
            finding.status = "fallback"
            finding.ip = infra[0]["ip"]
            finding.ip_role = "phishing_server"
            finding.confidence = 62.0
            finding.fallbacks_used.append("phishing_infrastructure")
            signals.append(RiskSignal("lure_domain_infra", 1, 65,
                                      explanation=f"sender mailbox IP is hidden but the linked lure host {infra[0]['host']} resolves to {infra[0]['ip']} — "
                                                  f"that infrastructure is attacker-side and is what we can actually trace",
                                      source="resolve_origin"))
            finding.notes.append("the mailbox-sending IP is unrecoverable; the *lure server* IP below belongs to the attacker's hosting, which is usually fully resolvable")
            signals.append(RiskSignal("origin_webmail_relay", 1, 55,
                                      explanation="no usable sender IP in any Received: hop (webmail-only chain) → falling back to phishing-infrastructure trace",
                                      source="resolve_origin"))
        else:
            finding.source_kind = "unrecovered"
            finding.status = "unrecovered"
            finding.confidence = 0.0
            signals.append(RiskSignal("origin_unrecovered", 0, 0,
                                      explanation="sender origin IP unrecoverable from headers and no resolvable linked infrastructure — geolocation will be reported as unknown, not guessed",
                                      source="resolve_origin"))
    else:
        finding.source_kind = "unrecovered"
        finding.status = "unrecovered"

    # (b) Message-ID internal hostname leak
    if parsed.message_id_host and not skip_rdns:
        ips, err = dns_a(parsed.message_id_host, timeout=2.5)
        public_ips = [i for i in ips if classify_ip(i) == "public"] if ips else []
        ptr, _ = ("", "")
        if public_ips:
            ptr, _ = reverse_dns(public_ips[0], timeout=2.0)
            rdns_host = ", ".join(ptr[:2]) or "no PTR"
        messageid_notes.append(
            f"Message-ID host '{parsed.message_id_host}': {'A→' + ','.join(ips) if ips else 'no A record (' + (err or 'n/a') + ')'}"
            + (f", rDNS→{rdns_host}" if rdns_host else "")
        )
        if public_ips and not origin_ip:
            finding.source_kind = finding.source_kind or "messageid_rdns"
            finding.fallbacks_used.append("messageid_hostname")
            finding.confidence = max(finding.confidence, 0.0)
            signals.append(RiskSignal("messageid_hostname_leak", 1, 55,
                                      explanation=f"Message-ID embeds hostname '{parsed.message_id_host}' resolving to {public_ips[0]} — provider-side hostname leak, low attribution value",
                                      source="resolve_origin"))
        elif not public_ips and parsed.message_id_host:
            finding.fallbacks_used.append("messageid_hostname(none)")
            signals.append(RiskSignal("messageid_hostname_leak", 1, 20,
                                      explanation=f"Message-ID hostname '{parsed.message_id_host}' present but unresolvable publicly — leak noted, no location value",
                                      source="resolve_origin"))

    # (c) timezone offset hint
    tz = tz_hint(parsed.tz_minutes)
    if tz.get("present"):
        finding.fallbacks_used.append(f"date_tz_offset({tz['offset']})")
        finding.notes.append(f"Date offset {tz['offset']} → soft hint: {tz['candidate_region']} — treated as {tz['strength']} confidence, never as a pin")
        signals.append(RiskSignal("tz_hint", 1, 22,
                                  explanation=f"Date-header offset {tz['offset']} is consistent with {tz['candidate_region']} (soft signal: client-configurable, trivially spoofable)",
                                  source="resolve_origin"))

    # (d)/(e) availability notes — surfaced, never auto-invoked. The numbers here are the
    # real weights, not a rounded reassurance: (e) is one of the lowest-tier factors and is
    # absent from risk.classify()'s strong-indicator set, so style can never convict alone.
    finding.notes.append("fallback (d) tracking-pixel reply: available via redact_reply (human-sends-only, "
                         "case confidence stays capped while origin is unrecovered); "
                         "(e) LLM writing-style analysis: llm_style_indicator, weight 0.80, never a "
                         "'strong indicator' in classify() — so style alone cannot reach MALICIOUS")

    ctx.state["origin"] = finding.as_dict()
    ctx.state["origin_confidence_ceiling"] = finding.confidence
    ctx.state["phishing_infra"] = infra
    ctx.state["messageid_notes"] = messageid_notes

    data = {
        "finding": finding.as_dict(),
        "hop_candidates": candidates,
        "spf_client_ips": spf_client_ips,
        "phishing_infrastructure": infra,
        "messageid_notes": messageid_notes,
        "tz_hint": tz,
        "skipped_hops": skipped[:12],
    }
    summary = (f"origin={origin_ip or 'UNRECOVERABLE'} kind={finding.source_kind} "
               f"confidence_ceiling={finding.confidence:.0f}%"
               + (f" | infra={infra[0]['ip']} ({infra[0].get('host','')})" if infra else ""))
    return ToolResult(tool="resolve_origin", ok=True, summary=summary, data=data, signals=signals)


# ─────────────────────────────────────────────────────────────────────────────
def _trace_urls(ctx: ToolContext, *, allow_private: bool) -> list[dict[str, Any]]:
    """Resolve the hosts the message actually points at, so we can trace the
    *lure server* when the mailbox IP is unrecoverable (fallback 3a).

    Two privacy/ethics rules baked in:
      * known-good brand domains are dropped **before** any DNS query — resolving
        paypal.com and then geolocating its CDN would attribute a legitimate
        company's infrastructure to the attacker (and leak the case to GeoIP
        providers);
      * ≤3 lookups × 2.5s, so the tool stays inside its 15s hard cap (SAFETY #5)."""
    url_result = ctx.state.get("extract_urls")
    hosts: list[str] = []
    if url_result is not None:
        for u in url_result.data.get("urls", []) or []:
            for cand in (u.get("registrable_domain"), u.get("host")):
                if cand and cand not in hosts:
                    hosts.append(cand)
        # IP-literal links need no DNS at all — they are already the infra address
        for u in url_result.data.get("urls", []) or []:
            if u.get("is_ip_literal") and u.get("host") and u["host"] not in hosts:
                hosts.append(u["host"])
    else:
        from urllib.parse import urlparse

        from ..evidence.eml import extract_url_pairs

        for pair in extract_url_pairs(ctx.parsed.html_body, ctx.parsed.text_body)[:8]:
            try:
                h = urlparse(pair["url"]).hostname
            except ValueError:
                h = None
            if h and h not in hosts:
                hosts.append(h)

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    lookups = 0
    for host in hosts:
        if not host or host in seen:
            continue
        seen.add(host)
        org = registrable_domain(host)
        if org and org != host and _is_known_good(org):
            continue                     # legit brand infra → never used as "attacker" origin
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            ip = host
        else:
            if _is_known_good(host):
                continue
            if lookups >= 3:
                continue
            lookups += 1
            ips, _err = dns_a(host, timeout=2.5)
            ip = next((i for i in ips if classify_ip(i) == "public"), (ips[0] if ips else None))
        if not ip or not is_traceable(ip, allow_private=allow_private):
            continue
        out.append({"ip": ip, "host": host, "registrable_domain": org or host,
                    "note": "linked lure/redirect infrastructure"})
    return out


def _is_known_good(domain: str) -> bool:
    from ..evidence.eml import BRANDS

    for spec in BRANDS.values():
        for d in spec["domains"]:
            if domain == d or domain.endswith("." + d):
                return True
    return False
