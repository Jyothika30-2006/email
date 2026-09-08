"""TOOL 1 — parse_headers: extract and walk every Received: hop, parse SPF/DKIM/
DMARC from Authentication-Results and Received-SPF, mine the Message-ID, note the
Date offset, list attachments. No network calls: this tool is pure static parsing,
so it always works air-gapped.
"""
from __future__ import annotations

from typing import Any

from ..evidence.eml import (addr_of, brand_for_text, display_name_of, domain_of,
                            parse_dkim_signature, tz_hint)
from ..models import RiskSignal
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "detail": {"type": "string", "enum": ["compact", "full"],
                   "description": "how much of the hop chain to return"},
    },
}

BAD_AUTH = {"fail", "permerror", "temperror"}
SOFT_AUTH = {"softfail", "neutral", "none"}


@register()
@tool_meta(name="parse_headers", parameters=PARAMS,
           llm_hint="Run this first (after hash_evidence). Its output feeds resolve_origin; do not re-run it.")
def tool_parse_headers(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Parse .eml structure: all Received hops (oldest→newest), auth results, Message-ID, date offset, attachments."""
    parsed = ctx.parsed
    signals: list[RiskSignal] = []
    detail = (args.get("detail") or "compact").lower()

    hops_view = [h.as_dict() for h in parsed.hops]
    if detail == "compact":
        hops_view = [{k: v for k, v in h.items() if k != "raw"} for h in hops_view]

    # ── authentication results ────────────────────────────────────────────
    auth = {"spf": "", "dkim": "", "dmarc": "", "client_ips": [], "sources": []}
    for rec in parsed.auth_results:
        for mech in ("spf", "dkim", "dmarc"):
            if rec.get(mech):
                auth[mech] = rec[mech]
        if rec.get("client_ip"):
            auth["client_ips"].append({"ip": rec["client_ip"], "key": rec.get("client_ip_key", "client-ip"),
                                       "from": "Authentication-Results"})
        auth["sources"].append({k: v for k, v in rec.items() if k != "raw"})
    for rec in parsed.received_spf:
        if rec.get("result") and not auth["spf"]:
            auth["spf"] = rec["result"]
        if rec.get("client_ip"):
            auth["client_ips"].append({"ip": rec["client_ip"], "key": "client-ip", "from": "Received-SPF"})
        auth["sources"].append({"received_spf": rec})

    for mech in ("spf", "dkim", "dmarc"):
        val = auth.get(mech, "")
        if val in BAD_AUTH:
            weight = {"spf": 100, "dmarc": 95, "dkim": 85}[mech]
            factor = "spf_fail" if mech == "spf" else f"{mech}_fail"
            signals.append(RiskSignal(factor, 1, weight,
                                      explanation=f"{mech.upper()}={val} — the message failed cryptographic/mailflow authentication",
                                      source="parse_headers"))
        elif val in SOFT_AUTH:
            factor = "spf_soft_fail" if mech == "spf" else "spf_none_temperror"
            why = "failed/soft-fail" if val in {"softfail"} else ("not signed at all" if val == "none" else "verification temporarily errored")
            signals.append(RiskSignal(factor, 1, {"none": 30, "neutral": 35, "temperror": 40, "permerror": 70, "softfail": 55}.get(val, 40),
                                      explanation=f"{mech.upper()}={val} — {why}; weak authentication posture for the claimed sender",
                                      source="parse_headers"))
    if all(auth.get(m) == "pass" for m in ("spf", "dkim", "dmarc")):
        # A free webmail mailbox that passes SPF/DKIM/DMARC proves the *mailbox* is
        # authentic — not that the message is legitimate. That is precisely the BEC
        # / account-compromise case, so the mitigation is deliberately halved there.
        from ..evidence.eml import RELAY_DOMAINS, domain_of as _dom

        from_dom = _dom(addr_of(parsed.envelope.get("from", "")))
        is_free_webmail = any(from_dom == d or from_dom.endswith("." + d) for d in RELAY_DOMAINS
                               if d in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "live.com", "icloud.com", "proton.me", "pm.me"})
        strength = 45.0 if is_free_webmail else 100.0
        why = ("SPF/DKIM/DMARC pass — but on a FREE WEBMAIL domain, which proves only that a real "
               "mailbox sent this, not that the request is genuine (classic account-abuse/BEC case)"
               if is_free_webmail else
               "SPF, DKIM and DMARC all pass for the From-domain — sender domain was cryptographically attested")
        signals.append(RiskSignal("auth_pass", -1, strength, explanation=why, source="parse_headers"))

    # ── hop-level signals ─────────────────────────────────────────────────
    if not parsed.hops:
        signals.append(RiskSignal("sandbox_unavailable", 1, 40,
                                  explanation="no Received: headers at all — origin tracing impossible; verdict rests on other evidence",
                                  source="parse_headers"))
    else:
        oldest = parsed.hops[0]
        if oldest.is_webmail_relay:
            signals.append(RiskSignal("origin_webmail_relay", 1, 45,
                                      explanation=f"oldest hop is a {oldest.relay_org} relay ({oldest.by_host or oldest.from_host}) — the composing client's IP is not in this header chain",
                                      source="parse_headers"))

    # ── display-name / brand + reply-to checks ────────────────────────────
    from_raw = parsed.envelope.get("from", "")
    brand = brand_for_text(display_name_of(from_raw))
    from_domain = domain_of(addr_of(from_raw))
    if brand and from_domain and not _domain_is_brand_official(from_domain, brand):
        signals.append(RiskSignal("display_name_spoof", 1, 70,
                                  explanation=f"display name claims “{brand}” but the sender domain is {from_domain}",
                                  source="parse_headers"))
    reply_to = parsed.envelope.get("reply-to", "")
    if reply_to and domain_of(addr_of(reply_to)) and domain_of(addr_of(reply_to)) != from_domain:
        signals.append(RiskSignal("reply_to_mismatch", 1, 70,
                                  explanation=f"Reply-To points at {domain_of(addr_of(reply_to))} while From is {from_domain} — replies would be diverted",
                                  source="parse_headers"))

    # ── Message-ID leak + date offset ─────────────────────────────────────
    style_notes = []
    if parsed.message_id_host:
        style_notes.append(f"Message-ID embeds hostname '{parsed.message_id_host}' (potential internal-hostname leak)")
    tz = tz_hint(parsed.tz_minutes)
    if tz.get("present"):
        style_notes.append(f"Date offset {tz['offset']} → soft regional hint: {tz['candidate_region']} ({tz['strength']} confidence)")

    ctx.state.setdefault("dkim", parse_dkim_signature(",".join(parsed.headers.get("dkim-signature", []))))
    attachments = [{k: v for k, v in a.items() if k != "payload"} for a in parsed.attachments]
    if attachments:
        risky = [a for a in attachments if _risky_ext(a["filename"])]
        if risky:
            signals.append(RiskSignal("attachment_risky_ext", 1, 65,
                                      explanation="attachment(s) with executable/office macro-capable extensions: "
                                                  + ", ".join(a["filename"] for a in risky) + " (not yet inspected)",
                                      source="parse_headers"))
        else:
            signals.append(RiskSignal("attachment_present", 1, 30,
                                      explanation=f"{len(attachments)} attachment(s) present: " + ", ".join(a["filename"] for a in attachments),
                                      source="parse_headers"))

    body_preview = (parsed.text_body or parsed.html_body or "")[:600]
    if brand_for_text(body_preview) and brand and not _domain_is_brand_official(from_domain, brand):
        pass  # handled by extract_urls for the actual links

    data = {
        "envelope": {k: v for k, v in parsed.envelope.items()},
        "hop_count": len(parsed.hops),
        "hops": hops_view,
        "hop_raw": [h.raw for h in parsed.hops] if detail == "full" else [],
        "authentication": auth,
        "message_id": parsed.message_id,
        "message_id_host": parsed.message_id_host,
        "date": parsed.date_raw,
        "tz_hint": tz,
        "dkim_signature": ctx.state["dkim"],
        "attachments": attachments,
        "structural_notes": parsed.notes,
        "analysis_notes": style_notes,
    }
    ctx.state["parse_headers_data"] = data

    summary_bits = [f"{len(parsed.hops)} hop(s) walked oldest→newest",
                    f"SPF={auth.get('spf') or 'n/a'} DKIM={auth.get('dkim') or 'n/a'} DMARC={auth.get('dmarc') or 'n/a'}"]
    if parsed.tz_minutes:
        summary_bits.append(f"date offset {tz['offset']}")
    return ToolResult(tool="parse_headers", ok=True, summary="; ".join(summary_bits),
                      data=data, signals=signals)


# ── small local helpers (kept out of eml.py for clarity) ────────────────────
def brand_domains(from_domain: str, brand: str) -> set[str]:
    return {from_domain}


def _domain_is_brand_official(domain: str, brand: str) -> bool:
    from ..evidence.eml import brand_domains_for

    official = brand_domains_for(brand)
    return any(domain == d or domain.endswith("." + d) for d in official)


def _risky_ext(filename: str) -> bool:
    from ..evidence.eml import RISKY_EXTENSIONS

    low = (filename or "").lower()
    return any(low.endswith(ext) for ext in RISKY_EXTENSIONS)
