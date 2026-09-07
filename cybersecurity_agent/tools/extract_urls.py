"""TOOL 5 — extract_urls: every hyperlink in the message, with the *visible* text
kept next to the *actual* target so we can compare them.

Strong phishing signals here (each with its own factor weight in risk.py):
  * brand mismatch  — anchor says "https://paypal.com" but href points elsewhere;
  * homoglyph / punycode look-alikes — "РАYРАL" (Cyrillic) normalizes to a real
    brand name while the real host is not that brand;
  * digit-substitution typosquats ("paypa1.com") via Levenshtein ≤2 against the
    claimed brand's domain;
  * IP-literal URLs, plain http://, shorteners, and a credential-harvest URL shape
    (`/login?redirect_uri=`, `action="...php"` forms);
  * urgency vocabulary in body/subject (soft: phrasing alone never decides a verdict).
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

from ..evidence.eml import (BRANDS, CRED_HARVEST_PATTERNS, HOMOGLYPHS, LOOKALIKE_DIGITS,
                            SHORTENERS, SUSPICIOUS_TLDS, URGENCY_PATTERNS,
                            brand_for_text, extract_url_pairs, has_homoglyphs,
                            normalize_homoglyphs, registrable_domain)
from ..models import RiskSignal, UrlEvidence
from ..net import classify_ip
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS: dict[str, Any] = {
    "type": "object",
    "properties": {"limit": {"type": "integer", "description": "max URLs to analyze (default 12)"}},
}


@register()
@tool_meta(name="extract_urls", parameters=PARAMS,
           llm_hint="Brand-domain mismatch and homoglyph domains are among the strongest signals — if present, say so explicitly.")
def tool_extract_urls(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Extract hyperlinks from the email body and compare visible branding vs actual target domains."""
    parsed = ctx.parsed
    limit = int(args.get("limit") or 12)
    signals: list[RiskSignal] = []

    pairs = extract_url_pairs(parsed.html_body, parsed.text_body)[: max(1, limit)]
    evidences: list[dict[str, Any]] = []
    url_brands: set[str] = set()
    mismatch_count = 0

    for pair in pairs:
        raw = pair["url"].strip()
        if raw.lower().startswith(("mailto:", "tel:", "javascript:")):
            evidences.append({"url": raw[:160], "note": f"non-http scheme ({raw.split(':', 1)[0]})", "skip": True})
            if raw.lower().startswith("javascript:"):
                signals.append(RiskSignal("url_domain_age_unknown", 1, 80,
                                          explanation="javascript: URL present — classic click-jacking/redirect trick",
                                          source="extract_urls"))
            continue
        try:
            u = urlparse(raw if re.match(r"^https?://", raw, re.I) else "http://" + raw)
        except ValueError:
            continue
        host = (u.hostname or "").lower()
        if not host:
            continue
        ev = UrlEvidence(url=raw, scheme=u.scheme or "http", host=host, visible_text=(pair.get("visible_text") or "")[:160])

        ev.uses_http = (u.scheme or "").lower() == "http"
        ev.is_ip_literal = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)) or host.startswith("[")
        ev.punycode = host.startswith("xn--") or ".xn--" in host
        ev.is_shortener = registrable_domain(host) in SHORTENERS
        reg = registrable_domain(host)

        # ── claimed brand: from visible text, else from the URL path/anchor ──
        shown = (ev.visible_text or "") + " " + (u.path or "")[:120]
        claimed = brand_for_text(shown) or brand_for_text(parsed.envelope.get("subject", ""))
        ev.claimed_brand = claimed
        if claimed:
            url_brands.add(claimed)
            official = BRANDS.get(claimed, {}).get("domains", set())
            matches = any(host == d or host.endswith("." + d) for d in official)
            ev.host_matches_brand = matches
            if not matches:
                ev.brand_mismatch = True
                mismatch_count += 1
                ev.note = f"visible branding says ‘{claimed}’ but the link host is {reg}"

        # ── homoglyphs / punycode / digit-substitution typosquat ──────────
        if has_homoglyphs(host) or ev.punycode:
            decoded = unquote(host)
            norm = normalize_homoglyphs(decoded)
            ev.normalized_host = norm
            ev.homoglyph_risk = True
            ev.note = (ev.note + "; " if ev.note else "") + f"host contains non-ASCII look-alike characters → normalizes to “{norm}”"
        else:
            approx = normalize_homoglyphs(host).lower()
            for ch, repl in LOOKALIKE_DIGITS.items():
                approx = approx.replace(ch, repl)
            for brand, spec in BRANDS.items():
                for d in spec["domains"]:
                    if d in {"amzn.to", "goo.gl"}:
                        continue
                    if approx == d or (approx != d and _edit_distance_le(approx, d, 1) and brand_for_text(shown)):
                        ev.homoglyph_risk = True
                        ev.normalized_host = approx
                        ev.note = (ev.note + "; " if ev.note else "") + f"typosquat-shaped host “{host}” ≈ {d}"
                        break

        if ev.is_ip_literal and classify_ip(host) in {"public", "test_net", "loopback", "private"}:
            ev.note = (ev.note + "; " if ev.note else "") + "URL uses a raw IP literal instead of a hostname (no certificate, no domain reputation)"
        if reg.split(".")[-1] in SUSPICIOUS_TLDS:
            ev.note = (ev.note + "; " if ev.note else "") + f"suspicious TLD .{reg.split('.')[-1]}"

        evidences.append({**ev.as_dict(), "registrable_domain": reg})

    # ── aggregate signals ───────────────────────────────────────────────────
    if mismatch_count:
        signals.append(RiskSignal("brand_mismatch", 1, min(100, 60 + 15 * mismatch_count),
                                  explanation=f"{mismatch_count} link(s) advertise a brand whose domain they do not belong to — strong phishing indicator",
                                  source="extract_urls"))
    if any(e.get("homoglyph_risk") for e in evidences):
        signals.append(RiskSignal("homoglyph_domain", 1, 95,
                                  explanation="look-alike / typosquatted host in at least one link (Unicode homoglyph or digit substitution)",
                                  source="extract_urls"))
    if any(e.get("is_ip_literal") for e in evidences):
        signals.append(RiskSignal("ip_literal_url", 1, 70,
                                  explanation="at least one link targets a bare IP address — no TLS identity, no domain reputation available",
                                  source="extract_urls"))
    if any(e.get("uses_http") for e in evidences):
        signals.append(RiskSignal("http_url", 1, 45,
                                  explanation="credential-relevant link served over plain http:// (major brands force https)",
                                  source="extract_urls"))
    if any(e.get("is_shortener") for e in evidences):
        signals.append(RiskSignal("shortener", 1, 50,
                                  explanation="URL shortener hides the true destination (legitimate in marketing, common in lures)",
                                  source="extract_urls"))
    if any(str(e.get("registrable_domain", "")).rsplit(".", 1)[-1] in SUSPICIOUS_TLDS for e in evidences):
        signals.append(RiskSignal("suspicious_tld", 1, 45, explanation="linked domain uses a cheap/abuse-heavy TLD", source="extract_urls"))

    # form-based credential harvesting
    harvest = bool(re.search(r"(?is)<form[^>]+action", parsed.html_body or "")) and bool(
        re.search(r"(?is)type=[\"']password[\"']", parsed.html_body or ""))
    if harvest or any(re.search(p, (parsed.text_body or "") + " " + (parsed.html_body or ""), re.I) for p in CRED_HARVEST_PATTERNS):
        signals.append(RiskSignal("credential_harvest_form", 1, 92 if harvest else 70,
                                  explanation="password field / credential-harvest URL shape present in the message body"
                                  if harvest else "body matches credential-harvest phrasing (/login?redirect_uri=…, “verify your password”)",
                                  source="extract_urls"))

    # BEC-shaped tactic vocabulary (soft by design: weight 0.7–0.9, never decisive)
    low_body = (parsed.text_body or "").lower()[:5000]
    if re.search(r"do not reply|don.t reply to this|no reply needed|do not (?:share|tell|cc)|without (?:informing|telling) (?:them|your staff)|speak of this to no one|do not attempt to (?:identify|contact)", low_body, re.I):
        signals.append(RiskSignal("contact_isolation_request", 1, 55,
                                  explanation="message asks the recipient to isolate the thread (no reply / tell nobody) — a pressure tactic, common in fraud and also in legitimate sensitive mail",
                                  source="extract_urls"))
    if re.search(r"remittance|inward funds|held at our clearing desk|transfer (?:approval|authorization)|beneficiary details|next of kin|settlement desk", low_body, re.I):
        signals.append(RiskSignal("money_request_context", 1, 60,
                                  explanation="money-movement framing (remittance/clearing/settlement/beneficiary) with no verifiable institutional identity — the classic BEC shape",
                                  source="extract_urls"))

    # urgency vocabulary (soft)
    joined = ((parsed.envelope.get("subject", "") + " " + (parsed.text_body or ""))[:4000])
    if any(re.search(p, joined, re.I) for p in URGENCY_PATTERNS):
        signals.append(RiskSignal("urgency_language", 1, 40,
                                  explanation="urgency/threat-of-loss vocabulary in subject/body (soft signal: common in marketing too)",
                                  source="extract_urls"))
    # link text vs href mismatch even when no brand is claimed
    for e in evidences:
        vis, host = (e.get("visible_text") or "").lower(), (e.get("host") or "").lower()
        if vis and "://" in vis:
            vis_host = registrable_domain(re.sub(r"^https?://", "", vis).split("/")[0])
            if vis_host and host and vis_host != e.get("registrable_domain") and vis_host not in str(host):
                signals.append(RiskSignal("link_text_mismatch", 1, 65,
                                          explanation=f"anchor text shows “{vis_host}” while the href resolves to “{e.get('registrable_domain')}”",
                                          source="extract_urls"))
                break

    # URL hosts for the pipeline (reputation + origin fallback consume these)
    hosts = sorted({e["registrable_domain"] for e in evidences if e.get("registrable_domain")})
    ctx.state["url_hosts"] = hosts
    ctx.state["url_evidences"] = evidences
    summary = (f"{len(evidences)} link(s) analyzed; {mismatch_count} brand/domain mismatch; "
               f"{sum(1 for e in evidences if e.get('homoglyph_risk'))} look-alike host(s); "
               f"{sum(1 for e in evidences if e.get('is_ip_literal'))} IP-literal")
    return ToolResult(tool="extract_urls", ok=True, summary=summary,
                      data={"urls": evidences, "domains": hosts, "url_brands": sorted(url_brands),
                            "html_form_with_password": harvest},
                      signals=signals)


def _edit_distance_le(a: str, b: str, max_dist: int) -> bool:
    """Bounded Levenshtein (only used for typosquat checks, so tiny inputs)."""
    if abs(len(a) - len(b)) > max_dist:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > max_dist:
            return False
        prev = cur
    return prev[-1] <= max_dist
