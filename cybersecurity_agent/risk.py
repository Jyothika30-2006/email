"""Ensemble risk fusion + confidence math.

This is the "not a single rule" part of the pitch. Every tool contributes
`RiskSignal(factor, direction, strength, weight, explanation)` objects; this module
combines them into one 0–100 risk score, a confidence %, and a verdict, with
documented weights (see docs/FORENSIC_METHODOLOGY.md). Both numbers are computed
*deterministically* from the evidence — the LLM narrates and reasons about them but
cannot talk its way out of the arithmetic (a hackathon judge can rerun the code).

Design notes
------------
* Mitigating signals (direction<0) pull the score down multiplicatively, because a
  `dmarc=pass` on a trusted brand is real evidence, and dropping it into the same
  weighted mean would let a strong signal be "averaged away".
* `corroboration` gives a modest boost when ≥3 *independent* tool families agree —
  the whole point of an ensemble.
* Corroboration is disabled when the only signals come from a single tool call, so
  no one tool can inflate the score by repeating itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import RiskSignal

# Factor weights: 0.0–3.0. Higher = more trusted by DFIR practice.
FACTOR_WEIGHTS: dict[str, float] = {
    # authentication / header forensics
    "spf_fail": 3.0,
    "spf_soft_fail": 1.6,
    "spf_none_temperror": 1.0,
    "dmarc_fail": 2.8,
    "dkim_fail": 2.4,
    "auth_pass": -2.6,            # mitigating
    "arc_pass": -0.4,
    # mail infrastructure trust
    "origin_open_proxy": 1.4,
    "origin_webmail_relay": 1.2,
    "origin_unrecovered": 0.0,
    "origin_direct_host": -0.6,
    "tor_exit": 2.2,
    "messageid_hostname_leak": 1.0,
    "tz_hint": 0.3,
    # URL / brand forensics
    "brand_mismatch": 3.0,
    "homoglyph_domain": 3.2,
    "ip_literal_url": 1.8,
    "http_url": 0.8,
    "shortener": 0.6,
    "suspicious_tld": 1.0,
    "url_domain_age_unknown": 0.2,
    "brand_match": -1.0,
    "safe_domain_reputation": -1.4,
    "urgency_language": 1.0,
    "credential_harvest_form": 2.8,
    "attachment_present": 0.6,
    "attachment_risky_ext": 1.4,
    "clean_static_scan": -0.35,   # a clean static scan is a WEAK negative (see comment in static_file_scan)
    # file forensics (sandboxed static analysis)
    "file_type_mismatch": 2.8,
    "high_entropy": 2.0,
    "embedded_macro": 2.4,
    "pdf_active_content": 2.2,
    "known_malware_hash": 3.4,
    "evidence_integrity_failure": 3.4,
    "av_detections": 3.2,
    "av_clean": -1.0,
    "sandbox_unavailable": 0.0,
    # reputation
    "abuse_reports": 2.0,
    "reputation_skipped": 0.0,
    # agent behaviour integrity (meta-signals)
    "prompt_injection_attempt": 2.0,
    "invented_tool_request": 2.4,
    "tool_timeout": 0.4,
    "human_denied_scan": 0.8,
    "llm_style_indicator": 0.8,   # (e) low weight by design — never decisive
    "link_text_mismatch": 1.6,
    "lure_domain_infra": 1.4,               # attacker infrastructure we CAN trace, while the mailbox IP is hidden
    "contact_isolation_request": 0.7,       # "don't reply/notify nobody/talk to no one" — a tactic, not a crime
    "money_request_context": 0.9,           # transfer/payment framing without any brand claim (BEC-shaped)
    "secrecy_pressure": 0.8,
    "reply_to_mismatch": 1.8,
    "display_name_spoof": 1.6,
    "new_domain": 1.2,
    "tracking_pixel_captured": 1.6,
}

# How much confidence each origin source kind can support (ceiling for geoloc).
ORIGIN_CONFIDENCE_CEILING: dict[str, float] = {
    "received_hop": 82.0,       # real client IP in an inbound MTA hop — best case
    "spf_client_ip": 78.0,      # Authentication-Results/Received-SPF client-ip=
    "phishing_infrastructure": 62.0,  # traces the *lure server*, not the mailbox
    "messageid_rdns": 34.0,     # hosting context of a leaked internal hostname
    "unrecovered": 0.0,
}

VERDICT_ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


@dataclass
class RiskState:
    """Mutable, ordered log of every signal the agent has accumulated."""
    signals: list[RiskSignal] = field(default_factory=list)
    score: float = 0.0
    last_delta: float = 0.0
    last_reason: str = ""

    def add_all(self, signals: Iterable[RiskSignal]) -> tuple[float, str]:
        before = self.score
        self.signals.extend(signals)
        self.score = fuse(self.signals)
        self.last_delta = self.score - before
        return self.last_delta, self._explain_delta()

    def _explain_delta(self) -> str:
        if abs(self.last_delta) < 0.5:
            return "no material change"
        arrow = "▲" if self.last_delta > 0 else "▼"
        return f"{arrow} {self.last_delta:+.1f} pts"

    def as_dicts(self) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.signals]


def fuse(signals: list[RiskSignal]) -> float:
    """Log-odds fusion → 0..100 risk score.

    Why log-odds instead of a weighted mean: a mean lets *one* strong signal be
    diluted by four weak ones, and lets three weak ones fake a high score.
    score = 100·σ((Σ wᵢ·sᵢ − 2.4)/1.8) means each independent signal multiplies the
    odds, so risk grows with *corroboration* and saturates near 100 only when many
    heavyweights actually fired. Mitigating evidence scales positive mass down but
    can never drive it below 15% of its value (a "clean" static scan cannot
    launder a phishing kit).
    """
    pos = 0.0
    mitig = 1.0
    families: set[str] = set()
    for sig in signals:
        weight = FACTOR_WEIGHTS.get(sig.factor, sig.weight)
        if weight == 0:
            continue
        strength = max(0.0, min(100.0, sig.strength)) / 100.0
        if weight < 0:
            mitig *= 1.0 + weight * strength          # weight negative → factor < 1
            continue
        pos += abs(weight) * strength
        families.add(sig.source or sig.factor)
    if pos <= 0:
        return 0.0
    pos = max(pos * max(0.15, min(1.0, mitig)), 0.15 * pos)
    pos *= 1.0 + 0.05 * max(0, len(families) - 1)      # corroboration bonus (capped)
    import math

    logit = (pos - 2.4) / 1.8
    logit = max(-6.0, min(6.0, logit))
    score = 100.0 / (1.0 + math.exp(-logit))
    return round(max(0.0, min(99.0, score)), 1)


def confidence_score(
    *,
    origin_ceiling: float,
    origin_kind: str,
    origin_status: str = "none",
    geoloc_confidence: float,
    tool_coverage: int,
    expected_tools: int,
    corroboration_families: int,
    had_timeouts: int = 0,
) -> float:
    """Confidence = how much of the evidence we *wanted* we actually got.

    Never derived from how scary the email is: a scary email with no origin data
    must be reported with LOW confidence even when the risk score is high — that
    asymmetry is the honesty property the spec asks for.
    """
    coverage = (tool_coverage / expected_tools) if expected_tools else 1.0
    # Provenance discount: geolocating an IP that only tells us about *attacker
    # infrastructure* (or that we never recovered at all) cannot support the same
    # confidence as a genuine sender-side origin. This is the arithmetic version of
    # "never fabricate certainty" (system-prompt rule 5).
    provenance_factor = {"resolved": 1.0, "fallback": 0.82, "degraded": 0.68, "none": 0.45}.get(origin_status, 0.7)
    geo_part = max(geoloc_confidence, origin_ceiling) * provenance_factor
    corrob = min(1.0, 0.72 + 0.07 * max(0, corroboration_families - 1))
    base = 0.45 * geo_part + 0.30 * (100.0 * coverage) + 0.25 * (100.0 * corrob)
    penalty = 6.0 * had_timeouts
    return round(max(10.0, min(96.0, base - penalty)), 1)


def classify(score: float, signals: list[RiskSignal]) -> str:
    """Verdict thresholds. MALICIOUS additionally requires at least one
    *strong* indicator — a high score assembled only from soft hints stays
    SUSPICIOUS (avoids crying wolf on 6 mediocre signals)."""
    strong = {
        "known_malware_hash", "brand_mismatch", "homoglyph_domain", "spf_fail",
        "dmarc_fail", "av_detections", "file_type_mismatch", "pdf_active_content",
        "embedded_macro", "credential_harvest_form",
    }
    has_strong = any(s.factor in strong and s.direction > 0 and s.strength >= 45 for s in signals)
    if score >= 65 and has_strong:
        return "MALICIOUS"
    if score >= 65:
        return "SUSPICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def severity_color(score: float) -> str:
    if score >= 65:
        return "red"
    if score >= 45:
        return "dark_orange"
    if score >= 30:
        return "yellow"
    if score >= 15:
        return "cyan"
    return "green"


def summary_lines(signals: list[RiskSignal], limit: int = 12) -> list[str]:
    """Evidence bullets for the final verdict block (rule #7 of the system prompt)."""
    ranked = sorted(
        (s for s in signals if s.factor and s.explanation),
        key=lambda s: -abs(FACTOR_WEIGHTS.get(s.factor, s.weight) * (s.strength / 100.0)),
    )
    seen: set[str] = set()
    out: list[str] = []
    for s in ranked:
        key = s.factor + "|" + s.explanation[:40]
        if key in seen:
            continue
        seen.add(key)
        sign = "↑" if s.direction > 0 else ("↓" if s.direction < 0 else "•")
        out.append(f"{sign} {s.explanation}")
        if len(out) >= limit:
            break
    return out
