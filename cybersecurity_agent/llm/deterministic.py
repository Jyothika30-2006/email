"""Deterministic reasoning engine — the agent's offline brain.

Two jobs:
  1. Provide the next action when the local LLM is unavailable (or when the LLM
     produced nothing parseable), following the project's documented working flow.
     The pipeline is a *queue of whitelisted calls*; the engine may choose which
     pending tool to run next, never invent one — that is enforced by tools.dispatch.
  2. Analyze writing style/language patterns (fallback signal (e)) with cheap,
     explainable heuristics — explicitly low-confidence, never decisive.

Why keep this even with Ollama wired up: a hackathon demo must not die because a
model didn't load, and the deterministic path is the same code the LLM's tool
calls flow through — so what you demo is what actually runs.
"""
from __future__ import annotations

import re
from typing import Any

from ..models import RiskSignal

# Ordered pipeline (design doc §WORKING FLOW). Conditional steps are decided in
# next_action(), not by deleting entries.
PIPELINE: list[str] = [
    "parse_headers",
    "extract_urls",
    "resolve_origin",
    "geolocate_ip",
    "check_tor_exit",
    "check_reputation",
    "resolve_origin",        # second pass: now extract_urls' hosts make the infra fallback available
    "geolocate_ip",         # re-run so the phishing-IP geolocation is cross-validated too
    "check_reputation",     # re-run for the infra IP/domain
    "static_file_scan",     # gated by the human; skipped automatically when denied/no attachments
    "redact_reply",         # optional draft (only when origin is unrecoverable)
]


class DeterministicEngine:
    """Rule-based planner + narrator. `is_llm = False` (shown in the UI badge)."""

    is_llm = False
    name = "deterministic-engine"

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    # ── planner ───────────────────────────────────────────────────────────
    def next_action(self, ctx: Any, history: list[dict[str, Any]]) -> dict[str, Any]:
        """Return {"thought": str, "tool_call": {"name","arguments"}} or a "final"."""
        done = {h["tool"] for h in history if h.get("status") in {"✓", "⏱", "⊘", "✗"}}
        runs: dict[str, int] = {}
        for h in history:
            runs[h["tool"]] = runs.get(h["tool"], 0) + 1

        origin = dict(ctx.state.get("origin") or {})
        geoloc_ok = bool((ctx.state.get("geolocate") or {}).get("primary", {}).get("consensus", {}).get("confidence"))

        for tool in PIPELINE:
            if tool in done and not self._should_rerun(tool, runs, ctx):
                continue
            if tool not in done and runs.get(tool, 0) >= 2:
                continue
            if tool == "geolocate_ip" and not origin.get("ip") and not ctx.state.get("phishing_infra"):
                continue          # nothing to locate: recorded as a gap, not a guess
            if tool == "check_tor_exit" and not (origin.get("ip") or (ctx.state.get("phishing_infra") or [])):
                continue
            if tool == "static_file_scan":
                if not ctx.attachment_files:
                    continue
                if runs.get(tool, 0) >= 1:
                    continue
            if tool == "redact_reply" and origin.get("status") != "unrecovered":
                continue
            if tool in {"resolve_origin", "geolocate_ip", "check_reputation"} and runs.get(tool, 0) >= 1 and tool in done:
                # second pass only makes sense when new data arrived
                if tool == "resolve_origin" and origin.get("status") != "unrecovered":
                    continue
            return {"thought": self._narrate(tool, ctx, runs), "tool_call": {"name": tool, "arguments": {}}}

        return {"thought": "Evidence collection complete; synthesizing verdict from the ensemble score.",
                "final": self._final_stub(ctx)}

    def _should_rerun(self, tool: str, runs: dict[str, int], ctx: Any) -> bool:
        if tool not in {"resolve_origin", "geolocate_ip", "check_reputation"}:
            return False
        if runs.get(tool, 0) >= 2:
            return False
        origin = dict(ctx.state.get("origin") or {})
        if tool == "resolve_origin":
            return runs.get(tool, 0) == 1 and origin.get("status") == "unrecovered"
        if tool == "geolocate_ip":
            return runs.get(tool, 0) == 1 and bool(ctx.state.get("phishing_infra"))
        return runs.get(tool, 0) == 1 and runs.get("resolve_origin", 0) >= 2

    def _narrate(self, tool: str, ctx: Any, runs: dict[str, int]) -> str:
        origin = dict(ctx.state.get("origin") or {})
        nth = " (2nd pass — now that link hosts are resolved)" if runs.get(tool) else ""
        table = {
            "parse_headers": "walking every Received: hop bottom→top and reading SPF/DKIM/DMARC before trusting any IP",
            "extract_urls": "comparing visible link branding against the actual href hosts",
            "resolve_origin": f"picking the oldest non-relay IP, then client-ip= from auth headers, then fallbacks{nth}",
            "geolocate_ip": f"cross-validating 2–3 GeoIP sources; radius instead of a pin (origin ceiling {origin.get('confidence', 0):.0f}%)",
            "check_tor_exit": "querying Tor DNSEL for the candidate IP — anonymization is flagged, not condemned",
            "check_reputation": "asking AbuseIPDB/VirusTotal/Spamhaus about the IPs, domains and attachment hashes{nth}",
            "static_file_scan": "[CONFIRM_NEEDED] I want to read the attachment bytes for static analysis inside the sandbox. "
                                "Reasoning: header/URL evidence alone cannot clear an attachment; magic, entropy, OLE/PDF "
                                "structure may reveal a renamed executable. Nothing will be executed.",
            "redact_reply": f"sender IP unrecovered (webmail relay only) → offering a human-gated reply draft with optional pixel (fallback 3d)",
        }
        return table.get(tool, f"running {tool}").replace("{nth}", nth)

    def _final_stub(self, ctx: Any) -> dict[str, Any]:
        """The engine does not own verdict math (risk.py does) — this only satisfies
        the protocol shape; the controller recomputes and overrides."""
        return {"verdict": "SUSPICIOUS", "confidence": 50, "summary": "(computed by risk fusion)", "evidence": []}


# ─────────────────────────────────────────────────────────────────────────────
# fallback (e): writing-style / language analysis — cheap, explainable, LOW weight
# ─────────────────────────────────────────────────────────────────────────────
CLOSERS = {
    "kind regards": "common in Commonwealth/Nordic business mail",
    "best regards": "global business standard",
    "warm regards": "common in India/SEA business correspondence",
    "respectfully": "formal South-Asian / legal register",
    "sincerely": "formal US/UK",
    "yours faithfully": "formal UK",
    "regards only": "curt; seen in BEC pressure tactics",
}
HONORIFICS = [r"\bdear (?:sir|madam|customer|client)\b", r"\brespected (?:sir|madam|client)\b",
              r"\bdear valued\b", r"\bkindly\b", r"\balteration\b", r"\bdo the needful\b",
              r"\bat the earliest\b", r"\bimmediate acknowledgement\b", r"\bhighly confidential\b"]
PAYOUT = [r"\b(?:funds?|transfer|payment|sum of|amount)\b[^.\n]{0,60}\b(?:usd|naira|rupees|eur|pounds|dollars)\b",
          r"\bnext of kin\b", r"\bbank details\b", r"\bholding (?:bank|account)\b"]


def analyze_style(text: str, subject: str = "") -> tuple[list[RiskSignal], dict[str, Any]]:
    """Return (signals, facts). Weight per signal is 0.8 in risk.py — by design a
    style profile can nudge, never convict (rule 5's honesty requirement)."""
    body = f"{subject}\n{text or ''}"[:6000]
    signals: list[RiskSignal] = []
    facts: dict[str, Any] = {}
    if not body.strip():
        return signals, {"note": "no text body to analyze"}

    hits = {p: len(re.findall(p, body, re.IGNORECASE)) for p in HONORIFICS}
    honor = sum(hits.values())
    pay = sum(len(re.findall(p, body, re.IGNORECASE)) for p in PAYOUT)
    closers = {k: body.lower().count(k) for k in CLOSERS if k in body.lower()}
    sents = [s for s in re.split(r"(?<=[.!?\n])\s+", body) if len(s.strip()) > 1]
    avg_len = round(sum(len(s.split()) for s in sents) / max(1, len(sents)), 1)
    non_ascii_frac = round(sum(1 for ch in body if ord(ch) > 0x2100) / max(1, len(body)), 4)

    facts.update({
        "sentences": len(sents), "avg_words_per_sentence": avg_len,
        "formal_register_hits": honor, "payment_mention_hits": pay,
        "closer_style": closers, "non_ascii_ratio": non_ascii_frac,
        "exclamations": body.count("!"),
    })

    if pay >= 2 and honor >= 2:
        signals.append(RiskSignal("llm_style_indicator", 1, 45,
                                  explanation=f"style: money-transfer register ({pay} payment phrases) combined with archaic formality "
                                              f"({honor} marker(s)) — classic advance-fee/BEC pattern (soft signal, weight 0.8)",
                                  source="style-analysis"))
    elif honor >= 4:
        signals.append(RiskSignal("llm_style_indicator", 1, 28,
                                  explanation=f"style: heavy archaic-formality markers ({honor}) — inconsistent with most modern corporate templates",
                                  source="style-analysis"))
    if closers:
        signals.append(RiskSignal("llm_style_indicator", 0, 8,
                                  explanation="style: closing “" + ", ".join(closers) + "” — regional register noted as context only",
                                  source="style-analysis"))
    if non_ascii_frac > 0.02:
        signals.append(RiskSignal("homoglyph_domain", 1, 25,
                                  explanation=f"style: {non_ascii_frac * 100:.1f}% non-ASCII letters in visible text (look-alike characters possible)",
                                  source="style-analysis"))
    return signals, facts
