"""TOOL 4 — check_tor_exit via the Tor Project's real-time DNSEL.

Protocol (documented at https://2020.zsandre.com/exitlist.txt / tor exit list docs):
  query   <reversed-ip>.ip-port.exitlist.torproject.org   (A record)
  127.0.0.2 → listed: active Tor exit node (port 25 also listed ⇒ it can send mail)
  127.0.0.10 → listed for port 25 only
  NXDOMAIN  → not listed
Also cross-checked against the bulk `exitlist.txt` if the operator cached it
(SENTINEL_TOR_EXITLIST=/path), because DNSEL answers can lag a few hours.

Semantics (system-prompt rule 6): a hit means **origin anonymized** — it raises
scrutiny, and we explicitly annotate that it is NOT proof of guilt (Tor is used by
journalists, activists, and ordinary privacy-conscious people).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from ..models import RiskSignal
from ..net import dns_a
from .base import ToolContext, ToolResult, register, tool_meta

DNSEL_SUFFIX = ".ip-port.exitlist.torproject.org"
TORPORT = {"127.0.0.2": "listed (tor exit, all ports incl. 25)", "127.0.0.10": "listed for port 25 only"}

PARAMS = {
    "type": "object",
    "properties": {"ip": {"type": "string", "description": "IPv4 to check; defaults to the resolved origin IP"}},
}


@register(timeout_override=8.0)
@tool_meta(name="check_tor_exit", parameters=PARAMS,
           llm_hint="Treat a hit as 'origin anonymized' (elevated scrutiny), never as proof of malicious intent (rule 6).")
def tool_check_tor_exit(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Check whether the sending IP is a live Tor exit node (DNSEL + optional cached bulk list)."""
    origin = dict(ctx.state.get("origin") or {})
    ip = (args.get("ip") or origin.get("ip") or "").strip()
    if not ip:
        return ToolResult(tool="check_tor_exit", ok=True, skipped=True,
                          summary="no IP to check (origin unrecovered)",
                          data={"note": "DNSEL needs a candidate IP; nothing was resolved"},
                          signals=[RiskSignal("origin_unrecovered", 0, 0,
                                              explanation="Tor status unknown because no origin IP was recovered",
                                              source="check_tor_exit")])

    reversed_ip = ".".join(ip.split(".")[::-1])
    name = f"{reversed_ip}{DNSEL_SUFFIX}"
    ips, err = dns_a(name, timeout=4.0)

    listed_via = ""
    answer = ips[0] if ips else ""
    if answer in TORPORT:
        listed_via = f"DNSEL → {answer}"
    elif answer == "127.0.0.0":
        listed_via = f"DNSEL → {answer} (unspecified port)"
    elif err == "NXDOMAIN":
        listed_via = ""
    elif err:
        listed_via = ""

    exitlist_note = ""
    fixture_hit = _fixture_hit(ctx, ip)
    if fixture_hit:
        # demo/CI path only — labelled 'simulated' so a fixture can never masquerade
        # as a live DNSEL answer in a report.
        listed_via = fixture_hit
        exitlist_note = fixture_hit
    else:
        bulk_hit = _cached_exitlist(ctx, ip)
        if bulk_hit:
            listed_via = listed_via or "cached exitlist.txt"
            exitlist_note = bulk_hit

    is_exit = bool(listed_via)
    notes = [
        "DNSEL answers are real-time but can lag several hours; a *non-hit never clears* an exit that just rotated.",
        exitlist_note or "no cached bulk exitlist (set SENTINEL_TOR_EXITLIST to enable cross-check)",
    ]
    signals: list[RiskSignal] = []
    if is_exit:
        notes.append("flagging as origin anonymized — elevated scrutiny, NOT proof of guilt; "
                     "true sender location is unrecoverable by construction")
        # Tor alone is not guilt, but it *is* a strong scrutiny factor: weight 2.2
        # × 62 strength ≈ +20 risk pts for one signal — "elevated scrutiny, not proof",
        # exactly as rule 6 demands. Live 127.0.0.2 (mail-capable exit) scores higher.
        strength = 85.0 if ("port 25" in listed_via or answer in {"127.0.0.2"}) else (62.0 if "simulated" not in listed_via else 52.0)
        signals.append(RiskSignal("tor_exit", 1, strength,
                                  explanation=f"origin IP {ip} is listed as a Tor exit node ({listed_via}) → origin anonymized: the sender's real "
                                              f"network is masked by design; elevated scrutiny, NOT proof of guilt (Tor serves legitimate privacy too)",
                                  source="check_tor_exit"))
    else:
        reason = "not listed in DNSEL (NXDOMAIN)" if err == "NXDOMAIN" else (f"DNS lookup failed: {err or 'no answer'}")
        notes.append(reason)
        if err not in {"NXDOMAIN", "NODATA", ""}:
            # Unknown ≠ cleared: record it as an evidence gap, not as a "safe" verdict.
            signals.append(RiskSignal("tool_timeout", 1, 15,
                                      explanation=f"Tor exit status could not be determined ({err}) — treated as unknown",
                                      source="check_tor_exit"))

    data = {"ip": ip, "dns_name": name, "answers": ips, "listed": is_exit, "via": listed_via,
            "simulated": "simulated" in (listed_via or ""),
            "notes": notes, "confidence_note": "high-confidence for listed; low for 'not listed'"}
    ctx.state["tor"] = data
    summary = f"{ip}: {'TOR EXIT (origin anonymized)' if is_exit else 'not a listed Tor exit'} — {listed_via or reason}"
    return ToolResult(tool="check_tor_exit", ok=True, summary=summary, data=data, signals=signals)


def _fixture_hit(ctx: ToolContext, ip: str) -> Optional[str]:
    """Demo/CI only — see Config.tor_exit_fixture. Clearly labelled 'simulated' so a
    fixture can never be mistaken for a live Tor Project answer."""
    path = Path(getattr(ctx.cfg, "tor_exit_fixture", "") or "")
    if not path.is_file():        # Path("") == Path(".") — exists() is True, is_file() is not
        return None
    lines = [l.strip() for l in path.read_text(errors="replace").splitlines()]
    return f"simulated via fixture {path.name} (NOT a live DNSEL answer)" if ip in lines else None


def _cached_exitlist(ctx: ToolContext, ip: str) -> Optional[str]:
    """Optional offline cross-check against a cached Tor bulk exitlist (the DNSEL
    is authoritative for "right now", the bulk list catches recently rotated exits)."""
    p = Path(getattr(ctx.cfg, "tor_exitlist", "") or "")
    if not p.exists():
        return None
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return None
    return f"IP present in cached Tor exitlist ({p.name}, {len(lines)} entries)" if ip in lines else None
