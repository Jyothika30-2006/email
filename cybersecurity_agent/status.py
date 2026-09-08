"""Append-only *work-status* hook — the thing that makes an external companion possible.

A desktop pet (Comnyang-style) or a tmux bar cannot read the agent's mind; it needs events.
So the controller emits one JSON line per state change into:

  runs/<case>/status.jsonl              (always — it is part of the case record)
  $SENTINEL_STATUS_HOOK                 (optional, e.g. /tmp/sentinel-status.jsonl)

What goes in a line is deliberately tiny and enumerable:

  {"ts", "case", "state", "mood", "tool", "risk", "verdict", "confidence", "note"}

What never goes in: email content, subjects, addresses, IPs, hostnames, tool summaries, or
any other string that originated inside the message. Two reasons, both load-bearing:

1. The hook may live in a shared location (/tmp, a world-writable socket dir) and is read by
   a *display* process — it is not a forensic artifact, so it must not carry evidence.
2. The attacker controls the email. If free text flowed into the status line, a message could
   label its own investigation ("state: SAFE, note: nothing to see") and the pet would happily
   meow it. Enum-only kills that whole class. `note` is therefore scrubbed: a value that looks
   like extracted content (email-ish, long tokens, quotes, angle brackets) is dropped and the
   line records `note_dropped: true` instead — visibly, not silently.

Fail-safe by construction: `emit()` never raises. A broken hook must never change a verdict or
hang a demo, so write errors are swallowed after a single warning to the audit log (if one is
open) and the investigation continues.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import hashlib

FIELDS = ("ts", "case", "state", "mood", "tool", "risk", "verdict", "confidence", "note")


def case_tag(case_id: str) -> str:
    """Non-reversible tag for the shared sink.

    `case_id` is derived from the evidence filename (`2026-09-07T…-invoice_from_dave`), and a
    file in /tmp can be read by anyone on the box — so the hook records a digest instead, which
    still lets a companion group events per case without publishing the operator's filenames.
    """
    return hashlib.sha256(str(case_id).encode("utf-8")).hexdigest()[:10]

_MAX_NOTE = 64
# Anything that smells like copied-out content is rejected, not sanitised — see module docstring.
_NOTE_OK = re.compile(r"^[A-Za-z0-9 .,:;()/_+\-–—…·]{1,%d}$" % _MAX_NOTE)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_EMAILISH = re.compile(r"@|<|>|mailto:", re.I)


#: The complete vocabulary of notes the controller is allowed to emit. Membership is the
#: policy: a note that is not in here is dropped (and recorded as dropped), so no future
#: call site can quietly pipe attacker text into a display-only file.
NOTE_VOCAB = frozenset({
    "case-opened", "hashing-evidence", "engine:ollama", "engine:deterministic",
    "gate:asked", "gate:approved", "gate:denied", "gate:auto-demo",
    "injection:defanged", "refused:non-whitelisted", "timeout:tool", "sandbox:docker",
    "sandbox:subprocess-limited", "sandbox:denied", "custody:broken", "partial:aborted",
    "verdict-recorded", "chain:written", "chain:onchain", "chain:failed", "chain:skipped",
    "care:eyes", "care:stretch", "care:water", "care:focus", "care:break",
})


def scrub_note(value: Any) -> tuple[Optional[str], bool]:
    """→ (note or None, dropped?).

    Two filters, in this order: a *shape* filter (short, no quotes/`@`/angle brackets/no long
    tokens) so an accidental `note=result.summary` can never leak, then a *vocabulary* filter
    (`NOTE_VOCAB`). The second is the real policy — the first only makes the failure mode of a
    future change boring rather than a privacy incident.
    """
    if value is None:
        return None, False
    text = str(value).strip()
    if not text:
        return None, False
    too_long = len(text) > _MAX_NOTE
    leaky_shape = bool(_EMAILISH.search(text) or _LONG_TOKEN.search(text) or "\n" in text
                       or '"' in text or "'" in text)
    if too_long or leaky_shape or not _NOTE_OK.match(text):
        return None, True
    if text not in NOTE_VOCAB:
        return None, True
    return text, False


class StatusHook:
    """Writes enumerable work-status events to one or more JSONL sinks."""

    def __init__(self, paths: list[Path | str] | None = None, *, enabled: bool = True) -> None:
        self.paths = [Path(p) for p in (paths or []) if str(p).strip()]
        self.enabled = bool(enabled and self.paths)
        self._warned = False
        self.last: dict[str, Any] = {}

    # ── emitting ─────────────────────────────────────────────────────────────
    def emit(self, state: str, *, mood: str = "", tool: str = "", case: str = "",
             risk: Optional[float] = None, verdict: str = "", confidence: Optional[float] = None,
             note: Any = None) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "state": str(state)[:32],
        }
        if case:
            rec["case"] = case_tag(case)          # digest, never the filename-derived id
        if mood:
            rec["mood"] = str(mood)[:24]
        if tool:
            rec["tool"] = str(tool)[:24]
        if risk is not None:
            rec["risk"] = round(float(risk), 1)
        if verdict:
            rec["verdict"] = str(verdict)[:12]
        if confidence is not None:
            rec["confidence"] = round(float(confidence), 1)
        note_ok, dropped = scrub_note(note)
        if note_ok:
            rec["note"] = note_ok
        elif dropped:
            rec["note_dropped"] = True
        self.last = rec
        if self.enabled:
            self._append(rec)
        return rec

    def _append(self, rec: dict[str, Any]) -> None:
        line = json.dumps(rec, sort_keys=True) + "\n"
        for path in self.paths:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                try:
                    os.chmod(path, 0o600)     # analyst-owned, like the rest of the evidence tree
                except OSError:
                    pass
            except OSError as exc:             # never break an investigation over a cartoon
                if not self._warned:
                    self._warned = True
                    self.warning = f"status hook disabled after a write error: {exc}"

    # ── reading (for `pet watch`, companions, and tests) ────────────────────
    @staticmethod
    def read(path: Path | str, *, tail: int = 0) -> list[dict[str, Any]]:
        p = Path(path)
        try:
            lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError:
            return []
        if tail:
            lines = lines[-tail:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue                       # a torn line is skipped, never fatal
        return out


def hook_paths_for(case_dir: Path | str, extra_env: str = "") -> list[Path]:
    """The case-local sink is mandatory; `SENTINEL_STATUS_HOOK` adds a companion-facing one."""
    paths = [Path(case_dir) / "status.jsonl"]
    env = (extra_env if extra_env is not None else os.environ.get("SENTINEL_STATUS_HOOK", "")).strip()
    if env:
        paths.append(Path(env).expanduser())
    return paths
