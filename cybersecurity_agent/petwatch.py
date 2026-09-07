"""`sentinel-ir pet` — the companion side of the work-status protocol.

Reads the append-only JSONL the controller writes (`status.py`) and renders the cat in its own
terminal, so you can keep a second window watching while the investigation runs in the first —
the same shape as a desktop pet sitting beside Claude Code / Codex / Cursor.

Trust boundary, stated plainly: **this file is display data, not evidence.** Anything that can
write to the sink can make the cat show any mood and print any verdict number, so:

* only allowlisted fields are read, unknown keys are ignored, and an unknown `mood` falls back
  to `watching` — the vocabulary lives in `ui/pet.MOODS`, not in the file;
* nothing is ever *executed* or interpolated into a shell, a path, or a report;
* the panel header repeats the rule that the authoritative answer is `runs/<case>/run.json`.

Modes: `--once` prints a summary of the last events (for scripts and CI), `--follow` animates
until Ctrl-C, and with no events at all the pet just keeps the care clock running (stretch /
water / eyes, optional Pomodoro) — it works standalone, like the reference product does when no
agent is connected.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

from .status import StatusHook
from .ui.care import CareClock, parse_pomodoro, parse_reminders
from .ui.pet import BOX_WIDTH, DEFAULT_MOOD, MOODS, SentinelCat, is_known, label, render_plain, status_caption

TRUST_NOTE = ("status hook is an ADVISORY display, not evidence — the verdict of record is "
              "runs/<case>/run.json")


def latest_sink(runs_dir: Path, env_path: str = "") -> Optional[Path]:
    """Which file to watch: `$SENTINEL_STATUS_HOOK` if set, else the newest case's sink."""
    env = (env_path or os.environ.get("SENTINEL_STATUS_HOOK", "")).strip()
    if env:
        p = Path(env).expanduser()
        return p if p.exists() else None
    runs = Path(runs_dir)
    if not runs.is_dir():
        return None
    found = sorted(runs.glob("*/status.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return found[0] if found else None


def summarize(records: list[dict[str, Any]], *, tail: int = 6) -> dict[str, Any]:
    """Collapse a JSONL tail into what the panel shows. Unknown moods degrade to watching —
    a corrupt or hostile line must not be able to invent a reaction."""
    out: dict[str, Any] = {"mood": DEFAULT_MOOD, "state": "", "tool": "", "note": "",
                           "risk": None, "verdict": "", "confidence": None, "events": len(records)}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        state = str(rec.get("state") or "")
        mood = str(rec.get("mood") or "")
        out["state"] = state[:32] or out["state"]
        if is_known(mood):
            out["mood"] = mood
        if rec.get("tool"):
            out["tool"] = str(rec["tool"])[:24]
        if rec.get("note"):
            out["note"] = str(rec["note"])[:64]
        if isinstance(rec.get("risk"), (int, float)):
            out["risk"] = float(rec["risk"])
        if rec.get("verdict"):
            out["verdict"] = str(rec["verdict"])[:12]
        if isinstance(rec.get("confidence"), (int, float)):
            out["confidence"] = float(rec["confidence"])
    out["recent"] = [{"state": str(r.get("state", "")), "mood": str(r.get("mood", "")),
                      "note": str(r.get("note", "")), "tool": str(r.get("tool", "")),
                      "ts": str(r.get("ts", ""))[:19]}
                     for r in records[-tail:] if isinstance(r, dict)]
    return out


def render_text(snapshot: dict[str, Any], *, care_caption: str = "", skin: str = "default",
                source: str = "") -> str:
    """The whole panel as plain text (no rich, no ANSI) — the `--plain` and non-TTY path."""
    mood = snapshot.get("mood") if is_known(str(snapshot.get("mood", ""))) else DEFAULT_MOOD
    art = render_plain(mood)
    head = f"sentinel-cat · watching {source}" if source else "sentinel-cat"
    caption = status_caption(str(mood), tool=str(snapshot.get("tool") or ""),
                             risk=float(snapshot.get("risk") or 0.0))
    bits = [f"{caption}"]
    # The verdict moods already say the verdict in their label ("verdict: SAFE"), so repeat it
    # only when the caption would not — otherwise the panel reads like a stutter.
    verdict = str(snapshot.get("verdict") or "")
    if verdict and f"verdict: {verdict}" not in caption:
        bits.append(f"last verdict {verdict}")
    if isinstance(snapshot.get("confidence"), (int, float)):
        bits.append(f"confidence {snapshot['confidence']:.1f}%")
    bits.append(f"{snapshot.get('events', 0)} event(s)")
    if skin and skin != "default":
        bits.append(f"skin {skin}")
    lines = [head, "─" * max(BOX_WIDTH, min(78, len(bits[0]) + 4)), art, " · ".join(bits)]
    if snapshot.get("note"):
        lines.append(f"note: {snapshot['note']}")
    if care_caption:
        lines.append(f"care: {care_caption}")
    lines.append(TRUST_NOTE)
    return "\n".join(ln for ln in lines if ln is not None)


def run_pet(*, path: Optional[Path] = None, follow: bool = False, once: bool = False,
            plain: bool = False, skin: str = "default", fps: float = 2.0,
            remind: str = "", pomodoro: str = "", tail: int = 6,
            max_seconds: float = 0.0, sleep: float = 0.5) -> int:
    """Entry point for `sentinel-ir pet`. Returns a process exit code; never raises on a
    missing file (an empty panel with an explanation is more honest than a traceback)."""
    src = Path(path) if path else latest_sink(Path("runs"))
    cat = SentinelCat(enabled=True, fps=fps, skin=skin)
    reminders, unknown = parse_reminders(remind)
    care = CareClock(enabled=True, reminders=reminders, pomodoro=parse_pomodoro(pomodoro))
    live = (not plain) and sys_stdout_isatty()

    if src is None or not src.exists():
        print("sentinel-cat: no status sink yet.")
        print("  start an investigation (`sentinel-ir investigate …`) or point --path at a "
              "runs/<case>/status.jsonl, or set SENTINEL_STATUS_HOOK.")
        print("  " + TRUST_NOTE)
        if unknown:
            print(f"  (ignored unknown reminder keys: {', '.join(unknown)})")
        if not follow:
            return 0
        # In --follow we keep the care clock alive anyway, but we do not spin silently forever.
        print("  waiting for the sink to appear (Ctrl-C to stop)…")

    seen = 0
    records: list[dict[str, Any]] = []
    t0 = time.monotonic()
    try:
        while True:
            if src:
                records, seen = _read_from(src, seen)
            snap = summarize(records, tail=tail)
            if is_known(snap["mood"]):
                cat.set_mood(snap["mood"])
            for rem in care.due():
                cat.show_care(rem.label, hold_s=90.0)
                if not live:
                    print(f"[care] {rem.label}")
            phase = care.mood_for_pomodoro()
            if phase:
                cat.set_mood(phase)
            if live:
                os.system("clear" if os.name != "nt" else "cls")
            print(render_text(snap, care_caption=cat.care_line() or care.caption(),
                              skin=skin, source=str(src) if src else "no sink"))
            if once or not follow:
                return 0
            if src is None:
                src = latest_sink(Path("runs"))     # appear later? pick it up
            if max_seconds and (time.monotonic() - t0) > max_seconds:
                print(f"(stopped after {max_seconds:.0f}s — pet watch is not meant to run forever)")
                return 0
            time.sleep(max(0.05, sleep))
    except KeyboardInterrupt:
        print("\nsentinel-cat: stopped watching. nothing about the case changed.")
        return 0


MAX_RECORDS = 240        # a case writes ~40 lines; this only bounds a long-lived `--follow`


def _read_from(path: Path, seen: int) -> tuple[list[dict[str, Any]], int]:
    """Read the sink, remembering how many lines were already counted.

    Deliberately line-based rather than offset-based: the writer flushes a line at a time, so a
    torn final line is simply unparseable and `StatusHook.read` skips it — it shows up complete
    on the next poll instead of rendering half an event.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], seen
    if len(lines) < seen:            # truncated or rotated: start over
        seen = 0
    if not lines:
        return [], seen
    recs = StatusHook.read(path, tail=0)[-MAX_RECORDS:]
    return recs, len(lines)


def sys_stdout_isatty() -> bool:
    import sys
    return bool(sys.stdout.isatty())


def mood_vocab() -> dict[str, str]:
    """Exposed for `--help`/docs: the complete set of reactions a companion may ever show."""
    return {k: str(v["label"]) for k, v in sorted(MOODS.items())}
