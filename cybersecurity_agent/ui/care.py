"""Care: stretch / water / eyes reminders and a Pomodoro clock — the second half of the idea.

The reference product is not only "cat reacts to agent": it also *nudges the human* (stretch,
drink water, Pomodoro focus blocks). Long IR sessions are exactly when people forget to do
those things, so the terminal pet carries the same reminders.

Rules this module obeys:

* **Pure time math, no threads, no subprocesses.** Everything is computed from an injectable
  monotonic clock, so tests drive it deterministically and a broken clock can't hang a run.
* **It cannot influence the case.** No function here reads or writes evidence, risk, or
  confidence. The only effect on the run is one extra caption line under the cat.
* **Fixed vocabulary.** `key`, `label`, and `mood` come from the table below; a reminder can
  never contain text derived from the email.
* **Opt-out, and quiet by default in short runs.** Default intervals (20/30/45 min) are longer
  than any demo, so nothing nags during a 20-second investigation; a 3-hour manual review does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

MIN = 60.0


@dataclass(frozen=True)
class Reminder:
    key: str
    label: str
    every_s: float
    mood: str

    def due_line(self, minutes_left: float = 0.0) -> str:
        if minutes_left > 0:
            return f"{self.label} (next in {minutes_left:.0f} min)"
        return self.label


#: The complete set. Unknown keys in a spec string are dropped by the parser (and reported by
#: the CLI), never silently turned into something else.
DEFAULT_REMINDERS: tuple[Reminder, ...] = (
    Reminder("eyes", "20-20-20: look 6 m away for 20 s", 20 * MIN, "nap"),
    Reminder("stretch", "stand up: shoulders back, neck roll, 20 s", 30 * MIN, "stretch"),
    Reminder("water", "drink some water", 45 * MIN, "water"),
)

BY_KEY = {r.key: r for r in DEFAULT_REMINDERS}


@dataclass
class Pomodoro:
    """Focus/break cycle. `focus_s=0` disables it entirely (the default)."""

    focus_s: float = 0.0
    break_s: float = 5 * MIN
    started_at: float = 0.0
    cycles_done: int = field(default=0, init=False)

    @property
    def enabled(self) -> bool:
        return self.focus_s > 0

    def phase(self, now: float) -> tuple[str, float]:
        """→ ("focus"|"break", minutes_left)."""
        if not self.enabled:
            return ("", 0.0)
        cycle = self.focus_s + self.break_s
        elapsed = max(0.0, now - self.started_at)
        self.cycles_done = int(elapsed // cycle)
        into = elapsed % cycle
        if into < self.focus_s:
            return ("focus", (self.focus_s - into) / MIN)
        return ("break", (cycle - into) / MIN)

    def line(self, now: float) -> str:
        name, left = self.phase(now)
        if not name:
            return ""
        tag = "focus block" if name == "focus" else "break"
        # Sub-minute precision, so the last minute of a focus block doesn't read "0 min left".
        when = f"{left * 60:.0f} s" if left < 1.0 else f"{left:.0f} min"
        return f"pomodoro {tag} · {when} left · {self.cycles_done} done"


class CareClock:
    """When is the human due a nudge, given only elapsed wall-clock time?"""

    def __init__(self, *, enabled: bool = True,
                 reminders: tuple[Reminder, ...] = DEFAULT_REMINDERS,
                 pomodoro: Optional[Pomodoro] = None,
                 now: Optional[Callable[[], float]] = None) -> None:
        self.now = now or _monotonic
        self.enabled = bool(enabled and reminders)
        self.reminders: tuple[Reminder, ...] = tuple(reminders) if enabled else ()
        self.pomodoro = pomodoro
        self._last: dict[str, float] = {}
        self._t0 = self.now()
        if self.pomodoro is not None and not self.pomodoro.started_at:
            self.pomodoro.started_at = self._t0

    # ── scheduling ──────────────────────────────────────────────────────────
    def due(self) -> list[Reminder]:
        """Reminders whose interval has elapsed. Marks them fired, so each fires once."""
        if not self.enabled:
            return []
        now = self.now()
        out: list[Reminder] = []
        for r in self.reminders:
            last = self._last.get(r.key, self._t0)
            if (now - last) >= r.every_s:
                out.append(r)
                self._last[r.key] = now
        return out

    def minutes_to_next(self) -> float:
        """Shortest wait to any reminder — for the caption, so it reads as a clock, not a nag."""
        if not self.enabled:
            return 0.0
        now = self.now()
        left = [max(0.0, (self._last.get(r.key, self._t0) + r.every_s - now)) for r in self.reminders]
        return min(left) / MIN if left else 0.0

    # ── display ─────────────────────────────────────────────────────────────
    def caption(self) -> str:
        """One dim line under the cat: what is next, plus Pomodoro state if it is running."""
        bits: list[str] = []
        if self.enabled and self.reminders:
            bits.append(f"next break in {self.minutes_to_next():.0f} min")
        if self.pomodoro is not None:
            line = self.pomodoro.line(self.now())
            if line:
                bits.append(line)
        return "  ·  ".join(bits)

    def mood_for_pomodoro(self) -> str:
        if self.pomodoro is None:
            return ""
        name, _ = self.pomodoro.phase(self.now())
        return {"focus": "sentry", "break": "nap"}.get(name, "")


def _monotonic() -> float:
    import time
    return time.monotonic()


# ── parsing (config / CLI) ─────────────────────────────────────────────────
def parse_reminders(spec: str) -> tuple[tuple[Reminder, ...], list[str]]:
    """`"stretch=30,water=60"` → (reminders, unknown_keys). `"off"` → (). Minutes as the unit.

    A malformed or unknown entry is reported rather than guessed at: a mistyped reminder key
    should not quietly re-enable a default the operator meant to disable.
    """
    text = (spec or "").strip()
    if not text:
        return DEFAULT_REMINDERS, []
    if text.lower() in {"off", "none", "no", "0"}:
        return (), []
    out: list[Reminder] = []
    unknown: list[str] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, _, mins = chunk.partition("=")
        key = key.strip().lower()
        base = BY_KEY.get(key)
        if base is None:
            unknown.append(chunk)
            continue
        try:
            every = float(mins.strip()) * MIN if mins.strip() else base.every_s
        except ValueError:
            unknown.append(chunk)
            continue
        if every <= 0:
            continue                     # `stretch=0` means "never"
        out.append(Reminder(base.key, base.label, every, base.mood))
    return tuple(out), unknown


def parse_pomodoro(spec: str) -> Optional[Pomodoro]:
    """`"25,5"` → 25-min focus / 5-min break. Empty or `off` → None."""
    text = (spec or "").strip()
    if not text or text.lower() in {"off", "none", "no"}:
        return None
    parts = [p.strip() for p in text.replace(":", ",").split(",") if p.strip()]
    try:
        focus = float(parts[0]) * MIN
        brk = float(parts[1]) * MIN if len(parts) > 1 else 5 * MIN
    except (IndexError, ValueError):
        return None
    if focus <= 0:
        return None
    return Pomodoro(focus_s=focus, break_s=max(0.0, brk))
