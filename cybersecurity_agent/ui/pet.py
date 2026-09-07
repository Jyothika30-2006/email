"""Work-status reactions for the terminal (the Comnyang idea, in a TUI).

Comnyang is a pixel cat that lives on your desktop and *reacts to what the agent you are
driving is doing* — thinking face while the model plans, a happy hop when a task finishes.
This module gives SENTINEL-IR the same legibility without breaking the one UI rule the brief
is emphatic about (terminal only, no dashboard, no browser): a small ASCII sentinel cat
rendered inside the existing `rich` Live frame, whose mood is driven by real agent events.

Design constraints, in order of importance:

1. **The pet is a status surface, not a data surface.** Frames are hand-written constants
   drawn from a fixed vocabulary. Nothing attacker-controlled (subject, sender, body text,
   tool summaries) is ever interpolated into a frame, so a malicious email cannot put words
   in the mascot's mouth — the caption carries numbers and enum labels only.
2. **No jitter.** Every frame of every mood is padded to the same box, so `rich` Live cannot
   resize the panel mid-run (a resizing live region flickers badly on small terminals).
3. **No new dependencies, and it works without `rich`.** `render_plain()` returns a `str`.
4. **Optional.** `--no-pet` / `SENTINEL_PET=0` removes it entirely: a security tool should
   never force a cartoon on someone reviewing a real case.
"""
from __future__ import annotations

import time
from typing import Any, Optional

_HEAD = r" /\_/\ "          # ears + crown; ears are the only part that never changes
_BOX_W = 13
_BOX_H = 6


def _cat(face: str, body: str, *, top: str = "", bottom: str = "", aside: str = "") -> list[str]:
    """Compose one frame of the cat. Backslashes are always followed by a space so the art
    reads correctly in every font and never ends a source string on an escape."""
    return [top, _HEAD, f"({face})", body, bottom, aside]


#: mood → {"label": fixed human-readable status line, "frames": 2+ ASCII frames}.
#: Keys are the vocabulary the status hook may contain — nothing else is ever rendered.
MOODS: dict[str, dict[str, Any]] = {
    "watching": {
        "label": "watching the mailbox",
        "frames": [
            _cat(" o.o ", " >   < ", bottom=" /| |\\ "),
            _cat(" -.- ", " >   < ", bottom=" /| |\\ "),
        ],
    },
    "thinking": {
        "label": "planning the next tool call",
        "frames": [
            _cat(" ?_? ", " >   < ", top="  .   ", bottom=" /| |\\ "),
            _cat(" ?_? ", " >   < ", top="   .  ", bottom=" /| |\\ "),
            _cat(" ?_? ", " >   < ", top="    . ", bottom=" /| |\\ "),
        ],
    },
    "typing": {
        "label": "a whitelisted tool is running",
        "frames": [
            _cat(" o.o ", " >v< ", bottom=" /| |\\ ", aside="tap tap "),
            _cat(" o.o ", " >^< ", bottom=" /| |\\ ", aside=" tap tap"),
        ],
    },
    "hunting": {
        "label": "tracing link and origin infrastructure",
        "frames": [
            _cat(" o.o ", " _  _ ", bottom=" /| |\\~", aside=" wiggle"),
            _cat(" o.o ", " _  _ ", bottom=" /| | \\", aside="wiggle  "),
        ],
    },
    "fur": {
        "label": "prompt-injection attempt in this message",
        "frames": [
            _cat(" O_O ", " >   < ", top=" /\\ /\\ ", bottom=" /| |\\ ", aside="fur up "),
            _cat(" O_O ", " >   < ", top="/\\ /\\ /", bottom=" /| |\\ ", aside=" fur up"),
        ],
    },
    "bristle": {
        "label": "evidence integrity problem — treat this case as contaminated",
        "frames": [
            _cat(" >w< ", " >   < ", top=" ! \\ / ! ", bottom=" /| |\\ ", aside="puffed up"),
            _cat(" >w< ", " >   < ", top="!  \\ /  !", bottom=" /| |\\ ", aside=" puffed up"),
        ],
    },
    "steam": {
        "label": "a tool hit its hard timeout",
        "frames": [
            _cat(" >_< ", " >   < ", top="  ~   ~", bottom=" /| |\\ ", aside=" (slow)"),
            _cat(" >_< ", " >   < ", top=" ~   ~ ", bottom=" /| |\\ ", aside=" (slow)"),
        ],
    },
    "denied": {
        "label": "the human denied the file-touching tool",
        "frames": [
            _cat(" -_- ", " >   < ", bottom=" /| |\\ ", aside="won't touch"),
            _cat(" -, - ", " >   < ", bottom=" /| |\\ ", aside=" won't touch"),
        ],
    },
    "tilt": {
        "label": "suspicious, and the evidence is thin",
        "frames": [
            _cat(" o_o ", " >   < ", bottom=" /| |\\ ", aside="hmm?"),
            _cat(" _o ", " >   < ", bottom=" /| |\\ ", aside="hmm ?"),
        ],
    },
    "hop": {
        "label": "verdict: SAFE",
        "frames": [
            _cat(" ^.^ ", "\\|/   \\|/", top="  \\ / ", bottom="   v   ", aside="* meow *"),
            _cat(" ^.^ ", " >   < ", top=" /|\\ /|\\", bottom="  ~ ~  ", aside=" hop!   "),
        ],
    },
    "arch": {
        "label": "verdict: MALICIOUS",
        "frames": [
            _cat(" >.< ", "/ |   | \\", top="  \\   / ", bottom=" hisss ", aside="hiss! "),
            _cat(" >.< ", "\\ |   | /", top="   \\ /  ", bottom=" hisss ", aside=" HISS!"),
        ],
    },
    "flee": {
        "label": "kill-switch pressed, tearing down",
        "frames": [
            _cat(" o.o ", " _==_ ", aside="   ===> flee"),
            _cat(" o.o ", " _===", aside=" ====> flee"),
        ],
    },
    "waiting": {
        "label": "blocked on you: type 'yes' at the confirmation gate",
        "frames": [
            _cat(" o.o ", " >   ? ", bottom=" /| |\\ ", aside=" your call"),
            _cat(" -.- ", " >   ? ", bottom=" /| |\\ ", aside="your call "),
        ],
    },
    # ── care moods: the other half of the reference product (reminders, Pomodoro) ──
    "sentry": {
        "label": "focus block running — the case has the floor",
        "frames": [
            _cat(" o.o ", " >   < ", top="  t i c k", bottom=" /| |\\ ", aside="sentry"),
            _cat(" o.o ", " >   < ", top=" t o c k ", bottom=" /| |\\ ", aside=" sentry"),
        ],
    },
    "stretch": {
        "label": "stand up: shoulders back, neck roll, 20 seconds",
        "frames": [
            _cat(" -.- ", "  \\_/  ", bottom="\\_|_|_/", aside="stretch "),
            _cat(" -.- ", " _/\\_ ", bottom=" /| |\\ ", aside=" stretch"),
        ],
    },
    "water": {
        "label": "drink some water",
        "frames": [
            _cat(" o.o ", " >   < ", bottom=" /| |\\ ", aside=" glug..."),
            _cat(" ^.^ ", " >   < ", bottom=" /| |\\ ", aside="glug ..."),
        ],
    },
    "nap": {
        "label": "break time — the mailbox can wait two minutes",
        "frames": [
            _cat(" -.- ", " >   < ", top="     z  ", bottom=" /| |\\ ", aside="    Zz"),
            _cat(" -.- ", " >   < ", top="    zZ ", bottom=" /| |\\ ", aside="   zZ"),
        ],
    },
}

DEFAULT_MOOD = "watching"

#: Moods that are *transient*: if no event renews them, the cat settles back to watching.
#: Without this, a run that ends between two events would leave the pet stuck mid-reaction.
TRANSIENT_MOODS = frozenset({"thinking", "typing", "hunting", "steam", "fur", "bristle",
                             "denied", "tilt", "hop", "arch", "flee", "sentry", "stretch",
                             "water", "nap"})
# `waiting` is intentionally NOT transient: while the gate is open the cat should still be
# saying "blocked on you" an hour later, because that is still true.
NOT_TRANSIENT = frozenset({"watching", "waiting"})
#: How long a transient mood is held before the cat calms down (seconds).
MOOD_HOLD_S = 25.0

#: Exact box width `_pad` guarantees — the UI uses it to size the panel so the live region
#: can never resize because of the pet.
BOX_WIDTH = _BOX_W

#: Colour per mood (a `rich` style name that is also a sane ANSI-16 fallback). Colour is a
#: mood cue, not a verdict: the verdict numbers are printed next to it either way.
MOOD_STYLE: dict[str, str] = {
    "watching": "green",
    "thinking": "blue",
    "typing": "cyan",
    "hunting": "magenta",
    "fur": "red",
    "steam": "dark_orange",
    "denied": "grey62",
    "waiting": "yellow",
    "tilt": "yellow",
    "hop": "green",
    "arch": "bold red",
    "flee": "bold magenta",
}

#: Skins — the reference product's "custom colour/pattern" feature, reduced to what a terminal
#: can honestly offer: a palette per mood. The ASCII art never changes between skins, so
#: screenshots stay comparable and a skin can never alter what the cat is reporting.
SKINS: dict[str, dict[str, str]] = {
    "default": {},
    "high-contrast": {
        "watching": "white", "thinking": "white", "typing": "white", "hunting": "white",
        "fur": "bold yellow", "steam": "bold yellow", "denied": "white", "tilt": "bold yellow",
        "hop": "bold green", "arch": "bold red", "flee": "bold red",
    },
    "colour-blind": {
        # red/green is the worst palette for verdict glances: safe=blue, unsure=yellow, bad=bold white.
        "hop": "blue", "tilt": "yellow", "arch": "bold white", "fur": "bold white",
        "watching": "cyan", "steam": "magenta", "flee": "bold white",
    },
    "calm": {
        "watching": "grey58", "thinking": "grey58", "typing": "grey58", "hunting": "grey58",
        "fur": "yellow", "steam": "yellow", "tilt": "grey70", "hop": "green",
        "arch": "red", "flee": "red", "denied": "grey51",
    },
    "mono": {m: "" for m in MOOD_STYLE},     # no colour at all (terminals without ANSI, logs)
}


def skin_names() -> list[str]:
    return sorted(SKINS)


def resolve_skin(name: str) -> dict[str, str]:
    """Mood → style map for a skin name (unknown names fall back to `default`, loudly enough
    for the caller to print a warning; the pet is cosmetic and must never break a run)."""
    return dict(SKINS.get((name or "default").strip().lower(), {}))


def style_for(mood: str, skin: str = "default") -> str:
    table = resolve_skin(skin)
    if mood in table:
        return table[mood]
    return MOOD_STYLE.get(mood, "white")


#: Verdict → closing mood. Rule 7 ends every case; the cat's last frame is the same
#: three-value answer the report carries, so a glance and the record cannot disagree.
VERDICT_MOOD = {"SAFE": "hop", "SUSPICIOUS": "tilt", "MALICIOUS": "arch"}

#: Tool family → mood, so the reaction says something true about the *phase* rather than
#: animating at random. Anything unmapped reads as ordinary work (`typing`).
MOOD_FOR_TOOL = {
    "parse_headers": "typing",
    "parse_body": "typing",
    "extract_urls": "hunting",
    "resolve_origin": "hunting",
    "geolocate_ip": "hunting",
    "check_reputation": "hunting",
    "check_tor_exit": "hunting",
    "static_file_scan": "hunting",
    "redact_reply": "typing",
}

#: Events that make the cat stop being cute, in priority order — used by the controller so a
#: safety event is never overwritten by a routine one in the same tick.
ALERT_MOODS = ("flee", "bristle", "fur", "arch", "denied", "steam")


def moods() -> list[str]:
    return sorted(MOODS)


def is_known(mood: str) -> bool:
    return mood in MOODS


def label(mood: str) -> str:
    """Fixed one-liner for the panel caption and the status log (never email content)."""
    return str(MOODS.get(mood, MOODS[DEFAULT_MOOD])["label"])


def frames(mood: str) -> list[list[str]]:
    return list(MOODS.get(mood, MOODS[DEFAULT_MOOD])["frames"])


def _pad(frame: list[str]) -> list[str]:
    """Uniform box: same width and height for every frame of every mood."""
    body = [ln.rstrip() for ln in frame]
    body += [""] * (_BOX_H - len(body))
    w = max(_BOX_W, max((len(ln) for ln in body), default=0))
    return [ln.ljust(w)[:w] for ln in body[:_BOX_H]]


def render_lines(mood: str, frame_index: int = 0) -> list[str]:
    fr = frames(mood)
    return _pad(fr[int(frame_index) % len(fr)])


def render_plain(mood: str, frame_index: Optional[int] = None) -> str:
    """A frame as text (blank filler lines dropped) — used by the non-TTY demo log."""
    return "\n".join(ln for ln in render_lines(mood, 0 if frame_index is None else frame_index)
                     if ln.strip())


def one_line(mood: str) -> str:
    """What the quiet/CI log prints when the mood *changes* (the box is too big per step)."""
    return f"[sentinel-cat] {label(mood)}"


def status_caption(mood: str, *, tool: str = "", risk: float = 0.0) -> str:
    """Caption under the cat: enum label + tool name + numbers. Never case content."""
    bits = [label(mood)]
    if tool:
        bits.append(f"tool {tool}")
    bits.append(f"risk {risk:.1f}/100")
    return " · ".join(bits)


class SentinelCat:
    """Wall-clock animation plus event-driven mood changes, with decay back to a calm state.

    `rich` Live refreshes on its own, so tying the frame to `time.monotonic()` keeps the cat
    breathing between events without the controller ticking it; `advance()` forces the next
    frame when something real happens, so a reaction lands immediately instead of up to a
    second later.

    Two things it deliberately also does:

    * **decay** — a transient mood (a reaction to a single event) relaxes to `watching` after
      `hold_s`, so the pet never lies about what is happening right now;
    * **care line** — `show_care()` lets the reminders clock put one short line under the cat.
      It is text from a fixed list (`ui/care.py`), never case data, and it expires.
    """

    def __init__(self, *, enabled: bool = True, fps: float = 2.0, mood: str = DEFAULT_MOOD,
                 skin: str = "default", hold_s: float = MOOD_HOLD_S,
                 now: Optional[callable] = None) -> None:  # noqa: ANN401 - injectable clock
        self.enabled = bool(enabled)
        self.fps = max(0.2, float(fps))
        self.skin = (skin or "default").strip().lower()
        self.hold_s = max(1.0, float(hold_s))
        self._now = now or time.monotonic
        self._mood = mood if is_known(mood) else DEFAULT_MOOD
        self._mood_set_at = self._now()
        self._pinned = False
        self._care = ""
        self._care_until = 0.0
        self._manual: Optional[int] = None
        self._t0 = self._now()

    @property
    def mood(self) -> str:
        """The mood the operator should see *now* (after decay)."""
        m = self._mood
        if not self.enabled or self._pinned or m in NOT_TRANSIENT:
            return m
        if m in TRANSIENT_MOODS and (self._now() - self._mood_set_at) > self.hold_s:
            return DEFAULT_MOOD
        return m

    @property
    def raw_mood(self) -> str:
        return self._mood

    def set_mood(self, mood: str, *, pin: bool = False) -> bool:
        """True when the mood actually changed, so callers log/announce it exactly once.

        `pin=True` is for terminal states (the verdict): those must not decay away while the
        operator is still reading the summary.
        """
        if not self.enabled or not is_known(mood):
            return False
        # Compare against the *displayed* mood, so a reaction that already decayed re-fires
        # (a second injection attempt 30s later must be visible, not swallowed as "no change").
        changed = mood != self.mood
        self._mood = mood
        self._mood_set_at = self._now()
        self._pinned = bool(pin)
        self._manual = None
        return changed

    def pin(self, mood: str) -> bool:
        return self.set_mood(mood, pin=True)

    def advance(self) -> None:
        self._manual = (self._frame_index() + 1) % max(1, len(frames(self.mood)))

    def _frame_index(self) -> int:
        if self._manual is not None:
            return self._manual
        return int((self._now() - self._t0) * self.fps) % max(1, len(frames(self.mood)))

    # ── care line (reminders), not a verdict line ───────────────────────────
    def show_care(self, text: str, *, hold_s: float = 45.0) -> None:
        self._care = str(text or "")[:80]
        self._care_until = self._now() + max(1.0, float(hold_s))

    def care_line(self) -> str:
        return self._care if (self._care and self._now() < self._care_until) else ""

    def clear_care(self) -> None:
        self._care, self._care_until = "", 0.0

    def style(self) -> str:
        return style_for(self.mood, self.skin)

    def lines(self) -> list[str]:
        return render_lines(self.mood, self._frame_index())

    def text(self) -> str:
        return "\n".join(self.lines())
