"""Live terminal UI (rich) — explicitly NO web server, NO dashboard.

Renders, updating in place:
  * header: case, model/brain badge, elapsed, kill-switch status (SAFETY #8)
  * two live progress bars: the colour-coded risk gauge (0–100, verdict floors marked
    inside the bar) and the evidence-coverage bar (tool results collected vs expected)
  * the origin/geolocation honesty panel (source kind + confidence + radius)
  * a per-step tool table (✓/✗/⏱ + signal delta)
  * the agent's streaming reasoning ("THINK") lines
In --demo/CI (non-TTY) it degrades to a linear log of the *same* content, and the
kill-switch panel states plainly that the raw key listener needs a TTY (Ctrl+C
still aborts: SIGINT is translated into the same teardown flow by the controller).
"""
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree

    RICH_OK = True
except ImportError:  # pragma: no cover
    RICH_OK = False

from ..risk import severity_bar, severity_color
from .pet import BOX_WIDTH, SentinelCat, one_line, status_caption, style_for

# ─────────────────────────────────────────────────────────────────────────────


def gauge_string(fraction: float, width: int = 26, ticks: tuple[float, ...] = ()) -> str:
    """A text progress bar for a 0.0–1.0 fraction. `ticks` are positions drawn on top of
    it (`┼` already reached, `·` still ahead), so the frame can show *where a threshold
    sits* and not merely how full the bar is — the same marker convention as
    `risk.severity_bar`. Plain text on purpose: it has to survive a dumb terminal, the
    non-TTY demo log and `report.md`."""
    width = max(4, int(width))
    filled = int(round(width * max(0.0, min(1.0, float(fraction)))))
    chars = ["█"] * filled + ["░"] * (width - filled)
    for t in ticks:
        i = min(width - 1, max(0, int(round(width * float(t)))))
        chars[i] = "┼" if i < filled else "·"
    return "".join(chars)



@dataclass
class StepRow:
    n: int
    tool: str
    status: str = "…"
    summary: str = ""
    delta: str = ""
    ms: str = ""


class ConsoleUI:
    def __init__(self, *, quiet: bool = False, case_name: str = "", kill_status: str = "",
                 pet_enabled: bool = True, pet_fps: float = 2.0, pet_skin: str = "default",
                 care: Any = None) -> None:
        self.quiet = quiet or not RICH_OK or not sys.stdout.isatty()
        self.case_name = case_name
        self.kill_status = kill_status
        self._lock = threading.RLock()
        self.risk: float = 0.0
        self.confidence: float = 0.0
        self.origin_lines: list[str] = []
        self.steps: list[StepRow] = []
        self.thoughts: list[str] = []
        self.badges: dict[str, str] = {}
        self.expected: int = 0              # denominator of the coverage bar (0 = unknown)
        self.header = ""                    # set by start(); _frame() must not depend on it
        self.t0 = time.monotonic()
        self._live: Optional["Live"] = None
        self.console = Console(highlight=False, soft_wrap=False, width=110)
        # Work-status reactions (see `ui/pet.py`): a status surface, never a data surface.
        self.pet = SentinelCat(enabled=pet_enabled, fps=pet_fps, skin=pet_skin)
        self.care = care                      # optional `ui.care.CareClock`; display only
        self._pet_echoed = ""          # mood already announced in the quiet/CI log
        self.current_tool = ""         # what the pet panel captions as "doing"

    # ── live frame lifecycle ───────────────────────────────────────────────
    def start(self, header: str = "") -> None:
        self.header = header
        if self.quiet:
            self.console.print(Panel(header, border_style="cyan", expand=False) if header else "")
            return
        self._live = Live(self._frame(), console=self.console, auto_refresh=True,
                          refresh_per_second=6, vertical_overflow="visible")
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def _tick(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._frame(), refresh=True)
            except Exception:  # noqa: BLE001 - UI must never break an investigation
                pass

    def _frame(self) -> "Any":
        elapsed = time.monotonic() - self.t0
        head = f"[bold]{self.case_name}[/bold]  ·  {elapsed:5.1f}s  ·  kill-switch: {self.kill_status}"
        if self.header:
            head += f"\n[dim]{self.header}[/dim]"
        parts = [Panel(Text.from_markup(head), border_style="blue", expand=False, title="SENTINEL-IR")]

        gauge_color = severity_color(self.risk)
        exp, done = self.expected, self.done_steps
        risk_text = Text()
        # Two progress bars, both as plain Text so they survive a non-rich terminal:
        # the risk gauge (coloured by severity, threshold ticks drawn in) and the
        # evidence-coverage bar the confidence formula is actually scored on.
        risk_text.append(f"{severity_bar(self.risk)}  ", style=gauge_color)
        risk_text.append(f"risk {self.risk:5.1f}/100", style=f"bold {gauge_color}")
        risk_text.append(f"    confidence {self.confidence:4.1f}%",
                         style="bold white on grey23" if self.confidence else "dim")
        if exp:
            risk_text.append(f"\n{gauge_string(min(1.0, done / max(1, exp)), width=40)}  ", style="cyan")
            risk_text.append(f"evidence {done}/{exp} tool results · "
                             f"floors: ≥30 SUSPICIOUS, ≥65 MALICIOUS (+1 strong indicator)",
                             style="dim")
        if self.pet.enabled and RICH_OK:
            # Work-status reactions, perched left of the gauge in the SAME panel: a second
            # narrow panel just wastes width. Two properties matter here:
            #   · the cat box is a fixed size (`pet._pad`), so the live region can never resize
            #     mid-run — a resizing Live frame flickers on real terminals;
            #   · the caption carries enum labels and numbers only. Tool summaries, subjects and
            #     addresses are never echoed here: this panel is a display an attacker's text
            #     must not be able to speak through.
            style = style_for(self.pet.mood, self.pet.skin)
            caption = status_caption(self.pet.mood, tool=self.current_tool, risk=self.risk)
            care_line = self.pet.care_line() or (self.care.caption() if self.care is not None else "")
            # While a care mood is on screen its label *is* the reminder, so suppress a care line
            # that the caption already carries — one line per fact. (The Pomodoro timer line does
            # not collide: "pomodoro focus block · 18 s left" adds information the mood omits.)
            if care_line and care_line.rstrip(" .") in caption:
                care_line = ""
            risk_text.append("\n" + caption, style="dim")
            if care_line:
                # A reminder about the human, not the case — visually separate, and dim.
                risk_text.append("\n" + care_line, style="grey58")
            grid = Table.grid(padding=(0, 2))
            grid.add_column(width=BOX_WIDTH)
            grid.add_column(ratio=1)
            grid.add_row(Text("\n".join(self.pet.lines()), style=style), risk_text)
            parts.append(Panel(grid, border_style=style, expand=True, title="work-status · running score"))
        else:
            parts.append(Panel(risk_text, border_style=gauge_color, expand=False, title="running score"))

        if self.badges:
            parts.append(Panel(Text.from_markup("  ".join(f"[magenta]{k}[/magenta] [dim]{v}[/dim]" for k, v in self.badges.items())),
                               border_style="magenta", expand=False, title="state"))
        if self.origin_lines:
            parts.append(Panel(Text.from_markup("\n".join(self.origin_lines)), border_style="yellow",
                               expand=False, title="origin trace (honesty panel)"))
        if self.steps:
            table = Table(box=None, pad_edge=False, expand=False)
            table.add_column("#", style="dim", width=3)
            table.add_column("tool", width=22)
            table.add_column("status", width=7)
            table.add_column("Δ", width=8)
            table.add_column("ms", width=6)
            table.add_column("observation", overflow="fold")
            for s in self.steps[-9:]:
                style = {"✓": "green", "✗": "red", "⏱": "dark_orange", "…": "dim", "⊘": "blue"}.get(s.status, "white")
                table.add_row(str(s.n), s.tool, Text(s.status, style=style), s.delta, s.ms,
                              Text(s.summary[:150], style="white"))
            parts.append(Panel(table, border_style="cyan", expand=False, title="tool log (whitelisted)"))
        if self.thoughts:
            parts.append(Panel(Text.from_markup("\n".join(self.thoughts[-4:])), border_style="white",
                               expand=False, title="reasoning"))
        return Group(*parts) if RICH_OK else None

    # ── mutations ──────────────────────────────────────────────────────────
    def set_badge(self, key: str, value: str) -> None:
        with self._lock:
            self.badges[key] = value
        self._tick()

    def set_kill_status(self, status: str) -> None:
        self.kill_status = status
        self._tick()

    # ── work-status reactions (the pet) ─────────────────────────────────────
    def set_mood(self, mood: str, *, tool: str = "", pin: bool = False) -> None:
        """Called by the controller on real events (tool start, gate, injection, verdict).
        In the live UI this repaints the pet panel; in the non-TTY log it prints one short
        line per *change*, so a demo recording still shows what the cat was reacting to."""
        if tool:
            self.current_tool = tool
        changed = self.pet.set_mood(mood, pin=pin)
        if not changed:
            return
        if self.quiet:
            if self.pet.enabled:
                # Text(), not markup: the label contains `[sentinel-cat]`, which rich would
                # otherwise try to read as a style tag.
                self.console.print(Text("  " + one_line(self.pet.mood), style="dim"))
        else:
            self._tick()

    def show_care(self, text: str, *, mood: str = "", hold_s: float = 45.0) -> None:
        """Surface a care reminder (fixed vocabulary from `ui/care.py`): a line under the cat,
        and in the non-TTY log one printed line. Nothing here touches scores or evidence."""
        if mood:
            self.pet.set_mood(mood)
        self.pet.show_care(text, hold_s=hold_s)
        if self.quiet:
            self.console.print(Text(f"  [care] {text}", style="grey58"))
        else:
            self._tick()

    def advance_mood(self) -> None:
        """Force the next animation frame (event-driven liveliness between refreshes)."""
        if not self.pet.enabled:
            return
        self.pet.advance()
        if not self.quiet:
            self._tick()

    def set_origin(self, lines: list[str]) -> None:
        with self._lock:
            self.origin_lines = lines[:8]
        self._tick()

    def update_scores(self, *, risk: float, confidence: Optional[float] = None) -> None:
        with self._lock:
            self.risk = risk
            if confidence is not None:
                self.confidence = confidence
            conf = self.confidence
            exp, done = self.expected, self.done_steps
        if self.quiet:
            # The same gauge the live frame shows, as one line per tool result, so a
            # non-TTY demo/CI run still prints a moving progress bar instead of a number.
            tail = f" · conf {conf:4.1f}%" if conf else ""
            if exp:
                tail += f" · tools {done}/{exp}"
            self.console.print(f"  [dim]gauge[/dim] {severity_bar(risk)}  [bold]{risk:5.1f}/100[/bold]{tail}")
        else:
            self._tick()

    def set_expected(self, n: int) -> None:
        """How many tool results a complete investigation needs — the denominator of the
        coverage bar. Set by the controller from `agent.EXPECTED_FAMILIES`, so the bar
        measures the same thing the confidence formula's coverage term does."""
        with self._lock:
            self.expected = max(0, int(n))
        self._tick()

    @property
    def done_steps(self) -> int:
        return len([s for s in self.steps if s.status != "…"])

    def add_thought(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        with self._lock:
            self.thoughts.append(text[:400])
        if self.quiet:
            self.console.print(f"[dim]THINK[/dim]  {text[:400]}")
        else:
            self._tick()

    def record_step(self, *, tool: str, status: str, summary: str, delta: str = "", ms: str = "") -> None:
        with self._lock:
            self.steps.append(StepRow(len(self.steps) + 1, tool, status, summary, delta, ms))
        if self.quiet:
            self.console.print(f"  [{status}] [bold]{tool}[/bold] {delta} {ms}  {summary[:200]}")
        else:
            self._tick()

    def print_line(self, markup: str) -> None:
        self.console.print(markup)

    # ── final rendering ────────────────────────────────────────────────────
    def verdict_panel(self, *, verdict: str, confidence: float, risk: float, bullets: list[str], meta: list[str]) -> None:
        style = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "SAFE": "green"}.get(verdict, "white")
        tree = Tree(f"[bold {style}]{verdict}[/bold {style}]  ·  confidence [bold]{confidence:.1f}%[/bold]  ·  risk [bold]{risk:.1f}/100[/bold]")
        tree.add(Text(f"{severity_bar(risk)}  {risk:5.1f}/100  (floors: 30 suspicious · 65 malicious)", style="dim"))
        for b in bullets:
            tree.add(Text.from_markup(b))
        body = [tree]
        if meta:
            body.append(Panel(Text.from_markup("\n".join(meta)), border_style="dim", expand=False, title="case artifacts"))
        self.stop()
        self.console.print(Panel(Group(*body) if RICH_OK else "\n".join(bullets), border_style=style,
                                 expand=False, title="FINAL VERDICT (rule 7)"))

    def print_markdown(self, md: str) -> None:
        if RICH_OK and not self.quiet:
            self.console.print(Markdown(md))
        else:
            self.console.print(md)


# ─────────────────────────────────────────────────────────────────────────────
# SAFETY #4 — human confirmation gate.
# ─────────────────────────────────────────────────────────────────────────────
_ui_singleton: Optional[ConsoleUI] = None


def set_ui(ui: ConsoleUI) -> None:
    global _ui_singleton
    _ui_singleton = ui


def ask_confirmation(ctx: Any, tool_name: str, reason: str) -> bool:
    """Terminal gate shown before any file-touching tool. Approval requires typing
    `yes` (or `y`). Timeout / unreadable stdin / closed pipe → **DENIED** (fail
    closed). The decision is appended to the audit log so the chain of custody
    records who allowed what, when."""
    ui = _ui_singleton
    cfg = ctx.cfg
    case_dir = ctx.case_dir

    from ..evidence.hasher import append_audit

    if getattr(ctx, "auto_confirm", False) or not cfg.require_confirmation:
        append_audit(case_dir, "gate_auto_approved", f"{tool_name} (auto-confirm flag; NOT a human approval)")
        if ui:
            ui.print_line(f"[dark_orange][GATE][/dark_orange] {tool_name}: auto-approved via --yes/--demo (audit-logged, not a human approval)")
        return True

    message = (f"[bold red][CONFIRM_NEEDED][/bold red] The agent wants to run [bold]{tool_name}[/bold] on "
               f"attachment bytes.\n"
               f"  reason   : {reason[:400]}\n"
               f"  artifacts: {', '.join(sorted(ctx.attachment_files)) or '(none staged)'}\n"
               f"  isolation: {ctx.state.get('sandbox_mode', 'probing…')}\n"
               f"  static analysis only — the file is never executed or opened by a viewer.\n"
               f"[bold]Type yes to proceed[/bold] (anything else or {cfg.confirmation_timeout_s:.0f}s of silence = DENY): ")

    if ui:
        ui.stop()
        ui.print_line("")
        ui.set_mood("waiting")          # the run is now blocked on a human, and says so
        if not ui.quiet:                # Live is stopped while we read stdin, so draw it here
            from .pet import render_plain
            ui.print_line(Text(render_plain("waiting"), style="yellow"))
    answer = _read_line_with_timeout(message, cfg.confirmation_timeout_s)
    approved = answer.strip().lower() in {"yes", "y", "approve", "approved"}
    append_audit(case_dir, "gate_decision", f"{tool_name} answer={answer.strip()[:16] or '<timeout>'} approved={approved}")
    if ui:
        ui.pet.set_mood("typing" if approved else "denied")
        ui.print_line(f"[{'green' if approved else 'red'}][GATE][/{'green' if approved else 'red'}] {tool_name}: "
                      f"{'APPROVED by operator' if approved else 'DENIED (fail-closed; timeout or non-affirmative answer)'}")
        if not ui.quiet:
            ui.start(getattr(ui, "header", ""))
    return approved


def _read_line_with_timeout(prompt: str, timeout: float) -> str:
    """Read one line from stdin with a hard timeout, without touching termios."""
    if not sys.stdin or not sys.stdin.isatty():
        # Piped/redirected stdin: try one read with a select()-bounded wait so a
        # closed pipe can't hang the run. Anything non-affirmative = deny.
        try:
            import select

            if select.select([sys.stdin], [], [], min(timeout, 5.0))[0]:
                return sys.stdin.readline() or ""
        except Exception:  # noqa: BLE001
            return ""
        return ""
    result = {"line": ""}

    def _reader() -> None:
        try:
            result["line"] = input(prompt)
        except Exception:  # EOFError / KeyboardInterrupt / raw-mode tty
            result["line"] = ""

    t = threading.Thread(target=_reader, daemon=True)
    print(prompt, end="", flush=True)
    t.join(timeout)
    if t.is_alive():
        print("\n[dim](no answer within the timeout — denying)[/dim]", flush=True)
        return ""
    print("")
    return result["line"]
