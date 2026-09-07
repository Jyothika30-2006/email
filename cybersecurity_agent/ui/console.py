"""Live terminal UI (rich) — explicitly NO web server, NO dashboard.

Renders, updating in place:
  * header: case, model/brain badge, elapsed, kill-switch status (SAFETY #8)
  * a colour-coded risk gauge (0–100) that moves after every tool result
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

from ..risk import severity_color

# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class StepRow:
    n: int
    tool: str
    status: str = "…"
    summary: str = ""
    delta: str = ""
    ms: str = ""


class ConsoleUI:
    def __init__(self, *, quiet: bool = False, case_name: str = "", kill_status: str = "") -> None:
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
        self.t0 = time.monotonic()
        self._live: Optional["Live"] = None
        self.console = Console(highlight=False, soft_wrap=False, width=110)

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
        risk_text = Text()
        risk_text.append(f"risk {self.risk:5.1f}/100", style=f"bold {gauge_color}")
        risk_text.append(f"    confidence {self.confidence:4.1f}%", style="bold white on grey23" if self.confidence else "dim")
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

    def set_origin(self, lines: list[str]) -> None:
        with self._lock:
            self.origin_lines = lines[:8]
        self._tick()

    def update_scores(self, *, risk: float, confidence: Optional[float] = None) -> None:
        with self._lock:
            self.risk = risk
            if confidence is not None:
                self.confidence = confidence
        self._tick()

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
    answer = _read_line_with_timeout(message, cfg.confirmation_timeout_s)
    approved = answer.strip().lower() in {"yes", "y", "approve", "approved"}
    append_audit(case_dir, "gate_decision", f"{tool_name} answer={answer.strip()[:16] or '<timeout>'} approved={approved}")
    if ui:
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
