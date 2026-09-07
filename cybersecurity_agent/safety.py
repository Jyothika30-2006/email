"""Safety primitives, implemented once and reused everywhere (README §6).

  #1 no arbitrary execution       → FORBIDDEN_ACTIONS (enforced by tools.dispatch)
  #5 hard timeout per tool call  → run_with_timeout()
  #8 instant kill-switch keypress → KillSwitch (raw-mode key listener + teardown hooks)

The kill-switch listener owns the tty in raw mode while the agent is working; when
the human-confirmation gate needs a line of text it calls pause() (restore
canonical mode), then resume() (hand raw mode back). That is the only way to share
one stdin between "watch one keypress" and "read a line" without termios fights.
"""
from __future__ import annotations

import functools
import os
import shlex
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Anything that smells like arbitrary execution is refused before dispatch, even if
# a future refactor accidentally registered such a "tool".
FORBIDDEN_ACTIONS = {
    "shell", "exec", "system", "bash", "sh", "run_command", "popen", "eval",
    "subprocess", "docker_exec", "vm_exec", "delete", "rm", "send_email",
    "execute_attachment", "open_file", "network_scan", "port_scan", "exploit",
}


class AbortedError(RuntimeError):
    """Raised when the kill-switch fired (or the run was cancelled)."""


class ToolTimeoutError(TimeoutError):
    """Raised when a tool exceeded its hard timeout budget."""


@dataclass
class KillSwitch:
    """SAFETY #8 — single keypress aborts the agent and tears down the sandbox.

    Aborting sets a shared Event; every tool checks it before/after executing, and
    teardown hooks (registered by the sandbox runner, e.g. `docker rm -f <name>`)
    run immediately. Ctrl+C is translated into the same flow so the terminal never
    leaves a stray container behind. On non-POSIX terminals or non-tty stdin the
    listener reports that plainly and Ctrl+C remains available — we never claim a
    keypress hook that isn't actually installed.
    """
    key: str = "x"
    enabled: bool = True
    _abort: threading.Event = field(default_factory=threading.Event, repr=False)
    _hooks: list[Callable[[], None]] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)
    _restore_termios: Optional[Callable[[], None]] = field(default=None, repr=False)
    _raw_armed: bool = False
    reason: str = ""
    status: str = "not armed"

    # ── listener lifecycle ─────────────────────────────────────────────────
    def start(self) -> str:
        if not self.enabled:
            self.status = "disabled (--no-kill-key)"
            return self.status
        if self._thread and self._thread.is_alive():
            return self.status
        import sys

        if not sys.stdin or not sys.stdin.isatty():
            self.status = "stdin not a tty → Ctrl+C only"
            return self.status
        try:
            import termios
            import tty

            fd = sys.stdin.fileno()
            saved = termios.tcgetattr(fd)

            def _restore() -> None:
                try:
                    termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
                except Exception:  # noqa: BLE001
                    pass

            self._restore_termios = _restore

            def _watch() -> None:
                try:
                    tty.setraw(fd)
                    self._raw_armed = True
                except Exception:  # noqa: BLE001
                    self.status = "raw mode unavailable → Ctrl+C only"
                    return
                while not self._abort.is_set():
                    try:
                        ch = os.read(fd, 1)
                    except (OSError, ValueError):
                        return
                    if not ch:
                        time.sleep(0.05)
                        continue
                    if ch in (b"\x03",):
                        self.abort("Ctrl+C")
                        return
                    low = ch.decode("latin-1").lower()
                    if low in (self.key.lower(), "x"):
                        self.abort(f"kill-switch keypress {ch!r}")
                        return
                    if low == "q":
                        self.abort("kill-switch keypress 'q'")
                        return

            self._thread = threading.Thread(target=_watch, name="kill-switch", daemon=True)
            self._thread.start()
            time.sleep(0.05)
            self.status = f"armed (press '{self.key}' / 'q' / Ctrl-C)"
            return self.status
        except Exception as exc:  # noqa: BLE001  (Windows: no termios, etc.)
            self.status = f"unavailable ({type(exc).__name__}) → Ctrl+C only"
            return self.status

    def pause(self) -> None:
        """Hand the tty back to canonical mode (used by the confirmation gate)."""
        if self._restore_termios:
            try:
                self._restore_termios()
            except Exception:  # noqa: BLE001
                pass
        self._raw_armed = False

    def resume(self) -> str:
        """Re-arm raw mode without disturbing thread state."""
        import sys

        if not self.enabled or self._abort.is_set():
            return self.status
        try:
            import tty

            if sys.stdin and sys.stdin.isatty():
                tty.setraw(sys.stdin.fileno())
                self._raw_armed = True
                if not (self._thread and self._thread.is_alive()):
                    return self.start()
        except Exception:  # noqa: BLE001
            pass
        return self.status

    def disarm(self) -> None:
        self.pause()
        self.status = "disarmed"

    # ── state ──────────────────────────────────────────────────────────────
    @property
    def aborted(self) -> bool:
        return self._abort.is_set()

    def abort(self, reason: str = "aborted") -> None:
        with self._lock:
            already = self._abort.is_set()
            self._abort.set()
            self.reason = reason
        if not already:
            self.run_teardown()

    def raise_if_aborted(self) -> None:
        if self._abort.is_set():
            raise AbortedError(self.reason or "aborted by kill-switch")

    # ── teardown hooks (sandbox registers `docker rm -f` here) ─────────────
    def register_teardown(self, fn: Callable[[], None]) -> None:
        with self._lock:
            self._hooks.append(fn)
        if self.aborted:      # late registration after an abort: run now
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass

    def run_teardown(self) -> None:
        with self._lock:
            hooks, self._hooks = list(self._hooks), []
        for hook in hooks:
            try:
                hook()
            except Exception:  # noqa: BLE001  teardown must never mask the abort
                pass


def run_with_timeout(
    fn: Callable[..., Any],
    *args: Any,
    timeout: float,
    switch: Optional[KillSwitch] = None,
    label: str = "tool",
    **kwargs: Any,
) -> Any:
    """SAFETY #5 — bounded execution for every tool call.

    A short-lived worker thread with a hard join deadline. On timeout the worker is
    *abandoned*: Python cannot kill a thread, so tools are written to (a) check the
    kill-switch at their boundaries, (b) use socket-level timeouts ≤ this budget,
    and (c) have any subprocess they spawn killed by the sandbox runner's own
    timeout. That is the honest limit of a pure-Python, single-machine design.
    """
    if switch:
        switch.raise_if_aborted()
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"tool-{label}")
    try:
        future = pool.submit(functools.partial(fn, *args, **kwargs))
        try:
            result = future.result(timeout=timeout)
        except TimeoutError as exc:
            future.cancel()
            raise ToolTimeoutError(f"{label} exceeded its {timeout:.0f}s hard timeout") from exc
    finally:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # pragma: no cover
            pool.shutdown(wait=False)
    if switch:
        switch.raise_if_aborted()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess helper used ONLY by sandbox code and config probing.
# Never exposed to the agent: no tool takes a command string as an argument.
# ─────────────────────────────────────────────────────────────────────────────
def run_argv(argv: list[str], *, timeout: float = 15.0, env: Optional[dict[str, str]] = None,
             cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run an argv list with no shell (shell=False always), bounded, with
    kill-on-timeout of the whole process group."""
    proc = subprocess.Popen(  # noqa: S603 - argv is built from config constants
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=cwd,
        shell=False,
        start_new_session=(os.name != "nt"),
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "nt":
                proc.kill()
            else:
                os.killpg(os.getpgid(proc.pid), 9)
        except Exception:  # noqa: BLE001
            proc.kill()
        out, err = proc.communicate()
        raise TimeoutError(f"{shlex.join(argv[:3])}… exceeded {timeout:.0f}s") from None
