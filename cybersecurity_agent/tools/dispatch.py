"""Tool dispatch: the ONLY path by which a whitelisted tool executes.

Enforces, in order:
  #1 whitelist validation (unknown/invented/shell-like names → refusal *as evidence*)
  prerequisite ordering (a tool cannot run before its inputs exist)
  #8 kill-switch checks before and after execution
  #4 human gate for file-touching tools (fail-closed on timeout/denial)
  #5 hard timeout per call
  tool exceptions are converted to structured ToolResults — a bug in one tool must
  never abort the investigation.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from ..net import sanitize_untrusted
from ..safety import AbortedError, FORBIDDEN_ACTIONS, ToolTimeoutError, run_with_timeout
from .base import REGISTRY, RiskSignal, ToolContext, ToolResult

class WhitelistViolation(Exception):
    pass


def validate_call(name: str, args: Optional[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """Reject anything that is not a registered tool with registered argument
    names. Returns (name, sanitized_args). Raises WhitelistViolation otherwise."""
    clean = (name or "").strip().lower()
    if clean in FORBIDDEN_ACTIONS:
        raise WhitelistViolation(f"'{name}' is a forbidden action, not a whitelisted tool")
    tool = REGISTRY.get(clean)
    if tool is None:
        raise WhitelistViolation(
            f"tool '{name}' is not in the whitelist "
            f"(available: {', '.join(sorted(REGISTRY))})"
        )
    args = dict(args or {})
    allowed = set(tool.parameters.get("properties", {}))
    if allowed:
        dropped = {k: v for k, v in args.items() if k not in allowed}
        args = {k: v for k, v in args.items() if k in allowed}
        if dropped:
            # silently ignore extras rather than trusting them — but record it
            args["_dropped_args"] = sorted(dropped)
    # strings are sanitized so a tool can never forward injection tokens onward
    args = {k: (sanitize_untrusted(v, limit=400) if isinstance(v, str) else v) for k, v in args.items()}
    return clean, args


def describe_tools() -> str:
    return "\n".join(t.doc_line() for t in REGISTRY.values())


def ollama_tool_schemas() -> list[dict[str, Any]]:
    return [t.to_ollama_schema() for t in REGISTRY.values()]


def dispatch(ctx: ToolContext, name: str, args: Optional[dict[str, Any]] = None,
             *, confirm_reason: str = "") -> ToolResult:
    """The ONLY path by which a tool executes. Enforces #1, #4, #5, #8."""
    start = time.monotonic()
    try:
        clean_name, clean_args = validate_call(name, args)
    except WhitelistViolation as exc:
        return ToolResult(
            tool=str(name)[:40], ok=False, error=str(exc),
            summary="refused: not a whitelisted tool",
            signals=[RiskSignal("invented_tool_request", 1, 90,
                                explanation=f"agent/model requested non-existent tool “{str(name)[:40]}” → whitelist held; treated as tampering attempt",
                                source="whitelist")],
            skipped=True, duration_ms=round((time.monotonic() - start) * 1000, 1),
        )

    tool = REGISTRY[clean_name]
    missing = [n for n in tool.needs if n not in ctx.state]
    if missing:
        return ToolResult(tool=clean_name, ok=False, skipped=True,
                          summary=f"needs {', '.join(missing)} first",
                          error=f"prerequisite tools not yet run: {', '.join(missing)}")

    if ctx.switch:
        try:
            ctx.switch.raise_if_aborted()
        except AbortedError as exc:
            return ToolResult(tool=clean_name, ok=False, skipped=True, error=str(exc),
                              summary="aborted before execution (kill-switch)")

    # SAFETY #4 — human gate for file-touching tools.
    if tool.file_touching and not ctx.approved_file_tools:
        from ..ui.console import ask_confirmation   # deferred: UI imports rich

        approved = ask_confirmation(ctx, clean_name, confirm_reason or tool.description)
        if not approved:
            return ToolResult(
                tool=clean_name, ok=False, skipped=True, approved=False,
                summary="human denied the file-touching tool (fail-closed)",
                signals=[RiskSignal("human_denied_scan", 1, 55,
                                    explanation="analysis of attachment bytes was declined by the operator; verdict rests on header/URL/origin evidence only",
                                    source="gate")],
            )
        ctx.approved_file_tools = True

    timeout = tool.timeout_override or ctx.cfg.tool_timeout_s
    try:
        result = run_with_timeout(tool.fn, ctx, clean_args, timeout=timeout,
                                  switch=ctx.switch, label=clean_name)
    except ToolTimeoutError as exc:
        return ToolResult(tool=clean_name, ok=False, timed_out=True, error=str(exc),
                          summary=f"timed out after {timeout:.0f}s (hard cap)",
                          signals=[RiskSignal("tool_timeout", 1, 25,
                                              explanation=f"{clean_name} hit the {timeout:.0f}s safety cap; its evidence dimension is missing",
                                              source=clean_name)])
    except AbortedError as exc:
        return ToolResult(tool=clean_name, ok=False, skipped=True, error=str(exc),
                          summary="aborted mid-flight (kill-switch)")
    except Exception as exc:  # noqa: BLE001 - a tool bug must not kill the run
        return ToolResult(tool=clean_name, ok=False, error=f"{type(exc).__name__}: {exc}",
                          summary="tool crashed (caught; investigation continues)")
    result.duration_ms = round((time.monotonic() - start) * 1000, 1)
    ctx.state[clean_name] = result
    return result




def describe_tools() -> str:
    return "\n".join(t.doc_line() for t in REGISTRY.values())


def ollama_tool_schemas() -> list[dict[str, Any]]:
    return [t.to_ollama_schema() for t in REGISTRY.values()]
