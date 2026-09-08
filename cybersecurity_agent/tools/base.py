"""Shared tool-layer types (kept in its own module to avoid an import cycle:
tools/__init__ imports every tool module, so tool modules may only import `base`)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from ..config import Config
from ..models import RiskSignal

if TYPE_CHECKING:                       # annotation only — importing safety at runtime
    from ..safety import KillSwitch     # would re-create the cycle this module exists to avoid


@dataclass
class ToolContext:
    """Everything a tool is allowed to see. Populated by the agent controller."""
    cfg: Config
    case_dir: Path
    eml_path: Path
    raw_bytes: bytes
    parsed: Any = None                       # ParsedEmail (lazily parsed)
    state: dict[str, Any] = field(default_factory=dict)   # cross-tool scratchpad
    attachment_files: dict[str, Path] = field(default_factory=dict)
    evidence_hashes: dict[str, str] = field(default_factory=dict)
    switch: Optional[KillSwitch] = None
    approved_file_tools: bool = False
    auto_confirm: bool = False        # --yes/--demo: audit.log gets gate_auto_approved, never a human approval
    extra_iocs: list[dict[str, Any]] = field(default_factory=list)

    def rel(self, path: Path | str) -> str:
        p = Path(path)
        try:
            return str(p.relative_to(self.case_dir))
        except ValueError:
            return str(p)


@dataclass
class ToolResult:
    tool: str
    ok: bool = True
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    signals: list[RiskSignal] = field(default_factory=list)
    error: str = ""
    duration_ms: float = 0.0
    skipped: bool = False
    timed_out: bool = False
    approved: Optional[bool] = None    # set by the human gate on file-touching tools

    def as_dict(self, *, inline_bytes: bool = False) -> dict[str, Any]:
        d = {
            "tool": self.tool, "ok": self.ok, "summary": self.summary,
            "error": self.error, "duration_ms": self.duration_ms,
            "skipped": self.skipped, "timed_out": self.timed_out,
            "signals": [s.as_dict() for s in self.signals],
        }
        try:
            d["data"] = json.loads(json.dumps(self.data, default=str))
        except (TypeError, ValueError):
            d["data"] = {"_unserializable": str(self.data)[:2000]}
        return d


@dataclass
class ToolDef:
    name: str
    fn: Callable[[ToolContext, dict[str, Any]], ToolResult]
    description: str
    parameters: dict[str, Any]
    file_touching: bool = False      # requires the human gate
    timeout_override: Optional[float] = None
    needs: tuple[str, ...] = ()      # must run after these tools
    llm_hint: str = ""

    # ── schema for Ollama native tool calling ──
    def to_ollama_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def doc_line(self) -> str:
        args = ", ".join(f"{k}: {v.get('description', '')}" for k, v in self.parameters.get("properties", {}).items())
        gate = " [GATED: needs human 'yes']" if self.file_touching else ""
        return f"- {self.name}({args or '—'}) — {self.description}{gate}"


REGISTRY: dict[str, ToolDef] = {}


def register(*, file_touching: bool = False, timeout_override: Optional[float] = None,
             needs: tuple[str, ...] = ()) -> Callable[[Callable[..., ToolResult]], Callable[..., ToolResult]]:
    def deco(fn: Callable[..., ToolResult]) -> Callable[..., ToolResult]:
        meta = getattr(fn, "_tool_meta", {})
        name = meta.get("name") or fn.__name__.removeprefix("tool_")
        REGISTRY[name] = ToolDef(
            name=name, fn=fn, description=(fn.__doc__ or "").strip().splitlines()[0],
            parameters=meta.get("parameters", {"type": "object", "properties": {}}),
            file_touching=file_touching, timeout_override=timeout_override, needs=needs,
            llm_hint=meta.get("llm_hint", ""),
        )
        return fn
    return deco


def tool_meta(*, name: str, parameters: dict[str, Any], llm_hint: str = "") -> Callable:
    def deco(fn: Callable[..., ToolResult]) -> Callable[..., ToolResult]:
        fn._tool_meta = {"name": name, "parameters": parameters, "llm_hint": llm_hint}  # type: ignore[attr-defined]
        return fn
    return deco




def hash_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
