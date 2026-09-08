"""Local-LLM integration (Ollama) — no cloud inference, no data leaves the PC.

Two transport modes, auto-negotiated:
  A. NATIVE tool calling — if the model exposes a `tools` parameter and returns
     `message.tool_calls` (llama3.1/qwen2.5 in recent Ollama builds). We hand it the
     registry's JSON schemas, so the model literally calls whitelisted functions.
  B. JSON protocol — if the model has no tools support, we ask for exactly one JSON
     object per turn ({"thought","tool_call"|"final"}) and parse it defensively.

Everything returns None on any parse/API problem, and the controller falls back to
the deterministic engine for that step — a demo never dies, and the terminal shows
which brain is driving. Reasoning text is streamed to the UI as it arrives.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

from ..config import Config
from ..net import sanitize_untrusted
from ..prompts.agent_system_prompt import build_system_prompt


class OllamaUnavailable(RuntimeError):
    pass


class OllamaEngine:
    is_llm = True

    def __init__(self, cfg: Config, tool_schemas: list[dict[str, Any]], tool_docs: str) -> None:
        self.cfg = cfg
        self.host = cfg.ollama_host.rstrip("/")
        self.model = cfg.ollama_model
        self.schemas = tool_schemas
        self.system = build_system_prompt(tool_docs)
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": self.system}]
        self._supports_tools: Optional[bool] = None
        self.mode = "unknown"
        self._log: Callable[[str], None] = lambda s: None
        self.turns = 0
        self.parse_failures = 0

    # ── availability ───────────────────────────────────────────────────────
    def probe(self, log: Callable[[str], None] = lambda s: None) -> tuple[bool, str]:
        self._log = log
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=4.0) as resp:  # noqa: S310
                tags = json.loads(resp.read(400_000).decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            return False, f"Ollama not reachable at {self.host} ({type(exc).__name__}) → deterministic engine will drive"
        models = [m.get("name", "") for m in tags.get("models", [])]
        want = self.model.split(":")[0]
        if self.model not in models and not any(m == self.model or m.startswith(want) for m in models):
            return False, (f"Ollama is up but model '{self.model}' is not pulled "
                           f"(have: {', '.join(models[:6]) or 'none'}) → run `ollama pull {self.model}`; deterministic engine for now")
        # native tools? ask the model endpoint for its capability flags
        info = self._show()
        caps = (info or {}).get("details", {}).get("capability", []) or []
        self._supports_tools = any("tool" in str(c).lower() for c in caps) if caps else None
        self.mode = "native-tools" if self._supports_tools else "json-protocol"
        return True, f"Ollama online · model {self.model} · mode {self.mode}"

    def _show(self) -> Optional[dict[str, Any]]:
        try:
            body = json.dumps({"model": self.model}).encode()
            req = urllib.request.Request(f"{self.host}/api/show", data=body,  # noqa: S310
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                return json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            return None

    # ── the loop ───────────────────────────────────────────────────────────
    def prime(self, evidence_digest: dict[str, Any], email_block: str) -> None:
        """First user message: structured evidence digest + the sanitized email."""
        self.messages.append({
            "role": "user",
            "content": "Begin the investigation of ONE email. Case digest (produced by the harness, "
                       "already hash-verified):\n" + json.dumps(evidence_digest, indent=1, default=str)[:6000]
                       + "\n\n" + email_block,
        })

    def observe(self, tool: str, observation: dict[str, Any], risk_line: str) -> None:
        self.messages.append({
            "role": "user",
            "content": f"OBSERVATION after {tool} — running risk score: {risk_line}\n"
                       + json.dumps(observation, default=str, indent=0)[:5200]
                       + "\n\nChoose the next step (or finish). Remember: explain what changed the risk score and why (rule 4).",
        })

    def next_action(self, ctx: Any, history: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        self.turns += 1
        allowed = _allowed_names(ctx)
        try:
            if self._supports_tools:
                raw = self._chat(tools=self.schemas)
                parsed = _from_native(raw, allowed)
            else:
                raw = self._chat()
                parsed = _from_json(raw, allowed)
            if parsed is None and self._supports_tools:
                parsed = _from_json(raw, allowed)   # some builds emit JSON text anyway
            return parsed
        except OllamaUnavailable as exc:
            self._log(f"[LLM] {exc} → this step handled by deterministic engine")
            return None

    def _chat(self, tools: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self.messages,
            "stream": True,
            "options": {"temperature": self.cfg.llm_temperature, "num_predict": self.cfg.llm_max_tokens,
                        "num_ctx": 8192},
        }
        if tools:
            payload["tools"] = tools
        req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(payload).encode(),  # noqa: S310
                                     headers={"Content-Type": "application/json"})
        text_parts: list[str] = []
        message: dict[str, Any] = {}
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.llm_request_timeout_s) as resp:
                for line in resp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        continue
                    if chunk.get("error"):
                        raise OllamaUnavailable(str(chunk["error"])[:160])
                    msg = chunk.get("message") or {}
                    if msg.get("content"):
                        delta = msg["content"]
                        text_parts.append(delta)
                        self._log_delta(delta)
                    if chunk.get("done"):
                        message = msg or message
                        message["content"] = "".join(text_parts) or message.get("content", "")
                        if msg.get("tool_calls"):
                            message["tool_calls"] = msg["tool_calls"]
                    if msg.get("tool_calls") and not chunk.get("done"):
                        message.setdefault("tool_calls", msg["tool_calls"])
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise OllamaUnavailable(f"chat request failed: {type(exc).__name__}: {exc}") from exc
        except json.JSONDecodeError as exc:  # pragma: no cover
            raise OllamaUnavailable(f"malformed stream from Ollama: {exc}") from exc
        self._log("\n")
        if not message:
            raise OllamaUnavailable("empty completion")
        self.messages.append({"role": "assistant", "content": message.get("content", ""),
                              **({"tool_calls": message["tool_calls"]} if message.get("tool_calls") else {})})
        return message

    def _log_delta(self, delta: str) -> None:
        # stream into the UI without corrupting the live panel
        self._log(delta)

    def summarize(self, prompt: str) -> Optional[str]:
        """One-shot narrative helper (e.g. the final report intro). No tools."""
        try:
            payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}],
                       "stream": False, "options": {"temperature": 0.2, "num_predict": 320}}
            req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(payload).encode(),  # noqa: S310
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.cfg.llm_request_timeout_s) as resp:
                blob = json.loads(resp.read(1_500_000).decode("utf-8", "replace"))
            return sanitize_untrusted((blob.get("message") or {}).get("content", ""), limit=1800)
        except Exception as exc:  # noqa: BLE001
            self._log(f"[LLM] summary skipped ({type(exc).__name__})")
            return None


# ─────────────────────────────────────────────────────────────────────────────
def _allowed_names(ctx: Any) -> set[str]:
    from ..tools import REGISTRY

    return set(REGISTRY)


def _from_native(message: dict[str, Any], allowed: set[str]) -> Optional[dict[str, Any]]:
    calls = message.get("tool_calls") or []
    content = message.get("content") or ""
    if not calls:
        final = _extract_final(content)
        if final:
            return {"thought": _first_sentences(content), "final": final}
        if "finalize" in (content or "").lower() and not calls:
            return {"thought": _first_sentences(content), "finalize": True}
        return {"thought": (content.strip() or "(empty)")[:600]} if content.strip() else None
    call = calls[0] if isinstance(calls[0], dict) else {}
    fn = call.get("function") or {}
    name = (fn.get("name") or "").strip().lower()
    args = fn.get("arguments") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except json.JSONDecodeError:
            args = {}
    if name not in allowed:
        return {"thought": _first_sentences(content), "tool_call": {"name": name or "unknown", "arguments": args},
                "invented": True}
    confirm = "[CONFIRM_NEEDED]" in content
    return {"thought": _first_sentences(content), "tool_call": {"name": name, "arguments": args},
            "confirm_requested": confirm,
            "thought_full": content[:1200]}


def _from_json(content: str, allowed: set[str]) -> Optional[dict[str, Any]]:
    blob = _first_json_object(content or "")
    if blob is None:
        return None
    if "final" in blob:
        return {"thought": str(blob.get("thought", ""))[:600], "final": blob["final"] if isinstance(blob["final"], dict) else {}}
    call = blob.get("tool_call")
    if isinstance(call, dict):
        name = str(call.get("name", "")).strip().lower()
        args = call.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}
        if name not in allowed:
            return {"thought": str(blob.get("thought", ""))[:600], "tool_call": {"name": name or "unknown", "arguments": args},
                    "invented": True}
        return {"thought": str(blob.get("thought", ""))[:600], "tool_call": {"name": name, "arguments": args},
                "confirm_requested": "[CONFIRM_NEEDED]" in str(blob.get("thought", ""))}
    return {"thought": str(blob.get("thought", ""))[:600]}


def _extract_final(content: str) -> Optional[dict[str, Any]]:
    blob = _first_json_object(content or "")
    if blob and "final" in blob:
        return blob["final"] if isinstance(blob["final"], dict) else {}
    return None


def _first_json_object(text: str) -> Optional[dict[str, Any]]:
    text = re.sub(r"```(?:json)?|```", "", text or "").strip()
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        blob = json.loads(text[start:i + 1])
                        if isinstance(blob, dict):
                            return blob
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def _first_sentences(text: str, limit: int = 3) -> str:
    parts = re.split(r"(?<=[.!?\n])\s+", (text or "").strip())
    return " ".join(p for p in parts[:limit] if p)[:600]
