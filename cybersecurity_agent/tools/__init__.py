"""TOOL LAYER — the whitelist (SAFETY #1).

Design contract: see tools/base.py + dispatch() below.
"""
from __future__ import annotations

from typing import Any, Optional

from .base import REGISTRY, ToolContext, ToolDef, ToolResult, hash_of, register, tool_meta
from .dispatch import (WhitelistViolation, describe_tools, dispatch,
                       ollama_tool_schemas, validate_call)

# Importing each tool module executes its @register() decorators. This line IS the
# whitelist definition — nothing outside it can become callable, and there is no
# shell/exec tool in the list by design (SAFETY #1).
from . import (  # noqa: E402,F401
    check_reputation,
    check_tor_exit,
    extract_urls,
    geolocate_ip,
    hash_evidence,
    parse_headers,
    redact_reply,
    resolve_origin,
    static_file_scan,
)

__all__ = ["ToolContext", "ToolResult", "ToolDef", "REGISTRY", "register", "tool_meta",
           "dispatch", "validate_call", "describe_tools", "ollama_tool_schemas",
           "WhitelistViolation", "hash_of"]
