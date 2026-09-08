"""TOOL 7 — static_file_scan: the ONLY tool that touches file bytes, and even it
touches only a *copy* inside the sandbox.

Order of operations (enforced, not aspirational):
  1. hash every selected artifact (SAFETY #6 — before analysis)
  2. dispatch into the sandbox (Docker → read-only mount, `--network none`,
     destroyed after the run; else rlimit subprocess with an honest label)
  3. parse the scanner's JSON into FileScanFinding + risk signals
  4. re-verify the ORIGINAL file digests against the manifest — if a sandboxed (or
     any) analysis step somehow altered the evidence, the case reports INTEGRITY
     FAILURE rather than quietly continuing.

Nothing here ever executes, renders, extracts or opens a document with a real
application. Flags like `high_entropy` or `file_type_mismatch` are *heuristic*
and worded that way in the report — a clean static scan never means "safe".
"""
from __future__ import annotations

import hashlib
from typing import Any

from ..evidence.hasher import append_audit, digest_bytes, record_hash
from ..evidence.eml import extension_mismatch
from ..models import FileScanFinding, RiskSignal
from ..sandbox import docker_runner
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "artifact": {"type": "string", "description": "attachment filename from parse_headers, or 'all' (default)"},
        "why": {"type": "string", "description": "one sentence of reasoning for the human at the gate"},
    },
}

FLAG_TO_FACTOR = {
    "file_type_mismatch": "file_type_mismatch",
    "high_entropy": "high_entropy",
    "embedded_macro": "embedded_macro",
    "pdf_active_content": "pdf_active_content",
    "yara_matches": "known_malware_hash",
    "suspicious_strings": "av_detections",
    "zip_encrypted_entries": "high_entropy",
    "zip_executable_member(s)": "attachment_risky_ext",
    "eicar_test_signature": "known_malware_hash",
    "pe_packed_sections": "high_entropy",
}


@register(file_touching=True, timeout_override=15.0)   # SAFETY #5: even the sandboxed tool honours the 15s cap at the dispatch layer
@tool_meta(name="static_file_scan", parameters=PARAMS,
           llm_hint="FILE-TOUCHING. You MUST print the exact tag [CONFIRM_NEEDED] in your thought and get human approval; a denied gate is final, do not retry it.")
def tool_static_file_scan(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Sandboxed, non-executing static analysis of attachment bytes (magic/entropy/macros/PE/PDF)."""
    selected = (args.get("artifact") or "all").strip()
    files = dict(ctx.attachment_files)
    if not files:
        return ToolResult(tool="static_file_scan", ok=True, skipped=True,
                          summary="no attachments staged for this case",
                          data={"note": "attachments would be written to runs/<case>/attachments/ during evidence staging"})
    if selected != "all":
        key = f"attachment:{selected}"
        files = {k: v for k, v in files.items() if k == key or _art_name(k) == selected}
        if not files:
            return ToolResult(tool="static_file_scan", ok=False, error=f"unknown artifact '{selected}'",
                              summary="not in the whitelist of staged artifacts for this case")

    findings: list[dict[str, Any]] = []
    signals: list[RiskSignal] = []
    modes: set[str] = set()
    integrity_ok = True

    for name, path in files.items():
        data = path.read_bytes()
        sha, md5 = digest_bytes(data)
        # (1) hash BEFORE analysis, into the chain-of-custody manifest
        record_hash(ctx.case_dir, name=name, kind="attachment", path=str(path),
                    sha256=sha, md5=md5, size_bytes=len(data), recorded_before_analysis=True)
        ctx.evidence_hashes[name] = sha

        # (2) sandbox
        run = docker_runner.scan_file(ctx.cfg, ctx.case_dir, _art_name(name), path, switch=ctx.switch)
        modes.add(run.mode)
        docker_runner.register_kill_teardown(ctx.switch, run.container_name)   # #8: kill destroys container
        report = run.report or {}
        finding = _to_finding(name, path, sha, data, report, run)
        findings.append(finding)

        # (4) integrity re-check of the ORIGINAL bytes we hashed
        now_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if now_sha != sha:
            integrity_ok = False
            signals.append(RiskSignal("known_malware_hash", 1, 100,
                                       explanation=f"EVIDENCE INTEGRITY: artifact {name} changed on disk during analysis",
                                       source="static_file_scan"))
        for flag in report.get("flags", []):
            factor = FLAG_TO_FACTOR.get(flag.split(":", 1)[0], "av_detections")
            strength = 100 if flag.startswith("eicar") else 92 if flag.startswith("file_type_mismatch") else 80 if flag.startswith("high_entropy") else 70
            signals.append(RiskSignal(factor, 1, strength, explanation=f"{name}: {flag[:220]}", source="static_file_scan"))
        if not report.get("flags") and report.get("magic_type") and run.mode != "denied":
            signals.append(RiskSignal("clean_static_scan", -1, 35,
                                      explanation=f"{name}: no static indicators found (magic/entropy/structure consistent) — this is a WEAK negative: it cannot clear an intentionally-clean dropper",
                                      source="static_file_scan"))
        if run.mode == "denied":
            signals.append(RiskSignal("sandbox_unavailable", 1, 45,
                                       explanation=f"attachment analysis refused: {', '.join(run.notes)[:200]}",
                                       source="static_file_scan"))
        elif run.mode == "subprocess-limited":
            signals.append(RiskSignal("sandbox_unavailable", 0, 0,
                                      explanation="isolation was rlimit-guarded subprocess (no container available) — labeled honestly in the report",
                                      source="static_file_scan"))

    append_audit(ctx.case_dir, "static_scan_done", f"{len(findings)} artifact(s); modes={sorted(modes)}; integrity_ok={integrity_ok}")
    ctx.state["static_file_scan"] = {"findings": findings, "modes": sorted(modes)}
    risky = sum(1 for f in findings if f["flags"])
    summary = (f"{len(findings)} artifact(s) scanned in {sorted(modes)}; {risky} with static indicators"
               + ("" if integrity_ok else "; INTEGRITY FAILURE"))
    return ToolResult(tool="static_file_scan", ok=integrity_ok, summary=summary,
                      data={"findings": findings, "isolation": sorted(modes), "integrity_ok": integrity_ok,
                            "note": "static bytewise analysis only — nothing was executed, rendered or extracted"},
                      signals=signals)


def _art_name(name: str) -> str:
    """'attachment:invoice.pdf' → 'invoice.pdf' (artifact keys are namespaced)."""
    return name.split(":", 1)[-1]


def _to_finding(name: str, path: Any, sha: str, data: bytes, report: dict[str, Any], run: Any) -> dict[str, Any]:
    magic = report.get("magic_type", "")
    ext = path.name.rsplit(".", 1)[-1] if "." in path.name else ""
    mismatch = bool(report.get("flags")) and any(str(f).startswith("file_type_mismatch") for f in report["flags"])
    if not magic:
        mismatch = False
    finding = FileScanFinding(
        artifact=name, declared_extension=f".{ext}" if ext else "",
        magic_type=magic or "unavailable (no report)",
        magic_matches_extension=not mismatch,
        size_bytes=report.get("size_bytes", len(data)),
        sha256=sha, md5=report.get("md5", hashlib.md5(data).hexdigest()),
        entropy_bits_per_byte=float(report.get("entropy_bits_per_byte", 0.0)),
        flags=list(report.get("flags", [])) or ([] if report else [f"no scanner report: {run.raw_stderr[:120] or run.notes}"]),
        strings_preview=list(report.get("strings_preview", []))[:12],
        tool_outputs={k: v for k, v in report.items() if k in ("pdf", "ole", "zip", "pe", "optional_tools", "extension_note", "suspicious_strings")},
        isolation=run.mode,
        notes=list(run.notes) + ([f"elapsed {run.elapsed_s}s"] if run.elapsed_s else []),
    )
    d = finding.as_dict()
    d["scanner"] = {k: report.get(k) for k in ("entropy_bits_per_byte", "extension_note", "truncated_at",
                                               "elapsed_s", "execution_note", "error") if k in report}
    return d
