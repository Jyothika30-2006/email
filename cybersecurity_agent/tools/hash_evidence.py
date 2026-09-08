"""TOOL 8 — hash_evidence: SHA-256 (and MD5 for AV-corpus lookup) of the original
.eml and of every extracted artifact, recorded BEFORE any analysis runs.

SAFETY #6 (immutable evidence logging). Two properties matter:
  * ordering — the .eml is hashed by the controller before any other tool touches
    it; this tool also refuses to "re-hash" the source file silently: it re-verifies
    the recorded digest and flags a mismatch (that would mean tampering mid-case);
  * provenance — every entry carries a UTC timestamp + `recorded_before_analysis`,
    which is what the blockchain ledger later commits to.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..evidence.hasher import audit_log_path, record_hash, verify_recorded
from ..models import RiskSignal
from .base import ToolContext, ToolResult, register, tool_meta

PARAMS = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "string",
            "description": "'source' (default), 'artifacts', or 'all' — what to hash right now",
            "enum": ["source", "artifacts", "all"],
        }
    },
}


@register()
@tool_meta(name="hash_evidence", parameters=PARAMS,
           llm_hint="Already run at pipeline start (step 2). Call again only to hash newly extracted artifacts or to verify the source digest.")
def tool_hash_evidence(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Compute + record SHA-256 of the evidence file and extracted artifacts (no analysis side effects)."""
    targets = (args.get("targets") or "artifacts").lower()
    records = []
    mismatch: list[str] = []

    if targets in {"source", "all"}:
        rec, problem = _hash_source(ctx)
        if rec:
            records.append(rec)
        if problem:
            mismatch.append(problem)

    if targets in {"artifacts", "all"}:
        for name, path in sorted(ctx.attachment_files.items()):
            if not Path(path).exists():
                continue
            data = Path(path).read_bytes()
            sha, md5 = hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()
            rec = record_hash(ctx.case_dir, name=name, kind="attachment", path=str(path),
                              sha256=sha, md5=md5, size_bytes=len(data),
                              recorded_before_analysis=True)
            ctx.evidence_hashes[name] = sha
            records.append(rec)

    signals: list[RiskSignal] = []
    if mismatch:
        # This is an integrity failure of OUR record, not a malware finding — do not
        # launder it into `known_malware_hash` (that would fake a detection we never got).
        ctx.state["evidence_integrity_failure"] = True
        signals.append(RiskSignal("evidence_integrity_failure", 1, 100,
                                  explanation="EVIDENCE INTEGRITY: re-hash of the .eml did not match the chain-of-custody record — "
                                              "the file changed after hashing; nothing in this run can be treated as high-confidence",
                                  source="hash_evidence"))
    summary = f"hashed {len(records)} artifact(s); manifest + audit log updated"
    if mismatch:
        summary = "INTEGRITY FAILURE: " + "; ".join(mismatch)
    return ToolResult(
        tool="hash_evidence", ok=not mismatch, summary=summary,
        data={
            "records": records,
            "manifest": ctx.rel(ctx.case_dir / "evidence.json"),
            "audit_log": str(audit_log_path(ctx.case_dir).relative_to(ctx.case_dir)),
            "source_sha256": ctx.evidence_hashes.get("source", ""),
            "integrity_ok": not mismatch,
        },
        signals=signals,
    )


def _hash_source(ctx: ToolContext) -> tuple[dict[str, Any] | None, str]:
    data = ctx.raw_bytes
    sha = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    prior = ctx.evidence_hashes.get("source")
    if prior and prior != sha:
        # Never silently overwrite: the whole point of #6 is that a changed digest
        # is an *incident*, not a bookkeeping update.
        return None, (f"source digest changed after initial hashing "
                      f"(recorded {prior[:16]}… now {sha[:16]}…) — evidence may have been tampered with")
    rec = record_hash(ctx.case_dir, name=Path(ctx.eml_path).name, kind="source_email",
                      path=str(ctx.eml_path), sha256=sha, md5=md5, size_bytes=len(data),
                      recorded_before_analysis=(prior is None))
    ctx.evidence_hashes["source"] = sha
    return rec, ""
