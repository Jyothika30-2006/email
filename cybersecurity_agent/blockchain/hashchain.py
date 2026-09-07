"""Blockchain evidence log — back-end A: a local, append-only SHA-256 hash-chain.

Why a hash-chain and not "just a log file": each block commits to the previous
block's hash, so changing ANY historical field (e.g. quietly re-writing a verdict
from MALICIOUS to SAFE) breaks every link after it. `chain verify` recomputes the
whole chain from disk and reports the first broken index — the same property
judges/auditors care about, at zero cost and with zero network.

What goes on-chain (exactly what the brief specifies, nothing more):
  { file_hash, AI_verdict, confidence_score, timestamp, geolocation_summary }
  (+ origin_source_kind, artifact_hashes for chain-of-custody, risk score)
What NEVER goes on-chain: the raw email, the attachment bytes, the URL list,
recipients beyond the already-hashed evidence. Metadata only = cheap + private.

The remaining trust gap is stated honestly: whoever can rewrite the *entire* file
plus HEAD.json can forge a chain. That is why `chain anchor` prints the head hash
for you to commit/notarize externally (git commit, RFC3161 TSA, or the optional
Ganache contract) — after anchoring, wholesale forgery requires re-doing the
anchor too.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> bytes:
    """Stable serialization: sorted keys, no whitespace, no unicode escapes.
    Cross-platform deterministic hashing is the whole point of the chain."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Block:
    index: int
    timestamp: str
    payload: dict[str, Any]
    previous_block_hash: str
    nonce: str
    block_hash: str = ""

    def header(self) -> dict[str, Any]:
        return {"index": self.index, "timestamp": self.timestamp, "payload": self.payload,
                "previous_block_hash": self.previous_block_hash, "nonce": self.nonce}

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.header()))

    def to_json(self) -> str:
        d = self.header()
        d["block_hash"] = self.block_hash
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> "Block":
        d = json.loads(line)
        return cls(index=int(d["index"]), timestamp=d["timestamp"], payload=d["payload"],
                   previous_block_hash=d["previous_block_hash"], nonce=d.get("nonce", ""),
                   block_hash=d.get("block_hash", ""))


@dataclass
class VerifyReport:
    ok: bool
    blocks: int
    broken_at: Optional[int] = None
    reasons: list[str] = field(default_factory=list)
    head_hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class HashChain:
    def __init__(self, path: Path | str, head_path: Optional[Path | str] = None) -> None:
        self.path = Path(path)
        self.head_path = Path(head_path) if head_path else self.path.with_name("HEAD.json")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ── read ───────────────────────────────────────────────────────────────
    def __iter__(self) -> Iterator[Block]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield Block.from_json(line)
                except (json.JSONDecodeError, KeyError, ValueError):
                    yield Block(index=-1, timestamp="<corrupt line>", payload={}, previous_block_hash="", nonce="", block_hash="")

    def blocks(self) -> list[Block]:
        return list(self)

    def head(self) -> Optional[Block]:
        last = None
        for b in self:
            last = b
        return last

    # ── write ──────────────────────────────────────────────────────────────
    def append(self, payload: dict[str, Any], *, timestamp: Optional[str] = None) -> Block:
        prev = self.head()
        index = 0 if prev is None else prev.index + 1
        block = Block(
            index=index,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            payload=payload,
            previous_block_hash=(prev.block_hash if prev else GENESIS_HASH),
            nonce=secrets.token_hex(8),
        )
        block.block_hash = block.compute_hash()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(block.to_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())          # durable before we claim it was logged
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._write_head(block)
        return block

    def _write_head(self, block: Block) -> None:
        self.head_path.parent.mkdir(parents=True, exist_ok=True)
        self.head_path.write_text(json.dumps({
            "head_index": block.index, "head_hash": block.block_hash,
            "updated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "chain_file": self.path.name,
            "note": "public 'header' of the local chain; anchor this hash externally for tamper-PROOFNESS",
        }, indent=2, sort_keys=True), encoding="utf-8")

    # ── integrity ──────────────────────────────────────────────────────────
    def verify(self) -> VerifyReport:
        expected_prev = GENESIS_HASH
        count = 0
        head_hash = ""
        for b in self:
            count += 1
            if b.index == -1:
                return VerifyReport(False, count, count - 1, ["malformed line in ledger"], head_hash)
            if b.index != count - 1:
                return VerifyReport(False, count, b.index, [f"index gap: expected {count - 1}, found {b.index}"], head_hash)
            if b.previous_block_hash != expected_prev:
                return VerifyReport(False, count, b.index,
                                    ["linkage broken: previous_block_hash does not match the stored hash of block "
                                     f"{b.index - 1} (history was rewritten, not just reordered)"], head_hash)
            recomputed = b.compute_hash()
            if recomputed != b.block_hash:
                return VerifyReport(False, count, b.index,
                                    [f"block {b.index} content does not hash to its recorded block_hash "
                                     f"({b.block_hash[:12]}… vs {recomputed[:12]}…) — payload was edited after logging"], head_hash)
            expected_prev = b.block_hash
            head_hash = b.block_hash
        if count == 0:
            return VerifyReport(True, 0, None, ["chain is empty"], "")
        if self.head_path.exists():
            try:
                head = json.loads(self.head_path.read_text(encoding="utf-8"))
                if head.get("head_hash") and head["head_hash"] != head_hash:
                    return VerifyReport(False, count, count - 1,
                                        ["HEAD.json points at a different tip than the ledger contains "
                                         "(truncated ledger or forged head pointer)"], head_hash)
            except json.JSONDecodeError:
                return VerifyReport(False, count, count - 1, ["HEAD.json unreadable/corrupt"], head_hash)
        return VerifyReport(True, count, None, [f"{count} block(s) verified, links + hashes consistent"], head_hash)

    # ── human views ────────────────────────────────────────────────────────
    def export(self) -> dict[str, Any]:
        return {
            "chain_file": str(self.path),
            "blocks": [json.loads(b.to_json()) for b in self],
            "head": json.loads(self.head_path.read_text(encoding="utf-8")) if self.head_path.exists() else None,
        }


def evidence_payload(*, file_hash: str, ai_verdict: str, confidence_score: float,
                     geolocation_summary: str, risk_score: float, origin_source_kind: str,
                     artifact_hashes: dict[str, str]) -> dict[str, Any]:
    """Build the on-chain payload — the exact five fields from the brief plus the
    two the analyst needs to interpret them, and artifact digests."""
    return {
        "file_hash": file_hash,
        "AI_verdict": ai_verdict,
        "confidence_score": round(float(confidence_score), 1),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "geolocation_summary": (geolocation_summary or "no traceable IP — location unknown")[:400],
        "risk_score": round(float(risk_score), 1),
        "origin_source_kind": origin_source_kind,
        "artifact_hashes": {k: v[:64] for k, v in (artifact_hashes or {}).items()},
    }
