"""Chain-of-custody hashing (SAFETY #6) — used by the controller *before* any
analysis and by the `hash_evidence` tool afterwards.

`runs/<case>/evidence.json` is the human-readable manifest; `audit.log` is
an append-only trail. The blockchain layer later commits only `sha256` + verdict
metadata (never the file), so a reviewer can recompute the digest from the original
.eml and check it against the ledger.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..models import HashRecord

MANIFEST = "evidence.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def digest_file(path: Path | str) -> tuple[str, str, int]:
    """Streamed SHA-256 + MD5 + size. MD5 only because AV corpora key on it."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


def digest_bytes(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def audit_log_path(case_dir: Path) -> Path:
    return case_dir / "audit.log"


def append_audit(case_dir: Path, event: str, detail: str = "") -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": now_iso(), "event": event, "detail": detail}, sort_keys=True)
    with open(audit_log_path(case_dir), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        Path(fh.name).chmod(0o600)


def load_manifest(case_dir: Path) -> dict[str, Any]:
    """The case's chain-of-custody manifest. Public on purpose: a reviewer (or the
    report writer) must be able to read the custody record without private APIs."""
    path = case_dir / MANIFEST
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"case": case_dir.name, "records": [], "notes": ["manifest was unreadable; rebuilt"]}
    return {"case": case_dir.name, "created_utc": now_iso(), "records": [], "notes": []}


def record_hash(case_dir: Path, *, name: str, kind: str, path: str, sha256: str, md5: str,
                 size_bytes: int, recorded_before_analysis: bool = True) -> dict[str, Any]:
    rec = HashRecord(name=name, kind=kind, path=path, sha256=sha256, md5=md5,
                     size_bytes=size_bytes, recorded_at=now_iso(),
                     recorded_before_analysis=recorded_before_analysis).as_dict()
    manifest = load_manifest(case_dir)
    manifest["records"] = [r for r in manifest.get("records", []) if r.get("name") != name] + [rec]
    manifest["updated_utc"] = now_iso()
    (case_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    (case_dir / MANIFEST).chmod(0o600)
    append_audit(case_dir, "hash_recorded", f"{kind}:{name} sha256={sha256[:16]}… before_analysis={recorded_before_analysis}")
    return rec


def verify_recorded(case_dir: Path, name: str, current_sha256: str) -> tuple[bool, str]:
    """Return (ok, detail). Used by hash_evidence to detect mid-case tampering."""
    manifest = load_manifest(case_dir)
    for rec in manifest.get("records", []):
        if rec.get("name") == name:
            if rec.get("sha256") == current_sha256:
                return True, "matches recorded digest"
            return False, f"recorded {rec.get('sha256','')[:16]}… vs current {current_sha256[:16]}…"
    return True, "no prior record for this name"


def verify_source_untouched(eml_path: Path | str) -> tuple[bool, str]:
    """Convenience for reports: does the .eml on disk still hash to the manifest value?"""
    path = Path(eml_path)
    manifest_path = path.parent / MANIFEST
    if not manifest_path.exists():
        return False, "no manifest"
    sha, _, _ = digest_file(path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for rec in manifest.get("records", []):
        if rec.get("kind") == "source_email":
            return (rec.get("sha256") == sha, "source .eml is byte-identical to the hashed original"
                    if rec.get("sha256") == sha else "SOURCE MODIFIED after hashing")
    return False, "no source_email record"


def canonical_json(obj: Any) -> bytes:
    """Deterministic serialization — the ledger hashes this, so key order can never
    change a block hash between platforms."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def timed(label: str):  # pragma: no cover - tiny debug helper
    def deco(fn):
        def inner(*a, **k):
            t0 = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                print(f"[{label}] {fn.__name__} {time.perf_counter() - t0:.3f}s")
        return inner
    return deco
