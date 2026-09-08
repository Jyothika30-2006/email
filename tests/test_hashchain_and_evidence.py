"""Blockchain evidence log + chain-of-custody tests.

The property under test is *tamper evidence*: any edit to a historical block, any
reordering, any truncation must be detectable by `verify()` without trusting the
chain writer. That is what makes the verdict non-repudiable later.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cybersecurity_agent.blockchain.hashchain import HashChain, evidence_payload

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "samples"


def _p(**kw):
    base = dict(file_hash="a" * 64, ai_verdict="MALICIOUS", confidence_score=88.0,
                geolocation_summary="≈ Testville, TL · radius ±40 km · confidence 78%",
                risk_score=99.0, origin_source_kind="spf_client_ip", artifact_hashes={"attachment:x": "b" * 64})
    base.update(kw)
    return evidence_payload(**base)


def test_genesis_link_and_head_pointer(tmp_path):
    chain = HashChain(tmp_path / "c.jsonl", tmp_path / "HEAD.json")
    b0 = chain.append(_p())
    assert b0.index == 0 and b0.previous_block_hash == "0" * 64
    b1 = chain.append(_p(ai_verdict="SAFE"))
    assert b1.previous_block_hash == b0.block_hash
    assert chain.verify().ok
    head = json.loads((tmp_path / "HEAD.json").read_text())
    assert head["head_hash"] == b1.block_hash and head["head_index"] == 1


def test_editing_a_past_verdict_breaks_the_chain(tmp_path):
    chain = HashChain(tmp_path / "c.jsonl", tmp_path / "HEAD.json")
    chain.append(_p(ai_verdict="MALICIOUS"))
    chain.append(_p(ai_verdict="MALICIOUS"))
    chain.append(_p(ai_verdict="SAFE"))
    path = tmp_path / "c.jsonl"
    lines = path.read_text().splitlines()
    # the exact attack a corrupt analyst would try: flip block 0's verdict
    lines[0] = lines[0].replace('"MALICIOUS"', '"SAFE"')
    path.write_text("\n".join(lines) + "\n")
    rep = chain.verify()
    assert not rep.ok and rep.broken_at == 0
    assert "does not hash" in " ".join(rep.reasons)


def test_truncation_is_detected_via_head_pointer(tmp_path):
    chain = HashChain(tmp_path / "c.jsonl", tmp_path / "HEAD.json")
    for i in range(3):
        chain.append(_p(ai_verdict="MALICIOUS" if i else "SAFE"))
    path = tmp_path / "c.jsonl"
    path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")
    rep = chain.verify()
    assert not rep.ok and "HEAD.json" in " ".join(rep.reasons)


def test_reordering_blocks_is_detected(tmp_path):
    chain = HashChain(tmp_path / "c.jsonl", tmp_path / "HEAD.json")
    for i in range(3):
        chain.append(_p(risk_score=float(i)))
    path = tmp_path / "c.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    assert not chain.verify().ok


def test_payload_contains_only_metadata_no_email_content(tmp_path):
    payload = _p()
    blob = json.dumps(payload).lower()
    for leak in ("from:", "subject:", "@corp", "<html", "password", "base64", "received:"):
        assert leak not in blob, f"on-chain payload must not contain {leak!r}"
    assert set(payload) >= {"file_hash", "AI_verdict", "confidence_score", "timestamp", "geolocation_summary"}


def test_canonical_json_is_stable_across_key_order():
    from cybersecurity_agent.blockchain.hashchain import canonical_json

    a = canonical_json({"b": 1, "a": [1, {"z": 0, "y": 2}]})
    b = canonical_json({"a": [1, {"y": 2, "z": 0}], "b": 1})
    assert a == b


# ── chain-of-custody hashing ────────────────────────────────────────────────
def test_hash_before_analysis_manifest(tmp_path):
    from cybersecurity_agent.evidence.hasher import digest_file, record_hash, verify_source_untouched

    f = tmp_path / "case.eml"
    f.write_bytes(b"From: a@b.c\n\nhi")
    sha, md5, size = digest_file(f)
    assert sha == hashlib.sha256(f.read_bytes()).hexdigest() and size == len(f.read_bytes())
    record_hash(tmp_path, name=f.name, kind="source_email", path=str(f), sha256=sha, md5=md5,
                size_bytes=size, recorded_before_analysis=True)
    assert verify_source_untouched(f)[0] is True
    f.write_bytes(b"From: evil@d.e\n\nhi")           # tamper after hashing
    ok, note = verify_source_untouched(f)
    assert ok is False and "SOURCE MODIFIED" in note


def test_hash_evidence_tool_refuses_silent_overwrite(ctx):
    """Re-hashing a *changed* file must surface an integrity failure, not update."""
    from cybersecurity_agent.tools import hash_evidence
    from cybersecurity_agent.evidence.hasher import record_hash

    record_hash(ctx.case_dir, name="case.eml", kind="source_email", path=str(ctx.eml_path),
                sha256="f" * 64, md5="0" * 32, size_bytes=1, recorded_before_analysis=True)
    ctx.evidence_hashes["source"] = "f" * 64
    res = hash_evidence.tool_hash_evidence(ctx, {"targets": "source"})
    assert res.ok is False and "INTEGRITY" in res.summary.upper()
    assert any(s.factor == "evidence_integrity_failure" and "EVIDENCE INTEGRITY" in s.explanation
               for s in res.signals)
    # honesty: an integrity break must NOT be dressed up as an antivirus detection
    assert not any(s.factor == "known_malware_hash" for s in res.signals)
    assert ctx.state["evidence_integrity_failure"] is True
    # …and the manifest must still hold the ORIGINAL digest (no silent overwrite)
    from cybersecurity_agent.evidence.hasher import load_manifest
    recs = load_manifest(ctx.case_dir)["records"]
    assert [r["sha256"] for r in recs if r["name"] == "case.eml"] == ["f" * 64], \
        "a mismatched re-hash must not rewrite the custody record"


def test_attachments_are_hashed_at_staging_time(cfg, tmp_path):
    """Design step 2 + 6: digests exist before static_file_scan can ever run."""
    from cybersecurity_agent.agent import Agent
    from pathlib import Path

    agent = Agent(Path(__file__).resolve().parents[1] / "samples" / "phishing_obvious.eml",
                  demo=True, no_llm=True, case_prefix=tmp_path)  # tmp_path: no repo litter
    agent.cfg = cfg
    verdict = agent.run()
    manifest = json.loads((Path(verdict["report"]).parent / "evidence.json").read_text())
    att = [r for r in manifest["records"] if r["kind"] == "attachment"]
    assert att and att[0]["recorded_before_analysis"] is True
    src = [r for r in manifest["records"] if r["kind"] == "source_email"]
    assert src and src[0]["sha256"] == verdict["sha256"]


def test_a_missing_optional_crypto_extra_degrades_the_mirror_not_the_case(tmp_path, monkeypatch):
    """`.[chain]` is optional and `keccak256` refuses to be faked — so on a machine that
    installs only the two runtime deps, importing the Ganache logger raises at *import time*
    (it computes the contract selector with keccak).

    That used to end a completed investigation with a traceback after the verdict was already
    printed, which is the worst possible place to fail: the analyst has the answer and no
    artifacts. Found by running the suite in a venv without pycryptodome, i.e. by CI.
    """
    import sys

    from cybersecurity_agent.blockchain import pure_python_crypto as ppc
    from cybersecurity_agent.blockchain.pure_python_crypto import KeccakUnavailable

    def broken_keccak(_data: bytes) -> bytes:
        raise KeccakUnavailable("keccak256 needs `pycryptodome` (simulated: optional extra absent)")

    monkeypatch.setattr(ppc, "keccak256", broken_keccak)
    # Only the *dependent* module is re-imported, so it binds the broken keccak above while
    # pure_python_crypto itself stays patched-and-intact for everything else in the session.
    sys.modules.pop("cybersecurity_agent.blockchain.ganache_logger", None)
    try:

        from cybersecurity_agent.agent import Agent

        agent = Agent(SAMPLES / "phishing_obvious.eml", demo=True, no_llm=True, case_prefix=tmp_path,
                      cfg_overrides={"tool_timeout_s": 8.0, "max_agent_steps": 12,
                                     "geoip_allow_private": True, "require_confirmation": False,
                                     "auto_confirm": True, "offline": False, "sandbox_required": False})
        verdict = agent.run()                                                  # must not raise
        agent.close()
    finally:
        # leave no module whose SELECTOR was computed against the simulated failure
        sys.modules.pop("cybersecurity_agent.blockchain.ganache_logger", None)
        monkeypatch.undo()

    assert verdict["verdict"] == "MALICIOUS", "the verdict path cannot depend on an optional extra"
    assert (Path(verdict["report"]).parent / "evidence.json").exists()
    chain = verdict.get("chain") or {}
    ganache = chain.get("ganache") or {}
    assert ganache.get("skipped") is True, f"mirror must report a labelled skip, got {ganache!r}"
    assert ".[chain]" in ganache.get("note", ""), "and say how to switch it on"
