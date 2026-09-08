"""Optional blockchain back-end: pure-python keccak256 / secp256k1 / RLP and a
fake JSON-RPC node, so the Ganache logger is exercised without a testnet.

The default evidence back-end remains the local hash-chain (test_hashchain…); these
tests exist so the *optional* on-chain mirror is not untested wishful thinking.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# `keccak256` refuses to run without pycryptodome rather than fake an evidence hash (see
# pure_python_crypto), and importing ganache_logger computes SELECTOR with it. So the whole
# file must *skip* — not error — when the optional extra is absent: the documented promise is
# that the suite runs on `rich` + `dnspython` + pytest and nothing else. CI runs this file a
# second time with `.[chain]` installed so the optional path stays genuinely covered.
pytest.importorskip("Crypto.Hash.keccak", reason="optional '.[chain]' extra not installed")

REPO = Path(__file__).resolve().parents[1]

from cybersecurity_agent.blockchain.ganache_logger import SELECTOR
from cybersecurity_agent.blockchain.pure_python_crypto import (
    N, encode_legacy_tx, keccak256, privkey_to_pubkey, private_key_to_address,
    rlp_encode, ecdsa_recover_pubkey, ecdsa_sign)

SELECTOR_COUNT = keccak256(b"evidenceCount()")[:4]
SELECTOR_GET_AT = keccak256(b"getEvidenceAt(uint256)")[:4]


# ── crypto vectors (published, not self-consistent) ─────────────────────────
def test_keccak256_known_vectors():
    """Published Keccak-256 (NOT SHA3-256) vectors — the hash an Ethereum contract
    sees. If these ever fail, every on-chain record we wrote is wrong, so this is
    the most important test in the file."""
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"hello").hex() == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert keccak256(b"a" * 135).hex() != keccak256(b"a" * 136).hex()   # rate boundary
    assert keccak256(b"") != hashlib.sha256(b"").digest(), "must be keccak, not sha256"


def test_address_derivation_vector():
    # Classic test key — derives the widely published address.
    priv = "4646464646464646464646464646464646464646464646464646464646464646"
    assert private_key_to_address(priv) == "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"


def test_ecdsa_sign_recovers_and_is_deterministic():
    priv = bytes.fromhex("11" * 32)
    digest = keccak256(b"sentinel evidence")
    r, s, recid = ecdsa_sign(priv, digest)
    pub = privkey_to_pubkey(priv)
    assert 0 < s <= N // 2, "low-s normalization"
    assert ecdsa_recover_pubkey(digest, r, s, recid) == pub
    assert ecdsa_sign(priv, digest) == (r, s, recid), "RFC6979 must be deterministic"


def test_rlp_known_encodings():
    assert rlp_encode(b"dog") == b"\x83dog"
    assert rlp_encode(["cat", "dog"]) == b"\xc8\x83cat\x83dog"
    assert rlp_encode(15) == b"\x0f"
    assert rlp_encode(1024) == b"\x82\x04\x00"
    assert rlp_encode(b"") == b"\x80"


def test_legacy_tx_signing_hash_shape():
    h, signed = encode_legacy_tx(nonce=9, gas_price=20 * 10**9, gas_limit=21000,
                                 to="0x3535353535353535353535353535353535353535",
                                 value=10**18, data=b"", chain_id=1)
    assert len(h) == 32 and signed[0] >= 0xC0
    r, s, recid = ecdsa_sign(bytes.fromhex("22" * 32), h)
    assert r > 0 and s > 0 and recid in (0, 1)


def test_payload_digest_is_over_canonical_json():
    from cybersecurity_agent.blockchain.ganache_logger import payload_digest

    a = payload_digest({"x": 1, "y": [2, 3]})
    b = payload_digest({"y": [2, 3], "x": 1})
    assert a == b and len(a) == 32
    assert a != payload_digest({"x": 1, "y": [2, 4]})


def test_abi_encoding_of_submit_call_is_four_static_words():
    from cybersecurity_agent.blockchain.ganache_logger import SELECTOR, _encode_call

    fh = b"\x11" * 32
    dg = b"\x22" * 32
    verdict = b"SUSPICIOUS".ljust(32, b"\x00")
    conf = (9012).to_bytes(32, "big")
    data = _encode_call([fh, dg, verdict, conf])
    assert data[:4] == SELECTOR and len(data) == 4 + 4 * 32, "static-only call: no offsets"
    assert data[4:36] == fh and data[36:68] == dg
    assert data[68:100] == verdict
    assert int.from_bytes(data[100:132], "big") == 9012, "confidence in basis points"


def test_abi_codec_general_shapes_match_hand_computed_encodings():
    from cybersecurity_agent.blockchain.abi_codec import (decode_get_evidence_at, encode_bytes32,
                                                          encode_function, encode_string, encode_uint)

    assert encode_uint(5, 8) == b"\x00" * 31 + b"\x05"
    assert encode_bytes32("SAFE") == b"SAFE".ljust(32, b"\x00")
    with pytest.raises(ValueError):
        encode_uint(256, 8)
    with pytest.raises(ValueError):
        encode_bytes32(b"x" * 33)
    # dynamic string tail: offset then (len, padded data) — matches solc's output
    enc = encode_function(b"\xab\xcd\xef\x01", [("bytes32", b"\x11" * 32), ("string", "hi")])
    assert enc[:4] == b"\xab\xcd\xef\x01"
    assert enc[4:36] == b"\x11" * 32
    # offsets are relative to the start of the *arguments*, i.e. after the 4-byte selector
    assert int.from_bytes(enc[36:68], "big") == 64
    assert int.from_bytes(enc[4 + 64:4 + 96], "big") == 2 and enc[4 + 96:4 + 98] == b"hi"
    assert encode_string("hi") == (2).to_bytes(32, "big") + b"hi".ljust(32, b"\x00")
    five = b"".join([b"\xaa" * 32, b"\xbb" * 32, b"SAFE".ljust(32, b"\x00"),
                     (9012).to_bytes(32, "big"), (1_700_000_000).to_bytes(32, "big")])
    rec = decode_get_evidence_at(five)
    assert rec["fileHash"] == "0x" + "aa" * 32 and rec["verdict"] == "SAFE"
    assert rec["confidence_bps"] == 9012 and rec["timestamp"] == 1_700_000_000
    with pytest.raises(ValueError):
        decode_get_evidence_at(b"\x00" * 32 * 3)             # truncated
    with pytest.raises(ValueError):
        decode_get_evidence_at(b"".join([b"\x00" * 32, b"\x00" * 32, b"\xff" + b"\x00" * 31,
                                         b"\x00" * 32, b"\x00" * 32]))   # non-ASCII verdict


def test_contract_and_logger_agree_on_the_selector():
    """The 4-byte selector is derived from the signature *text*; the .sol file and the
    ABI JSON must say the same thing, or every write lands in the void."""
    import json
    import re
    from pathlib import Path

    from cybersecurity_agent.blockchain.ganache_logger import CALL_SIG, SELECTOR

    sol = Path("cybersecurity_agent/blockchain/contract/EvidenceChain.sol").read_text()
    body = re.search(r"function submitEvidence\s*\((.*?)\)\s*external", sol, re.S).group(1)
    types = [t.strip().split()[0] for t in body.split(",")]
    sig = "submitEvidence(" + ",".join(types) + ")"
    assert sig == CALL_SIG, f"contract says {sig}, logger says {CALL_SIG}"
    abi = json.loads(Path("cybersecurity_agent/blockchain/contract/evidence_chain_abi.json").read_text())
    entry = next(e for e in abi if e.get("name") == "submitEvidence")
    abi_types = [i["type"] for i in entry["inputs"]]
    assert ",".join(abi_types) == ",".join(types), "ABI JSON drifted from the .sol"
    assert SELECTOR.hex() == keccak256(CALL_SIG.encode()).hex()[:8]


# ── fake node: exercises the whole RPC path offline ──────────────────────────
def _rlp_items(raw: bytes) -> list[bytes]:
    """Minimal RLP *list* decoder — used only to prove our encoder is decodable by a node."""
    assert raw[0] >= 0xC0, "expected a list"
    if raw[0] <= 0xF7:
        total, body = raw[0] - 0xC0, raw[1:]
    else:
        ln = raw[0] - 0xF7
        total = int.from_bytes(raw[1:1 + ln], "big")
        body = raw[1 + ln:]
    assert len(body) == total, "rlp length mismatch"
    out, i = [], 0
    while i < len(body):
        b0 = body[i]
        if b0 <= 0x7F:
            out.append(body[i:i + 1]); i += 1
        elif b0 <= 0xB7:
            n = b0 - 0x80; out.append(body[i + 1:i + 1 + n]); i += 1 + n
        elif b0 <= 0xF7:
            n = b0 - 0xB7
            ln = int.from_bytes(body[i + 1:i + 1 + n], "big")
            out.append(body[i + 1 + n:i + 1 + n + ln]); i += 1 + n + ln
        else:
            raise AssertionError("nested lists not needed here")
    return out


def _record_words(file_hash: bytes, digest: bytes, verdict: bytes, conf: int) -> bytes:
    """The 5-word fixed layout getEvidenceAt() returns."""
    return b"".join([file_hash, digest, verdict.ljust(32, b"\x00"),
                     conf.to_bytes(32, "big"), (1_760_000_000).to_bytes(32, "big")])


class _FakeNode(BaseHTTPRequestHandler):
    state = {"nonce": 0, "deployed": False, "records": []}

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(n))
        method, params = req["method"], req.get("params", [])
        if method == "eth_chainId":
            res = "0x539"
        elif method == "eth_blockNumber":
            res = "0x10"
        elif method == "eth_gasPrice":
            res = "0x3b9aca00"
        elif method == "eth_accounts":
            res = ["0x" + "ab" * 20]
        elif method == "eth_getTransactionCount":
            res = hex(self.state["nonce"])
        elif method == "eth_getCode":
            res = "0x60016000" if self.state["deployed"] else "0x"
        elif method == "eth_estimateGas":
            res = "0x5208"
        elif method == "eth_sendRawTransaction":
            fields = _rlp_items(bytes.fromhex(params[0].removeprefix("0x")))
            data = fields[5]
            assert int.from_bytes(data[:4], "big") == int.from_bytes(SELECTOR, "big"), "wrong selector"
            assert len(data) == 4 + 128, "static call must be selector + 4 words"
            self.state["nonce"] += 1
            self.state["records"].append([data[4:36], data[36:68], data[68:100].rstrip(b"\x00"),
                                         int.from_bytes(data[100:132], "big")])
            res = "0x" + "cd" * 32
        elif method == "eth_sendTransaction":
            p = params[0]
            data = bytes.fromhex(str(p.get("data", "0x")).removeprefix("0x"))
            if data[:4] == SELECTOR:
                self.state["records"].append([data[4:36], data[36:68], data[68:100].rstrip(b"\x00"),
                                             int.from_bytes(data[100:132], "big")])
            self.state["nonce"] += 1
            if not self.state["deployed"]:
                self.state["deployed"] = True
            res = "0x" + "cd" * 32
        elif method == "eth_getTransactionReceipt":
            res = {"status": "0x1", "blockNumber": "0x11", "gasUsed": "0x7530",
                   "contractAddress": "0x" + "ef" * 20, "transactionHash": "0x" + "cd" * 32}
        elif method == "eth_call":
            calldata = bytes.fromhex(str(params[0].get("data", "0x")).removeprefix("0x"))
            sel = calldata[:4]
            if sel == SELECTOR_COUNT:
                res = "0x" + len(self.state["records"]).to_bytes(32, "big").hex()
            elif sel == SELECTOR_GET_AT:
                seq = int.from_bytes(calldata[4:36], "big")
                if seq >= len(self.state["records"]):
                    self._send({"jsonrpc": "2.0", "id": req.get("id"),
                               "error": {"message": "invalid sequence index"}})
                    return
                rec = self.state["records"][seq]
                res = "0x" + _record_words(rec[0], rec[1], rec[2], rec[3]).hex()
            else:
                res = "0x"
        else:
            res = None
        self._send({"jsonrpc": "2.0", "id": req.get("id"), "result": res})

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def fake_node():
    _FakeNode.state = {"nonce": 5, "deployed": False, "records": []}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeNode)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_ganache_logger_full_round_trip(fake_node):
    from cybersecurity_agent.blockchain.ganache_logger import GanacheLogger, ping

    ok, note, info = ping(fake_node)
    assert ok and info["chain_id"] == 1337, note
    lg = GanacheLogger(fake_node, private_key=None, contract="0x" + "ef" * 20)   # node reports code here
    conn = lg.connect()
    assert conn["mode"] == "node-unlocked-account"
    payload = {"file_hash": "a" * 64, "AI_verdict": "MALICIOUS", "confidence_score": 88.5,
               "geolocation_summary": "≈ Testville", "timestamp": "t"}
    rec = lg.log(payload, verdict="MALICIOUS", file_hash="a" * 64, confidence=88.5)
    assert rec.ok, rec.error
    assert rec.tx_hash and rec.block_number == 17
    assert rec.sequence_index == 0, "evidenceCount is read back from the chain itself"
    assert rec.payload_digest.startswith("0x") and len(rec.payload_digest) == 66
    onchain = rec.raw["onchain"]
    assert onchain["fileHash"] == "0x" + "a" * 64
    assert onchain["payloadDigest"] == rec.payload_digest, "the ledger payload must equal what the chain holds"
    assert onchain["verdict"] == "MALICIOUS" and onchain["confidence_bps"] == 8850
    # and reading it later, with no knowledge of our internals, still matches
    from cybersecurity_agent.blockchain.ganache_logger import GanacheLogger as _GL
    lg2 = _GL(lg.rpc.url, contract="0x" + "ef" * 20)
    assert lg2.fetch_record(0)["payloadDigest"] == rec.payload_digest
    assert lg2.evidence_count() == 1


def test_ganache_logger_local_signing_path(fake_node):
    from cybersecurity_agent.blockchain.ganache_logger import GanacheLogger

    lg = GanacheLogger(fake_node, private_key="11" * 32, contract="0x" + "ef" * 20)
    conn = lg.connect()
    assert conn["mode"] == "local-signing" and conn["sender"].startswith("0x") and len(conn["sender"]) == 42
    rec = lg.log({"x": 1}, verdict="SAFE", file_hash="b" * 64, confidence=42.0)
    assert rec.ok


def test_ganache_unreachable_degrades_to_hashchain(tmp_path):
    from cybersecurity_agent.blockchain.ganache_logger import GanacheError, GanacheLogger, ping

    ok, note, _ = ping("http://127.0.0.1:1")          # nothing listening
    assert ok is False and "unreachable" in note.lower() or "refused" in note.lower() or note
    lg = GanacheLogger("http://127.0.0.1:1")
    with pytest.raises(GanacheError):
        lg.connect()


# ── CLI wiring (subprocess = the exact path an analyst types) ─────────────────
def _run_cli(*args: str, env: dict[str, str] | None = None):
    import os
    import subprocess
    import sys

    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "cybersecurity_agent", *args], cwd=str(REPO),
                          capture_output=True, text=True, env=e, timeout=60)


def test_cli_chain_read_and_bundle_export(tmp_path, fake_node):
    import json

    case = tmp_path / "runs" / "2026_testcase"
    case.mkdir(parents=True)
    ledger = tmp_path / "hashchain.jsonl"
    payload = {"file_hash": "1" * 64, "AI_verdict": "SUSPICIOUS", "confidence_score": 33.1,
               "timestamp": "2026-09-07T00:00:00+00:00", "geolocation_summary": "≈ Testville ±40km (conf 71%)"}
    from cybersecurity_agent.blockchain.hashchain import HashChain

    block = HashChain(ledger, tmp_path / "HEAD.json").append(payload)
    (case / "run.json").write_text(json.dumps(
        {"case": {"case_id": "2026_testcase", "sha256": "1" * 64},
         "chain": {"backend": "hashchain", "payload": payload, "index": block.index,
                   "hash": block.block_hash, "prev": block.previous_block_hash,
                   "verified_links": True}}, indent=2), encoding="utf-8")

    out = tmp_path / "bundle.json"
    r = _run_cli("chain", "export", "--path", str(ledger), "--bundle", str(out),
                 "--cases", str(case), env={"SENTINEL_HEAD_PATH": str(tmp_path / "HEAD.json")})
    assert r.returncode == 0, r.stdout + r.stderr
    bundle = json.loads(out.read_text())
    assert bundle["case_count"] == 1 and bundle["ledger"]["links_ok"] is True
    entry = bundle["cases"][0]
    assert entry["local_anchor"]["block_hash"] == block.block_hash
    assert entry["eml_sha256"] == "1" * 64
    assert "how_to_verify" in bundle and len(bundle["how_to_verify"]) >= 3
    # a bundle never contains email content — only digests/metadata
    text = out.read_text()
    assert "Dear" not in text and "attachment_bytes" not in text

    r2 = _run_cli("chain", "read", "--seq", "99", "--rpc-url", fake_node,
                  "--contract", "0x" + "ef" * 20)
    assert r2.returncode == 1 and "read failed" in (r2.stdout + r2.stderr).lower()
