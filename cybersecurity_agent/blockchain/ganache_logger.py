"""Blockchain evidence log — back-end B (optional): a local Ethereum testnet
(Ganache / Anvil / Hardhat node) running `EvidenceChain.sol`.

Deliberately dependency-free: JSON-RPC over urllib + our own keccak256/secp256k1/
RLP (blockchain/pure_python_crypto.py). `web3` is NOT required, because the whole
project must survive an air-gapped demo day.

Honesty rules baked in:
  * only `bytes32 fileHash + bytes32 payloadDigest + verdict + confidence` go on-chain;
  * a failed/slow RPC never changes the verdict — the caller logs the error into the
    report and the *local hash-chain* remains the durable record;
  * the contract is a testnet demo artifact, not an immutability claim about a
    production chain.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..evidence.hasher import canonical_json
from .abi_codec import (decode_get_evidence_at, decode_uint, encode_bytes32, encode_uint,
                        encode_function)
from .pure_python_crypto import (encode_legacy_tx, keccak256, privkey_to_pubkey,
                                 ecdsa_sign, private_key_to_address, pubkey_to_address)

ABI_PATH = Path(__file__).resolve().parent / "contract" / "evidence_chain_abi.json"
ADDRESS_CACHE = Path(__file__).resolve().parents[2] / "evidence" / "ganache_contract.json"
# The verdict is stored as a right-padded bytes32 rather than a Solidity `string`,
# so the whole call is *static*: no offsets, decodable by a verifier with no ABI
# library. Signature string must match contract/EvidenceChain.sol exactly.
CALL_SIG = "submitEvidence(bytes32,bytes32,bytes32,uint64)"
SELECTOR = keccak256(CALL_SIG.encode())[:4]


class GanacheError(RuntimeError):
    pass


@dataclass
class TxReceipt:
    ok: bool
    tx_hash: str = ""
    block_number: Optional[int] = None
    contract_address: str = ""
    sequence_index: Optional[int] = None
    gas_used: Optional[int] = None
    error: str = ""
    payload_digest: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "tx_hash": self.tx_hash, "block_number": self.block_number,
                "contract": self.contract_address, "seq": self.sequence_index,
                "gas_used": self.gas_used, "payload_digest": self.payload_digest,
                "error": self.error}


class Rpc:
    """Minimal JSON-RPC 2.0 client (stdlib only, no batch, hard timeout)."""

    def __init__(self, url: str, timeout: float = 8.0) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: Optional[list[Any]] = None) -> Any:
        import urllib.error
        import urllib.request

        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raise GanacheError(f"RPC HTTP {exc.code} from {method}") from exc
        except Exception as exc:  # noqa: BLE001
            raise GanacheError(f"RPC unreachable for {method}: {type(exc).__name__}: {exc}") from exc
        if "error" in payload:
            raise GanacheError(f"{method}: {payload['error'].get('message', payload['error'])}")
        return payload.get("result")


def ping(rpc_url: str) -> tuple[bool, str, dict[str, Any]]:
    """Is a node listening, and what chain is it? (never raises)"""
    try:
        rpc = Rpc(rpc_url, timeout=4.0)
        chain_id = int(rpc.call("eth_chainId"), 16)
        block = int(rpc.call("eth_blockNumber"), 16)
        return True, f"rpc ok (chainId={chain_id}, block={block})", {"chain_id": chain_id, "block": block}
    except GanacheError as exc:
        return False, str(exc)[:200], {}


def payload_digest(payload: dict[str, Any]) -> bytes:
    """keccak256 over the canonical JSON of the SAME payload that the local
    hash-chain stored — so an on-chain entry can be cross-verified against the
    local ledger byte-for-byte."""
    return keccak256(canonical_json(payload))


def _selector(sig: str) -> bytes:
    return keccak256(sig.encode())[:4]


def _encode_call(args: list[bytes]) -> bytes:
    """ABI-encode submitEvidence(bytes32,bytes32,bytes32,uint64) — 4 static words."""
    return encode_function(SELECTOR, [("bytes32", args[0]), ("bytes32", args[1]),
                                      ("bytes32", args[2]), ("uint64", int.from_bytes(args[3], "big"))])


def _encode_get_at(seq: int) -> str:
    """calldata for getEvidenceAt(uint256), hex without 0x."""
    return _selector("getEvidenceAt(uint256)").hex() + encode_uint(int(seq), 256).hex()


def _decode_uint(data_hex: str) -> int:
    raw = bytes.fromhex(data_hex.removeprefix("0x"))
    return int.from_bytes(raw[:32], "big") if raw else 0


class GanacheLogger:
    def __init__(self, rpc_url: str, private_key: Optional[str] = None, contract: Optional[str] = None) -> None:
        import os

        self.rpc = Rpc(rpc_url)
        self.private_key = private_key
        # precedence: explicit arg → SENTINEL_CONTRACT_ADDRESS → address cached by `chain deploy`
        self.contract = contract or os.environ.get("SENTINEL_CONTRACT_ADDRESS") or _cached_contract()
        self.chain_id: int = 0

    # ── node / key bootstrap ───────────────────────────────────────────────
    def connect(self) -> dict[str, Any]:
        self.chain_id = int(self.rpc.call("eth_chainId"), 16)
        if not self.private_key:
            # Ganache dev-mode only: ask the node for an unlocked account. This is
            # exactly as secure as a local testnet and it avoids embedding keys.
            try:
                accounts = self.rpc.call("eth_accounts") or []
            except GanacheError:
                accounts = []
            if accounts:
                self.sender = accounts[0]
                self._signer = None
                return {"mode": "node-unlocked-account", "sender": self.sender, "chain_id": self.chain_id}
            raise GanacheError("no unlocked eth_accounts and SENTINEL_ETH_PRIVATE_KEY unset")
        self._signer = self.private_key.removeprefix("0x")
        self.sender = private_key_to_address(self._signer)
        return {"mode": "local-signing", "sender": self.sender, "chain_id": self.chain_id}

    def ensure_contract(self) -> str:
        if self.contract and self._has_code(self.contract):
            return self.contract
        info = _artifact_path_info()
        if not info:
            raise GanacheError(
                "no contract address cached and no compiled artifact found → run "
                "./scripts/compile_contract.sh (or: python -m cybersecurity_agent chain deploy), "
                "or keep back-end 'hashchain' (default)"
            )
        bytecode, contract_json = info
        tx_hash = self._send(to=None, data=bytecode, gas=6_000_000)
        receipt = self._wait(tx_hash, timeout=25)
        if not receipt:
            raise GanacheError("deployment tx not mined within 25s")
        addr = receipt.get("contractAddress") or ""
        if not addr:
            raise GanacheError("no contractAddress in receipt")
        _cache_contract(addr, receipt.get("transactionHash", tx_hash), contract_json)
        self.contract = addr
        return addr

    # ── main entry ─────────────────────────────────────────────────────────
    def log(self, payload: dict[str, Any], *, verdict: str, file_hash: str, confidence: float) -> TxReceipt:
        if not self.contract:
            self.ensure_contract()
        digest = payload_digest(payload)
        vword = encode_bytes32(verdict.encode()[:32])
        data = _encode_call([bytes.fromhex(file_hash.removeprefix("0x")), digest,
                             vword,
                             int(min(confidence, 100.0) * 100).to_bytes(32, "big")])
        tx_hash = self._send(to=self.contract, data=data, gas=400_000)
        receipt = self._wait(tx_hash, timeout=25)
        if not receipt:
            return TxReceipt(False, tx_hash=tx_hash, error="tx not mined within 25s (testnet stall?)",
                             payload_digest="0x" + digest.hex())
        if int(receipt.get("status") or "0x0", 16) == 0:
            return TxReceipt(False, tx_hash=tx_hash, error="receipt status=0 (reverted)",
                             payload_digest="0x" + digest.hex(), raw=receipt)
        seq = None
        onchain: dict[str, Any] = {}
        try:  # read it back from the chain — proves the write actually landed *and* says what
            count = self.rpc.call("eth_call", [{"to": self.contract,
                                                "data": "0x" + _selector("evidenceCount()").hex()}, "latest"])
            n = decode_uint(bytes.fromhex(count.removeprefix("0x")), 0) if count else 0
            seq = n - 1
            raw = self.rpc.call("eth_call", [{"to": self.contract,
                                              "data": "0x" + _encode_get_at(seq)}, "latest"])
            onchain = decode_get_evidence_at(bytes.fromhex(raw.removeprefix("0x")))
            if onchain.get("fileHash") != "0x" + file_hash.removeprefix("0x").lower():
                return TxReceipt(False, tx_hash=tx_hash, sequence_index=seq,
                                 error="on-chain read-back fileHash mismatch (wrong contract?)",
                                 payload_digest="0x" + digest.hex(), raw=onchain)
            if onchain.get("payloadDigest") != "0x" + digest.hex():
                return TxReceipt(False, tx_hash=tx_hash, sequence_index=seq,
                                 error="on-chain payloadDigest mismatch vs local ledger",
                                 payload_digest="0x" + digest.hex(), raw=onchain)
        except (GanacheError, ValueError) as exc:
            onchain = {"readback_error": str(exc)[:180]}
        return TxReceipt(True, tx_hash=tx_hash, block_number=int(receipt.get("blockNumber") or 0, 16),
                         contract_address=self.contract, sequence_index=seq,
                         gas_used=int(receipt.get("gasUsed") or 0, 16) or None,
                         payload_digest="0x" + digest.hex(),
                         raw={"gasUsed": receipt.get("gasUsed"), "blockNumber": receipt.get("blockNumber"),
                              "onchain": onchain})

    # ── plumbing ───────────────────────────────────────────────────────────
    def _send(self, *, to: Optional[str], data: bytes, gas: int) -> str:
        nonce = int(self.rpc.call("eth_getTransactionCount", [self.sender, "latest"]), 16)
        gas_price = int(self.rpc.call("eth_gasPrice"), 16)
        if self._signer:
            signing_hash, signed = encode_legacy_tx(nonce=nonce, gas_price=gas_price, gas_limit=gas,
                                                     to=to, value=0, data=data, chain_id=self.chain_id)
            r, s, recid = ecdsa_sign(bytes.fromhex(self._signer), signing_hash)
            _, signed = encode_legacy_tx(nonce=nonce, gas_price=gas_price, gas_limit=gas, to=to, value=0,
                                         data=data, chain_id=self.chain_id, v=recid, r=r, s=s)
            return self.rpc.call("eth_sendRawTransaction", ["0x" + signed.hex()])
        params: dict[str, Any] = {"from": self.sender, "to": to, "data": "0x" + data.hex(),
                                 "gas": hex(gas), "gasPrice": hex(gas_price), "nonce": hex(nonce)}
        return self.rpc.call("eth_sendTransaction", [params])

    def _wait(self, tx_hash: str, timeout: float) -> Optional[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                receipt = self.rpc.call("eth_getTransactionReceipt", [tx_hash])
            except GanacheError:
                receipt = None
            if receipt:
                return receipt
            time.sleep(0.4)
        return None

    # ── read-back / verification ──────────────────────────────────────────────
    def evidence_count(self) -> int:
        raw = self.rpc.call("eth_call", [{"to": self.contract,
                                          "data": "0x" + _selector("evidenceCount()").hex()}, "latest"])
        return decode_uint(bytes.fromhex((raw or "0x").removeprefix("0x")), 0)

    def fetch_record(self, seq: int) -> dict[str, Any]:
        """Decode getEvidenceAt(seq) — fixed 5-word layout, no ABI library needed."""
        if not self.contract:
            raise GanacheError("no contract address configured")
        raw = self.rpc.call("eth_call", [{"to": self.contract,
                                         "data": "0x" + _encode_get_at(int(seq))}, "latest"])
        rec = decode_get_evidence_at(bytes.fromhex((raw or "0x").removeprefix("0x")))
        rec["seq"] = int(seq)
        rec["contract"] = self.contract
        return rec

    def _has_code(self, address: str) -> bool:
        try:
            code = self.rpc.call("eth_getCode", [address, "latest"])
        except GanacheError:
            return False
        return bool(code) and code not in {"0x", "0x0"}


# ─────────────────────────────────────────────────────────────────────────────
def _cached_contract() -> Optional[str]:
    if ADDRESS_CACHE.exists():
        try:
            return json.loads(ADDRESS_CACHE.read_text(encoding="utf-8")).get("address")
        except json.JSONDecodeError:
            return None
    return None


def _cache_contract(address: str, tx_hash: str, source: str) -> None:
    ADDRESS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    ADDRESS_CACHE.write_text(json.dumps({"address": address, "deployment_tx": tx_hash,
                                         "artifact": source,
                                         "cached_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                                        indent=2, sort_keys=True), encoding="utf-8")


def _artifact_path_info() -> Optional[tuple[str, str]]:
    """Find compiled artifact: env override, then scripts/geoip-style artifacts dir,
    then hardhat/foundry defaults. Returns (bytecode_hex, source_path) or None."""
    import os

    candidates = [
        os.environ.get("SENTINEL_CONTRACT_ARTIFACT", ""),
        str(Path(__file__).resolve().parents[2] / "artifacts" / "EvidenceChain.json"),
        str(Path(__file__).resolve().parents[2] / "artifacts" / "contracts" / "EvidenceChain.sol" / "EvidenceChain.json"),
        str(Path(__file__).resolve().parents[2] / "out" / "EvidenceChain.sol" / "EvidenceChain.json"),
    ]
    for path in [c for c in candidates if c]:
        p = Path(path)
        if not p.exists():
            continue
        try:
            blob = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        code = (blob.get("bytecode") or blob.get("bin") or "").removeprefix("0x")
        if code:
            return code, str(p)
    return None


def abi_json() -> str:
    return ABI_PATH.read_text(encoding="utf-8") if ABI_PATH.exists() else "[]"


def export_verification_bundle(case_dirs: list[Path], *, out_path: Path, chain_path: Path,
                               head_path: Optional[Path] = None, rpc_url: Optional[str] = None,
                               contract: Optional[str] = None) -> dict[str, Any]:
    """Write a *third-party-verifiable* bundle for a set of cases.

    A recipient gets everything needed to re-derive the integrity claim with their
    own tools and no trust in ours:

      * the exact payload the agent logged per case (hashes + verdict metadata only —
        no email body, by construction),
      * the local ledger file they can re-hash themselves (path + head + link status),
      * and, for cases mirrored on a chain, the decoded on-chain record so they can
        compare `keccak256(canonical_json(payload))` with `payloadDigest`.

    Deliberately includes no signature or "trusted" verdict from us: the bundle is
    the *inputs* to a verification, not its conclusion.
    """
    from .hashchain import HashChain

    chain = HashChain(Path(chain_path), Path(head_path) if head_path else None)
    report = chain.verify()
    bundle: dict[str, Any] = {
        "generator": "SENTINEL-IR (evidence bundle, verification inputs only)",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "contract_abi": json.loads(abi_json()),
        "ledger": {"path": str(chain_path), "blocks": report.blocks,
                   "links_ok": report.ok, "notes": report.reasons[:5],
                   "head_hash": report.head_hash,
                   "broken_at": report.broken_at},
        "how_to_verify": [
            "1. re-hash the ledger yourself: for each line, sha256(canonical_json(block minus block_hash)) "
            "must equal block_hash and chain to previous_block_hash",
            "2. sha256 the original .eml and compare with payload.file_hash",
            "3. keccak256(canonical_json(payload)) must equal onchain.payload_digest where present",
            "4. compare ledger.head_hash against wherever it was published (git tag, RFC3161 TSA, public chain)",
        ],
        "cases": [],
    }
    for case in case_dirs:
        run_json = Path(case) / "run.json"
        if not run_json.exists():
            continue
        blob = json.loads(run_json.read_text(encoding="utf-8"))
        chain_sec = blob.get("chain", {}) or {}
        payload = chain_sec.get("payload") or (blob.get("verdict", {}) or {}).get("payload") or {}
        entry: dict[str, Any] = {
            "case_id": (blob.get("case") or {}).get("case_id", Path(case).name),
            "eml_sha256": (blob.get("case") or {}).get("sha256", ""),
            "payload": payload,
            "local_anchor": {"index": chain_sec.get("index"), "block_hash": chain_sec.get("hash"),
                             "previous_block_hash": chain_sec.get("prev"),
                             "links_ok_at_write_time": chain_sec.get("verified_links")},
        }
        gan = chain_sec.get("ganache") or {}
        if gan.get("tx_hash"):
            entry["onchain"] = {"tx_hash": gan.get("tx_hash"), "seq": gan.get("seq"),
                                "contract": gan.get("contract"), "ok": gan.get("ok"),
                                "note": gan.get("note") or gan.get("error") or ""}
            if rpc_url and entry["onchain"]["ok"] and entry["onchain"]["seq"] is not None:
                try:
                    lg = GanacheLogger(rpc_url, contract=contract or gan.get("contract"))
                    lg.rpc.timeout = 6.0
                    entry["onchain"]["record"] = lg.fetch_record(int(entry["onchain"]["seq"]))
                except (GanacheError, ValueError) as exc:
                    entry["onchain"]["record_error"] = str(exc)[:200]
        bundle["cases"].append(entry)

    out_path = Path(out_path)
    bundle["bundle_path"] = str(out_path)
    bundle["case_count"] = len(bundle["cases"])
    bundle["complete"] = bool(bundle["cases"])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True, default=str), encoding="utf-8")
    try:
        out_path.chmod(0o600)
    except OSError:
        pass
    return bundle
