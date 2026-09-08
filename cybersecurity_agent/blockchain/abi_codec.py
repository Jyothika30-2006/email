"""Minimal Solidity ABI codec — hand-rolled, but *fixed-shape* only.

Why hand-rolled: the whole point of the on-chain mirror is that a third party can
verify a SENTINEL-IR record with nothing installed except Python. A general ABI
library would be a second implementation to trust; instead we support exactly the
four argument types `EvidenceChain.submitEvidence` takes and the five return types
of `getEvidenceAt`, and every function here is unit-tested against hand-computed
encodings (tests/test_ganache_logger.py).

Layout notes (Solidity ≥0.8):
  * static types occupy one 32-byte word each, in declaration order, no offsets
  * a dynamic `string`/`bytes` argument is a head word holding a byte offset into
    the tail, then (length, ceil32-padded data)
  * `bytes32` is right-padded with zeros; `uint*` is left-padded
"""
from __future__ import annotations

from typing import Any, Iterable

WORD = 32


def _pad32(b: bytes) -> bytes:
    return b + b"\x00" * ((WORD - len(b) % WORD) % WORD)


def encode_bytes32(value: bytes | str) -> bytes:
    raw = value.encode() if isinstance(value, str) else bytes(value)
    if len(raw) > WORD:
        raise ValueError(f"bytes32 value is {len(raw)} bytes (max 32)")
    return raw.ljust(WORD, b"\x00")


def encode_uint(value: int, bits: int = 256) -> bytes:
    if value < 0:
        raise ValueError("unsigned type")
    if bits % 8 or value >= (1 << bits):
        raise ValueError(f"value out of range for uint{bits}")
    return value.to_bytes(WORD, "big")


def encode_string(value: str) -> bytes:
    """Tail-only encoding of a dynamic `string` (length + padded bytes)."""
    raw = value.encode("utf-8")
    return encode_uint(len(raw), 256) + _pad32(raw)


def encode_function(selector: bytes, args: Iterable[tuple[str, Any]]) -> bytes:
    """Encode `f(args)` for the small type set we support.

    `args` is a sequence of (solidity_type, value); supported types:
    bytes32, uint8..uint256 (multiples of 8), string (dynamic, only as the last
    argument is *not* required — offsets are computed properly).
    """
    args = list(args)
    static_size = 2 * WORD if any(t == "string" for t, _ in args) else 0
    # head = one word per argument (dynamic types contribute their offset word)
    head_words = len(args)
    head = bytearray(selector)
    tail = bytearray()
    for typ, value in args:
        if typ == "bytes32":
            head += encode_bytes32(value)
        elif typ.startswith("uint"):
            head += encode_uint(int(value), int(typ[4:] or "256"))
        elif typ == "string":
            offset = head_words * WORD + len(tail)     # offsets are relative to the
            tail += encode_string(value)                # start of the *arguments*
            head += encode_uint(offset, 256)            # (i.e. after the 4-byte selector)
        else:
            raise ValueError(f"unsupported solidity type: {typ!r}")
    assert not static_size or len(tail) >= static_size
    return bytes(head + tail)


def decode_word(data: bytes, i: int) -> bytes:
    if len(data) < (i + 1) * WORD:
        raise ValueError(f"abi data too short for word {i} ({len(data)} bytes)")
    return data[i * WORD:(i + 1) * WORD]


def decode_bytes32(data: bytes, i: int) -> bytes:
    return decode_word(data, i)


def decode_uint(data: bytes, i: int) -> int:
    return int.from_bytes(decode_word(data, i), "big")


def decode_string(data: bytes, offset_word: int) -> str:
    """Decode `string memory` given the index of the word holding its byte offset.

    `data` must be the argument/return section *without* the 4-byte selector (that is
    what `eth_call` returns), because head offsets are relative to its first byte.
    """
    offset = decode_uint(data, offset_word)
    length = int.from_bytes(decode_word(data, offset // WORD), "big")
    start = offset + WORD
    need = start + length
    if len(data) < need:
        raise ValueError("truncated dynamic string in abi data")
    return data[start:start + length].decode("utf-8", "replace")


def decode_get_evidence_at(data: bytes) -> dict[str, Any]:
    """Decode the 5-word fixed return of `getEvidenceAt(uint256)`."""
    verdict = decode_bytes32(data, 2).rstrip(b"\x00")
    for b in verdict:                            # mirror the contract's validation
        if not 0x20 <= b <= 0x7E:
            raise ValueError("verdict word is not printable ASCII — record may be corrupt")
    return {
        "fileHash": "0x" + decode_bytes32(data, 0).hex(),
        "payloadDigest": "0x" + decode_bytes32(data, 1).hex(),
        "verdict": verdict.decode(),
        "confidence_bps": decode_uint(data, 3),
        "timestamp": decode_uint(data, 4),
    }
