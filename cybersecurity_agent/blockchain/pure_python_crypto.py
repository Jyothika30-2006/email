"""Crypto for the *optional* Ganache logger: secp256k1 ECDSA + RLP in pure Python
(so a demo can sign a legacy transaction with no web3/eth_account), plus keccak-256.

Scope, honestly stated:
  * keccak-256 — NOT implemented here. An evidence hash must be byte-identical to
    `web3.keccak`/Solidity, so we require a vetted library (pycryptodome) and raise
    `KeccakUnavailable` instead of shipping an unverified sponge.
  * secp256k1 / RLP — pure Python, because they are exercised *through* keccak and
    the node accepts or rejects the transaction; a bug shows up as a failed broadcast,
    not as silently-wrong evidence. They are unit-tested against published vectors
    (see tests/test_ganache_logger.py).
  * the default evidence back-end (local hash-chain) needs none of this.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# keccak-256 — deliberately NOT hand-rolled.
#
# An evidence-log hash has to be byte-identical to what `web3.keccak`/Solidity
# `keccak256` produces, otherwise the on-chain record cannot be re-verified by
# anyone else. A from-scratch sponge is exactly the kind of code that *looks*
# right, passes self-consistency tests, and is wrong — so this module refuses to
# invent one and requires a vetted implementation instead.
# ─────────────────────────────────────────────────────────────────────────────
try:                                                    # preferred: pycryptodome
    from Crypto.Hash import keccak as _pycryptodome_keccak
except ImportError:                                     # pragma: no cover
    _pycryptodome_keccak = None


class KeccakUnavailable(RuntimeError):
    pass


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (original padding, *not* SHA3-256) via pycryptodome.

    Install:  pip install pycryptodome     (see scripts/setup.sh — it is a
    requirement of the *optional* --chain-backend ganache path only; the default
    hash-chain evidence log uses hashlib SHA-256 and needs nothing.)
    """
    if _pycryptodome_keccak is None:
        raise KeccakUnavailable(
            "keccak256 needs `pycryptodome` (pip install pycryptodome). "
            "We will not fake an evidence hash with an unverified implementation.")
    h = _pycryptodome_keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ─────────────────────────────────────────────────────────────────────────────
# secp256k1 (affine + modular inverse — slow is fine for one tx per case)
# ─────────────────────────────────────────────────────────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a: int, m: int = P) -> int:
    return pow(a % m, m - 2, m)


def _point_add(p1: Optional[tuple[int, int]], p2: Optional[tuple[int, int]]) -> Optional[tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        if y1 == 0:
            return None
        lam = (3 * x1 * x1 * _inv(2 * y1)) % P
    else:
        lam = ((y2 - y1) * _inv(x2 - x1)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _mul(k: int, point: Optional[tuple[int, int]] = None) -> Optional[tuple[int, int]]:
    point = point or (Gx, Gy)
    result: Optional[tuple[int, int]] = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_pubkey(priv: bytes) -> tuple[int, int]:
    k = int.from_bytes(priv, "big") % N
    q = _mul(k)
    if q is None:  # pragma: no cover - degenerate key
        raise ValueError("invalid private key")
    return q


def pubkey_to_address(pub: tuple[int, int]) -> str:
    raw = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def private_key_to_address(priv_hex: str) -> str:
    return pubkey_to_address(privkey_to_pubkey(bytes.fromhex(priv_hex.removeprefix("0x"))))


def _rfc6979_k(priv_int: int, msg_hash: bytes) -> int:
    """Deterministic nonce per RFC 6979 with HMAC-SHA256 (secp256k1's usual choice)."""
    h1 = msg_hash[:32]
    x = priv_int.to_bytes(32, "big")
    v = b"\x01" * 32
    kk = b"\x00" * 32
    kk = hmac.new(kk, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(kk, v, hashlib.sha256).digest()
    while True:
        kk = hmac.new(kk, v + b"\x01", hashlib.sha256).digest()
        v = hmac.new(kk, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t


def ecdsa_sign(priv: bytes, msg_hash: bytes) -> tuple[int, int, int]:
    """Sign a 32-byte digest → (r, s, recovery_id) with low-s normalization."""
    z = int.from_bytes(msg_hash, "big") % N
    d = int.from_bytes(priv, "big") % N
    while True:
        k = _rfc6979_k(d, msg_hash)
        point = _mul(k)
        if point is None:
            continue
        r = point[0] % N
        if r == 0:
            continue
        s = (_inv(k, N) * (z + r * d)) % N
        if s == 0:
            continue
        recid = (point[1] & 1) | (2 if point[0] >= N else 0)
        if s > N // 2:
            s, recid = N - s, recid ^ 1
        return r, s, recid


def ecdsa_recover_pubkey(msg_hash: bytes, r: int, s: int, recid: int) -> tuple[int, int]:
    z = int.from_bytes(msg_hash, "big") % N
    x = r + (N if recid & 2 else 0)
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    y = beta if (beta & 1) == (recid & 1) else (P - beta)
    R = (x, y)
    r_inv = _inv(r, N)
    q = _point_add(_mul((-z % N) * r_inv % N), _mul(s * r_inv % N, R))
    if q is None:  # pragma: no cover
        raise ValueError("recovery failed")
    return q


# ─────────────────────────────────────────────────────────────────────────────
# RLP (EIP-155 legacy transaction encoding)
# ─────────────────────────────────────────────────────────────────────────────
def rlp_encode(value) -> bytes:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("RLP cannot encode negative integers")
        return rlp_encode(_int_be(value))
    if isinstance(value, bytes):
        if len(value) == 1 and value[0] < 0x80:
            return value
        return _rlp_header(len(value), 0x80) + value
    if isinstance(value, str):
        return rlp_encode(value.encode())
    if isinstance(value, (list, tuple)):
        payload = b"".join(rlp_encode(v) for v in value)
        return _rlp_header(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode {type(value)}")


def _int_be(v: int) -> bytes:
    if v == 0:
        return b""
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def _rlp_header(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    be = _int_be(length)
    return bytes([offset + 55 + len(be)]) + be


def encode_legacy_tx(*, nonce: int, gas_price: int, gas_limit: int, to: Optional[str],
                     value: int, data: bytes, chain_id: int,
                     v: int = 0, r: int = 0, s: int = 0) -> tuple[bytes, bytes]:
    """Returns (signing_hash, signed_rlp). EIP-155 replay protection is always on."""
    unsigned = [nonce, gas_price, gas_limit, (to or "").removeprefix("0x"), value, data, chain_id, 0, 0]
    enc = rlp_encode(unsigned)
    signing_hash = keccak256(enc)
    base_v = chain_id * 2 + 35
    signed = [nonce, gas_price, gas_limit, (to or "").removeprefix("0x"), value, data,
              base_v + v, r, s]
    return signing_hash, rlp_encode(signed)
