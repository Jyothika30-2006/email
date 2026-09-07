// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SENTINEL-IR evidence anchoring contract (local testnet / demo chain).
///
/// Design rule from the brief: **only hashes and verdict metadata ever touch the
/// chain.** No email body, no attachment, no URL, no IP, no name. Two things are
/// stored per case:
///
///   fileHash      = SHA-256 of the original .eml (so the chain proves *that exact
///                 file* existed when the verdict was written)
///   payloadDigest = keccak256 of the canonical JSON that the local hash-chain
///                 logged for the same case (so chain and ledger cross-check)
///
/// plus the verdict string, the confidence in basis points, and block.timestamp.
///
/// Storage layout is deliberately fixed and simple, so a verifier that has *no*
/// ABI encoder library installed (SENTINEL-IR's pure-python path) can still decode
/// `getEvidenceAt()` by word offsets. Do not "tidy" the struct: inserting a field
/// in the middle would silently shift every later word.
contract EvidenceChain {
    uint256 public immutable genesis;      // slot 0 — ties records to this deployment
    uint256 public evidenceCount;          // slot 1 — number of anchored cases
    Evidence[] private _log;               // slot 2 — length; data from slot 3

    struct Evidence {
        bytes32 fileHash;                  // +0
        bytes32 payloadDigest;             // +1
        bytes32 verdict;                   // +2  ASCII, right-padded (SAFE|SUSPICIOUS|MALICIOUS)
        uint64  confidenceBps;             // +3  0..10000 (basis points: 9012 = 90.12%)
        uint256 timestamp;                 // +4  block.timestamp of the anchoring tx
    }

    event EvidenceAppended(
        uint256 indexed seq,
        bytes32 indexed fileHash,
        bytes32 payloadDigest,
        bytes32 verdict,
        uint64 confidenceBps,
        uint256 timestamp
    );

    constructor() {
        genesis = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), address(this))));
    }

    /// @param verdict must be 1..32 ASCII bytes (SAFE / SUSPICIOUS / MALICIOUS)
    function submitEvidence(
        bytes32 fileHash,
        bytes32 payloadDigest,
        bytes32 verdict,
        uint64 confidenceBps
    ) external returns (uint256 seq) {
        require(fileHash != bytes32(0), "null file hash");
        require(payloadDigest != bytes32(0), "null payload digest");
        require(confidenceBps <= 10000, "confidence out of range");
        // verdict must be plain ASCII, right-padded with zeros — keeps it decodable
        // by any verifier and prevents a 32-byte blob of garbage being called a verdict.
        uint256 v = uint256(verdict);
        require(v != 0, "empty verdict");
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(v >> (8 * (31 - i)));
            if (b == 0) {
                // only trailing zeros allowed
                require((v & ((uint256(1) << (8 * (31 - i))) - 1)) == 0, "verdict must be padded zeros");
                break;
            }
            require(b >= 0x20 && b <= 0x7e, "verdict must be printable ASCII");
        }

        seq = _log.length;
        _log.push(Evidence(fileHash, payloadDigest, verdict, confidenceBps, block.timestamp));
        emit EvidenceAppended(seq, fileHash, payloadDigest, verdict, confidenceBps, block.timestamp);
    }

    /// Raw fixed-layout record — decodeable without an ABI library:
    /// word0=fileHash word1=payloadDigest word2=verdict word3=confidenceBps word4=timestamp
    function getEvidenceAt(uint256 seq)
        external
        view
        returns (bytes32 fileHash, bytes32 payloadDigest, bytes32 verdict, uint64 confidenceBps, uint256 timestamp)
    {
        require(seq < _log.length, "no such sequence index");
        Evidence storage e = _log[seq];
        return (e.fileHash, e.payloadDigest, e.verdict, e.confidenceBps, e.timestamp);
    }

    /// Human-readable view for block explorers (dynamic ABI).
    function verdictAt(uint256 seq) external view returns (string memory) {
        require(seq < _log.length, "no such sequence index");
        bytes32 v = _log[seq].verdict;
        uint256 len = 0;
        while (len < 32 && uint8(v >> (8 * (31 - len))) != 0) {
            len++;
        }
        bytes memory s = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            s[i] = v[i];                       // bytes32 is indexable in 0.8.x
        }
        return string(s);
    }
}
