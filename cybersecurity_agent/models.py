"""Shared dataclasses passed between the agent controller, the tool layer and the
evidence/blockchain layers. Kept dependency-free (stdlib only)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Header-parsing structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Hop:
    """One `Received:` header, normalized.

    sequence: 0 = the *ingress* hop (bottom of the header block = oldest = closest
    to the true origin). We deliberately number bottom→top so the "walk from the
    oldest hop" rule in the design is a simple ascending iteration.
    """
    sequence: int
    raw: str
    from_host: str = ""          # first token after "from"
    from_label: str = ""         # parenthetical comment e.g. (mail-io1-f46.google.com)
    by_host: str = ""
    via: str = ""
    for_addr: str = ""
    ip: Optional[str] = None     # best candidate IP seen on this hop
    ip_field: str = ""           # where the IP was found ("by", "from[...]", ...)
    ip_kind: str = ""            # public/loopback/private/reserved/test_net/unknown
    is_webmail_relay: bool = False   # hop belongs to Google/MS/Yahoo relay infra
    relay_org: str = ""
    timestamp: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Origin resolution (the Gmail-hiding fallback logic)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class OriginFinding:
    """Result of resolve_origin(). `source_kind` is what honesty looks like in
    data: a consumer can tell immediately whether this IP is the sender's machine
    or a proxy for it."""
    source_kind: str = "unresolved"   # received_hop|spf_client_ip|phishing_infrastructure|
                                      # messageid_rdns|unrecovered
    status: str = "none"              # resolved|fallback|degraded|unrecovered
    ip: Optional[str] = None
    ip_role: str = ""                 # sender_machine|open_proxy_or_relay|phishing_server|unknown
    hop_sequence: Optional[int] = None
    confidence: float = 0.0           # 0-100, ceiling of any geolocation confidence
    notes: list[str] = field(default_factory=list)
    fallbacks_used: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Geolocation
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class GeoPoint:
    source: str
    ok: bool = False
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    accuracy_km: Optional[float] = None
    asn: str = ""
    org: str = ""
    timezone: str = ""
    raw_error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GeoConsensus:
    """NEVER a fake precise pin: agreement across sources is converted into a
    confidence radius; disagreement widens the radius and slashes confidence."""
    ip: str = ""
    points: list[dict[str, Any]] = field(default_factory=list)
    agreeing_sources: list[str] = field(default_factory=list)
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius_km: float = 500.0
    confidence: float = 0.0
    summary: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# URLs / reputation / files
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class UrlEvidence:
    url: str
    scheme: str = ""
    host: str = ""
    visible_text: str = ""
    claimed_brand: str = ""
    host_matches_brand: bool = True
    brand_mismatch: bool = False
    homoglyph_risk: bool = False
    normalized_host: str = ""
    is_shortener: bool = False
    is_ip_literal: bool = False
    uses_http: bool = False
    punycode: bool = False
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReputationHit:
    source: str            # virustotal|abuseipdb|local_observation|skipped
    target: str
    ok: bool = False
    malicious: int = 0
    total: int = 0
    abuse_confidence: Optional[int] = None
    categories: list[str] = field(default_factory=list)
    last_seen: str = ""
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileScanFinding:
    """Emitted by static_file_scan — the ONLY tool that ever touches file bytes,
    and it touches them inside the sandbox. Nothing is executed, ever."""
    artifact: str = ""
    declared_extension: str = ""
    magic_type: str = ""
    magic_matches_extension: bool = True
    size_bytes: int = 0
    sha256: str = ""
    md5: str = ""
    entropy_bits_per_byte: float = 0.0
    flags: list[str] = field(default_factory=list)
    strings_preview: list[str] = field(default_factory=list)
    tool_outputs: dict[str, Any] = field(default_factory=dict)
    isolation: str = "unknown"       # docker|subprocess-limited|denied
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Risk + evidence plumbing
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RiskSignal:
    """One piece of evidence in the ensemble.

    direction: +1 pushes risk up, -1 pushes it down (mitigating), 0 = contextual.
    weight 0..3 = how much analysts historically trust that class of signal.
    """
    factor: str
    direction: int
    strength: float = 50.0            # 0..100 severity of this specific instance
    weight: float = 1.0               # 0..3
    explanation: str = ""
    source: str = ""
    mitigating: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HashRecord:
    """Chain-of-custody record — SAFETY #6 (hash BEFORE analysis)."""
    name: str
    kind: str            # source_email|attachment|extracted_artifact|report
    path: str
    sha256: str
    md5: str
    size_bytes: int
    recorded_at: str
    recorded_before_analysis: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LedgerEntry:
    """What goes to the blockchain: hash + verdict metadata ONLY. Never the raw
    email, never attachment bytes, never recipient PII beyond what the header
    summary already contains."""
    case_id: str
    file_hash: str
    ai_verdict: str
    confidence_score: float
    risk_score: float
    timestamp: str
    geolocation_summary: str
    origin_source_kind: str
    artifact_hashes: dict[str, str] = field(default_factory=dict)
    schema: str = "sentinel-evidence/v1"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def payload_json(self) -> str:
        import json
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
