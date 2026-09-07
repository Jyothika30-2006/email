"""Central configuration for SENTINEL-IR.

Every number/policy that affects SAFETY or honesty is here so an auditor can read
one file and know the truth. Env vars override the defaults (prefix SENTINEL_).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "runs"
EVIDENCE_DIR = REPO_ROOT / "evidence"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    try:
        return float(raw) if raw is not None else default
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


@dataclass
class Config:
    # ── safety-critical policies (see README §6) ───────────────────────────
    tool_timeout_s: float = _env_float("SENTINEL_TOOL_TIMEOUT", 15.0)
    """SAFETY #5: hard timeout per tool call so a hung API can't stall a live demo."""

    sandbox_timeout_s: float = _env_float("SENTINEL_SANDBOX_TIMEOUT", 120.0)
    """static_file_scan is the one tool granted a longer explicit budget (docker run
    + scan). It is still bounded, and it is the one tool gated by a human."""

    require_confirmation: bool = _env_bool("SENTINEL_REQUIRE_CONFIRMATION", True)
    """SAFETY #4: human 'yes' before any file-touching tool. --demo/--yes weaken
    this deliberately and the report records that they did."""

    confirmation_timeout_s: float = _env_float("SENTINEL_CONFIRM_TIMEOUT", 120.0)
    """If nobody answers the gate, the default answer is DENY (fail closed)."""

    kill_switch_key: str = os.environ.get("SENTINEL_KILL_KEY", "x")
    """SAFETY #8: single keypress aborts agent + destroys sandbox."""

    # ── work-status reactions (terminal pet) + companion hook ────────────────
    pet_enabled: bool = _env_bool("SENTINEL_PET", True)
    """ASCII sentinel cat in the live UI whose mood tracks real agent events (thinking while
    the planner runs, fur up on an injection attempt, hop/hiss at the verdict). It is a status
    surface only: frames come from `ui/pet.MOODS`, never from the email. `--no-pet` or
    SENTINEL_PET=0 removes the panel without touching anything else."""

    pet_fps: float = _env_float("SENTINEL_PET_FPS", 2.0)
    """Animation rate for the pet (frames/second of wall-clock time, event-driven on top)."""

    pet_skin: str = os.environ.get("SENTINEL_PET_SKIN", "default")
    """Colour palette for the pet (`default`, `high-contrast`, `colour-blind`, `calm`, `mono`).
    Cosmetics only — the art and every number on screen are identical across skins, so a skin
    can never change what a case looks like. Unknown names fall back to `default`."""

    pet_reminders: str = os.environ.get("SENTINEL_REMINDERS", "eyes=20,stretch=30,water=45")
    """Care reminders (`ui/care.py`) — minutes between nudges: `eyes=20,stretch=30,water=45`,
    or `off` to disable. They are about the analyst, not the case: they cannot change a score,
    a verdict, or the tool plan, and they never quote the email."""

    pet_pomodoro: str = os.environ.get("SENTINEL_POMODORO", "")
    """Optional Pomodoro for long manual reviews: `25,5` (focus min, break min). Empty = off."""

    status_hook_enabled: bool = _env_bool("SENTINEL_STATUS_HOOK_ENABLED", True)
    """Set to 0 to stop writing `runs/<case>/status.jsonl` as well as the shared hook."""

    status_hook_path: str = os.environ.get("SENTINEL_STATUS_HOOK", "")
    """Optional extra JSONL sink for work-status events, so an external companion or tmux bar
    can react (see `status.py`). `runs/<case>/status.jsonl` is always written. Lines carry
    enums and numbers only — never email content, addresses, IPs or tool summaries."""

    offline: bool = _env_bool("SENTINEL_OFFLINE", False)
    """Air-gap mode: zero outbound HTTP. DNS-based Tor checks still run (cheap,
    and the Tor Project DNSEL is a DNSBL, not an HTTP API)."""

    # ── LLM (local only — no cloud inference) ──────────────────────────────
    ollama_host: str = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    ollama_model: str = os.environ.get("SENTINEL_MODEL", "llama3.1:8b")
    llm_temperature: float = _env_float("SENTINEL_LLM_TEMP", 0.1)
    llm_max_tokens: int = _env_int("SENTINEL_LLM_MAX_TOKENS", 900)
    llm_request_timeout_s: float = _env_float("SENTINEL_LLM_TIMEOUT", 90.0)
    max_agent_steps: int = _env_int("SENTINEL_MAX_STEPS", 14)

    # ── external lookups (free tiers; all optional) ────────────────────────
    geoip_sources: tuple[str, ...] = ("ip-api", "ipinfo", "maxmind_offline")
    http_timeout_s: float = _env_float("SENTINEL_HTTP_TIMEOUT", 10.0)
    geo_base_url_override: Optional[str] = os.environ.get("SENTINEL_GEO_BASE_URL") or None
    """Demo/CI hook: point GeoIP lookups at `python -m cybersecurity_agent mock-apis`."""
    reputation_base_url_override: Optional[str] = os.environ.get("SENTINEL_REPUTATION_BASE_URL") or None

    ipinfo_token: str = os.environ.get("IPINFO_TOKEN", "")
    """ipinfo's HTTPS path demands a token. ip-api HTTPS needs a paid key, so we
    use its free *HTTP* endpoint unless this token is set."""
    virustotal_api_key: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
    abuseipdb_api_key: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    geoip_mmdb_path: str = os.environ.get(
        "GEOIP_MMDB", str(Path.home() / ".local/share/GeoIP/GeoLite2-City.mmdb")
    )
    """Offline MaxMind GeoLite2 DB (free with registration). Used as 3rd source +
    tie-breaker, and it's the only GeoIP source that works fully air-gapped."""

    geoip_allow_private: bool = _env_bool("SENTINEL_GEO_ALLOW_PRIVATE", False)
    """Demo-corpus switch: samples use 127.0.0.x/TEST-NET addresses so a live demo
    can never poke a stranger's host. Real investigations leave this False."""

    dns_fixtures: str = os.environ.get("SENTINEL_DNS_FIXTURES", "")
    # With a fixture file loaded, absence from it = "no answer", rather than
    # falling through to a real resolver. Keeps demos and CI hermetic; a DNSBL
    # that sometimes answers is the one thing that can make two runs of the same
    # sample differ, so it is the first thing to switch off.
    dns_strict: bool = os.environ.get("SENTINEL_DNS_STRICT", "") == "1"
    """DEMO/TEST ONLY: JSON map of {name: [ips]} consulted before real DNS, so a
    network-restricted lab (or pytest) can exercise origin/Tor/reputation code
    paths. Every answer served from a fixture is labelled 'fixture' in the tool
    output — it is never reported as if it came from live DNS."""

    tor_exitlist: str = os.environ.get("SENTINEL_TOR_EXITLIST", "")
    tor_exit_fixture: str = os.environ.get("SENTINEL_TOR_EXIT_FIXTURE", "")
    """DEMO/TEST ONLY: a file of IPs to treat as listed, so a network-restricted
    environment (CI, air-gapped demo room) can exercise the Tor branch of the
    pipeline. The real signal is the live DNSEL DNS query; a fixture hit is always
    reported with via="fixture" and is labelled 'simulated' in every output."""
    """Optional cached copy of https://check.torproject.org/torbulkexitlist for an
    offline cross-check in check_tor_exit (DNSEL remains authoritative)."""

    # ── sandbox (SAFETY #2/#3) ─────────────────────────────────────────────
    sandbox_image: str = os.environ.get("SENTINEL_SANDBOX_IMAGE", "sentinel-sandbox:latest")
    sandbox_required: bool = _env_bool("SENTINEL_SANDBOX_REQUIRED", False)
    """True → refuse to touch attachment bytes at all unless Docker is usable."""
    sandbox_cpus: float = _env_float("SENTINEL_SANDBOX_CPUS", 1.0)
    sandbox_memory: str = os.environ.get("SENTINEL_SANDBOX_MEMORY", "512m")
    sandbox_pids: int = _env_int("SENTINEL_SANDBOX_PIDS", 128)
    sandbox_tmpfs_size: str = os.environ.get("SENTINEL_SANDBOX_TMPFS", "64m")

    # ── blockchain evidence log ────────────────────────────────────────────
    blockchain_backend: str = os.environ.get("SENTINEL_CHAIN_BACKEND", "auto")
    """auto → use ganache if RPC answers, else local hash-chain. Force with
    'hashchain' or 'ganache'."""
    ganache_rpc_url: str = os.environ.get("GANACHE_RPC_URL", "http://127.0.0.1:8545")
    evidence_chain_path: Path = Path(os.environ.get("SENTINEL_CHAIN_PATH", str(EVIDENCE_DIR / "hashchain.jsonl")))
    head_pointer_path: Path = Path(os.environ.get("SENTINEL_HEAD_PATH", str(EVIDENCE_DIR / "HEAD.json")))

    # ── misc behaviour ─────────────────────────────────────────────────────
    integrity_confidence_cap: float = _env_float("SENTINEL_INTEGRITY_CONFIDENCE_CAP", 35.0)
    """If chain-of-custody hashing shows the evidence changed after it was hashed,
    no verdict from this run may claim more than this confidence (SAFETY #6)."""

    max_body_chars_for_llm: int = _env_int("SENTINEL_MAX_BODY_CHARS", 2600)
    risk_floor: float = 0.0
    style_analysis: bool = True
    """(e) LLM writing-style signal. Always low-confidence, never sole basis."""

    extra: dict[str, Any] = field(default_factory=dict)

    # helpers ────────────────────────────────────────────────────────────────
    @property
    def geo_http_allowed(self) -> bool:
        return not self.offline

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # never leak key material into reports/ledgers
        for k in ("ipinfo_token", "virustotal_api_key", "abuseipdb_api_key"):
            d[k] = "***set***" if d[k] else ""
        return d


def load_config(**overrides: Any) -> Config:
    cfg = Config()
    for key, value in overrides.items():
        if value is not None and hasattr(cfg, key):
            setattr(cfg, key, value)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    return cfg
