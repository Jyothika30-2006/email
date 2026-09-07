"""Network + text-safety helpers shared by the whole tool layer.

Three rules are enforced *here* instead of in every tool:

1. **Redirectable egress.** `--geo-base-url` / `--reputation-base-url` rewrite the
   host of any API call so the identical production code path can run against the
   bundled `python -m cybersecurity_agent mock-apis` server. That is how the test
   suite exercises real request/parsing logic in a sandbox with no egress, and it
   is what keeps a demo-day Wi-Fi failure from killing the run.
2. **Failures are data, never exceptions.** One dead API must not abort an
   investigation, so `http_json` returns a normalized dict and never raises.
3. `sanitize_untrusted()` implements SAFETY #7 (prompt-injection defense): email
   text is attacker-controlled, so before it is embedded in <EMAIL_DATA> we
   defang any sequence that could act as a *control token* in our own protocol
   (`</EMAIL_DATA>`, `[CONFIRM_NEEDED]`, `SYSTEM:` role lines, XML-ish tags).

No key material is ever logged. Timeouts default to `config.http_timeout_s`.
"""
from __future__ import annotations

import ipaddress
import os
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "SENTINEL-IR/1.0 (local forensic agent; no third-party tracking)"
MAX_RESPONSE_BYTES = 2_000_000

# RFC5737 documentation ranges + loopback: the sample corpus lives here so a live
# demo can never touch a stranger's host. classify_ip() flags them explicitly.
TEST_NET_BLOCKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP (stdlib only → works even in an air-gapped lab with no pip)
# ─────────────────────────────────────────────────────────────────────────────
def apply_base_override(url: str, override: Optional[str]) -> str:
    """Swap scheme://host[:port] in, keeping the original path+query."""
    if not override:
        return url
    parsed = urllib.parse.urlsplit(url)
    base = override if "://" in override else "http://" + override
    b = urllib.parse.urlsplit(base)
    path = parsed.path.lstrip("/")
    base_path = b.path.rstrip("/")
    new_path = f"{base_path}/{path}" if path else (base_path or "/")
    return urllib.parse.urlunsplit((b.scheme, b.netloc, new_path, parsed.query, ""))


def http_json(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    payload: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    offline: bool = False,
    base_override: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch JSON over HTTP(S). Returns {ok, status, data|error, latency_ms, skipped?}."""
    if offline:
        return {"ok": False, "skipped": True, "error": "offline mode (outbound HTTP disabled)", "latency_ms": 0.0}
    url = apply_base_override(url, base_override)
    body_bytes: Optional[bytes] = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    if payload is not None:
        body_bytes = json.dumps(payload).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method.upper())
    start = time.monotonic()
    try:
        # noqa: S310 - URL is built from config constants, never from email content
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES)
            status = int(resp.status)
    except urllib.error.HTTPError as exc:      # 4xx/5xx often still carry a JSON body
        try:
            raw = exc.read(500_000) if exc.fp else b""
        except Exception:  # noqa: BLE001
            raw = b""
        status = int(exc.code)
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, ValueError) as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
            "url": url,
        }
    latency = round((time.monotonic() - start) * 1000, 1)
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {"_non_json": text[:2000]}
    out: dict[str, Any] = {"ok": 200 <= status < 300, "status": status, "data": data, "latency_ms": latency, "url": url}
    if not out["ok"]:
        out["error"] = f"HTTP {status}"
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────────────────────────────────────
_fixture_cache: dict[str, Any] = {}
_fixture_loaded = False


def dns_fixture(name: str) -> Optional[list[str]]:
    """Demo/CI only (Config.dns_fixtures / SENTINEL_DNS_FIXTURES): a JSON map
    {name: [ips]} consulted BEFORE real DNS, so an air-gapped demo room or pytest can
    exercise the origin/Tor/reputation code paths. Callers label these answers
    'fixture' — a canned value is never reported as if it came from live DNS."""
    global _fixture_cache, _fixture_loaded
    if not _fixture_loaded:
        _fixture_loaded = True
        path = os.environ.get("SENTINEL_DNS_FIXTURES", "")
        _fixture_cache = {}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    blob = json.load(fh)
                if isinstance(blob, dict):
                    _fixture_cache = {str(k).lower(): v for k, v in blob.items()}
            except (json.JSONDecodeError, OSError):
                _fixture_cache = {}
    hit = _fixture_cache.get((name or "").lower())
    return [str(i) for i in hit] if isinstance(hit, list) else None


def clear_dns_fixture_cache() -> None:
    global _fixture_cache, _fixture_loaded
    _fixture_cache, _fixture_loaded = {}, False


def dns_a(name: str, timeout: float = 2.5) -> tuple[list[str], str]:
    """Resolve A records → (ips, error). 'NXDOMAIN'/'NODATA' matter: the Tor DNSEL
    protocol distinguishes *listed* (127.0.0.2) from *not listed* (NXDOMAIN)."""
    fixture = dns_fixture(name)
    if fixture is not None:
        return fixture, "fixture"
    try:
        import dns.exception
        import dns.resolver

        try:
            answers = dns.resolver.resolve(name, "A", lifetime=timeout)
            return [r.address for r in answers], ""
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return [], "NODATA"
        except (dns.exception.DNSException, OSError) as exc:
            return [], f"{type(exc).__name__}: {exc}"
    except ImportError:
        try:
            infos = socket.getaddrinfo(name, None, family=socket.AF_INET)
            return sorted({i[4][0] for i in infos}), ""
        except socket.gaierror as exc:
            code = exc.args[0] if exc.args else None
            nodata = getattr(socket, "EAI_NODATA", None)
            if code in (getattr(socket, "EAI_NONAME", -2), nodata):
                return [], "NXDOMAIN"
            return [], f"gaierror: {exc}"


def reverse_dns(ip: str, timeout: float = 3.0) -> tuple[list[str], str]:
    """PTR lookup — used for Message-ID hostname leaks and hop labelling."""
    fixture = dns_fixture(f"PTR:{ip}")
    if fixture is not None:
        return [str(h) for h in fixture], "fixture"
    try:
        import dns.reversename
        import dns.resolver

        answers = dns.resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=timeout)
        return sorted({str(r.target).rstrip(".") for r in answers}), ""
    except Exception:  # noqa: BLE001 - degrade quietly; rDNS is a bonus signal
        try:
            return [socket.gethostbyaddr(ip)[0]], ""
        except (socket.herror, socket.gaierror, OSError) as exc:
            return [], f"{type(exc).__name__}: {exc}"


def rdns_or_none(name: str, timeout: float = 3.0) -> tuple[list[str], str]:
    """Forward A lookup for a bare hostname (Message-ID leak → hosting context)."""
    return dns_a(name, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────────
# IP classification (shared by resolve_origin + geolocate_ip)
# ─────────────────────────────────────────────────────────────────────────────
def classify_ip(ip: str) -> str:
    """public | loopback | private | reserved | test_net | multicast | link_local | invalid"""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "invalid"
    if addr.version != 4:
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        if addr.is_reserved:
            return "reserved"
        return "public"
    if addr.is_loopback:
        return "loopback"
    if any(addr in blk for blk in TEST_NET_BLOCKS):
        return "test_net"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link_local"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def is_traceable(ip: str, *, allow_private: bool = False) -> bool:
    """Can a GeoIP provider give a meaningful answer for this address?"""
    kind = classify_ip(ip)
    if kind == "public":
        return True
    return allow_private and kind in {"loopback", "private", "test_net"}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance — the basis of our cross-source agreement metric."""
    from math import asin, cos, radians, sin, sqrt

    r = 6371.0
    p1, p2 = radians(lat1), radians(lat2)
    dp, dl = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dp / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
    return 2 * r * asin(min(1.0, sqrt(a)))


# Public relay networks of the big webmail providers. Used for ONE purpose: when a
# header's client-ip belongs to these, it identifies "a Google/Microsoft edge", NOT
# a person — so we must not report 78% confidence "sender origin" from it.
PROVIDER_NETWORKS: dict[str, list[str]] = {
    "Google": ["8.35.0.0/16", "8.12.0.0/16", "8.14.0.0/16", "8.25.0.0/16", "8.34.0.0/16",
               "23.236.48.0/20", "34.0.0.0/14", "35.186.192.0/18", "35.190.247.0/24", "64.18.0.0/20",
               "64.233.160.0/19", "66.102.0.0/20", "66.249.80.0/20", "70.32.32.0/19", "72.14.192.0/18",
               "74.125.0.0/16", "104.196.0.0/14", "108.177.0.0/17", "130.211.0.0/22", "142.250.0.0/15",
               "142.251.160.0/19", "172.217.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.239.32.0/19"],
    "Microsoft": ["13.104.0.0/14", "13.107.2.0/23", "20.0.0.0/8", "23.96.0.0/14", "40.96.0.0/13",
                  "40.107.128.0/17", "52.96.0.0/12", "104.47.0.0/17", "131.253.32.0/19",
                  "132.245.0.0/16", "157.55.0.0/16", "191.232.160.0/19", "204.79.197.0/24", "51.4.0.0/16"],
    "Yahoo": ["66.196.80.0/20", "66.228.160.0/19", "67.195.0.0/16", "68.142.192.0/18", "69.147.160.0/19",
              "72.30.192.0/18", "74.6.0.0/16", "76.13.0.0/18", "98.136.0.0/16", "98.137.0.0/16"],
    "Apple": ["17.0.0.0/8"],
    "Proton": ["185.70.42.0/23", "45.166.108.0/22"],
}


def provider_network_for(ip: str) -> str:
    """Which webmail provider owns this network ("" if it looks like an ordinary
    network). Prefix list is indicative, maintained in config-visible code."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return ""
    for org, cidrs in PROVIDER_NETWORKS.items():
        for cidr in cidrs:
            if addr in ipaddress.ip_network(cidr):
                return org
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Prompt-injection defense (SAFETY #7)
# ─────────────────────────────────────────────────────────────────────────────
_CONTROL_TAGS = re.compile(r"</?\s*(EMAIL_DATA|SYSTEM|USER|ASSISTANT|TOOL_RESULT)\s*/?>", re.IGNORECASE)
_ANGLE_TAGS = re.compile(r"</?[A-Za-z][A-Za-z0-9_.:-]*(?:\s[^<>\n]{0,160})?/?>")
_BRACKET_CONTROLS = re.compile(r"\[\s*(CONFIRM_NEEDED|CONFIRM|KILL|ABORT|OVERRIDE|APPROVED|APPROVE|SYSTEM)\b[^\]\n]{0,80}\]", re.IGNORECASE)
_ROLE_LINES = re.compile(r"^([ \t]*)(system|assistant|developer|tool)[ \t]*:", re.IGNORECASE | re.MULTILINE)
_IGNORE_INSTRUCTIONS = re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)\b", re.IGNORECASE)


def sanitize_untrusted(text: str, *, limit: int = 4000) -> str:
    """Defang attacker text that is about to be embedded in <EMAIL_DATA>.

    Deliberately *defangs* instead of deleting: the transcript must still show
    that an injection attempt existed (that is itself a risk signal), while it can
    no longer function as a control token in our agent protocol.
    """
    if not text:
        return ""
    out = _CONTROL_TAGS.sub(lambda m: "＜" + m.group(0).strip("<>/ ").lower() + "＞", text)
    out = _BRACKET_CONTROLS.sub(lambda m: "[" + m.group(1).upper() + "·defanged]", out)
    out = _ANGLE_TAGS.sub(lambda m: "〈" + m.group(0).strip("<>/ ").split()[0] + "〉", out)
    out = _ROLE_LINES.sub(lambda m: m.group(1) + "【" + m.group(2).upper() + "-lookalike (untrusted)】:", out)
    out = _IGNORE_INSTRUCTIONS.sub(lambda m: "⟦injection-phrase: " + m.group(0).strip().lower() + "⟧", out)
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    out = re.sub(r"\n{4,}", "\n\n\n", out)
    if len(out) > limit:
        out = out[:limit] + f"\n…[truncated by agent; {len(out) - limit} chars withheld — raw bytes remain in the hashed .eml]"
    return out


def injection_attempts(text: str) -> list[str]:
    """Report (not obey) control-sequence attempts found in untrusted content so
    the agent can raise a risk signal and the report documents them."""
    hits: list[str] = []
    for label, rx in (
        ("EMAIL_DATA breakout", _CONTROL_TAGS),
        ("fake [CONFIRM_NEEDED]/approval marker", _BRACKET_CONTROLS),
        ("role-prefix spoofing", _ROLE_LINES),
        ("'ignore previous instructions' phrasing", _IGNORE_INSTRUCTIONS),
    ):
        if rx.search(text or ""):
            hits.append(label)
    return hits


def redact_addresses(value: str) -> str:
    """Mask the local-part of addresses for anything echoed into LLM context or
    the terminal (mailbox owners are not the subject of a threat investigation)."""
    def _m(m: re.Match[str]) -> str:
        local, domain = m.group(1), m.group(2)
        keep = local[:2] if len(local) > 3 else local[:1]
        return f"{keep}{'•' * max(1, len(local) - len(keep))}@{domain}"

    return re.sub(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", _m, value or "")


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
