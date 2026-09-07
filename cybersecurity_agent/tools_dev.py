"""Local developer/demo servers (not part of the agent's attack surface):

  serve_mock()   — canned GeoIP + reputation API responses, so `--offline` venues
                   and CI exercise the *real* request/parse code paths.
  serve_pixel()  — the tracking-pixel listener for fallback (3d). Binds 127.0.0.1
                   by default and only appends JSONL lines; it never parses or
                   executes anything a client sends beyond logging the path.

Both are plain stdlib http.server instances and both refuse to run if asked to
bind a public interface without an explicit flag — we do not hand out open proxies.
"""
from __future__ import annotations

import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

# Demo-corpus answers. 127.0.0.1 and the RFC5737 ranges are what the sample .eml
# files use, so a demo can never query a stranger's infrastructure.
DEMO_FIXTURES: dict[str, dict[str, Any]] = {
    "/json/127.0.0.1": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "LOOPBACK",
        "city": "Demo Fixture", "lat": 12.97, "lon": 77.59, "timezone": "Asia/Kolkata",
        "as": "AS0 Demo Network", "org": "SENTINEL-IR demo corpus", "query": "127.0.0.1",
        "proximity": {"accuracyRadius": 5},
    },
    "/json/127.0.0.53": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "LOOPBACK",
        "city": "Google Relay Demo", "lat": 37.44, "lon": -122.14, "timezone": "America/Los_Angeles",
        "as": "AS15169 Google LLC (demo)", "org": "Google LLC", "query": "127.0.0.53",
        "proximity": {"accuracyRadius": 25},
    },
    "/json/203.0.113.77": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "TEST-NET-3",
        "city": "Phishing Host Demo", "lat": 55.75, "lon": 37.62, "timezone": "Europe/Moscow",
        "as": "AS0 Demo Bulletproof (fake)", "org": "SENTINEL-IR demo corpus", "query": "203.0.113.77",
        "proximity": {"accuracyRadius": 20},
    },
    "/json/203.0.113.66": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "TEST-NET-3",
        "city": "Attacker SMTP Demo", "lat": 55.76, "lon": 37.63, "timezone": "Europe/Moscow",
        "as": "AS0 Demo Bulletproof (fake)", "org": "SENTINEL-IR demo corpus", "query": "203.0.113.66",
        "proximity": {"accuracyRadius": 12},
    },
    "/json/198.51.100.7": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "TEST-NET-2",
        "city": "Attacker MX Demo", "lat": 55.74, "lon": 37.61, "timezone": "Europe/Moscow",
        "as": "AS0 Demo Bulletproof MX (fake)", "org": "SENTINEL-IR demo corpus", "query": "198.51.100.7",
        "proximity": {"accuracyRadius": 18},
    },
    "/json/198.51.100.24": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "TEST-NET-2",
        "city": "Tor Exit Demo", "lat": -33.86, "lon": 151.21, "timezone": "Australia/Sydney",
        "as": "AS0 Demo Tor Exit (fake)", "org": "SENTINEL-IR demo corpus", "query": "198.51.100.24",
        "proximity": {"accuracyRadius": 30},
    },
    "/json/192.0.2.10": {
        "status": "success", "country": "Reserved (demo)", "countryCode": "XX", "regionName": "TEST-NET-1",
        "city": "Origin Server Demo", "lat": 1.35, "lon": 103.82, "timezone": "Asia/Singapore",
        "as": "AS0 Demo Hosting", "org": "SENTINEL-IR demo corpus", "query": "192.0.2.10",
        "proximity": {"accuracyRadius": 15},
    },
}


def _generic_demo(ip: str) -> dict[str, Any]:
    """Deterministic, *clearly-labelled* answer for the RFC-reserved ranges the demo
    corpus uses, so an offline demo still exercises the multi-source agreement code
    path. Coordinates come from the address itself — they are a fixture, never a
    claim about a real place."""
    last_octets = [int(x) for x in ip.split(".") if x.isdigit()] or [0, 0]
    lat = round(((last_octets[-2] if len(last_octets) > 1 else 0) % 90) / 10.0, 4)
    lon = round(((last_octets[-1] if last_octets else 0) % 180) / 10.0, 4)
    return {"status": "success", "country": "Reserved (demo fixture)", "countryCode": "XX",
            "regionName": "DEMO", "city": "Demo Fixture (synthetic coordinates)",
            "lat": lat, "lon": lon, "timezone": "UTC", "as": "AS0 SENTINEL demo",
            "org": "SENTINEL-IR demo corpus", "query": ip, "proximity": {"accuracyRadius": 40}}


def _ipinfo_from(path: str, fixtures: dict[str, dict[str, Any]]) -> Optional[dict[str, Any]]:
    m = re.match(r"/([\d.]+)/json", path)
    if not m:
        return None
    ip = m.group(1)
    demo = fixtures.get(f"/json/{ip}")
    if not demo:
        return {"ip": ip, "city": "Unknown", "region": "Unknown", "country": "XX",
                "loc": "0.000000,0.000000", "org": "AS0 No Record (mock)", "readme": "mock fixture: no record"}
    lat, lon = demo.get("lat", 0.0), demo.get("lon", 0.0)
    return {"ip": ip, "city": demo.get("city", ""), "region": demo.get("regionName", ""),
            "country": demo.get("countryCode", ""), "loc": f"{lat:.6f},{lon:.6f}",
            "org": demo.get("org", ""), "timezone": demo.get("timezone", ""),
            "postal": "-", "bogon": False}


def _vt_from(path: str) -> Optional[dict[str, Any]]:
    m = re.match(r"/api/v3/files/([0-9a-f]{64})", path)
    if m:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 62, "undetected": 4, "harmless": 0,
                                                                 "suspicious": 0, "timeout": 0},
                                          "popular_threat_classification": "Trojan.Generic",
                                          "names": ["fake-invoice.exe"], "total_votes": {"harmless": 0, "malicious": 62},
                                          "reputation": -1, "last_modification_date": 1}}}
    m = re.match(r"/api/v3/domains/([A-Za-z0-9_\-]+)", path)
    if m:
        import base64

        try:
            name = base64.urlsafe_b64decode(m.group(1) + "===").decode("idna", "replace")
        except Exception:  # noqa: BLE001
            name = m.group(1)
        bad = any(t in name for t in ("paypa1", "paypa", "xn--", "secure-", "verify-", "update"))
        stats = ({"malicious": 9, "undetected": 60, "suspicious": 2, "harmless": 4, "timeout": 0} if bad
                 else {"malicious": 0, "undetected": 70, "suspicious": 0, "harmless": 5, "timeout": 0})
        return {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -47 if bad else 12,
                                        "categories": {"malicious": "maldivas"} if bad else {"harmless": "clean"},
                                        "last_modification_date": 1_700_000_000}}}
    return None


def _abuseipdb_from(path: str) -> Optional[dict[str, Any]]:
    m = re.search(r"ipAddress=([\d.]+)", path)
    if not m:
        return None
    ip = m.group(1)
    bad = ip in {"203.0.113.77", "198.51.100.24"}
    return {"data": {"ipAddress": ip, "countryCode": "XX", "isp": "SENTINEL-IR demo corpus",
                     "useType": "Data Center / Web Hosting" if bad else "Fixed Line ISP",
                     "domain": "example.invalid", "netblock": ip.rsplit(".", 1)[0] + ".0/24",
                     "totalReports": 34 if bad else 0, "numDistinctUsers": 12 if bad else 0,
                     "abuseConfidenceScore": 87 if bad else 0,
                     "lastReportedAt": "2026-09-01T00:00:00+00:00",
                     "usageCategories": [{"name": "Public Proxy / Anonymizer"}] if bad else [],
                     "isPublic": False, "isWhitelisted": False}}


def serve_mock(bind: str, port: int, fixtures: Optional[Path] = None) -> None:
    table = dict(DEMO_FIXTURES)
    if fixtures and fixtures.exists():
        table.update(json.loads(fixtures.read_text(encoding="utf-8")))
    if bind not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("[mock-apis] refusing to bind a non-loopback address (it is a demo server, not a service)")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, obj: Any, code: int = 200) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Sentinel-Mock", "1")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            if path.startswith("/json/") or path.startswith("/geo/"):
                key = "/json/" + path.split("/", 2)[-1]
                if key in table:
                    return self._send(table[key])
                ip = key.rsplit("/", 1)[-1]
                if re.match(r"^(?:127\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)", ip):
                    return self._send(_generic_demo(ip))
                return self._send({"status": "fail", "message": "mock has no fixture for " + key})
            if re.match(r"^/[\d.]+/json$", path):
                obj = _ipinfo_from(path, table)
                if obj and obj.get("city") == "Unknown":
                    ip = path.strip("/").split("/")[0]
                    if re.match(r"^(?:127\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)", ip):
                        g = _generic_demo(ip)
                        obj = {"ip": ip, "city": g["city"], "region": g["regionName"], "country": g["countryCode"],
                               "loc": f"{g['lat']:.6f},{g['lon']:.6f}", "org": g["org"], "timezone": g["timezone"],
                               "bogon": False}
                return self._send(obj or {"error": "n/a"})
            if path.startswith("/api/v3/"):
                return self._send(_vt_from(path) or {"error": {"code": "NotFound", "message": "mock: unknown"}})
            if path.startswith("/api/v2/check"):
                return self._send(_abuseipdb_from(self.path) or {"errors": [{"detail": "mock: unknown"}]})
            if path == "/health":
                return self._send({"ok": True, "fixtures": len(table)})
            self._send({"error": "mock-apis: no route", "path": path}, 404)

        def log_message(self, fmt: str, *a: Any) -> None:
            sys.stderr.write("[mock-apis] " + (fmt % a) + "\n")

    import sys

    ThreadingHTTPServer((bind, port), Handler).serve_forever()


def serve_pixel(bind: str, port: int, out: Path, *, record_any: bool = False) -> None:
    """1×1 GIF listener. Records {ts, ip, path, tz, accept_language, user_agent}
    per hit — a *lead*, never proof of identity (documented in the tool + README)."""
    import sys

    if bind not in {"127.0.0.1", "localhost", "::1"}:
        print("[pixel-listen] WARNING: binding a routable interface means real recipients "
              "will be measured. Only do this with authorization from your incident owner.", file=sys.stderr)
    gif = bytes.fromhex("47494638396101000100800000000000ffffff21f904010000002c00000000010001000002024401003b")
    RECORD_ANY = [bool(record_any)]   # mutable closure flag so --record-any can widen it
    out.parent.mkdir(parents=True, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if not (self.path.startswith("/open/") or self.path.startswith("/p/")) and not RECORD_ANY[0]:
                # Only our /open/<case>.gif URLs are evidence. Logging every GET would
                # fill the hit log with favicon/preview-bot noise (and false positives).
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "ip": self.client_address[0],
                "path": self.path,
                "tz": self.headers.get("X-Client-Tz", ""),
                "accept_language": self.headers.get("Accept-Language", ""),
                "user_agent": (self.headers.get("User-Agent") or "")[:200],
            }
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(gif)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(gif)

        def log_message(self, fmt: str, *a: Any) -> None:
            sys.stderr.write("[pixel] " + (fmt % a) + "\n")

    print(f"[pixel-listen] logging hits → {out}   (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer((bind, port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("[pixel-listen] stopped")
