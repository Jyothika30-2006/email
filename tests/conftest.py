"""Shared fixtures: case dirs, configs and a tiny HTTP mock so the *real* network
code paths (urllib + JSON parsing) run under pytest without any egress."""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "samples"


@pytest.fixture(scope="session", autouse=True)
def _isolate_evidence(tmp_path_factory):
    """Tests never touch the repo's real ledger or leave runs/ litter behind: the
    evidence chain (and the demo Tor fixture) are pointed at a session temp dir."""
    d = tmp_path_factory.mktemp("evidence")
    iso = pytest.MonkeyPatch()
    iso.setenv("SENTINEL_CHAIN_PATH", str(d / "hashchain.jsonl"))
    iso.setenv("SENTINEL_HEAD_PATH", str(d / "HEAD.json"))
    # …and any test that forgets case_prefix= still writes under tmp_path, never the repo.
    import cybersecurity_agent.agent as _agent_mod
    iso.setattr(_agent_mod, "RUNS_DIR", d / "runs")
    iso.setenv("SENTINEL_TOR_EXIT_FIXTURE", str(SAMPLES / "fixtures" / "tor_exit_ips.txt"))
    yield d
    iso.undo()

FIXTURES = {
    "203.0.113.66": {"city": "Testville", "country": "Testland", "countryCode": "TL", "lat": 10.0, "lon": 20.0,
                     "regionName": "Testregion", "timezone": "UTC", "as": "AS0 Test", "org": "Test ISP",
                     "status": "success", "proximity": {"accuracyRadius": 10}},
    "198.51.100.24": {"city": "Torville", "country": "Testland", "countryCode": "TL", "lat": 10.1, "lon": 20.1,
                      "regionName": "Testregion", "timezone": "UTC", "as": "AS0 Test", "org": "Test ISP",
                      "status": "success", "proximity": {"accuracyRadius": 10}},
    "203.0.113.67": {"city": "Faraway", "country": "Elsewhere", "countryCode": "EL", "lat": -33.0, "lon": 151.0,
                     "regionName": "Other", "timezone": "UTC", "as": "AS0 Other", "org": "Other ISP",
                     "status": "success", "proximity": {"accuracyRadius": 200}},
}


class _MockHandler(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/json/"):
            ip = path[len("/json/"):]
            rec = dict(FIXTURES.get(ip, {"status": "fail", "message": "no fixture"}))
            rec["query"] = ip
            rec.setdefault("status", "success")
            return self._send(rec)
        import re

        m = re.match(r"/([\d.]+)/json", path)
        if m:
            ip = m.group(1)
            fx = FIXTURES.get(ip)
            if not fx:
                return self._send({"ip": ip, "error": "no record"})
            return self._send({"ip": ip, "city": fx["city"], "region": fx["regionName"], "country": fx["countryCode"],
                               "loc": f"{fx['lat']:.6f},{fx['lon']:.6f}", "org": fx["org"], "timezone": "UTC", "bogon": False})
        if path.startswith("/api/v3/files/"):
            return self._send({"data": {"attributes": {"last_analysis_stats": {"malicious": 40, "undetected": 5, "suspicious": 0, "harmless": 0},
                                                        "names": ["test.trojan"], "reputation": -5}}})
        if path.startswith("/api/v2/check"):
            return self._send({"data": {"abuseConfidenceScore": 80, "totalReports": 12, "usageCategories": [{"name": "Botnet"}],
                                       "countryCode": "TL", "isp": "Test ISP", "lastReportedAt": "x"}})
        self._send({"error": "404", "path": path}, 404)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture(scope="session")
def mock_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture()
def dns_fixtures(tmp_path, monkeypatch):
    """Point the demo DNS-fixture switch at a temp file (documented as demo-only)."""
    f = tmp_path / "dns.json"
    f.write_text(json.dumps({
        "mail.attacker.test": ["203.0.113.66"],
        "lure.attacker.test": ["203.0.113.66"],
        "exit-node.tor.test": ["198.51.100.24"],
        "66.113.0.203.ip-port.exitlist.torproject.org": ["127.0.0.2"],
        "PTR:203.0.113.66": ["mail.attacker.test"],
    }))
    from cybersecurity_agent.net import clear_dns_fixture_cache

    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(f))
    clear_dns_fixture_cache()
    yield f
    clear_dns_fixture_cache()


@pytest.fixture()
def case_dir(tmp_path):
    d = tmp_path / "case"
    d.mkdir()
    return d


@pytest.fixture()
def cfg(tmp_path, mock_server, monkeypatch):
    from cybersecurity_agent.config import load_config

    monkeypatch.setenv("SENTINEL_CHAIN_PATH", str(tmp_path / "chain.jsonl"))
    monkeypatch.setenv("SENTINEL_HEAD_PATH", str(tmp_path / "HEAD.json"))
    c = load_config(offline=False, tool_timeout_s=5.0, confirmation_timeout_s=1.0,
                    geoip_allow_private=True, geo_base_url_override=mock_server,
                    reputation_base_url_override=mock_server, max_agent_steps=12)
    c.tor_exit_fixture = ""
    return c


@pytest.fixture()
def ctx(cfg, case_dir, dns_fixtures):
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.evidence import eml
    from cybersecurity_agent.config import REPO_ROOT  # noqa: F401

    raw = (SAMPLES / "phishing_obvious.eml").read_bytes()
    parsed = eml.parse_bytes(raw, path=str(SAMPLES / "phishing_obvious.eml"))
    return ToolContext(cfg=cfg, case_dir=case_dir, eml_path=SAMPLES / "phishing_obvious.eml",
                       raw_bytes=raw, parsed=parsed,
                       evidence_hashes={})
