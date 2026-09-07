"""Header-parsing + origin-resolution unit tests (no network; DNS via the
demo-fixture switch, HTTP via the local mock server)."""
from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _parse(name: str):
    from cybersecurity_agent.evidence import eml

    return eml.parse_bytes((SAMPLES / name).read_bytes(), path=name)


def test_hops_numbered_oldest_first():
    p = _parse("phishing_obvious.eml")
    assert len(p.hops) == 3, "all Received: headers must be collected, not just the top one"
    # Bottom-most Received: (in the file) is the *oldest* hop → sequence 0. In this
    # sample that is the receiving MTA accepting from the attacker's MX, and the
    # topmost header is the newest stamp added by the last relay.
    assert [h.sequence for h in p.hops] == [0, 1, 2]
    assert p.hops[0].ip == "198.51.100.7" and p.hops[0].by_host == "mail.corp.example"
    assert p.hops[1].ip is None, "the internal sendmail hop carries no routable IP"
    assert p.hops[2].ip == "203.0.113.66" and "seguros-billing" in p.hops[2].raw
    assert p.hops[0].timestamp.startswith("Tue, 01 Sep 2026 19:14:11")


def test_provider_relay_hops_are_flagged_not_trusted():
    p = _parse("gmail_bec_subtle.eml")
    assert p.hops, "sample must contain the relay hop"
    google = [h for h in p.hops if h.is_webmail_relay]
    assert google and google[0].relay_org == "Google"
    assert google[0].ip == "74.125.20.46"


def test_auth_results_client_ip_and_mechanisms():
    p = _parse("phishing_obvious.eml")
    assert p.auth_results and p.auth_results[0].get("spf") == "fail"
    assert p.auth_results[0].get("client_ip") == "203.0.113.66"
    assert p.received_spf[0]["result"] == "fail"


def test_messageid_and_tz_extraction():
    p = _parse("phishing_obvious.eml")
    assert p.message_id_host == "payload01.secure-p0nyail.com"
    assert p.tz_minutes == 3 * 60 + 30
    from cybersecurity_agent.evidence.eml import tz_hint

    assert tz_hint(p.tz_minutes)["candidate_region"] == "Iran"


def test_multipart_bodies_and_attachment_decoded():
    p = _parse("phishing_obvious.eml")
    assert "unusual sign-in activity" in p.text_body
    assert "<form" in p.html_body
    assert len(p.attachments) == 1
    att = p.attachments[0]
    assert att["filename"] == "invoice.pdf"
    assert att["payload"].startswith(b"%PDF")          # base64 decoded, NOT executed
    assert "invoice.pdf" in str(att["size_declared"]) or att["size_declared"] > 5000


def test_dkim_signature_parsed():
    p = _parse("clean_newsletter.eml")
    assert p.dkim["domain"] == "news.example.com" and p.dkim["selector"] == "selector1"
    assert p.dkim["algorithm"] == "rsa-sha256"


def test_structural_notes_flag_replyto_and_brand():
    p = _parse("phishing_obvious.eml")
    joined = " ".join(p.notes)
    assert "Reply-To domain" in joined and "Display name claims brand" in joined


def test_resolve_origin_prefers_authenticated_client_ip(ctx):
    from cybersecurity_agent.tools import extract_urls, resolve_origin

    extract_urls.tool_extract_urls(ctx, {})
    r = resolve_origin.tool_resolve_origin(ctx, {})
    f = r.data["finding"]
    # lowest hop is the attacker's own MX (self-written header) → client-ip= wins
    assert f["ip"] == "203.0.113.66"
    assert f["source_kind"] == "spf_client_ip"
    assert 70 <= f["confidence"] <= 85


def test_resolve_origin_degrades_for_pure_webmail(cfg, tmp_path):
    """The headline requirement: no fake pin when Gmail hid the IP."""
    from cybersecurity_agent.evidence import eml
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.tools import extract_urls, resolve_origin

    raw = (SAMPLES / "gmail_bec_subtle.eml").read_bytes()
    parsed = eml.parse_bytes(raw, path="gmail_bec_subtle.eml")
    case = tmp_path / "c"
    case.mkdir()
    c = ToolContext(cfg=cfg, case_dir=case, eml_path=SAMPLES / "x.eml", raw_bytes=raw, parsed=parsed)
    extract_urls.tool_extract_urls(c, {})
    r = resolve_origin.tool_resolve_origin(c, {})
    f = r.data["finding"]
    assert f["ip"] is None or f["ip_role"] != "sender_machine_or_open_relay"
    assert f["source_kind"] in {"unrecovered", "phishing_infrastructure", "webmail_relay_only"}
    assert f["confidence"] <= 62, "webmail fallback may never claim sender-level confidence"
    assert f["fallbacks_used"], "must state WHICH fallback replaced the missing origin IP"
    kinds = " ".join(f["fallbacks_used"])
    assert "phishing_infrastructure" in kinds or "date_tz_offset" in kinds
    # The provider edge may be *named* as context, but never as the sender, and the
    # report must say so in words.
    if f.get("ip_role") == "provider_edge":
        assert f["ip"] != "74.125.20.46" or f["confidence"] <= 15, "edge IP must not carry sender-level confidence"
        assert "not attributable" in " ".join(f["notes"]).lower() or "not the sender" in " ".join(f["notes"]).lower()
    else:
        assert f["source_kind"] in {"phishing_infrastructure", "unrecovered"}


def test_resolve_origin_reports_provider_edge_context(cfg, tmp_path, monkeypatch):
    """Without a resolvable lure host, we must say 'unrecovered' rather than pin the
    message to Google's datacenter."""
    from cybersecurity_agent.evidence import eml
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.tools import resolve_origin

    monkeypatch.delenv("SENTINEL_DNS_FIXTURES", raising=False)
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    raw = (SAMPLES / "gmail_bec_subtle.eml").read_bytes()
    parsed = eml.parse_bytes(raw, path="g.eml")
    case = tmp_path / "c2"
    case.mkdir()
    c = ToolContext(cfg=cfg, case_dir=case, eml_path=SAMPLES / "g.eml", raw_bytes=raw, parsed=parsed,
                    state={})
    # no DNS fixtures → the lure host cannot be traced
    c.cfg.geoip_allow_private = True
    r = resolve_origin.tool_resolve_origin(c, {})
    f = r.data["finding"]
    assert f["source_kind"] in {"webmail_relay_only", "unrecovered"}
    assert f["confidence"] <= 15, "provider edge context is not a location claim"
    clear_dns_fixture_cache()


# ── DNS fixture semantics: hermetic answers, and the difference between ──────────
#    "we asked and it is clean" and "we never got to ask"
#
# A live DNSBL query is the one thing that can make two runs of the same sample
# differ on different networks, so the demo and CI pin DNS to the fixture file.
# These tests are what keep that pinning honest.


@pytest.fixture()
def dns_at(tmp_path, monkeypatch):
    """Point SENTINEL_DNS_FIXTURES at `blob`, and restore the session state afterwards
    (the fixture cache is a module global, so leaving it loaded would leak into
    later tests)."""
    import json

    from cybersecurity_agent.net import clear_dns_fixture_cache

    def _write(blob):
        f = tmp_path / "dns.json"
        f.write_text(json.dumps(blob))
        monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(f))
        clear_dns_fixture_cache()
        return f

    yield _write
    clear_dns_fixture_cache()


def test_empty_fixture_entry_is_an_answer_not_a_miss(dns_at):
    """`[]` means "the name exists and has no A record" (NODATA). For a blocklist that
    is a *clean* answer; treating it as a miss would silently drop the mitigator."""
    from cybersecurity_agent.net import dns_a

    dns_at({"x.zen.spamhaus.org": []})
    assert dns_a("x.zen.spamhaus.org") == ([], "NODATA")


def test_string_fixture_entry_can_assert_nxdomain(dns_at):
    from cybersecurity_agent.net import dns_a

    dns_at({"99.0.2.192.ip-port.exitlist.torproject.org": "NXDOMAIN"})
    assert dns_a("99.0.2.192.ip-port.exitlist.torproject.org") == ([], "NXDOMAIN")


def test_strict_mode_replaces_the_resolver_with_a_declared_universe(dns_at, monkeypatch):
    """With SENTINEL_DNS_STRICT=1 a name the fixture file does not mention must come back
    as 'FIXTURE_ONLY' — never as whatever the network felt like answering today."""
    from cybersecurity_agent import net

    dns_at({"known.test": ["1.2.3.4"]})
    monkeypatch.setenv("SENTINEL_DNS_STRICT", "1")
    assert net.dns_a("never-mentioned.test") == ([], "FIXTURE_ONLY")
    assert net.dns_a("known.test") == (["1.2.3.4"], "fixture"), "hits still come from the file"
    assert net.fixtures_configured() is True


def test_strict_mode_is_inert_when_no_fixture_file_is_loaded(tmp_path, monkeypatch):
    """Strict is a *fixture* switch. Production never sets it, and a test that unsets the
    fixture file must not end up blind: without a loaded file there is no declared
    universe to be strict about, so a real lookup still happens."""
    from cybersecurity_agent import net
    from cybersecurity_agent.net import clear_dns_fixture_cache

    monkeypatch.delenv("SENTINEL_DNS_FIXTURES", raising=False)
    monkeypatch.setenv("SENTINEL_DNS_STRICT", "1")
    clear_dns_fixture_cache()
    assert net.fixtures_configured() is False
    ips, err = net.dns_a("sentinel-dns-strict-probe.invalid")
    assert ips == []
    assert err != "FIXTURE_ONLY", "a missing fixture file must not fake an answer"
    clear_dns_fixture_cache()


def test_unresolved_blocklist_answer_is_never_reported_as_clean(dns_at, monkeypatch, cfg, tmp_path):
    """The fail-open trap this mode exists to avoid: 'we could not ask' must not turn
    into 'not listed'."""
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.tools.check_reputation import _spamhaus_sbl

    dns_at({})
    monkeypatch.setenv("SENTINEL_DNS_STRICT", "1")
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml",
                      raw_bytes=b"", parsed={}, state={})
    hit = _spamhaus_sbl(ctx, "192.0.2.55")
    assert hit.ok is False, "an unanswered lookup is not a clean bill of health"
    assert "not listed" not in str(hit.note).lower()
    assert "fixture" in str(hit.note).lower() or "failed" in str(hit.note).lower()
