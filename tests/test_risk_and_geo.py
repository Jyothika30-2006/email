"""Risk fusion honesty + geolocation cross-validation (the two anti-BS engines)."""
from __future__ import annotations

from cybersecurity_agent.models import GeoPoint, RiskSignal
from cybersecurity_agent.risk import (classify, confidence_score, fuse, severity_color,
                                       summary_lines)


def _s(factor, direction=1, strength=90, source="t"):
    return RiskSignal(factor, direction, strength, explanation=f"{factor}", source=source)


def test_single_soft_signal_does_not_max_the_score():
    assert fuse([_s("attachment_present", strength=30, source="parse_headers")]) < 40


def test_three_strong_independent_signals_reach_malicious():
    sig = [_s("brand_mismatch", 1, 90, "extract_urls"),
           _s("spf_fail", 1, 100, "parse_headers"),
           _s("homoglyph_domain", 1, 95, "extract_urls")]
    score = fuse(sig)
    assert score >= 85 and classify(score, sig) == "MALICIOUS"


def test_mitigating_evidence_cannot_launder_a_phishing_kit():
    sig = [_s("brand_mismatch", 1, 90, "a"), _s("spf_fail", 1, 100, "b"),
           _s("homoglyph_domain", 1, 95, "a"), _s("attachment_risky_ext", 1, 65, "b"),
           RiskSignal("clean_static_scan", -1, 100, explanation="clean", source="f"),
           RiskSignal("auth_pass", -1, 100, explanation="passes", source="h")]
    score = fuse(sig)
    assert 25 < score < 92, "mitigation must move the needle but never erase it"


def test_malice_requires_a_strong_indicator():
    soft = [_s("urgency_language", 1, 40, "a"), _s("tz_hint", 1, 22, "b"),
            _s("shortener", 1, 50, "c"), _s("http_url", 1, 45, "d")]
    score = fuse(soft)
    assert score < 65 or classify(score, soft) != "MALICIOUS", "no conviction on vibes alone"


def test_confidence_is_provenance_capped_not_scare_capped():
    """A scary email with no origin data must report LOW confidence (rule 5)."""
    low = confidence_score(origin_ceiling=0.0, origin_kind="unrecovered", geoloc_confidence=0.0,
                          tool_coverage=7, expected_tools=8, corroboration_families=4, origin_status="none")
    high = confidence_score(origin_ceiling=82.0, origin_kind="received_hop", geoloc_confidence=95.0,
                            tool_coverage=8, expected_tools=8, corroboration_families=6, origin_status="resolved")
    assert low <= 52 < 80 <= high, "no-origin evidence must not report >52% confidence"
    fallback = confidence_score(origin_ceiling=82.0, origin_kind="phishing_infrastructure", geoloc_confidence=95.0,
                                tool_coverage=8, expected_tools=8, corroboration_families=6, origin_status="fallback")
    resolved = confidence_score(origin_ceiling=82.0, origin_kind="received_hop", geoloc_confidence=95.0,
                               tool_coverage=8, expected_tools=8, corroboration_families=6, origin_status="resolved")
    assert fallback < resolved, "same data, weaker provenance → lower confidence (rule 5)"
    assert low != high, "confidence must actually track evidence quality"


def test_color_band_and_bullets():
    assert severity_color(70) == "red" and severity_color(5) == "green"
    lines = summary_lines([_s("spf_fail", 1, 100, "parse_headers"), _s("brand_mismatch", 1, 90, "extract_urls")], limit=1)
    assert len(lines) == 1 and lines[0].startswith("↑")


# ── geolocation consensus ───────────────────────────────────────────────────
def test_agreeing_sources_produce_a_tight_radius():
    from cybersecurity_agent.tools.geolocate_ip import build_consensus

    pts = [GeoPoint(source="ip-api", ok=True, lat=10.0, lon=20.0, country="Testland", country_code="TL", city="Testville", accuracy_km=10),
           GeoPoint(source="ipinfo", ok=True, lat=10.01, lon=20.01, country="TL", city="Testville", accuracy_km=12)]
    c = build_consensus("203.0.113.66", pts, ceiling=82.0)
    assert c.confidence >= 75 and c.radius_km < 120 and "Testville" in c.summary
    assert c.confidence <= 82.0, "ceiling must cap confidence"


def test_disagreeing_sources_widen_radius_and_cut_confidence():
    from cybersecurity_agent.tools.geolocate_ip import build_consensus

    pts = [GeoPoint(source="ip-api", ok=True, lat=10.0, lon=20.0, country_code="TL", city="Testville"),
           GeoPoint(source="ipinfo", ok=True, lat=-33.0, lon=151.0, country_code="AU", city="Sydney")]
    c = build_consensus("203.0.113.67", pts, ceiling=82.0)
    assert c.radius_km > 300 and c.confidence < 45
    assert "CONFLICT" in " ".join(c.notes)


def test_single_source_is_never_sold_as_precise():
    from cybersecurity_agent.tools.geolocate_ip import build_consensus

    c = build_consensus("203.0.113.66", [GeoPoint(source="ip-api", ok=True, lat=1.0, lon=2.0, city="X", country_code="XX")],
                        ceiling=82.0)
    assert c.radius_km >= 300 and "single-source" in " ".join(c.notes)


def test_unusable_sources_report_unknown_not_a_guess():
    from cybersecurity_agent.tools.geolocate_ip import build_consensus

    c = build_consensus("203.0.113.66", [GeoPoint(source="ip-api", ok=False, raw_error="timeout"),
                                         GeoPoint(source="ipinfo", ok=False, raw_error="429")], ceiling=82.0)
    assert c.confidence <= 10 and "unknown" in c.summary.lower() and c.lat is None


def test_geolocate_hits_the_real_http_code_path_via_mock(ctx):
    """Uses the production urllib path against a localhost fixture server."""
    from cybersecurity_agent.tools import geolocate_ip, resolve_origin, extract_urls

    extract_urls.tool_extract_urls(ctx, {})
    resolve_origin.tool_resolve_origin(ctx, {})
    r = geolocate_ip.tool_geolocate_ip(ctx, {})
    cons = r.data["primary"]["consensus"]
    assert cons["confidence"] >= 60 and "Testville" in cons["summary"]
    sources = [p["source"] for p in r.data["primary"]["points"] if p.get("ok")]
    assert {"ip-api", "ipinfo"} <= set(sources), "the multi-source claim must be testable"
    assert ctx.state["origin"]["ip"] == "203.0.113.66"


def test_non_traceable_ip_is_skipped_with_an_explanation(ctx):
    ctx.state["origin"] = {"ip": "10.1.2.3", "source_kind": "received_hop", "confidence": 80}
    ctx.cfg.geoip_allow_private = False
    from cybersecurity_agent.tools import geolocate_ip

    r = geolocate_ip.tool_geolocate_ip(ctx, {})
    assert "non-routable" in r.data["targets"][0]["consensus"]["summary"]


def test_tor_exit_listed_and_not_listed(ctx, dns_fixtures, monkeypatch):
    from cybersecurity_agent.tools import check_tor_exit

    # fixture says 203.0.113.66 IS a listed exit (127.0.0.2)
    ctx.state["origin"] = {"ip": "203.0.113.66", "source_kind": "received_hop", "confidence": 80}
    r = check_tor_exit.tool_check_tor_exit(ctx, {})
    assert r.data["listed"] is True
    sig = [s for s in r.signals if s.factor == "tor_exit"]
    assert sig and "anonymized" in sig[0].explanation and "NOT proof of guilt" in sig[0].explanation

    # an IP with no fixture answer → not listed (and we never invent a hit)
    ctx.state["origin"] = {"ip": "203.0.113.99", "source_kind": "received_hop", "confidence": 80}
    r2 = check_tor_exit.tool_check_tor_exit(ctx, {})
    assert r2.data["listed"] is False
    assert any("not listed" in n or "could not be determined" in n for n in r2.data["notes"])
    assert not any(s2.factor == "tor_exit" for s2 in r2.signals), "absence of a hit must not score"


def test_tor_fixture_is_always_labelled_simulated(ctx, tmp_path):
    from cybersecurity_agent.tools import check_tor_exit

    f = tmp_path / "exits.txt"
    f.write_text("198.51.100.24\n")
    ctx.cfg.tor_exit_fixture = str(f)
    ctx.state["origin"] = {"ip": "198.51.100.24", "source_kind": "received_hop", "confidence": 80}
    r = check_tor_exit.tool_check_tor_exit(ctx, {})
    assert r.data["listed"] and r.data["simulated"] is True
    assert "simulated" in r.data["via"] and "NOT a live DNSEL answer" in r.data["via"]
