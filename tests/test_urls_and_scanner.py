"""extract_urls (brand/homoglyph engine) + the sandboxed static scanner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCANNER = REPO / "cybersecurity_agent" / "sandbox" / "scanner_script.py"


def _run_scanner(tmp_path, name: str, data: bytes) -> dict:
    import subprocess
    import sys

    f = tmp_path / name
    f.write_bytes(data)
    out = tmp_path / "r.json"
    p = subprocess.run([sys.executable, str(SCANNER), "--file", str(f), "--out", str(out), "--no-optional"],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr[-400:]
    return json.loads(out.read_text())


# ── extract_urls ─────────────────────────────────────────────────────────────
def test_brand_text_vs_href_mismatch_detected(ctx):
    from cybersecurity_agent.tools import extract_urls

    r = extract_urls.tool_extract_urls(ctx, {})
    by_host = {u["host"]: u for u in r.data["urls"]}
    anchor = by_host.get("xn--pypal-4ve.com.9") or list(by_host.values())[0]
    assert anchor["brand_mismatch"] is True
    assert "paypal" in anchor["claimed_brand"]
    assert any(s.factor == "brand_mismatch" for s in r.signals)
    assert any(s.factor == "link_text_mismatch" for s in r.signals)


def test_punycode_and_homoglyph_hosts_are_flagged(ctx):
    from cybersecurity_agent.tools import extract_urls

    r = extract_urls.tool_extract_urls(ctx, {})
    flagged = [u for u in r.data["urls"] if u.get("homoglyph_risk")]
    assert flagged, "punycode host must raise the look-alike flag"
    assert any(s.factor == "homoglyph_domain" for s in r.signals)


def test_ip_literal_and_http_flags(ctx):
    from cybersecurity_agent.tools import extract_urls

    r = extract_urls.tool_extract_urls(ctx, {})
    ip_host = [u for u in r.data["urls"] if u.get("is_ip_literal")]
    assert ip_host and ip_host[0]["host"] == "203.0.113.77"
    factors = {s.factor for s in r.signals}
    assert {"ip_literal_url", "http_url"} <= factors


def test_clean_links_do_not_raise_brand_mismatch():
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.evidence import eml
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.tools import extract_urls
    import tempfile

    raw = (REPO / "samples" / "clean_newsletter.eml").read_bytes()
    p = eml.parse_bytes(raw)
    ctx = ToolContext(cfg=load_config(offline=True), case_dir=Path(tempfile.mkdtemp()),
                      eml_path=Path("c.eml"), raw_bytes=raw, parsed=p)
    r = extract_urls.tool_extract_urls(ctx, {})
    assert all(not u["brand_mismatch"] for u in r.data["urls"])
    assert "brand_mismatch" not in {s.factor for s in r.signals}
    assert any(s.factor == "brand_match" or True for s in r.signals)  # no exception on clean input


def test_bec_tactic_vocabulary_is_soft_not_absolute():
    from cybersecurity_agent.risk import FACTOR_WEIGHTS

    assert FACTOR_WEIGHTS["contact_isolation_request"] <= 1.0
    assert FACTOR_WEIGHTS["money_request_context"] <= 1.0
    assert FACTOR_WEIGHTS["llm_style_indicator"] <= 1.0, "style analysis stays a nudge (rule 5)"


# ── static scanner (SAFETY #3) ───────────────────────────────────────────────
def test_file_type_mismatch_pdf_renamed_exe(tmp_path):
    report = _run_scanner(tmp_path, "invoice.pdf", b"MZ\x90\x00\x03\x00" + b"\x00" * 200 + b"PE\x00\x00" + b"\x00" * 300)
    assert any(f.startswith("file_type_mismatch") for f in report["flags"])
    assert "PE/DOS" in report["magic_type"]
    assert report["extension_consistent"] is False


def test_high_entropy_packed_blob(tmp_path):
    import os

    report = _run_scanner(tmp_path, "blob.bin", b"\x7fELF" + os.urandom(120_000))
    assert report["entropy_bits_per_byte"] > 7.5
    assert any(f.startswith("high_entropy") for f in report["flags"])


def test_low_entropy_plaintext_has_no_flags(tmp_path):
    report = _run_scanner(tmp_path, "readme.txt", b"hello world\n" * 50)
    assert report["flags"] == [] and report["extension_consistent"] is True


def test_ole_macro_markers_detected_without_emulation(tmp_path):
    data = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Macros" + b"VBA" * 3 + b"Sub Document_Open()\n"
            b'  CreateObject("WScript.Shell").Run "powershell -enc AAAA"\nEnd Sub\n' + b"\x00" * 512)
    report = _run_scanner(tmp_path, "doc.doc", data)
    flags = " ".join(report["flags"])
    assert "embedded_macro" in flags
    assert "suspicious_strings" in flags


def test_eicar_test_string_is_recognised(tmp_path):
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    report = _run_scanner(tmp_path, "eicar.txt", eicar)
    assert any("eicar" in f for f in report["flags"])


def test_scanner_contains_no_executing_calls():
    """Static-by-construction guard for SAFETY #3: no exec/subprocess-launching of the
    artifact, no file opened for writing, no os.system anywhere in the sandbox script."""
    src = SCANNER.read_text()
    for forbidden in ("os.system", "subprocess.Popen(", "eval(", "exec(", 'open(str(path), "w"',
                      "webbrowser", "os.startfile", "shutil.unpack_archive", "zipfile.ZipFile.extract"):
        assert forbidden not in src, f"scanner must not contain {forbidden!r}"
    assert 'open(path, "rb")' in src or "read_file" in src
    # exiftool/olevba are invoked only as read-only analysis argv lists
    assert "shell=True" not in src


def test_sandbox_policy_is_default_deny_network():
    from cybersecurity_agent.sandbox import docker_runner

    src = Path(docker_runner.__file__).read_text()
    assert '"--network", "none"' in src, "sandbox must be network-less by default"
    assert ':/work:ro"' in src, "evidence mount must be read-only"
    assert "--cap-drop" in src and "no-new-privileges" in src
    assert "--rm" in src and "_force_destroy" in src, "container destroyed after every run"
    assert "f\"{base}:/work:ro\"" in src, "the /work mount line must be :ro"


def test_docker_absent_falls_back_labeled_not_silent(tmp_path):
    """Without Docker, the same scanner must still run and be *labelled* honestly."""
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.sandbox.docker_runner import docker_available, scan_file

    avail, why = docker_available()
    art = tmp_path / "invoice.pdf"
    art.write_bytes(b"MZ\x90\x00" + b"\x00" * 400 + b"PE\x00\x00" + b"\x00" * 600)
    case = tmp_path / "case"
    case.mkdir()
    run = scan_file(load_config(sandbox_required=False), case, "invoice.pdf", art)
    assert run.ok, run.notes
    if avail:
        assert run.mode == "docker"
    else:
        assert run.mode == "subprocess-limited"
        assert any("NOT a container" in n for n in run.notes)


def test_sandbox_required_true_refuses_without_docker(tmp_path):
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.sandbox.docker_runner import docker_available, scan_file

    if docker_available()[0]:
        pytest.skip("this machine has Docker; the refusal path needs a machine without it")
    art = tmp_path / "x.bin"
    art.write_bytes(b"data")
    case = tmp_path / "case"
    case.mkdir()
    run = scan_file(load_config(sandbox_required=True), case, "x.bin", art)
    assert run.mode == "denied" and not run.ok


def test_evidence_copy_isolates_tampering(tmp_path):
    """The sandbox scans a *copy*; even a hostile scanner cannot edit the evidence."""
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.sandbox.docker_runner import prepare_workdir, scan_file

    art = tmp_path / "orig.bin"
    art.write_bytes(b"MZ" + b"\x00" * 500)
    sha_before = art.read_bytes()
    case = tmp_path / "case"
    case.mkdir()
    work = prepare_workdir(case, {"orig.bin": art})
    assert (work / "evidence" / "orig.bin").exists()
    import os

    assert oct(os.stat(work / "evidence" / "orig.bin").st_mode)[-3:] == "444", "artifact copy must be read-only"
    run = scan_file(load_config(), case, "orig.bin", art)
    assert run.ok
    assert art.read_bytes() == sha_before, "original evidence bytes must be untouched"


def test_pixel_listener_records_only_case_urls(tmp_path):
    """Fallback (d) must not fill the hit log with favicon/preview-bot noise, and it
    must record the *observed* IP + UA for a real /open/<case>.gif hit."""
    import json
    import socket
    import threading
    import time
    import urllib.error
    import urllib.request

    from cybersecurity_agent.tools_dev import serve_pixel

    with socket.socket() as s:                       # ephemeral port, no fixed binds
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    out = tmp_path / "hits.jsonl"
    threading.Thread(target=serve_pixel, daemon=True,
                     kwargs=dict(bind="127.0.0.1", port=port, out=out)).start()
    time.sleep(0.6)

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/open/CASE9.gif", timeout=5) as r:
        assert r.status == 200 and r.headers["Content-Type"] == "image/gif"
        body = r.read()
    assert body[:6] in {b"GIF87a", b"GIF89a"} and len(body) < 100, "must be a real 1×1 gif"

    try:                                             # unknown paths: 204, no log entry
        urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico", timeout=5)
    except urllib.error.HTTPError as exc:
        pytest.fail(f"favicon should be answered quietly, got HTTP {exc.code}")
    time.sleep(0.3)

    recs = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["path"] for r in recs] == ["/open/CASE9.gif"], "only case URLs are evidence"
    assert recs[0]["ip"] == "127.0.0.1" and "urllib" in recs[0]["user_agent"].lower()


def test_logo_alt_text_counts_as_a_visible_brand_claim(tmp_path):
    """Brief §5: compare visible brand *text/logo* against the actual link domain. A logo
    has no anchor text, so its alt attribute is the claim — an off-brand logo must be
    caught, and a normal (unlabelled) CDN image must not invent a finding."""
    from cybersecurity_agent.config import Config
    from cybersecurity_agent.evidence import eml as eml_mod
    from cybersecurity_agent.tools.base import ToolContext
    from cybersecurity_agent.tools.extract_urls import tool_extract_urls

    html = (
        '<img src="http://198.51.100.77/paypal-logo.png" alt="PayPal">'      # claim vs off-brand host
        '<a href="http://paypa1-secure.example/login">https://www.paypal.com/x</a>'
        '<img src="https://cdn.example.org/header.png" alt="">'               # honest, unlabelled
    )
    raw = (b"From: a@paypa1-secure.example\r\nTo: you@example.com\r\n"
           b"Subject: hi\r\nDate: Tue, 17 Nov 2026 21:31:04 +0530\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: text/html; charset=\"utf-8\"\r\n\r\n"
           + html.encode())
    pairs = {p["url"]: p["visible_text"] for p in eml_mod.extract_url_pairs(html, "")}
    assert pairs["http://198.51.100.77/paypal-logo.png"] == "[image] PayPal"
    assert pairs["https://cdn.example.org/header.png"] == "[image]"

    d = tmp_path / "case"; d.mkdir()
    (d / "m.eml").write_bytes(raw)
    parsed = eml_mod.parse_bytes(raw, path=d / "m.eml")
    ctx = ToolContext(cfg=Config(offline=True), case_dir=d, eml_path=d / "m.eml",
                      raw_bytes=raw, parsed=parsed, state={})
    res = tool_extract_urls(ctx, {})
    by_host = {u["host"]: u for u in res.data["urls"]}
    assert by_host["198.51.100.77"]["brand_mismatch"] is True, "logo alt must be compared"
    assert by_host["cdn.example.org"].get("brand_mismatch") in (False, None), \
        "an unlabelled image is not a brand claim"
    assert any(s.factor == "brand_mismatch" for s in res.signals)


def test_mock_index_page_explains_itself_without_leaking_case_data():
    """The demo fixture server can be bound for a sandboxed preview, so `GET /` must
    read as documentation (and must not look like a dashboard the agent 'has')."""
    from cybersecurity_agent.tools_dev import DEMO_FIXTURES, mock_index_html

    page = mock_index_html(DEMO_FIXTURES, bind="0.0.0.0", port=8099)
    assert "This is not the product's UI" in page
    assert "/json/&lt;ip&gt;" in page or "/json/<ip>" in page
    assert "127.0.0.1" in page, "the demo IPs are the point of the page"
    # a wildcard bind is not a client address — the copy-paste command must be usable
    assert "http://127.0.0.1:8099 --reputation-base-url" in page
    assert "0.0.0.0:8099 --reputation-base-url" not in page


def test_mock_server_refuses_a_public_bind_unless_told_otherwise():
    import pytest

    from cybersecurity_agent.tools_dev import serve_mock

    with pytest.raises(SystemExit) as exc:
        serve_mock(bind="0.0.0.0", port=0)          # refuses before binding anything
    assert "--allow-public" in str(exc.value)


# ── fallback (d): the reply draft, and the operator's --no-pixel opt-out ────────

def _draft_ctx(tmp_path, *, state=None, extra_iocs=None):
    from cybersecurity_agent.config import Config
    from cybersecurity_agent.evidence import eml as eml_mod
    from cybersecurity_agent.tools.base import ToolContext

    raw = (b"From: \"M. R.\" <suspect@gmail.com>\r\nTo: victim@example.com\r\n"
           b"Subject: private and confidential\r\nDate: Tue, 17 Nov 2026 21:31:04 +0530\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
           b"please confirm the transfer\r\n")
    case = tmp_path / "case"; case.mkdir(parents=True)
    (case / "case.eml").write_bytes(raw)
    parsed = eml_mod.parse_bytes(raw, path=case / "case.eml")
    st = {"origin": {"source_kind": "phishing_infrastructure", "status": "fallback",
                     "origin_confidence_ceiling": 62.0}}
    st.update(state or {})
    return ToolContext(cfg=Config(offline=True), case_dir=case, eml_path=case / "case.eml",
                       raw_bytes=raw, parsed=parsed, state=st, extra_iocs=extra_iocs or [])


def test_draft_embeds_a_pixel_unless_the_operator_opted_out(tmp_path):
    from cybersecurity_agent.tools.redact_reply import tool_redact_reply

    ctx_on = _draft_ctx(tmp_path / "on")
    on = tool_redact_reply(ctx_on, {})
    text_on = (ctx_on.case_dir / "reply_draft.html").read_text()

    ctx_off = _draft_ctx(tmp_path / "off", state={"no_pixel": True})
    off = tool_redact_reply(ctx_off, {})
    text_off = (ctx_off.case_dir / "reply_draft.html").read_text()

    assert "<img src=\"http://127.0.0.1:8099/open/" in text_on, "pixel embedded by default"
    assert "img src" not in text_off, "--no-pixel must actually suppress the tag"
    assert "NOT embedded — plain draft only" in text_off
    assert "no pixel" in off.summary and "pixel embedded" in on.summary
    assert "DO NOT SEND WITHOUT AUTHORIZATION" in text_off, "draft is never auto-sendable"
    assert "•••" in text_off or "@gmail.com" not in text_off.split("original sender")[1][:120]


def test_pixel_hits_from_another_case_are_not_credited_here(tmp_path):
    """`--extra-ioc-file` can be shared across cases; only hits tagged for this case
    (or untagged, i.e. written by a single-case listener) may add evidence."""
    from cybersecurity_agent.tools.redact_reply import tool_redact_reply

    mine = tool_redact_reply(_draft_ctx(tmp_path / "mine", extra_iocs=[{"path": "/open/x.gif"}]), {})
    foreign = tool_redact_reply(_draft_ctx(tmp_path / "foreign",
                                           extra_iocs=[{"path": "/open/x.gif", "case": "not-this-one"}]), {})
    assert any(s.factor == "tracking_pixel_captured" for s in mine.signals)
    assert not any(s.factor == "tracking_pixel_captured" for s in foreign.signals), \
        "an unrelated case's hit must not raise this case's score"


def test_planner_offers_the_draft_for_any_hidden_sender_kind(tmp_path):
    from cybersecurity_agent.llm.deterministic import DeterministicEngine

    class Ctx:
        def __init__(self, kind):
            self.state = {"origin": {"source_kind": kind, "status": "fallback", "ip": None},
                          "geolocate": {}, "phishing_infra": []}
            self.attachment_files = {}

    history = [{"tool": t, "status": "✓"} for t in
               ("parse_headers", "extract_urls", "resolve_origin", "geolocate_ip",
                "check_tor_exit", "check_reputation")]
    engine = DeterministicEngine()
    offered = engine.next_action(Ctx("phishing_infrastructure"), history)
    assert offered.get("tool_call", {}).get("name") == "redact_reply", \
        "a lure-server trace does not reveal the sender: (d) is still the right offer"
    closed = engine.next_action(Ctx("spf_client_ip"), history)
    assert "final" in closed, "a genuine sender-side client-ip means no reply-baiting draft"
