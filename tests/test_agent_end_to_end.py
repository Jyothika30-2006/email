"""End-to-end agent tests: the whole flow (hash → headers → origin → geo → tor →
URLs → reputation → gated sandbox scan → verdict → ledger → report) must run in a
plain CI box, offline, and produce an honest, self-consistent artifact set.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "samples"


def _agent(sample: str, tmp_path, **kw):
    from cybersecurity_agent.agent import Agent

    cfg_over = {"tool_timeout_s": 8.0, "max_agent_steps": 12, "offline": True,
                "geoip_allow_private": True, "sandbox_required": False,
                "require_confirmation": False, "auto_confirm": True}
    cfg_over.update(kw.pop("cfg_overrides", {}))
    a = Agent(SAMPLES / sample, demo=True, no_llm=True, case_prefix=tmp_path,
              cfg_overrides=cfg_over, **kw)
    a._log_to_chain_orig = a._log_to_chain
    return a


def test_phishing_sample_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    a = _agent("phishing_obvious.eml", tmp_path)
    v = a.run()
    a.close()
    assert v["verdict"] == "MALICIOUS"
    assert v["risk"] >= 65
    assert v["evidence"], "rule 7: verdict must enumerate the evidence"
    case_dir = Path(v["report"]).parent
    for f in ("report.md", "evidence.json", "audit.log", "run.json"):
        assert (case_dir / f).exists(), f"{f} must be written (step 11)"
    md = (case_dir / "report.md").read_text()
    assert "prompt-injection" in md.lower() or "injection" in md.lower()
    assert "SUSPICIOUS" in md or "MALICIOUS" in md
    assert "static analysis only" in md.lower() or "never executed" in md.lower()
    # ledger entry was written with hash + verdict metadata only
    payload = v["chain"]["payload"]
    assert payload["file_hash"] == v["sha256"] and payload["AI_verdict"] == "MALICIOUS"
    assert "<" not in json.dumps(payload) or "html" not in json.dumps(payload).lower()
    # chain-of-custody: source hashed before analysis
    manifest = json.loads((case_dir / "evidence.json").read_text())
    assert any(r["kind"] == "source_email" and r["recorded_before_analysis"] for r in manifest["records"])
    clear_dns_fixture_cache()


def test_clean_sample_is_low_risk(tmp_path):
    a = _agent("clean_newsletter.eml", tmp_path)
    v = a.run()
    a.close()
    assert v["verdict"] == "SAFE" and v["risk"] < 35
    assert not any("brand_mismatch" in str(b) for b in v["evidence"])
    assert v["confidence"] >= 55, "a fully authenticated, cleanly traced sender should earn decent confidence"


def test_gmail_webmail_honesty_path(tmp_path, monkeypatch):
    """The core promise: unrecoverable origin → say so, degrade, lower confidence."""
    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    a = _agent("gmail_bec_subtle.eml", tmp_path)
    v = a.run()
    a.close()
    assert v["origin_source_kind"] in {"phishing_infrastructure", "webmail_relay_only", "unrecovered"}
    assert v["verdict"] in {"SUSPICIOUS", "SAFE"}
    assert v["confidence"] <= 80, "fallback provenance must cap confidence"
    joined = " ".join(v["evidence"]).lower()
    assert "unrecover" in joined or "hidden" in joined or "fallback" in joined or "lure" in joined
    md = Path(v["report"]).read_text().lower()
    assert "never invent" in md or "unknown" in md or "unrecoverable" in md
    clear_dns_fixture_cache()


def test_tor_sample_flags_anonymization_not_guilt(tmp_path):
    from cybersecurity_agent.agent import Agent

    a = Agent(SAMPLES / "tor_exit_legit.eml", demo=True, no_llm=True, case_prefix=tmp_path,
              cfg_overrides={"offline": True, "geoip_allow_private": True, "require_confirmation": False,
                             "auto_confirm": True,
                             "tor_exit_fixture": str(SAMPLES / "fixtures" / "tor_exit_ips.txt")})
    v = a.run()
    a.close()
    md = Path(v["report"]).read_text()
    assert "anonymized" in md.lower()
    assert "not proof of guilt" in md.lower() or "not proof" in md.lower()


def test_gate_denial_is_fail_closed_and_recorded(tmp_path, monkeypatch):
    """`printf 'no\\n'` style stdin must DENY and the report must record the gap."""
    from cybersecurity_agent.agent import Agent
    import sys
    import io

    a = Agent(SAMPLES / "phishing_obvious.eml", no_llm=True, case_prefix=tmp_path, auto_confirm=False,
              cfg_overrides={"offline": True, "require_confirmation": True, "confirmation_timeout_s": 1.0,
                             "tool_timeout_s": 8.0, "geoip_allow_private": True, "max_agent_steps": 12})
    monkeypatch.setattr(sys, "stdin", io.StringIO("definitely not\n"))
    v = a.run()
    a.close()
    md = Path(v["report"]).read_text()
    assert "DENIED" in md or "denied" in md
    assert any("gate" in g.lower() or "never inspected" in g.lower() for g in v["gaps"]), v["gaps"]
    # the gap must also be *in the report*, not only in the JSON
    assert "human gate" in md.lower() or "never inspected" in md.lower()


def test_kill_switch_aborts_mid_run(tmp_path):
    from cybersecurity_agent.agent import Agent

    a = Agent(SAMPLES / "phishing_obvious.eml", demo=True, no_llm=True, case_prefix=tmp_path,
              cfg_overrides={"offline": True, "tool_timeout_s": 8.0, "require_confirmation": False,
                             "auto_confirm": True})
    a.switch.abort("kill-switch keypress 'x'")     # simulate the operator hitting 'x'
    v = a.run()
    a.close()
    assert v["verdict"].startswith("ABORTED")
    assert a.aborted is True
    assert (Path(v["report"])).exists(), "partial report must still be flushed"


def test_llm_native_tool_path_with_stub(tmp_path):
    """Ollama absent in CI → stub the transport but exercise the real JSON/tool-call
    parsing, observe() round-trips and refusal handling through the agent loop."""
    from cybersecurity_agent.agent import Agent
    from cybersecurity_agent.tools import REGISTRY

    calls = []

    class StubEngine:
        is_llm = True
        name = "stub"

        def __init__(self):
            self.i = 0
            self.tools = list(REGISTRY)

        def probe(self, log=lambda s: None):
            return True, "stub"

        def prime(self, digest, block):
            calls.append(("prime", bool(digest)))

        def observe(self, tool, obs, risk_line):
            calls.append(("observe", tool))

        def next_action(self, ctx, history):
            if "static_file_scan" in {h["tool"] for h in history}:
                return {"thought": "evidence complete", "final": {"verdict": "SAFE", "confidence": 1,
                                                                   "summary": "stub", "evidence": []}}
            # first invent a tool (must be refused), then walk the whitelist
            if self.i == 0:
                self.i += 1
                return {"thought": "let me just run shell", "tool_call": {"name": "shell", "arguments": {"cmd": "id"}}}
            nxt = [t for t in ("parse_headers", "extract_urls", "resolve_origin", "check_reputation")
                   if t not in {h["tool"] for h in history}]
            name = nxt[0] if nxt else "parse_headers"
            self.i += 1
            return {"thought": f"calling {name}", "tool_call": {"name": name, "arguments": {}}}

        def summarize(self, prompt):
            return "stub narrative"

    a = Agent(SAMPLES / "phishing_obvious.eml", demo=True, case_prefix=tmp_path,
              cfg_overrides={"offline": True, "tool_timeout_s": 8.0, "max_agent_steps": 8,
                             "require_confirmation": False, "auto_confirm": True})
    a._select_brain = lambda: ("ollama:stub", "stubbed transport")
    a.engine = StubEngine()
    v = a.run()
    a.close()
    assert ("prime", True) in calls
    assert any(c[0] == "observe" for c in calls), "observations must be fed back to the model"
    # the invented 'shell' call is refused, recorded as a signal, and never executed
    events = json.loads(Path(v["report"]).parent.joinpath("run.json").read_text())["events"]
    assert any("refused" in e.get("text", "").lower() for e in events)
    run = json.loads(Path(v["report"]).parent.joinpath("run.json").read_text())
    assert any(s["factor"] == "invented_tool_request" for s in run["signals"]), \
        "refusal must be recorded in the ledger the report is built from"
    assert any(s["factor"] == "invented_tool_request" for s in run["signals"])
    assert "not whitelisted" in Path(v["report"]).read_text().lower()
    assert "shell" not in Path(v["report"]).read_text() or "refused" in Path(v["report"]).read_text().lower()


def test_llm_protocol_parser_accepts_both_shapes():
    from cybersecurity_agent.llm.ollama_client import _from_json, _from_native

    allowed = {"parse_headers", "geolocate_ip", "static_file_scan"}
    a = _from_json('```json\n{"thought": "look at hops", "tool_call": {"name": "parse_headers", "arguments": {"detail": "full"}}}\n```', allowed)
    assert a["tool_call"]["name"] == "parse_headers"
    b = _from_json("noise {\"thought\": \"x\", \"final\": {\"verdict\": \"SAFE\"}} noise", allowed)
    assert b["final"]["verdict"] == "SAFE"
    c = _from_json('{"thought": "run the shell", "tool_call": {"name": "shell", "arguments": {}}}', allowed)
    assert c["invented"] is True
    d = _from_native({"tool_calls": [{"function": {"name": "geolocate_ip", "arguments": {"ip": "1.2.3.4"}}}],
                      "content": ""}, allowed)
    assert d["tool_call"]["name"] == "geolocate_ip"
    e = _from_json("completely unhinged prose with no json", allowed)
    assert e is None, "unparseable model output must fall through to the deterministic engine"


def test_cli_entry_and_selftest():
    from cybersecurity_agent.cli import build_parser, main

    args = build_parser().parse_args(["investigate", "samples/x.eml", "--demo"])
    assert args.eml == "samples/x.eml" and args.demo
    with pytest.raises(SystemExit):
        build_parser().parse_args(["chain"])           # action is required
    assert main(["selftest"]) == 0


def test_closing_custody_check_detects_mid_case_mutation(tmp_path, monkeypatch):
    """The .eml must still match what we hashed when the verdict is written; if it
    changed (editor, sync client, AV quarantine), confidence is capped and the report
    says so — we never silently describe a file that no longer exists."""
    import shutil

    import json as _json

    from cybersecurity_agent.agent import Agent

    src = SAMPLES / "phishing_obvious.eml"
    work = tmp_path / "case.eml"
    shutil.copyfile(src, work)
    a = Agent(work, demo=True, no_llm=True, case_prefix=tmp_path,
              cfg_overrides={"offline": True, "tool_timeout_s": 8.0, "require_confirmation": False,
                             "auto_confirm": True, "max_agent_steps": 12})
    v = a.run()
    assert a.ctx.evidence_hashes["source"] == _json.loads(
        (Path(v["run_json"]).parent / "evidence.json").read_text())["records"][0]["sha256"]

    parsed = a.ctx.parsed
    work.write_bytes(work.read_bytes() + b"\nX-Injected: attacker edited the file after we hashed it\n")
    v2 = a._finalize(parsed, a.ctx.evidence_hashes["source"], work.read_bytes())
    assert v2["confidence"] <= a.cfg.integrity_confidence_cap
    assert any(s.factor == "evidence_integrity_failure" for s in a.state.signals)
    assert any("chain-of-custody" in g for g in v2["gaps"])
    # and the *report writer* surfaces it (not only the JSON): re-render with the
    # tampered close-out verdict and check the call-out is in the human-readable file.
    from cybersecurity_agent.evidence.transcript import render
    md = render(a._case_meta(a.ctx.evidence_hashes["source"]), a.events, a.results, v2,
                {"backend": "hashchain", "file": "n/a"})
    assert "chain-of-custody broken" in md
    a.close()


def test_a_planner_that_only_proposes_done_work_ends_the_loop(tmp_path, monkeypatch):
    """Three 'skipped' answers in a row = the model is stalling on already-completed steps,
    so the loop must close the pipeline and say why.

    This path once incremented a counter that was never initialised, which turned a
    boring stall into a NameError inside the controller. Found by `ruff check --select
    F821` in CI; this test is why it stays fixed rather than just patched.
    """
    from cybersecurity_agent.agent import Agent

    a = Agent(SAMPLES / "clean_newsletter.eml", demo=True, case_prefix=tmp_path,
              cfg_overrides={"offline": True, "tool_timeout_s": 8.0, "max_agent_steps": 12,
                             "require_confirmation": False, "auto_confirm": True})

    def fake_step(name, args, *, thought="", confirm_requested=False):     # noqa: ARG001
        a.results.append({"tool": name, "ok": True, "skipped": True, "summary": "nothing left here",
                          "signals": [], "elapsed_ms": 1})

    class StallEngine:
        is_llm = True
        name = "stub"

        def probe(self, log=lambda s: None):
            return True, "stub"

        def prime(self, digest, block):
            pass

        def observe(self, tool, obs, risk_line):
            pass

        def next_action(self, ctx, history):                                # noqa: ARG002
            return {"thought": "let me re-run what is already done",
                    "tool_call": {"name": "parse_headers", "arguments": {}}}

        def summarize(self, prompt):
            return "stub narrative"

    monkeypatch.setattr(a, "_run_step", fake_step)
    a._select_brain = lambda: ("ollama:stub", "stubbed transport")
    a.engine = StallEngine()
    v = a.run()                                                             # must not raise
    a.close()
    assert any("already-completed steps" in str(e.get("text", "")) for e in a.events), \
        "the stall must be recorded as a decision, not swallowed"
    assert v["verdict"] in {"SAFE", "SUSPICIOUS"}
