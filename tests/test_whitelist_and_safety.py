"""SAFETY #1 (whitelist), #5 (hard timeout), #8 (kill-switch), #4 (fail-closed gate)."""
from __future__ import annotations

import time

import pytest


def test_registry_contains_exactly_the_designed_tools():
    from cybersecurity_agent.tools import REGISTRY

    for name in ("parse_headers", "resolve_origin", "geolocate_ip", "check_tor_exit",
                 "extract_urls", "check_reputation", "static_file_scan", "hash_evidence"):
        assert name in REGISTRY, f"design doc tool {name} must exist"
    assert "static_file_scan" in REGISTRY and REGISTRY["static_file_scan"].file_touching


def test_no_execution_tool_exists_anywhere():
    """There must be no tool that takes a command/shell argument at all."""
    from cybersecurity_agent.tools import REGISTRY

    for tool in REGISTRY.values():
        props = tool.parameters.get("properties", {})
        for key in props:
            assert key not in {"cmd", "command", "shell", "script", "url_target"}
        assert not any(bad in tool.name for bad in ("exec", "shell", "system", "run"))


@pytest.mark.parametrize("name", ["shell", "exec", "bash", "docker_exec", "run_command", "rm", "eval"])
def test_forbidden_action_names_are_refused(name):
    from cybersecurity_agent.tools import WhitelistViolation, validate_call

    with pytest.raises(WhitelistViolation):
        validate_call(name, {})


def test_invented_tool_is_refused_and_unknown_args_dropped():
    from cybersecurity_agent.tools import WhitelistViolation, validate_call

    with pytest.raises(WhitelistViolation):
        validate_call("read_the_attachment_with_a_text_editor", {})
    clean, args = validate_call("geolocate_ip", {"ip": "203.0.113.66", "sudo": True})
    assert clean == "geolocate_ip" and "sudo" not in args and args["_dropped_args"] == ["sudo"]


def test_dispatch_refusal_becomes_an_evidence_signal(tmp_path):
    """An agent trying to escape its whitelist is itself a finding (rule 2)."""
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.tools import ToolContext, dispatch

    cfg = load_config(offline=True, tool_timeout_s=2.0)
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml",
                      raw_bytes=b"From: a@b.c\n\nhi", parsed=None)
    res = dispatch(ctx, "execute_attachment", {"path": "/etc/passwd"})
    assert res.ok is False and res.skipped
    assert any(s.factor == "invented_tool_request" for s in res.signals)


def test_prerequisite_ordering_is_enforced(tmp_path):
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.tools import ToolContext, ToolDef, dispatch, register

    cfg = load_config(offline=True, tool_timeout_s=2.0)
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml", raw_bytes=b"", parsed=None)
    reg = dict(register.__globals__["REGISTRY"])
    reg.setdefault("needs_a_first_step", ToolDef(name="needs_a_first_step", fn=lambda c, a: None,
                                                 description="x", parameters={"type": "object", "properties": {}},
                                                 needs=("parse_headers",)))
    from cybersecurity_agent.tools.base import REGISTRY as LIVE

    LIVE["needs_a_first_step"] = reg["needs_a_first_step"]
    try:
        res = dispatch(ctx, "needs_a_first_step", {})
        assert res.skipped and "parse_headers" in res.error
    finally:
        LIVE.pop("needs_a_first_step", None)


def test_hard_timeout_kills_a_hanging_tool(tmp_path):
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.tools import ToolContext, ToolDef, dispatch
    from cybersecurity_agent.tools.base import REGISTRY

    cfg = load_config(offline=True, tool_timeout_s=1.0)
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml", raw_bytes=b"", parsed=None)

    def hang(_c, _a):
        time.sleep(30)

    REGISTRY["hang"] = ToolDef(name="hang", fn=hang, description="test", parameters={"type": "object", "properties": {}})
    try:
        started = time.monotonic()
        res = dispatch(ctx, "hang", {})
        assert res.timed_out and res.ok is False
        assert any(s.factor == "tool_timeout" for s in res.signals)
        assert time.monotonic() - started < 5, "timeout must not wait for the sleeping tool"
    finally:
        REGISTRY.pop("hang", None)


def test_kill_switch_aborts_and_runs_teardown():
    from cybersecurity_agent.safety import AbortedError, KillSwitch, run_with_timeout

    calls = []
    sw = KillSwitch(key="x")
    sw.register_teardown(lambda: calls.append("destroyed"))
    assert sw.status == "not armed"
    sw.abort("kill-switch keypress 'x'")
    assert sw.aborted and calls == ["destroyed"]
    with pytest.raises(AbortedError):
        run_with_timeout(lambda: 1, timeout=1.0, switch=sw, label="x")
    assert sw.reason == "kill-switch keypress 'x'"


def test_kill_switch_destroys_sandbox_on_abort(tmp_path):
    """The teardown hook is what guarantees 'agent + sandbox die together'."""
    from cybersecurity_agent.sandbox.docker_runner import _force_destroy
    from cybersecurity_agent.safety import KillSwitch

    sw = KillSwitch(enabled=True)
    sw.register_teardown(lambda: _force_destroy("sentinel-sbx-test"))
    # No docker here: teardown must swallow the error and still mark the abort.
    sw.abort("test")
    assert sw.aborted


def test_human_gate_fail_closed_on_non_affirmative(tmp_path, monkeypatch):
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.tools import ToolContext, ToolDef
    from cybersecurity_agent.tools.base import REGISTRY
    from cybersecurity_agent.tools import dispatch

    cfg = load_config(offline=True, require_confirmation=True, confirmation_timeout_s=1.0, tool_timeout_s=2.0)
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml", raw_bytes=b"", parsed=None,
                      auto_confirm=False)

    def touchy(_c, _a):
        from cybersecurity_agent.tools.base import ToolResult

        return ToolResult(tool="touchy", ok=True, summary="touched")

    REGISTRY["touchy"] = ToolDef(name="touchy", fn=touchy, description="reads files",
                                 parameters={"type": "object", "properties": {}}, file_touching=True)
    try:
        monkeypatch.setattr("sys.stdin", None)          # no tty, no pipe → DENY
        res = dispatch(ctx, "touchy", {})
        assert res.skipped and "denied" in res.summary.lower()
        assert any(s.factor == "human_denied_scan" for s in res.signals)
    finally:
        REGISTRY.pop("touchy", None)


def test_tool_exceptions_never_abort_the_investigation(tmp_path):
    from cybersecurity_agent.config import load_config
    from cybersecurity_agent.tools import ToolContext, ToolDef, dispatch
    from cybersecurity_agent.tools.base import REGISTRY

    cfg = load_config(offline=True, tool_timeout_s=2.0)
    ctx = ToolContext(cfg=cfg, case_dir=tmp_path, eml_path=tmp_path / "x.eml", raw_bytes=b"", parsed=None)

    def boom(_c, _a):
        raise RuntimeError("simulated tool bug")

    REGISTRY["boom"] = ToolDef(name="boom", fn=boom, description="x", parameters={"type": "object", "properties": {}})
    try:
        res = dispatch(ctx, "boom", {})
        assert res.ok is False and "simulated tool bug" in res.error and "crashed" in res.summary
    finally:
        REGISTRY.pop("boom", None)
