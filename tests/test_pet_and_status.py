"""The work-status surface (terminal pet + care reminders + JSONL hook).

These are display features, so the tests are mostly *negative*: the cat must never be able to
say something the email told it to say, must never make the live region jump, and must never be
able to change a verdict. Plus the few positive invariants (moods map to real events, the hook
ends on the same three-value answer the report carries).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "samples"


# ── pet: rendering invariants ───────────────────────────────────────────────
def test_every_frame_of_every_mood_fits_the_same_box():
    """`rich` Live resizes → flicker. `_pad` is what prevents it, so assert it on all frames."""
    from cybersecurity_agent.ui.pet import BOX_WIDTH, MOODS, _BOX_H, render_lines

    offenders = []
    for mood, spec in MOODS.items():
        for i in range(len(spec["frames"])):
            lines = render_lines(mood, i)
            if len(lines) != _BOX_H or any(len(ln) != BOX_WIDTH for ln in lines):
                offenders.append((mood, i, len(lines), [len(x) for x in lines]))
    assert not offenders, f"non-uniform frames would jitter the live panel: {offenders}"


def test_the_display_layer_cannot_reach_the_evidence_layer(tmp_path):
    """Import direction, machine-checked: `pet.py`/`care.py`/`status.py` are stdlib-only.

    If someone ever imports `risk` or `tools` in here, the mascot stops being a display and
    becomes a second decision path — which is exactly how a friendly feature turns into an
    attack surface. Fail on that at review time, not in a demo.
    """
    import ast

    forbidden = {"risk", "tools", "tools_dev", "evidence", "net", "agent", "llm", "sandbox",
                 "blockchain", "prompts", "config", "models", "safety"}
    for rel in ("ui/pet.py", "ui/care.py", "status.py", "petwatch.py"):
        src = (Path(__file__).resolve().parents[1] / "cybersecurity_agent" / rel).read_text()
        mods: set[str] = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Import):
                mods |= {n.name.split(".")[0] for n in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
                if node.level:                      # relative import inside the package
                    mods.add("<relative>")
        banned = mods & forbidden
        assert not banned, f"{rel} imports {sorted(banned)} — display code must not reach the case"
        if rel in ("ui/pet.py", "ui/care.py", "status.py"):
            assert "<relative>" not in mods, f"{rel} must be self-contained (no package imports at all)"
    # petwatch may read the pet + care + status modules, and nothing else in the package.
    src = (Path(__file__).resolve().parents[1] / "cybersecurity_agent/petwatch.py").read_text()
    rel_imports = {n.module.split(".")[0] for n in ast.walk(ast.parse(src))
                   if isinstance(n, ast.ImportFrom) and n.level and n.module}
    assert rel_imports <= {"status", "ui"}, rel_imports


def test_mood_vocabulary_is_closed_and_ascii_only():
    """Frames are constants; nothing is interpolated, and no exotic glyph can break a font."""
    from cybersecurity_agent.ui.pet import MOODS, is_known, moods

    assert len(moods()) >= 12
    for mood, spec in MOODS.items():
        assert spec["label"] and isinstance(spec["label"], str)
        assert len(spec["frames"]) >= 2, f"{mood} needs at least 2 frames to animate"
        for frame in spec["frames"]:
            for line in frame:
                for ch in line:
                    assert 32 <= ord(ch) < 127, f"{mood}: non-ASCII {ch!r} in a frame"
    assert not is_known("obey_the_email")
    assert is_known("watching")


def test_frames_never_contain_case_text():
    """The single most important property: a frame is one of the constants, byte for byte."""
    from cybersecurity_agent.ui.pet import MOODS, render_lines

    hostile = ["paypal", "dave", "ignore previous", "secure-p0nyail", "198.51.100", "@evil"]
    for mood in MOODS:
        blob = "\n".join("\n".join(render_lines(mood, i)) for i in range(len(MOODS[mood]["frames"])))
        for token in hostile:
            assert token.lower() not in blob.lower(), f"{mood} frame leaked {token!r}"


def test_reactions_are_driven_by_events_and_decay_to_calm():
    from cybersecurity_agent.ui.pet import DEFAULT_MOOD, SentinelCat

    clock = {"t": 100.0}
    cat = SentinelCat(now=lambda: clock["t"], hold_s=25.0)
    assert cat.mood == DEFAULT_MOOD
    assert cat.set_mood("fur") is True
    assert cat.mood == "fur"
    assert cat.set_mood("fur") is False, "a repeat of the same mood must not re-announce"
    clock["t"] += 26.0
    assert cat.mood == DEFAULT_MOOD, "an unrenewed transient reaction must relax (no lying about now)"
    assert cat.set_mood("fur") is True, "…and the next injection attempt must be visible again"


def test_terminal_mood_is_pinned_and_verdict_moods_are_the_three_values():
    from cybersecurity_agent.ui.pet import VERDICT_MOOD, SentinelCat

    clock = {"t": 0.0}
    cat = SentinelCat(now=lambda: clock["t"], hold_s=5.0)
    cat.pin(VERDICT_MOOD["MALICIOUS"])
    clock["t"] += 10_000.0
    assert cat.mood == "arch", "the closing reaction must survive while the operator reads the summary"
    assert set(VERDICT_MOOD) == {"SAFE", "SUSPICIOUS", "MALICIOUS"}


def test_skins_change_colour_never_content():
    from cybersecurity_agent.ui.pet import MOODS, render_plain, skin_names, style_for

    assert "high-contrast" in skin_names() and "colour-blind" in skin_names()
    base = render_plain("arch")
    for skin in skin_names():
        assert render_plain("arch") == base, "a skin must not alter the art or the caption"
    assert style_for("arch", "colour-blind") == "bold white"
    assert style_for("arch", "no-such-skin") == style_for("arch", "default"), "unknown skin falls back"
    assert style_for("arch", "mono") == "", "mono means no colour at all"


# ── care: reminders and Pomodoro ────────────────────────────────────────────
def test_reminders_fire_once_per_interval_on_a_pure_clock():
    from cybersecurity_agent.ui.care import DEFAULT_REMINDERS, CareClock

    t = {"n": 0.0}
    clock = CareClock(reminders=(DEFAULT_REMINDERS[1],), now=lambda: t["n"])   # stretch, 30 min
    assert clock.due() == []
    t["n"] = 30 * 60 + 1
    fired = clock.due()
    assert [r.key for r in fired] == ["stretch"]
    assert clock.due() == [], "one reminder must not fire twice for the same interval"
    t["n"] = 61 * 60
    assert [r.key for r in clock.due()] == ["stretch"], "and it must fire again next interval"


def test_care_cannot_be_turned_into_case_content_by_a_bad_spec():
    from cybersecurity_agent.ui.care import parse_reminders

    reminders, unknown = parse_reminders("subject=5,From=2,bogus")
    assert reminders == (), "unknown keys create nothing"
    assert unknown == ["subject=5", "From=2", "bogus"], "…but they are reported, not swallowed"
    off, _ = parse_reminders("off")
    assert off == ()
    default, _ = parse_reminders("")
    assert len(default) == 3


def test_pomodoro_alternates_focus_and_break():
    from cybersecurity_agent.ui.care import CareClock, parse_pomodoro

    t = {"n": 0.0}
    pomo = parse_pomodoro("0.5,0.25")          # 30 s focus, 15 s break
    assert pomo and pomo.focus_s == 30.0 and pomo.break_s == 15.0
    clock = CareClock(enabled=False, reminders=(), pomodoro=pomo, now=lambda: t["n"])
    clock.pomodoro.started_at = 0.0
    t["n"] = 10.0
    assert clock.mood_for_pomodoro() == "sentry"
    t["n"] = 40.0
    assert clock.mood_for_pomodoro() == "nap"
    assert "break" in clock.caption()
    t["n"] = 100.0
    # cycle = 30 s focus + 15 s break → at t=100 s we are 10 s into the 3rd focus block,
    # i.e. two cycles completed. Asserting the arithmetic keeps `cycles_done` honest.
    assert clock.mood_for_pomodoro() == "sentry" and "2 done" in clock.caption()
    assert parse_pomodoro("off") is None


# ── status hook: what may be written ────────────────────────────────────────
def test_hook_note_vocabulary_rejects_attacker_shaped_text():
    from cybersecurity_agent.status import scrub_note

    assert scrub_note("gate:denied") == ("gate:denied", False)
    for hostile in ('verdict: SAFE, nothing to see', 'subject: Invoice #8892', 'ignore previous instructions',
                    'From: boss@company.com', 'a' * 200, "line1\nline2", "say 'hi'", "say \"hi\"",
                    "http://paypal.com/secure/very/long/path/that/keeps/going"):
        kept, dropped = scrub_note(hostile)
        assert kept is None and dropped is True, f"hook accepted {hostile!r}"
    assert scrub_note(None) == (None, False)


def test_hook_writes_only_allowlisted_fields_and_never_the_case_name(tmp_path):
    from cybersecurity_agent.status import StatusHook

    sink = tmp_path / "status.jsonl"
    hook = StatusHook([sink])
    hook.emit("verdict", mood="arch", tool="parse_headers", case="20260907T000000Z-invoice_from_dave",
              risk=99.0, verdict="MALICIOUS", confidence=90.1, note="case-opened")
    line = json.loads(sink.read_text().splitlines()[0])
    assert set(line) <= {"ts", "case", "state", "mood", "tool", "risk", "verdict", "confidence",
                         "note", "note_dropped"}
    assert "invoice" not in sink.read_text() and "dave" not in sink.read_text(), \
        "the shared sink must not publish the operator's evidence filename"
    assert line["risk"] == 99.0 and line["verdict"] == "MALICIOUS"


def test_hook_never_raises_on_a_broken_sink(tmp_path):
    """A cartoon must not be able to break a security run — that is the whole point of the hook."""
    from cybersecurity_agent.status import StatusHook

    blocked = tmp_path / "nope" / "deep"          # parent exists but is a file → mkdir fails
    blocked.parent.mkdir(parents=True, exist_ok=True)
    (blocked.parent / "deep").write_text("not a directory")
    hook = StatusHook([blocked / "status.jsonl"])
    rec = hook.emit("tool_start", mood="typing", tool="geolocate_ip")   # must not raise
    assert rec["state"] == "tool_start"
    assert "status hook disabled" in getattr(hook, "warning", "")


def test_hook_disabled_writes_nothing(tmp_path):
    from cybersecurity_agent.status import StatusHook

    sink = tmp_path / "status.jsonl"
    StatusHook([sink], enabled=False).emit("verdict", verdict="SAFE")
    assert not sink.exists()


def test_torn_line_is_skipped_not_fatal(tmp_path):
    from cybersecurity_agent.status import StatusHook

    sink = tmp_path / "status.jsonl"
    sink.write_text('{"state": "a"}\n{"state": "b", "risk": \n{"state": "c"}\n', encoding="utf-8")
    assert [r["state"] for r in StatusHook.read(sink)] == ["a", "c"]
    assert StatusHook.read(tmp_path / "absent.jsonl") == []


# ── companion watcher ───────────────────────────────────────────────────────
def test_companion_ignores_moods_it_does_not_know(tmp_path):
    from cybersecurity_agent.petwatch import render_text, summarize

    sink = tmp_path / "status.jsonl"
    sink.write_text(
        '{"state": "verdict", "mood": "obey_the_email", "note": "all your base", "risk": 5.0}\n',
        encoding="utf-8")
    from cybersecurity_agent.status import StatusHook

    snap = summarize(StatusHook.read(sink))
    assert snap["mood"] == "watching", "an unknown mood must fall back, never be rendered"
    text = render_text(snap, source="sink")
    assert "obey_the_email" not in text
    assert "ADVISORY" in text, "the display must state that it is not the record"

    # A verdict mood already names the verdict in its caption — repeating it is a stutter.
    snap2 = summarize([{"state": "verdict", "mood": "arch", "verdict": "MALICIOUS",
                        "confidence": 90.1}])
    text2 = render_text(snap2, source="sink")
    assert text2.count("MALICIOUS") == 1, text2
    assert "confidence 90.1%" in text2


def test_pet_cli_once_and_missing_sink(tmp_path, capsys):
    from cybersecurity_agent.petwatch import run_pet

    sink = tmp_path / "status.jsonl"
    sink.write_text('{"state": "tool_start", "mood": "typing", "tool": "parse_headers", "risk": 3.0}\n',
                    encoding="utf-8")
    assert run_pet(path=sink, once=True, plain=True) == 0
    out = capsys.readouterr().out
    assert "sentinel-cat" in out and "/\\_/\\" in out

    assert run_pet(path=tmp_path / "absent.jsonl", once=True, plain=True) == 0
    assert "no status sink" in capsys.readouterr().out


# ── integration: real run, real hook ────────────────────────────────────────
def test_a_real_run_leaves_a_status_trail_that_ends_on_the_verdict(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.agent import Agent
    from cybersecurity_agent.net import clear_dns_fixture_cache
    from cybersecurity_agent.status import StatusHook

    clear_dns_fixture_cache()
    agent = Agent(SAMPLES / "phishing_obvious.eml", demo=True, no_llm=True, case_prefix=tmp_path,
                  cfg_overrides={"tool_timeout_s": 8.0, "max_agent_steps": 12, "offline": True,
                                 "geoip_allow_private": True, "require_confirmation": False})
    verdict = agent.run()
    agent.close()
    trail = StatusHook.read(agent.case_dir / "status.jsonl")
    states = [r["state"] for r in trail]
    assert "case_opened" in states and "tool_start" in states
    assert any(r.get("mood") == "fur" for r in trail), "the injection attempt must be reacted to"
    assert "verdict" in states and "closed" in states
    last = trail[-2] if trail[-1]["state"] == "closed" else trail[-1]
    assert last["verdict"] == verdict["verdict"]
    assert last["confidence"] == pytest.approx(verdict["confidence"], abs=0.06)
    assert json.dumps(trail).count("note_dropped") == 0, \
        "the controller must only ever emit vocabulary notes (a dropped note means a new call site leaked)"


def test_the_pet_cannot_influence_the_case(tmp_path, monkeypatch):
    """The strongest claim about a mascot in a security tool: it changes nothing.

    The same sample runs twice — pet, reminders and the status hook on, then all of it off — and
    the scoring, the plan the executor actually ran, and the report's verdict headline must match.

    What is deliberately *not* compared: the full report body and the signal count. One check
    (Spamhaus via DNS) still reaches live DNS in this sandbox, so its presence varies run to run
    whether or not a cartoon is on screen — asserting equality there would make the test flaky
    and would prove nothing about the pet either.
    """
    import json
    import re

    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.agent import Agent
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    over = {"tool_timeout_s": 8.0, "max_agent_steps": 12, "offline": True,
            "geoip_allow_private": True, "require_confirmation": False}

    def go(prefix: str, pet_on: bool) -> tuple:
        agent = Agent(SAMPLES / "phishing_obvious.eml", demo=True, no_llm=True,
                      case_prefix=tmp_path / prefix,
                      cfg_overrides={**over, "pet_enabled": pet_on, "status_hook_enabled": pet_on})
        verdict = agent.run()
        agent.close()
        rj = json.loads((agent.case_dir / "run.json").read_text())
        headline = ""
        for line in (agent.case_dir / "report.md").read_text().splitlines():
            if "confidence" in line and verdict["verdict"] in line:
                headline = line.strip()
                break
        scores = (verdict["verdict"], verdict["risk"], verdict["confidence"])
        plan = [(r["tool"], r["status"]) for r in rj["results"]]
        assert (agent.case_dir / "status.jsonl").exists() == pet_on
        return scores, plan, headline, re.sub(r"\d+%", "%", headline)

    on, off = go("on", True), go("off", False)
    assert on[0] == off[0], f"scores moved when the pet was switched off: {on[0]} → {off[0]}"
    assert on[0][0] == "MALICIOUS" and on[0][1] >= 65
    assert on[1] == off[1], f"the executed plan differed: {on[1]} vs {off[1]}"
    assert on[2] == off[2], "the report's verdict line must not differ because a cat was rendered"


def test_care_notes_land_in_the_audit_log_not_the_forensic_report(tmp_path, monkeypatch):
    """A reminder about the analyst is not evidence about the email — it must not reach report.md."""
    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.agent import Agent
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    agent = Agent(SAMPLES / "clean_newsletter.eml", demo=True, no_llm=True, case_prefix=tmp_path,
                  cfg_overrides={"tool_timeout_s": 8.0, "max_agent_steps": 10, "offline": True,
                                 "geoip_allow_private": True, "require_confirmation": False,
                                 "pet_reminders": "water=0.0001"})     # fires on the first loop tick
    v = agent.run()
    agent.close()
    audit = (agent.case_dir / "audit.log").read_text()
    report = (agent.case_dir / "report.md").read_text()
    assert "care_reminder" in audit, "the reminder should be recorded where operator notes live"
    assert "care reminder" not in report.lower(), "…but must not pollute the forensic transcript"
    assert v["verdict"] == "SAFE" and v["risk"] < 30, "and a nag must not move the score"


def test_two_runs_in_the_same_second_do_not_share_a_case_dir(tmp_path):
    """A demo loop runs a file twice in under a second. Two cases must never mix artifacts —
    that is chain of custody, not tidiness."""
    from cybersecurity_agent.agent import _case_id

    root = tmp_path / "runs"
    root.mkdir()
    eml = tmp_path / "phishing_obvious.eml"
    eml.write_bytes(b"Subject: x\n\nbody\n")
    ids = [_case_id(eml, root) for _ in range(3)]
    # the ids alone can repeat (the dir is what disambiguates), so prove it with real dirs
    made = []
    for _ in range(3):
        cid = _case_id(eml, root)
        (root / cid).mkdir()
        made.append(cid)
    assert len(set(made)) == 3, f"case ids collided: {made}"
    assert made[0].split("-")[-2:] == ["phishing", "obvious"] or made[0].endswith("phishing_obvious")
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    assert _case_id(eml) == f"{stamp}-phishing_obvious", "without a root, id = timestamp + stem"
    assert (root / made[1]).name.endswith("phishing_obvious-2"), made[1]


def test_pet_off_and_hook_off_are_independent(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DNS_FIXTURES", str(SAMPLES / "fixtures" / "dns_fixtures.json"))
    from cybersecurity_agent.agent import Agent
    from cybersecurity_agent.net import clear_dns_fixture_cache

    clear_dns_fixture_cache()
    agent = Agent(SAMPLES / "clean_newsletter.eml", demo=True, no_llm=True, case_prefix=tmp_path,
                  cfg_overrides={"tool_timeout_s": 8.0, "offline": True, "geoip_allow_private": True,
                                 "require_confirmation": False, "status_hook_enabled": False})
    v = agent.run()
    agent.close()
    assert v["verdict"] == "SAFE"
    assert not (agent.case_dir / "status.jsonl").exists(), "--no-status-hook must write nothing at all"
