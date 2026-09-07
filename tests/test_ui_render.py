"""The brief asks for a live terminal UI with *progress bars* — these tests pin that
the gauge is a real bar (monotone, threshold-marked) and that it survives the non-TTY
demo/CI path, where `rich` Live is not available."""
from __future__ import annotations

from cybersecurity_agent.risk import severity_bar
from cybersecurity_agent.ui.console import ConsoleUI, gauge_string


def _reached(bar: str) -> int:
    """Cells the score has reached — including a cell that is also a threshold marker,
    because `┼` means 'the bar is at or past this floor'."""
    return bar.count("█") + bar.count("┼")


def _filled(bar: str) -> int:
    return bar.count("█")


def test_risk_bar_is_monotone_and_bounded():
    widths = [_reached(severity_bar(s)) for s in (0, 10, 30, 45, 65, 90, 100)]
    assert widths == sorted(widths), "the bar must never shrink as risk rises"
    assert widths[0] == 0 and _reached(severity_bar(100.0)) == 26
    assert _reached(severity_bar(-5)) == 0 and _reached(severity_bar(1e9)) == 26, "clamp both ends"
    assert len(severity_bar(50, width=13)) == 13
    assert severity_bar(100.0, width=20).count("░") == 0, "a 100 score leaves no empty cell"


def test_risk_bar_marks_the_verdict_thresholds():
    """A reader of a plain log must be able to see how close a case was to flipping
    verdict, so the 30/65 floors are drawn into the bar."""
    assert severity_bar(5.0) == severity_bar(5.0).replace("┼", "·"), "neither floor reached"
    assert severity_bar(5.0).count("·") == 2 and severity_bar(5.0).count("┼") == 0
    mid = severity_bar(40.0)
    assert mid.count("┼") == 1 and mid.count("·") == 1, "30 floor passed, 65 floor still ahead"
    assert severity_bar(64.9).count("┼") == 1 and severity_bar(65.0).count("┼") == 2, \
        "the marker flips exactly at the MALICIOUS floor"


def test_coverage_bar_fraction():
    assert _filled(gauge_string(0.0, width=20)) == 0
    assert _filled(gauge_string(1.0, width=20)) == 20
    assert _filled(gauge_string(6 / 9, width=18)) == 12


def test_quiet_mode_still_prints_a_moving_bar(capsys):
    """Non-TTY (--demo / CI) used to print only a number; the gauge must be there too,
    otherwise the honesty claim 'same content, linear log' is false."""
    ui = ConsoleUI(quiet=True, case_name="t")
    ui.set_expected(8)
    ui.record_step(tool="parse_headers", status="✓", summary="12 hops", delta="+1.0", ms="2ms")
    ui.update_scores(risk=33.1, confidence=72.4)
    out = capsys.readouterr().out
    assert "gauge" in out and "█" in out and "░" in out
    assert "33.1/100" in out and "conf 72.4%" in out and "tools 1/8" in out


def test_live_frame_renders_without_rich_or_tty(capsys):
    """_frame() is only called under Live, but a broken panel would hang the demo, so
    assert it builds for a mid-run state including the origin panel."""
    ui = ConsoleUI(quiet=False, case_name="t")
    ui.set_expected(8)
    ui.update_scores(risk=66.0, confidence=80.0)
    ui.set_origin(["origin=203.0.113.66 kind=spf_client_ip ceiling=78%"])
    frame = ui._frame()
    assert frame is not None, "frame must build even outside a TTY"
