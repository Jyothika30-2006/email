"""Docs-vs-code consistency, enforced.

Every number a README can advertise is also a number a maintainer can forget: the tool
count, the mood count, the test count, a flag renamed in `cli.py` and left documented
three files away. A stale doc in a forensics project is worse than a missing one, because
it reads like a measurement. So these tests compare the documentation to the thing it
describes, and nothing else here needs to be believed.

Rules for anyone who trips on these:

* fix the *document*, unless the document caught a real bug — then fix the code;
* the diagram copies in README/ARCHITECTURE are generated from `docs/diagrams/*.mmd`,
  so edit the source and re-copy, never the other way around.
"""
from __future__ import annotations

import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
ARCH = REPO / "docs" / "ARCHITECTURE.md"
DIAGRAMS = REPO / "docs" / "diagrams"


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────
def _norm(text: str) -> str:
    """Line-ending/trailing-space insensitive, so a reflow never fails a copy check."""
    return "\n".join(line.rstrip() for line in text.strip().splitlines()).strip()


def _mermaid_blocks(md: Path) -> list[str]:
    body = md.read_text(encoding="utf-8")
    return [m.group(1) for m in re.finditer(r"```mermaid\n(.*?)```", body, re.S)]


@lru_cache(maxsize=1)
def _collection() -> tuple[int, dict[str, int]]:
    """(total, per-file) test counts, asked of pytest itself.

    A `def test_` grep misses the parametrized cases and under-reports by a handful, so
    the number in the docs is compared against what the runner actually collects — same
    source of truth the CI badge reads.
    """
    out = subprocess.run(
        [sys.executable, "-m", "pytest", str(REPO / "tests"), "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    per_file = {f"tests/{m.group(1)}.py": int(m.group(2))
                for m in re.finditer(r"^tests/([a-z_0-9]+)\.py: (\d+)$", out, re.M)}
    if (m := re.search(r"(\d+) tests? collected", out)):
        return int(m.group(1)), per_file
    if per_file:
        return sum(per_file.values()), per_file       # quiet mode lists per-file counts only
    raise AssertionError(f"could not read a collection count out of pytest:\n{out[-400:]}")


def _collected_test_count() -> int:
    return _collection()[0]


@lru_cache(maxsize=1)
def _documented_flags_in_readme() -> set[str]:
    """`--flags` that the README shows *on a command line* for this program.

    Prose mentions and other tools' flags (pip's, setup.sh's) are deliberately out of
    scope: this checks copy-pasteable commands, which is the part that breaks a user.
    """
    flags: set[str] = set()
    body = README.read_text(encoding="utf-8")
    # only shell-labelled fences: an unlabelled ``` block in this README holds prose and
    # terminal output, and a flag mentioned in a sentence is not a documented invocation
    for fence in re.finditer(r"```(?:bash|sh|console)\n(.*?)```", body, re.S):
        chunk = fence.group(1)
        # join shell continuations so a multi-line invocation is read as one command
        for line in re.sub(r"\\\n", " ", chunk).splitlines():
            if "cybersecurity_agent" not in line and "sentinel-ir" not in line:
                continue
            if re.match(r"\s*(docker|podman|pip|npm|npx|git|curl|make|pytest)\b", line):
                continue        # flags belonging to someone else's tool, mentioned next to ours
            if line.lstrip().startswith("#"):
                continue
            flags.update(t for t in re.findall(r"--[a-z][a-z0-9-]*", line))
    return flags


# ─────────────────────────────────────────────────────────────────────────────
# diagrams
# ─────────────────────────────────────────────────────────────────────────────
def test_diagram_sources_exist_and_are_the_only_truth():
    sources = sorted(DIAGRAMS.glob("*.mmd"))
    assert [p.stem for p in sources] == ["architecture", "verdict", "workflow"]
    for p in sources:
        text = p.read_text(encoding="utf-8")
        assert text.lstrip().startswith("%%{init"), f"{p.name}: the init directive must be line 1 or GitHub ignores the theme"
        if text.lstrip().startswith("%%{init") and "flowchart" in text:
            assert "classDef" in text and ":::" in text, f"{p.name}: colour is the point — define classes and use them"
        else:
            # a sequence diagram carries no classDef; it earns its keep by numbering steps
            assert "autonumber" in text, f"{p.name}: a workflow nobody can cite a step number in"


def test_readme_and_architecture_carry_identical_copies():
    """One source, two renderings. A diagram that has been hand-edited in the README is
    the classic way documentation starts lying about architecture."""
    arch_src = _norm((DIAGRAMS / "architecture.mmd").read_text())
    flow_src = _norm((DIAGRAMS / "workflow.mmd").read_text())
    verd_src = _norm((DIAGRAMS / "verdict.mmd").read_text())

    readme_blocks = [_norm(b) for b in _mermaid_blocks(README)]
    arch_blocks = [_norm(b) for b in _mermaid_blocks(ARCH)]

    assert arch_src in readme_blocks, "README's architecture diagram drifted from docs/diagrams/architecture.mmd"
    assert set(readme_blocks) == {arch_src}, "README carries exactly the architecture diagram (the rest live in ARCHITECTURE.md)"
    assert {arch_src, flow_src, verd_src} <= set(arch_blocks), "docs/ARCHITECTURE.md §0 must contain all three diagrams verbatim"


def test_diagrams_describe_the_code_they_claim_to():
    """Numbers inside the pictures, checked against the module that owns them. A pretty
    diagram is worthless if the thresholds it prints are folklore."""
    from cybersecurity_agent import risk
    from cybersecurity_agent.tools import REGISTRY  # noqa: F401  (import registers the tools)
    from cybersecurity_agent.ui import pet

    text = "\n".join(_mermaid_blocks(ARCH) + _mermaid_blocks(README))
    assert f"{len(REGISTRY)} whitelisted tools" in text, "tool count in the diagram is stale"
    assert f"{len(risk.FACTOR_WEIGHTS)} weighted factors" in text, "factor count in the diagram is stale"
    assert f"{len(pet.MOODS)} work-status moods" in text, "mood count in the diagram is stale"

    # thresholds quoted in the verdict diagram vs the code that applies them
    src = (REPO / "cybersecurity_agent" / "risk.py").read_text()
    assert "score >= 65" in src and "score >= 30" in src
    assert "30 = SUSPICIOUS floor" in text and "65 + 1 strong = MALICIOUS" in text
    strong = set(re.search(r"strong = \{(.*?)\}", src, re.S).group(1).replace('"', "").split(","))
    named = {s.strip() for s in strong if s.strip()}
    assert named and named <= set(text.replace("<br/>", " ").replace("·", ",").replace("\n", " ")
                                   .split()), "every strong indicator must be named in the diagram"
    assert len(named) == 10, f"classify() has {len(named)} strong indicators; the diagram says 10"


def test_architecture_legend_colours_match_classdefs():
    """The README legend is the diagram's key. If a class exists with no legend row (or
    vice versa) the picture is unlabelled, which is how colour turns into decoration."""
    legend = README.read_text(encoding="utf-8")
    table = legend.split("| colour | what it means", 1)[1].split("\n\n", 1)[0]
    rows = {w for line in table.splitlines() if line.startswith("|")
            for w in re.findall(r"\b(red|amber|indigo|sky|green|violet|pink|dashed grey)\b", line)}
    classes = set(re.findall(r"classDef (\w+)", (DIAGRAMS / "architecture.mmd").read_text(encoding="utf-8")))
    assert rows >= {"red", "amber", "indigo", "sky", "green", "violet", "pink", "dashed grey"}, rows
    assert len(classes) == len(rows), f"{len(classes)} classes in the picture vs {len(rows)} rows in the legend"


# ─────────────────────────────────────────────────────────────────────────────
# claims a user can act on
# ─────────────────────────────────────────────────────────────────────────────
def test_every_documented_command_line_flag_exists():
    from cybersecurity_agent.cli import build_parser

    known = {a for a in build_parser()._actions}  # noqa: SLF001 — introspecting our own parser
    option_strings = {s for a in known for s in a.option_strings}
    for sub in build_parser()._subparsers._group_actions[0].choices.values():  # noqa: SLF001
        option_strings |= {s for a in sub._actions for s in a.option_strings}  # noqa: SLF001

    missing = _documented_flags_in_readme() - option_strings
    assert not missing, f"README documents flags the CLI does not accept: {sorted(missing)}"
    documented = _documented_flags_in_readme()
    assert {"--yes", "--offline", "--demo", "--no-llm"} <= documented, (
        f"the core documented flags vanished from the README's shell blocks: {sorted(documented)}"
    )


def test_documented_test_count_matches_the_suite():
    n, per_file = _collection()
    for md in (README, ARCH, REPO / "FINAL_REPORT.md", REPO / "DEMO.md"):
        text = md.read_text(encoding="utf-8")
        # per-file claims: "10 tests in `tests/test_agent_end_to_end.py`" — checked first,
        # then blanked out, so they cannot be misread as a claim about the whole suite
        for m in re.finditer(r"(\d+) tests in `tests/([a-z_0-9]+)\.py`", text):
            claimed, fname = int(m.group(1)), f"tests/{m.group(2)}.py"
            assert claimed == per_file.get(fname), f"{md.name} claims {claimed} in {fname}; it collects {per_file.get(fname)}"
        text = re.sub(r"\d+ tests in `tests/[a-z_0-9]+\.py`", "", text)
        # suite-level claims: "143 tests in ~6.4 s", "143 passed in 6.35s", "143 tests (2 537 lines)"
        for m in re.finditer(r"(\d+) tests(?: in| \()|(\d+) passed in", text):
            claimed = int(m.group(1) or m.group(2))
            assert claimed == n, f"{md.name} claims {claimed} tests; pytest collects {n} — re-measure, then fix the docs"
    assert n >= 100, "the suite shrank by more than a refactor should explain"


def test_documented_env_vars_are_real_ones():
    """README tells users to export these; `config/default.env.example` is where they are
    all enumerated. A variable in the README that no code reads is a rumour."""
    documented = set(re.findall(r"\b(SENTINEL_[A-Z0-9_]+|GEOIP_[A-Z0-9_]+|VIRUSTOTAL_API_KEY|ABUSEIPDB_API_KEY|IPINFO_TOKEN)\b",
                                README.read_text(encoding="utf-8")))
    example = (REPO / "config" / "default.env.example").read_text(encoding="utf-8")
    code = "\n".join(p.read_text(encoding="utf-8") for p in REPO.glob("cybersecurity_agent/**/*.py"))
    for var in sorted(documented):
        assert var in example or var in code, f"{var} is documented but appears in neither .env.example nor the code"
    assert "SENTINEL_DNS_STRICT" in example and "SENTINEL_DNS_STRICT" in code


def test_exit_code_contract_is_what_the_readme_says():
    from cybersecurity_agent.cli import build_parser  # noqa: F401  (import side effects)

    src = (REPO / "cybersecurity_agent" / "cli.py").read_text()
    assert '{"MALICIOUS": 2, "SUSPICIOUS": 1, "SAFE": 0}' in src
    readme = README.read_text(encoding="utf-8")
    assert "0" in readme and "SAFE" in readme
    for claim in ("exit 0", "exit 1", "exit 2"):
        assert claim in readme, f"README no longer documents {claim}"


def test_selftest_covers_every_display_surface():
    """The cat and the care clock are the newest things to break quietly, so `selftest`
    is the documented smoke check and must actually mention them."""
    src = (REPO / "cybersecurity_agent" / "cli.py").read_text()
    body = src[src.index("def cmd_selftest"):]
    for needle in ("pet", "status", "care", "whitelist", "timeout", "ledger"):
        assert needle in body.lower(), f"selftest no longer checks the {needle} surface"


def test_no_claim_of_a_web_ui_anywhere_in_the_docs():
    """Rule 2 of this project is 'terminal only'. If someone adds a dashboard, the docs
    have to be updated deliberately, not by accident."""
    negated = re.compile(r"\b(no|never|without|not|refus|declin|deliberately|instead of)\b")
    for md in (README, ARCH, REPO / "FINAL_REPORT.md", REPO / "DEMO.md"):
        text = md.read_text(encoding="utf-8").lower()
        for m in re.finditer(r"\b(dashboard|web ?ui|browser ?ui|web ?app|react|vue|svelte|fastapi|flask|django)\b", text):
            around = text[max(0, m.start() - 150):m.end() + 150]
            assert negated.search(around), (
                f"{md.name} mentions {m.group(0)!r} with no negation in sight — rule 2 says terminal only; "
                f"…{around[-160:]}"
            )
