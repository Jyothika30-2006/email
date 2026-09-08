# Contributing

Thanks for reading this before pushing. This repository is a *forensics* tool, which changes what
"a small improvement" means: a number that moves silently is worse than a bug, because someone will
quote it in a report.

## 30-second setup

```bash
./scripts/setup.sh                       # venv + the two runtime deps + pytest
.venv/bin/python -m cybersecurity_agent selftest
.venv/bin/python -m pytest tests -q
./scripts/demo.sh                          # ~5 s guided tour, exits 0 when every claim holds
```

Nothing here needs Docker, Ollama, an API key or internet access. If a check only passes with one
of those, that is a bug — fix the check.

## The rules the code is built around

1. **The whitelist is the capability set.** A tool that can run a program does not exist; inventing
   one is *recorded as evidence*, not executed (`tools/dispatch.py` is the only exec path).
2. **Terminal only.** No dashboard, no web framework, no browser route, no cloud LLM. `rich` in a
   tty is the UI. Test-proof: `test_no_claim_of_a_web_ui_anywhere_in_the_docs`.
3. **Sandbox by default-deny.** `--network none`, read-only mount, `--cap-drop ALL`, destroyed after
   the run. Missing Docker is a *labelled fallback*, never a silent skip.
4. **Fail closed.** A gate that gets no answer denies; a denied scan stays unobserved; an
   unavailable lookup is never reported as clean.
5. **Timeouts and a kill-switch** on every tool call (`SENTINEL_TOOL_TIMEOUT`, `x` in the UI).
6. **The LLM proposes, the harness decides.** The verdict comes from `risk.fuse() + classify()`.
   A model can *describe* a finding, never *grant* one.
7. **Explainable output.** Every signal carries its source, direction, strength and one-line
   explanation, in the report and in `run.json`.

A change that weakens any of these needs a very good reason in the PR description, and a test.

## Adding a tool (the only safe way to add capability)

1. `cybersecurity_agent/tools/<name>.py` — implement `tool_<name>(ctx, args) -> ToolResult`, and
   register with `@register(name, args_spec=…, needs=…, touches_files=…)`.
   `needs` is what keeps the plan honest (a tool cannot run before its inputs exist);
   `touches_files=True` puts it behind the human gate.
2. Add the factor names it can emit to `risk.FACTOR_WEIGHTS` — a signal with no weight is inert,
   and `test_risk_and_geo` will not complain about that, so do not rely on it being noticed.
3. Add it to `agent.EXPECTED_FAMILIES` if it belongs to the required evidence set (that changes
   coverage and therefore confidence — measure, do not guess).
4. Tests: one that it works, one that `dispatch` refuses it when `needs` are unmet, one that the
   gate blocks it without approval, one for its timeout.

## Documentation numbers

If you write a number into a doc (`145 tests`, `2 676 lines`, `15 s`, `cap 68 %`, `17 moods`,
`≈9.3k lines`), run the command that measures it, in this checkout, at that moment.
`tests/test_docs_are_honest.py` checks the counts, the diagram copies, the documented flags and the
documented env vars against the code, and it fails on a stale per-file test count too. When it
fails, the *doc* is usually the bug.

The diagrams are generated artefacts in spirit: edit `docs/diagrams/*.mmd`, then paste the same
text into README and `docs/ARCHITECTURE.md` §0. Colour means trust boundary there — see the legend
in the README. GitHub renders the `mermaid` blocks; there is no build step.

## Style

- Python ≥ 3.10, `from __future__ import annotations`, no new runtime dependency without a
  paragraph of justification in the PR (the current list is `rich` and `dnspython`).
- Line length 120. `ruff check cybersecurity_agent tests` is advisory in CI;
  `--select F821,F811,E9` gates it, and it has already caught two real bugs here — run it locally.
- Comments explain *why*, and are welcome to be opinionated. Do not delete a comment that records a
  decision unless you are reversing the decision in the same commit.

## Pull requests

Use the template. The short version: link the issue, show the measured output, say what you
deliberately did not do, and make the commit message a sentence a future reader would want.

One commit per claim is a good size. `git commit -m "fix"` is not.

## Adding a sample to `samples/`

Fabricated only (documentation IP ranges, no real addresses, EICAR or nothing as a payload), and
regenerate `samples/README.md` + run `./scripts/generate_samples.py` so the corpus stays
reproducible. Every sample needs an expectation in `test_agent_end_to_end.py` — verdict *and*
exit code, because the exit code is the contract for shell use.
