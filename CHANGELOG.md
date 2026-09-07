# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The versioned contract of this project is small on purpose: **the flags, the artifact set in
`runs/<case>/`, and the exit codes** (`0` SAFE · `1` SUSPICIOUS · `2` MALICIOUS). Risk scores and
confidence numbers are measurements of the corpus, not an API — they may move when weights,
thresholds or coverage change, and the end-to-end tests are what notice.

## 1.0.0 — 2026-09-07

Everything the README describes, as measured in this repository. First public shape.

### Added

- **Agent core** — `THINK → CHOOSE → ACT → OBSERVE` loop, ≤ 14 steps, 9 whitelisted tools reached
  only through `tools/dispatch.py` (whitelist, `needs`, 15 s hard timeout, human gate), risk fusion
  in `risk.py`, verdict thresholds `30` SUSPICIOUS and `65` + one strong indicator MALICIOUS.
- **Three brains, one contract** — local Ollama tool-calling, and a deterministic planner that is
  labelled *LLM OFFLINE* in the UI and the report instead of pretending to be a model.
- **Email forensics** — Received-hop chain with hop numbering and folded headers, SPF/DKIM/DMARC
  verdicts, `client-ip=` extraction for webmail, Message-ID hostname rDNS, lure-domain and L3
  trace, Tor DNSEL + optional cached exitlist, URL/defanging and homoglyph analysis, attachment
  hashing, entropy and OLE/PDF/PE structure via a static-only scanner.
- **Gmail/webmail honesty path** — when the composing client's address is not in the headers, the
  case is *degraded on purpose*: origin ceiling by source kind (`82 / 78 / 62 / 34 / 0`), provenance
  multipliers (`resolved 1.00 · fallback 0.82 · degraded 0.68 · none 0.45`), and confidence caps
  `35 / 58 / 68 %`.
- **Human gate + kill-switch** — `CONFIRM_NEEDED` panel for file-touching tools, silence or a
  non-affirmative answer denies and is recorded, `x` aborts the run and tears the sandbox down.
- **Sandbox** — Docker with `--network none`, read-only mount, `--cap-drop ALL`, tmpfs, resource
  limits, `--rm`; `--sandbox require` makes missing Docker a refusal; without Docker the same
  scanner runs in an rlimit subprocess and says so.
- **Custody** — source hashed before analysis, `report.md` / `run.json` / `evidence.json` /
  `audit.log` per case, append-only hash chain with a `HEAD.json`, `chain verify`, an optional
  Ganache contract mirror (metadata only, 12 s bound, non-fatal), and an `anchor` command to publish
  the head hash somewhere outside this machine.
- **Display surface** — `rich` live frame with risk + coverage bars, an ASCII work-status cat with
  17 moods and 5 skins, care reminders (20/30/45 min, opt-in), and `runs/<case>/status.jsonl` for an
  external companion. Inert by construction: constant frames, a closed note vocabulary, case ids only
  as a 10-hex digest, and `--no-pet --no-status-hook` proven not to move a verdict.
- **Docs, diagrams and their guard** — README, `docs/ARCHITECTURE.md`, `docs/FORENSIC_METHODOLOGY.md`,
  colour-coded Mermaid sources in `docs/diagrams/`, `DEMO.md`, and
  `tests/test_docs_are_honest.py`, which fails when a documented count, flag, env var or diagram copy
  stops matching the code.
- **Tooling** — `scripts/setup.sh`, `scripts/generate_samples.py`, `scripts/compile_contract.sh`,
  `scripts/demo.sh` (guided 8-step tour, self-checking, `--quick`), `selftest` (7 safety checks),
  `mock-apis` for offline GeoIP/reputation shapes, and CI that runs suite + selftest + demo on
  Python 3.10/3.11/3.12.

### Changed

- DNS in demos and CI is hermetic: `SENTINEL_DNS_STRICT=1` makes the fixture file the whole DNS
  universe, and a fixture entry may now be `[]` (exists, no record) or `NXDOMAIN`/`NODATA`
  (asserted non-existent) instead of only a list of answers. A blocklist we never reached is
  reported as *unavailable*, never as *not listed*.
- Case directories are unique per run: two investigations of the same file in the same second get
  `-2`, `-3`, so no run can overwrite another's evidence.
- The live frame de-duplicates a repeated care line, and the care caption says `break due now`
  instead of `next in 0 min`.

### Fixed

- `_agent_loop` incremented an uninitialised `dedup_strikes` counter, so three consecutive
  "already done, skipped" tool answers raised `NameError` inside the controller instead of closing
  the pipeline. Found by `ruff check --select F821`; regression-tested in
  `test_a_planner_that_only_proposes_done_work_ends_the_loop`.
- `tools/dispatch.py` defined `describe_tools()` and `ollama_tool_schemas()` twice (the second pair
  shadowed the first); the duplicates are gone (`ruff` `F811`).
- `tools/base.py` annotated `switch: Optional[KillSwitch]` without importing the type — fine at
  runtime under `from __future__ import annotations`, wrong for any type checker.
- `investigate --json` writes its summary *after* the live UI on the same stdout, which makes
  `… --json | jq` unusable. Documented, and the demo and tests read `runs/<case>/run.json`
  instead of trying to parse the pipe.

### Known limitations

README §15 is the honest list. The short version: static analysis only (no detonation), GeoIP is
registration data not geography, Tor hides origins by design, no AV engine, YARA/oletools/exiftool
branches depend on optional tooling, the on-chain mirror is unproven against a public chain, and a
`0`/`1`/`2` verdict is an input to a human decision, never the decision.
