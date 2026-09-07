# Security

**Read this first:** SENTINEL-IR analyses suspicious email *safely* — static only, sandboxed, no
active content ever executed. It is built for defenders working on their own organisation's mail
and on fabricated training samples. Do not point it at mailboxes or networks you are not authorised
to inspect.

## Reporting a vulnerability

Open a **private vulnerability report** through the Security tab of this repository
(`Advisories → Report a vulnerability`). Do not file a public issue for anything that can be
exploited.

This is a small project with one maintainer: expect a reply within about a week, and expect the
fix to come with a test that would have caught it. Nothing here is covered by an SLA, so please
do not treat a deadline as a promise — and if you would rather not wait, a patch in the advisory
is welcome and will be credited.

If you only have a question about hardening a deployment, a normal issue is fine.

## What counts as a vulnerability here

Anything that lets attacker-controlled text cross a boundary the harness exists to hold:

| class | concrete example | why it matters |
|---|---|---|
| injection escape | attacker text in a `.eml` causes a tool call, a shell argument, or an instruction the agent obeyed | the entire design assumes the input is hostile |
| whitelist bypass | reaching a code path that executes without going through `tools/dispatch.py` | rule 1: the whitelist *is* the capability set |
| sandbox escape | the scanner container gets network, write access, or survives past the run | rule 3: default-deny, destroyed after each run |
| gate bypass | a file-touching tool runs without approval while `require_confirmation` is on, or an approval is not distinguishable from a human one in `audit.log` | rule 4: silence must deny, and auto-approval must be visible |
| fail-open | a timeout, crash or missing key turns into "clean" / "not listed" instead of `unobserved` | a missing answer is never evidence of absence |
| ledger forgery | making `evidence/hashchain.jsonl` verify when a record was altered, or getting a verdict written *before* the custody hash | the log is the thing a court would look at |
| display channel | getting case text, an address, or a verdict-relevant decision into the pet frame, `status.jsonl`, or a companion's reply | the mascot must stay inert — see README §12 |
| credential/PII leak | an attachment, header block, or redacted reply leaving the machine through any path other than the analyst's own keyboard | two runtime deps, no telemetry, no cloud call |

## What is *not* a vulnerability (please do not spend your time)

- The samples are fabricated and the only "payload" in the repository is the EICAR test string;
  reporting that a sample "contains malware" is reporting a fixture.
- The risk score or verdict disagreeing with your judgement on a specific email. This is a
  calibrated, explainable heuristic — open a normal issue with the `.eml` (redacted) if a class of
  mail is systematically mis-scored.
- Anything that requires you to already control the machine, the `runs/` directory, or the git
  history: the ledger is tamper-*evident*, not tamper-*proof*. Publishing an anchor (git tag, TSA)
  is how you harden it, and README §9 explains why.
- The opt-in pixel listener (`tools_dev.serve_pixel`) being reachable from the LAN: it refuses a
  non-loopback bind unless you pass `--allow-public`, and that flag is the documentation.
- Prompt-injection *inside* a sample email. It is the test case, and `test_prompt_injection.py`
  is what proves it is handled.

## Hardening notes for anyone deploying this

- Keep `SENTINEL_TOR_EXIT_FIXTURE` and `SENTINEL_DNS_FIXTURES` **unset** in production; they are
  demo/CI switches that replace live answers with canned ones.
- Never set `SENTINEL_REQUIRE_CONFIRMATION=0`, and avoid `--yes` / `--demo` outside a scripted
  demo: they let file-touching tools run without a human. Auto-approval is written to `audit.log`
  as `gate_auto_approved` with the words "NOT a human approval" precisely so it stays visible —
  a report whose gate was auto-approved was not reviewed by anyone.
- `--geoip-allow-private` widens tracing to non-routable addresses. It is there for the sample
  corpus; leave it off when real mail may contain internal IPs.
- Run the sandbox with `--sandbox require` if Docker is present, so a missing Docker becomes a
  refusal instead of a degraded scan.
- `runs/` and `evidence/` are git-ignored on purpose. Do not commit case output; a pushed `runs/`
  directory is a disclosure *and* makes the chain trivially "repairable".
