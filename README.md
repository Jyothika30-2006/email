# 🔬 SENTINEL-IR — AI-Powered Cybersecurity Agent for Email Threat Detection, Geolocation Tracing, Forensic Analysis & Blockchain-Verified Evidence Logging

**A fully local, terminal-based autonomous agent.** No web dashboard. No browser UI.
No cloud LLM API. The "brain" is a local LLM (Ollama) driving a **whitelisted tool
loop** against a real suspicious `.eml` file — with a human confirmation gate, an
instant kill-switch, sandboxed static analysis, and tamper-evident blockchain logging.

```
                        ┌──────────────────────────────────────────────┐
   .eml  ──────────────►│  AGENT CONTROLLER  (terminal UI, rich)       │
   (CLI arg)           │  THINK → CHOOSE TOOL → ACT → OBSERVE → REPEAT│
                        │  • running risk score 0-100                  │
                        │  • [CONFIRM_NEEDED] gate before file access  │
                        │  • 'x' kill-switch (aborts agent + sandbox)  │
                        │  • hard 15s timeout on every tool call       │
                        └───────┬───────────────────────┬──────────────┘
                                │                       │
                 ┌──────────────▼─────────┐   ┌────────▼─────────────────┐
                 │ LOCAL LLM (Ollama)     │   │ TOOL LAYER (whitelist)   │
                 │ llama3.1:8b / qwen2.5  │   │ parse_headers, resolve_  │
                 │ tool-calling; if it is │   │ origin, geolocate_ip,    │
                 │ down → deterministic   │   │ check_tor_exit, extract_ │
                 │ engine (labelled!)     │   │ urls, check_reputation,  │
                 └────────────────────────┘   │ static_file_scan,        │
                                              │ hash_evidence (+redact_  │
                                              │  reply for pixel/lead)   │
                                              └───┬──────────────────┬───┘
                                     file-touching│                  │hash+verdict
                                              ┌───▼────────────┐ ┌──▼──────────────┐
                                              │ DOCKER SANDBOX │ │ BLOCKCHAIN      │
                                              │ --network none │ │ hash-chain (A) /│
                                              │ RO mount, dead │ │ Ganache contract│
                                              │ after each run │ │ (metadata only) │
                                              └────────────────┘ └─────────────────┘
```

---

## Table of contents
1. [What makes this different](#1-what-makes-this-different)
2. [The Gmail "hidden sender IP" problem](#2-the-gmail-hidden-sender-ip-problem)
3. [Install](#3-install)
4. [Run it](#4-run-it)
5. [Sample corpus (safe, all-fake)](#5-sample-corpus)
6. [Safety model — 8 non-negotiables](#6-safety-model--8-non-negotiables)
7. [Blockchain evidence log](#7-blockchain-evidence-log)
8. [Docker sandbox](#8-docker-sandbox)
9. [Ollama / LLM integration](#9-ollama--llm-integration)
10. [Free-tier API keys (optional)](#10-free-tier-api-keys-optional)
11. [Advanced: tracking-pixel origin capture](#11-advanced-tracking-pixel-origin-capture)
12. [Tests & demo harness](#12-tests--demo-harness)
13. [Project layout](#13-project-layout)
14. [Honest limitations](#14-honest-limitations)
15. [Ethics & legal](#15-ethics--legal)

---

## 1. What makes this different
| Existing free tools | SENTINEL-IR |
|---|---|
| Browser phishing-link checkers (one URL, no context) | Multi-signal ensemble: headers + auth + URLs (anchor text **and** logo `alt` vs actual host) + brand mismatch + reputation + static file forensics, fused into one **running risk score** |
| Single-source GeoIP sites (`"IP is in Ashburn, VA"`, no uncertainty) | 2–3 GeoIP sources cross-validated → **city + ±radius + confidence %**; "unknown" is a printed result, never a guessed pin |
| Webmail-hiding problem: every other tool just prints Google's relay IP as if it were the sender | Documented **fallback ladder** (SPF `client-ip=` → lure-infrastructure trace → Message-ID leak → timezone hint → optional pixel) each with a **confidence ceiling**, and an explicit "the personal IP is unrecoverable here" |
| Heavy commercial sandboxes (detonation, agents, licences) | **Static-only** analysis in a default-deny Docker container the agent cannot reconfigure, with a human `yes` gate before any byte is read |
| "AI" that writes plausible prose about an email | A local model that must *call tools*, cannot invent them, is defanged of injected instructions, and is refused + **scored** when it tries |
| Findings in a chat log | Chain-of-custody hashes **before** analysis + tamper-evident ledger (+ optional on-chain mirror) and a forensic `report.md` a third party can re-verify |

Two claims we deliberately **do not** make: it does not attribute email to a *person*
(IP ≈ device ≈ household at best, and webmail hides even that), and it is not a malware
detonation lab — nothing is ever executed.

## 2. The Gmail "hidden sender IP" problem
Gmail/Outlook **webmail compose** rewrites the header chain: the only `Received:` hops
are Google's/Microsoft's relays, and `client-ip=` often names their *edge* network, not
the sender's line. So origin resolution is a **fallback ladder**, and `ORIGIN_CONFIDENCE_CEILING`
(`risk.py`) caps how much confidence each rung can support — a ceiling, not a bonus:

| `origin_source_kind` | ceiling | honesty property |
|---|---|---|
| `received_hop` | **82 %** | oldest non-provider hop; may be an open proxy (`origin_open_proxy` +1.40), so it is flagged, not assumed |
| `spf_client_ip` | **78 %** | `client-ip=` stamped in `Authentication-Results`/`Received-SPF` by a *third-party* receiver ⇒ harder to forge than self-written `Received:` |
| `phishing_infrastructure` | **62 %** | the lure domain's IP — describes **attacker infrastructure**, never "where the sender is"; carries `lure_domain_infra` (+1.40, capped so it cannot fake a high score) |
| `messageid_rdns` | **34 %** | hostname leaked in the Message-ID, forward+reverse confirmed ⇒ usually the sending relay inside the sender's own domain |
| `unrecovered` | **0 %** | nothing at all — not even a resolvable lure host: geolocation is printed as *unknown*, never guessed |

`webmail_relay_only` (provider hops only, but a relay IP to name) is deliberately *not* in the
table above: it returns `status: degraded`, `confidence: 12 %`, and the note *"the composing
device's address is NOT in this message; geolocating the relay tells you where Google peered,
not where the sender was"*. Because no `source_kind` in that family yields a usable sender IP,
the close-out rule caps the whole verdict's confidence at **58 %** for a no-origin case
(`agent._finalize`), so a "traced" verdict can never outrank the evidence behind it.

Softer fallbacks stay **signals with their own (small, documented) weights** instead of posing
as an IP: `origin_webmail_relay` +1.20, `origin_unrecovered` 0.00 (neutral — an unlearnable
origin is not evidence of innocence either, it only caps confidence), `origin_direct_host`
−0.60, `messageid_hostname_leak` +1.00, `tz_hint` +0.30, `llm_style_indicator` +0.80 (never
decisive by design), `tracking_pixel_captured` +1.60 (strength 45, "a lead worth noting, not proof of identity").
Because a pixel hit is *not* written into `state["origin"]`, the case stays origin-degraded and
keeps the confidence caps above — the pixel adds a lead, not certainty.

```
# what the shipped Gmail-BEC sample actually reports (no direct origin exists):
| 3 | `resolve_origin` | ✓ | +4.0 | 32.4 | origin=UNRECOVERABLE kind=phishing_infrastructure
                                    confidence_ceiling=62% / infra=203.0.113.88 (corp-portal-sec.example)
candidates: hop0 74.125.20.46 role=provider_relay usable=false · 74.125.20.46 role=provider_edge
            note="context only — not attributable to the sender"
```
Provider relay hops are collected but marked `is_webmail_relay` and **skipped as origin
candidates**; the harness records that it skipped them, so the report explains the gap
instead of pretending the trace succeeded.

## 3. Install
Python **3.10+**. Two runtime dependencies (`rich`, `dnspython`); everything else is
stdlib, so it installs and runs on a locked-down laptop.

```bash
git clone <your-repo-url> && cd email
./scripts/setup.sh                     # venv + deps + samples + pytest + safety selftest
# …or the manual version:
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .
```

`setup.sh` takes opt-in flags for the layers that need more than pip:

| flag | what it does |
|---|---|
| `--with-ollama [model]` | checks Ollama and pulls `llama3.1:8b` (the brain stays local) |
| `--with-sandbox` | `docker build` of the network-less analysis image |
| `--with-chain` | `pycryptodome` (keccak) + `./scripts/compile_contract.sh` + ganache hint |

Optional extras, each *detected at runtime* — absence is reported, never faked:

```bash
ollama pull llama3.1:8b          # real LLM tool-calling (else: deterministic engine, labelled)
sudo apt install libimage-exiftool-perl yara   # richer static analysis inside the sandbox
pip install oletools             # OLE/macros
pip install pycryptodome         # ONLY needed by the optional --chain-backend ganache path
npm i -g ganache                 # local Ethereum testnet (optional mirror of the evidence log)
```

## 4. Run it
```bash
# one-shot investigation of a single .eml (live terminal UI)
python -m cybersecurity_agent investigate samples/phishing_obvious.eml

# headless demo / CI (auto-approves gates — and RECORDS that it did)
python -m cybersecurity_agent investigate samples/gmail_bec_subtle.eml --demo --yes

# fully air-gapped: zero outbound HTTP (local DNS checks still allowed)
python -m cybersecurity_agent investigate samples/phishing_obvious.eml --offline

# tune the loop itself (there are no hidden knobs: every flag has an env var too)
python -m cybersecurity_agent investigate samples/tor_exit_legit.eml \
        --model qwen2.5:7b-instruct --steps 10 --timeout 10 --kill-key x
```
You see, live in the terminal: the agent's reasoning lines, two progress bars (a colour-coded
risk gauge whose threshold ticks are drawn *into* the bar — `·` = verdict floor still ahead,
`┼` = passed — and an evidence-coverage bar), per-tool `▲ +n pts` rows, the `[CONFIRM_NEEDED]`
gate, the final verdict block, and then:

```text
  gauge ████████┼░░░░░░░░·░░░░░░░░   32.4/100 · tools 3/8     ← just crossed the SUSPICIOUS floor
```
```
runs/<case>/report.md       full forensic report (transcript + verdict + evidence)
runs/<case>/run.json        machine-readable: case/events/results/verdict/chain/signals
runs/<case>/evidence.json   chain-of-custody manifest (hash-before-analysis)
runs/<case>/audit.log       append-only timestamped audit entries
evidence/hashchain.jsonl    tamper-evident evidence chain (append-only ledger)
```
Verify the ledger any time:
```bash
python -m cybersecurity_agent chain verify
python -m cybersecurity_agent chain anchor     # print head hash → publish it (git tag, TSA, public chain)
```
Exit codes are verdicts, for transport hooks (`exit 2` = MALICIOUS):
```bash
python -m cybersecurity_agent investigate mail.eml --demo   # 0 SAFE · 1 SUSPICIOUS · 2 MALICIOUS
```
Also useful for triage of a standalone attachment (refuses without an explicit
acknowledgement of authorization):
```bash
python -m cybersecurity_agent analyze-file ~/Downloads/invoice.pdf.exe --confirm
```

## 5. Sample corpus
Four fabricated `.eml` files (`samples/README.md` explains every safe reference used:
loopback + RFC5737 documentation ranges + RFC2606 names, so no run can poke a stranger):

| file | exercises | result here (`--demo`, mock APIs, offline engine) |
|---|---|---|
| `clean_newsletter.eml` | honest sender, SPF/DKIM/DMARC pass, brand-matching https link | `SAFE` risk 23.5 · conf 76.5 % · `exit 0` |
| `phishing_obvious.eml` | typosquat/homoglyph host, IP-literal http URL, `dmarc=fail`, credential form, **`<EMAIL_DATA>` breakout attempt** in an HTML comment, high-entropy "invoice.pdf" | `MALICIOUS` risk 99.0 · conf 90.1 % · `exit 2` |
| `gmail_bec_subtle.eml` | **Gmail webmail sender** (relay-only), `+0530` date offset, Reply-To mismatch, lure-domain link, polite-archaic style | `SUSPICIOUS` risk 33.1 · conf 76.1 % · `origin=phishing_infrastructure` (ceiling 62 %) · 8/8 tools incl. the fallback-(d) draft · `exit 1` |
| `tor_exit_legit.eml` | origin on a (fixture-labelled) Tor exit, everything authenticates | `SAFE` risk 23.8 · conf 86.3 % · prints `tor_exit` **with** "anonymized — NOT proof of guilt" |

Regenerate the corpus (e.g. after editing a template): `python scripts/generate_samples.py`.

## 6. Safety model — 8 non-negotiables
Implemented *in code*, not just prose — each numbered item maps to a module:

1. **Tool whitelist only** — registry in `tools/dispatch.py` (`validate_call` rejects
   unknown names *and* unknown arguments); `safety.FORBIDDEN_ACTIONS` additionally blocks
   `shell`/`exec`/`subprocess`-shaped names forever. An invented tool is refused, appended as
   `invented_tool_request` (+2.40), and after 3 refused/blank steps the LLM is muted and the
   deterministic engine finishes the run. No shell tool exists, so none can be invoked.
2. **Sandbox isolation** — `cybersecurity_agent/sandbox/`: `--network none` (default-deny; the
   analysis path needs zero egress — GeoIP/reputation are queried by *host* tools),
   `--read-only` with the evidence mounted `:/work:ro`, `--tmpfs` scratch, dropped
   capabilities, `--memory/--cpus/--pids-limit`, **container destroyed after every run**
   (`--rm` + `_force_destroy`, also on timeout/abort).
3. **Static analysis only** — the file is read in binary and *parsed* (magic bytes, entropy,
   strings, OLE directory scan, PDF keyword scan, PE header sniff). Nothing is executed,
   rendered, or handed to a viewer. `oletools`/YARA/`exiftool` are used only if the image has
   them, and each is a read-only static tool.
4. **Human confirmation gate** — `ui/console.py:ask_confirmation()`: `[CONFIRM_NEEDED]` panel
   with the agent's *reasoning*, then typing `yes` (or `y`) is required before any
   file-touching tool; silence = timeout = **DENIED**. The harness inserts the gate even when
   the model forgets to ask, and denial is recorded as evidence (`human_denied_scan` + a
   "What was NOT observed" line) rather than silently skipped.
5. **Hard 15 s timeout per tool call** — `safety.run_with_timeout()`; `--timeout` /
   `SENTINEL_TOOL_TIMEOUT`. `static_file_scan` gets a longer *explicit* sandbox budget
   (docker start + scan), and a timeout becomes a `tool_timeout` signal, not a hung demo.
6. **Immutable evidence logging** — SHA-256 of the `.eml` and of every artifact **before**
   analysis (`evidence/hasher.py` → `evidence.json` + `audit.log`), chained on write. A
   re-hash that disagrees is an **incident**: nothing is silently re-recorded,
   `evidence_integrity_failure` fires, confidence is capped at
   `SENTINEL_INTEGRITY_CONFIDENCE_CAP` (35 % default) and the report prints
   "chain-of-custody broken". The `.eml` is re-hashed again at close-out.
7. **Prompt-injection defence** — untrusted email text is wrapped in `<EMAIL_DATA>` and
   defanged by `net.sanitize_untrusted()`: control tags become `＜email_data＞`, approval
   tokens become `[CONFIRM_NEEDED·defanged]`, role-lookalikes get
   `【SYSTEM-lookalike (untrusted)】`, injection phrases become
   `⟦injection-phrase: ignore previous instructions⟧`. Defanged, **not deleted** — the
   transcript still proves the attempt, and `injection_attempts()` scores it. The embedded
   system prompt forbids obeying anything found inside the block.
8. **Kill-switch** — press **`x`** (configurable) at any time: sets the global abort event,
   every tool checks it before/after executing, `docker rm -f` destroys the container, and
   partial state is flushed to the report marked as partial.

## 7. Blockchain evidence log
Two interchangeable back-ends, selected by `--chain-backend` / `SENTINEL_CHAIN_BACKEND`:

* **A. Local hash-chain (default; zero-dependency, offline).**
  `blockchain/hashchain.py` appends JSONL blocks `{index, timestamp, payload,
  previous_block_hash, nonce, block_hash}` where `block_hash =
  SHA256(canonical_json(header incl. payload))` — canonical = key-sorted, so cosmetic
  re-serialization cannot change a hash. `payload` is exactly the brief's metadata:
  `{file_hash, ai_verdict, confidence_score, geolocation_summary, timestamp}` (+ risk,
  origin kind, artifact digests). `chain verify` recomputes every link:
```
$ python -m cybersecurity_agent chain verify
✅ evidence chain: 4 block(s), head f005ed586785747d…
   · 4 block(s) verified, links + hashes consistent
$ # after someone edits a stored verdict (verification stops at the first broken link):
❌ evidence chain: 2 block(s), head 8a38827291bb7da7…
   · block 1 content does not hash to its recorded block_hash (e5f244bae351… vs e324f78b3236…) — payload was edited after logging
   first broken index: 1
```
  `chain anchor` prints the head hash to publish elsewhere — that is what turns
  *tamper-evident* into externally verifiable (see §14).
* **B. Ganache / local Ethereum testnet (optional).**
  `blockchain/ganache_logger.py` + `blockchain/contract/EvidenceChain.sol`. It speaks
  JSON-RPC over `urllib`, signs a legacy transaction with pure-Python secp256k1/RLP
  (`blockchain/pure_python_crypto.py`) and ABI-encodes the call by hand
  (`blockchain/abi_codec.py`) — so `web3` is *not* required. `pycryptodome` **is**, for one
  thing only: `keccak256`. We refuse to hand-roll a hash that must be byte-identical to
  Solidity's; without the library the chain path raises `KeccakUnavailable` and the hash-chain
  above remains the record. On-chain, exactly four 32-byte words per case:
  `fileHash`, `payloadDigest = keccak256(canonical_json(payload))`, `verdict`
  (right-padded ASCII), `confidenceBps` — never the email, never an attachment. After the
  write the logger **reads the record back** with `getEvidenceAt(seq)` and fails the receipt
  if either digest disagrees with the local ledger.
```bash
./scripts/compile_contract.sh                        # → artifacts/EvidenceChain.json
ganache --wallet.seed sentinel --chain.chainId 1337 &
python -m cybersecurity_agent chain deploy            # connect, deploy, cache the address
python -m cybersecurity_agent investigate samples/phishing_obvious.eml --demo --chain-backend ganache
python -m cybersecurity_agent chain read --seq 0       # decode a record (no ABI library needed)
python -m cybersecurity_agent chain export --bundle case-bundle.json --cases runs/<case>
python -m cybersecurity_agent chain record --case runs/<case>/run.json   # re-anchor; mirrors if --contract given
```
  `chain export --bundle` writes a **third-party verification bundle**: per-case payload,
  ledger path/head/link status, decoded on-chain record, the contract ABI, and the four manual
  steps to re-derive everything — and no email content, by construction.
* **Transparency about limits:** the on-chain path adds latency (broadcast + block inclusion),
  so evidence is logged **after** the verdict is displayed and its failure never changes a
  verdict; the hash-chain path is microsecond-cheap and always available. A chain proves
  *"this file and this verdict existed at this time"* — not that the verdict was correct.

## 8. Docker sandbox
```bash
docker build -t sentinel-sandbox:latest cybersecurity_agent/sandbox
# or: ./scripts/setup.sh --with-sandbox
```
The image is `python:3.12-slim-bookworm` + `libimage-exiftool-perl`, `libmagic1`, `yara`
(read-only static tools only) and has **no CMD/ENTRYPOINT**: the runner passes the scanner
argv, so the agent can never ask the image to "run something else". Container flags (built as
a list, never a shell string): `--network none`, `--read-only`, `-v <case>:/work:ro`,
`--tmpfs /tmp:size=64m`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--user <uid>`,
`--memory 512m --cpus 1 --pids-limit 128`, `--rm`.

If Docker is absent, `static_file_scan` **still runs the same scanner script** in a
network-less subprocess with `RLIMIT_AS/RLIMIT_CPU/RLIMIT_FSIZE`, and the run header reads
`sandbox=subprocess-limited (no docker)` — it never pretends Docker was used. Set
`--sandbox require` / `SENTINEL_SANDBOX_REQUIRED=1` and a missing Docker becomes a **refusal**
instead (`sandbox=required-but-missing → denied`).

REMnux/Kali note: the container deliberately mirrors REMnux's *task-organised* static
tooling (magic/entropy/OLE/PDF/strings) rather than a pentest distro's dynamic tools; if you
keep a REMnux VM, point `SENTINEL_SANDBOX_IMAGE` at it and the runner still enforces no-network,
read-only mount, and teardown.

## 9. Ollama / LLM integration
```bash
ollama serve && ollama pull llama3.1:8b        # or qwen2.5:7b-instruct
python -m cybersecurity_agent investigate mail.eml --model llama3.1:8b
```
* `llm/ollama_client.py` POSTs `/api/chat` with `tools=` (native function calling) **and**
  accepts a plain `{"thought": …, "tool_call": …}` / `{"final": …}` JSON object, because 8B
  local models do both inconsistently. `temperature 0.1`, bounded `num_predict`, and a
  per-request timeout (`SENTINEL_LLM_TIMEOUT`, default 90 s) so a stalled model cannot wedge the loop.
* Model output is **validated, never trusted**: names checked against the registry, arguments
  filtered against each tool's JSON schema, `[CONFIRM_NEEDED]` inserted by the harness if the
  model skipped it, and file-touching tools still gated by a human.
* `--no-llm` (or Ollama unreachable) ⇒ `llm/deterministic.py` runs the same pipeline with the
  same tools/signals/math. The UI badge says `LLM OFFLINE → deterministic engine`, and
  `run.json`'s `verdict_author` records who wrote the verdict.
* Nothing leaves the machine: no cloud provider import exists anywhere in the package.

## 10. Free-tier API keys (optional)
```bash
export VIRUSTOTAL_API_KEY="…"      # file-hash + domain reputation  (free tier: 4 req/min)
export ABUSEIPDB_API_KEY="…"       # IP abuse confidence + fraud reports
export IPINFO_TOKEN="…"            # ipinfo HTTPS quota (skip = ip-api HTTP still works)
export GEOIP_MMDB="$HOME/.local/share/GeoIP/GeoLite2-City.mmdb"   # offline MaxMind (best privacy)
```
Everything degrades honestly **without** keys: `check_reputation` returns
`reputation_skipped` (weight 0.0 — no key must not make mail look safer *or* scarier) and
the report gains `no reputation API answered … reputation is unobserved`.

## 11. Advanced: tracking-pixel origin capture (fallback 3d)
For a pure-webmail sender where you have authorization to reply:
```bash
python -m cybersecurity_agent pixel-listen --port 8099 --out runs/pixel-hits.jsonl
python -m cybersecurity_agent investigate samples/gmail_bec_subtle.eml --demo   # redact_reply drafts the reply
```
* `tools/redact_reply.py` writes `runs/<case>/reply_draft.html` — a **human-review draft**
  (never sent by this program) embedding `<img src="http://{host}/open/{case_id}.gif">` with a
  per-case unguessable token, plus the origin status and ceiling in its header.
* `pixel-listen` answers only `/open/<case>.gif` with a 1×1 GIF and appends
  `{ts, ip, path, tz, accept_language, user_agent}`; anything else gets a quiet `204` and is
  **not** logged, so preview bots and favicons don't create false hits.
* Feeding hits back: `investigate … --extra-ioc-file runs/pixel-hits.jsonl` folds them in as
  `tracking_pixel_captured` (+1.60). Hits tagged for a *different* case are ignored, so one
  shared hit log can't contaminate another investigation's evidence.
* `--no-pixel` drafts the same reply with the capture tag left out (the draft's own header
  states `NOT embedded — plain draft only`, and the tool result records which you chose), so
  the "we didn't bait them" claim is provable from the case file rather than from your word.
* Read the wording in the draft: a pixel reveals the IP/TZ of whatever client fetched it —
  which may be a proxy, CDN, or gateway. It is a lead for an investigation plan, never
  attribution of a human. Bind to `127.0.0.1` unless your incident owner authorised otherwise
  (the listener warns loudly if you bind a routable interface).

## 12. Tests & demo harness
```bash
.venv/bin/python -m pytest tests -q          # 106 tests in ~6 s, no network egress needed
python -m cybersecurity_agent selftest       # 5 checks: 9-tool registry, whitelist refuses
                                             # 'shell', timeout raises, fuse math, and a
                                             # deliberately tampered ledger is detected
```
Coverage targets the *claims*: hop numbering & folded headers, `client-ip=` (both phrasings),
the webmail degradation ladder and ceilings, defanging of injected control tokens, whitelist
refusal of invented tools, per-tool timeouts, the fail-closed gate (a non-affirmative or
timed-out answer must deny *and be recorded* — covered by test and reproducible with
`printf "no\n" |`), kill-switch abort (plus sandbox teardown on abort), GeoIP consensus vs disagreement, Tor
listed/NXDOMAIN/broken-DNS handling, hash-chain tamper detection, chain-of-custody drift and its
confidence cap, the EICAR/macro/high-entropy static scan, sandbox argv policy, keccak/secp256k1/
RLP/ABI published vectors, `EvidenceChain.sol` ↔ ABI ↔ logger selector agreement, the live
gauge being a real monotone bar whose threshold markers are semantic (so a non-TTY demo log
still shows *how far* a case was from flipping verdict), and
end-to-end runs of all four samples through both the deterministic engine and a stubbed LLM
transport (10 tests in `tests/test_agent_end_to_end.py`).

Air-gapped demo harness (this repo ships it because demo venues eat Wi-Fi):
```bash
python -m cybersecurity_agent mock-apis --port 8099 &      # fake GeoIP/reputation endpoints
export SENTINEL_DNS_FIXTURES=samples/fixtures/dns_fixtures.json
export SENTINEL_TOR_EXIT_FIXTURE=samples/fixtures/tor_exit_ips.txt
python -m cybersecurity_agent investigate samples/phishing_obvious.eml --demo \
      --geo-base-url http://127.0.0.1:8099 --reputation-base-url http://127.0.0.1:8099 \
      --geoip-allow-private
```
`GET /` on that server renders its own documentation — route table, the seven synthetic
GeoIP rows, and the exact `investigate` command to paste. It is *not* a dashboard (the agent
has no UI beyond the terminal); it exists so a preview or a confused judge sees an
explanation instead of a 404. Reaching it off-loopback requires `--bind 0.0.0.0 --allow-public`,
which prints a warning and still serves only synthetic fixtures — no case data, no credentials.

Canned answers stay labelled as canned: DNS/PTR fixture hits are tagged `fixture` at the
resolver boundary, the Tor check appends `simulated via fixture tor_exit_ips.txt (NOT a live
DNSEL answer)`, and the mock GeoIP rows carry `Reserved (demo fixture)` — so a demo can never be
mistaken for a live lookup. `--geoip-allow-private` is required for exactly this corpus
(loopback/RFC5737 ranges that cannot hurt anyone); without it `geolocate_ip` refuses the
address and prints `enable --geoip-allow-private only for the bundled demo corpus`. Real
investigations leave it off.

## 13. Project layout
```
cybersecurity_agent/            (≈7.7k lines; stdlib + rich + dnspython only)
├── cli.py                 argparse: investigate | analyze-file | chain | pixel-listen | mock-apis | selftest
├── agent.py               Agent controller: THINK→CHOOSE→ACT→OBSERVE loop, custody, gate, verdict, report
├── config.py              every tunable (timeouts, endpoints, sandbox policy, caps) + secret redaction
├── models.py              Hop · OriginFinding · GeoPoint/GeoConsensus · UrlEvidence ·
│                          ReputationHit · FileScanFinding · RiskSignal · HashRecord
├── risk.py                FACTOR_WEIGHTS · ORIGIN_CONFIDENCE_CEILING · fuse() (log-odds) ·
│                          RiskState · confidence_score() · classify() · severity_color()
├── safety.py              SAFETY #1/#4/#5/#8: FORBIDDEN_ACTIONS, KillSwitch, run_with_timeout, run_argv
├── net.py                 bounded HTTP (urllib), DNS + fixture hook, IP classification,
│                          provider-network tables, sanitize_untrusted()/injection_attempts()
├── tools_dev.py           mock GeoIP/reputation server (self-documenting index) + pixel listener
├── prompts/agent_system_prompt.py     the exact system prompt (verbatim) + <EMAIL_DATA> wrapper
├── evidence/
│   ├── eml.py             header/hop/auth/DKIM/attachment parsing, tz + Message-ID forensics
│   ├── hasher.py          chain-of-custody digests, evidence.json manifest, audit.log
│   └── transcript.py      report.md (human) + run.json (case/events/results/verdict/chain/signals)
├── tools/
│   ├── base.py            ToolContext, ToolResult, @register (file_touching/timeout), @tool_meta
│   ├── dispatch.py        validate_call → timeout → dispatch → ToolResult (the only exec path)
│   ├── parse_headers.py · resolve_origin.py · geolocate_ip.py · check_tor_exit.py
│   ├── extract_urls.py · check_reputation.py · static_file_scan.py · hash_evidence.py
│   └── redact_reply.py    optional fallbacks (3d)/(3e): sanitised reply draft + pixel URL
├── sandbox/
│   ├── Dockerfile         network-less, read-only, cap-dropped, static-tools-only image
│   ├── docker_runner.py   fixed argv, resource limits, guaranteed container teardown
│   ├── local_exec_helper.py  labelled fallback (rlimits, no network) when Docker is absent
│   ├── scanner_script.py  pure-stdlib static scanner (magic/entropy/OLE/PDF/PE/strings)
│   └── rules/sentinels.yar  optional YARA rules (loaded only if yara is present)
├── blockchain/
│   ├── hashchain.py       back-end A: JSONL SHA-256 chain, verify(), HEAD pointer, export
│   ├── ganache_logger.py  back-end B: JSON-RPC + legacy-tx signing + read-back verification
│   ├── abi_codec.py       hand-checked encoder/decoder for the contract's fixed shapes
│   ├── pure_python_crypto.py  secp256k1 ECDSA + RLP (keccak is pycryptodome's, never ours)
│   └── contract/          EvidenceChain.sol + evidence_chain_abi.json
├── llm/
│   ├── ollama_client.py   /api/chat tool-calling; native + JSON protocol parsers; retries
│   └── deterministic.py   offline planner (the no-LLM floor)
└── ui/console.py          rich Live layout, risk + coverage progress bars,
                           [CONFIRM_NEEDED] panel, kill-switch key (bars also render in the
                           non-TTY demo log and as a `gauge` column in report.md)

samples/                   4 .eml (clean · obvious phishing · subtle Gmail BEC · Tor exit)
  ├── payloads/            macro stub / renamed-EXE / EICAR (all harmless) + fixtures/
  └── fixtures/            dns_fixtures.json · tor_exit_ips.txt (demo/CI determinism)
scripts/                   generate_samples.py · setup.sh · compile_contract.sh
tests/                     106 tests (1 823 lines) — see §12
config/default.env.example every SENTINEL_* knob, commented
docs/ARCHITECTURE.md       module boundaries, trust model, the three brains, extension points
docs/FORENSIC_METHODOLOGY.md  weights, fusion math, confidence semantics, how to read a report
FINAL_REPORT.md            requirement-by-requirement ledger + measured results + limitations
```

## 14. Honest limitations
* **Genuine Gmail/Outlook webmail origin IPs are unrecoverable from headers alone.** No tool
  can fix that; anyone claiming a precise pin from a relay-only `Received:` chain is guessing.
  We output the fallback we used, a lowered ceiling, and the reason.
* GeoIP is ISP/registry-dependent: expect city-level, sometimes regional-level error. We
  report a radius and per-source disagreement instead of pretending precision.
* Tor status = *anonymization*, not guilt. A non-hit never clears an exit that just rotated.
* Reputation APIs rate-limit, miss novel infrastructure and disagree; we keep each provider's
  answer instead of averaging them into false precision.
* Static analysis ≠ detonation: a file can be malicious and score clean on magic/entropy/
  keywords. That is why every report lists what was **and was not** observed.
* The local hash-chain is **tamper-evident**, not tamper-proof: publish the head hash
  (`chain anchor` → git tag, RFC3161 TSA, public chain) or the on-chain mirror, otherwise
  someone with write access to this disk can rebuild a self-consistent chain.
* `run_with_timeout` cannot interrupt a *thread*: a tool that ignores its deadline is
  reported `timed_out` and its result discarded, while the thread finishes in the background.
  `static_file_scan` avoids this by running the scanner as a killable subprocess.
* The `--chain-backend ganache` path was validated here against a scripted fake JSON-RPC node
  (encoding, signing, read-back, failure paths), not against a real chain — `chain deploy`
  additionally needs a Solidity compiler and a node you run yourself.
* Ollama, Docker, oletools/YARA/exiftool were unavailable in the build environment, so those
  branches are covered by labelled fallbacks and tests rather than live runs here.

## 15. Ethics & legal
Built for **defensive** use on mail you are authorised to investigate (your own mailbox, your
organisation's quarantine, hackathon datasets). Investigating other people's infrastructure
— scanning, pixeling, tracing — without authorisation is illegal in most jurisdictions. The
tracking-pixel feature is opt-in, human-gated, ships pointed at `127.0.0.1`, and refuses to
send anything itself. `analyze-file` refuses without `--confirm`. Geolocation output is
investigative *lead generation*, never evidence of identity, and this project must not be used
to accuse a real person. All samples are fabricated; the only payload included is the EICAR
test string.
