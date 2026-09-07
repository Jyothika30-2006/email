# SENTINEL-IR — build report (what was asked, what exists, what was measured)

Repo: `/home/user/email` · package `cybersecurity_agent/` · 7.7k lines of Python +
1.82k lines of tests (106 tests) + 2 shell scripts + 1 Solidity contract + 4 sample `.eml`.
Everything below was verified in this sandbox on 2026-09-07; commands are copy-pasteable.

---

## 1. Requirement-by-requirement ledger

Legend: ✅ implemented & verified here · ⚠️ implemented but limited by this environment · ❌ not done

### Core role
| Requirement | Where | How to see it |
|---|---|---|
| Terminal-only agent, **no web dashboard / no browser UI** | whole repo (no Flask/FastAPI/HTML anywhere) | `grep -rn "flask\|fastapi\|django" cybersecurity_agent` → empty |
| Runs against a **local LLM via Ollama**, calls real tools, "not just chatting" | `llm/ollama_client.py` (`/api/chat` with `tools=`), `agent.py` loop | `python -m cybersecurity_agent investigate samples/phishing_obvious.eml --model llama3.1:8b` |
| THINK → CHOOSE TOOL → ACT → OBSERVE → REPEAT, live in the terminal | `agent.py:155` `_select_brain`, `:304` `_run_step`, `ui/console.py` (rich Live) | any run prints THINK/ACT/OBSERVE rows with per-step `▲ +n pts` |

### The Gmail/webmail hidden-sender-IP problem (the brief's centrepiece)
| Requirement | Where | Result here |
|---|---|---|
| 1. walk **all** `Received:` hops bottom→top, skip internal relay IPs | `evidence/eml.py:parse_received_hops` · `tools/resolve_origin.py:63` | 3 hops parsed on the phishing sample, numbered `0,1,2` oldest→newest; `hop#0: … (no routable IP)`, `hop#1: internal sendmail hop` recorded as skipped |
| 2. read `Received-SPF` / `Authentication-Results` `client-ip=` | `eml.py:parse_auth_results` (also handles the Postfix/MS `sender IP is 1.2.3.4` phrasing) + `parse_received_spf` | `kind=spf_client_ip origin=203.0.113.66 ceiling=78%` |
| 3. pure-webmail ⇒ genuinely unrecoverable: **do not fake a location** | `resolve_origin.py` `provider_edge` branch (`status="degraded"`, `webmail_relay_only`, `confidence ≤ 15`) | `gmail_bec_subtle.eml`: `origin=74.125.20.46 kind=webmail_relay_only … context only — not attributable to the sender` |
| 3a. trace the **phishing infrastructure** IP instead | `resolve_origin._trace_urls` → `kind=phishing_infrastructure`, ceiling 62 %, plus `lure_domain_infra` signal (+1.4) | present; with DNS fixtures the BEC sample lands on the lure host at ceiling 62 % |
| 3b. Message-ID internal hostname leak (+rDNS) | `eml.py:MSGID_HOST_RE`, `net.reverse_dns`, signal `messageid_hostname_leak` | `payload01.secure-p0nyail.com` extracted from the Message-ID |
| 3c. Date timezone offset as a soft hint | `eml.py:tz_hint`, signal `tz_hint` (+0.30) | `+0330 → Iran (soft hint, never sole basis)`; `+0530 → India (IST)` on the BEC sample |
| 3d. tracking pixel in an auto-generated reply (**advanced feature**) | `tools/redact_reply.py:53` builds `<img src="http://{host}/open/{case}.gif">`; `pixel-listen` records hits | verified live: `/open/CASE9.gif` → 200 image/gif + JSONL hit `{ts, ip, path, tz, accept_language, user_agent}`; `/favicon.ico` → 204 and **not** logged |
| 3e. LLM writing-style as a **low-confidence secondary** signal | `agent._style_pass` + `llm_style_indicator` (+0.80, weight deliberately small) | present; `SENTINEL_STYLE_ANALYSIS=0` disables it |
| 4. confidence % **always** beside any geolocation; never a fake precise pin | `tools/geolocate_ip.build_consensus` + `risk.confidence_score` + `_finalize` caps | every geo line prints `≈ city, CC · radius ±N km · confidence P%`; unknown prints `unknown — no usable GeoIP answer (confidence 6%)`; there is no code path emitting coordinates as an attribution |

### Architecture layers
| Requirement | Where | Notes |
|---|---|---|
| Local LLM layer, no cloud API, no data leakage | `llm/ollama_client.py` (host is `OLLAMA_HOST`, default `127.0.0.1:11434`) | `--offline` = zero outbound HTTP; UI header states `LLM OFFLINE → deterministic engine` |
| Agent controller + rich live UI (progress bars, coloured risk, streaming reasoning) | `ui/console.py`, `risk.severity_bar`, `llm/ollama_client.py` (`stream: True`) | Live transcript + **two progress bars** (risk, drawn with `·`/`┼` verdict-floor markers, and evidence coverage `n/8`) that also print in the non-TTY demo log and as a `gauge` column in `report.md` |
| Running risk score updated after **every** tool call | `risk.RiskState.add_all` (re-fuses the whole list, returns `(delta, explanation)`) | no incremental `+=` anywhere |
| Human confirmation before any file-touching tool (type `yes`) | `ui/console.py:199` `ask_confirmation`; `agent.py:318` records `gate` events | harness *forces* `[CONFIRM_NEEDED]` even if the model forgets to ask (`agent.py:314`) |
| Single-keypress kill-switch (abort agent + destroy sandbox) | `safety.KillSwitch`, `docker_runner.register_kill_teardown` | `--kill-key x`; abort ⇒ `AbortedError`, partial state still written to the report |
| Tool layer: **whitelist only**, agent cannot invent tools or run shell | `tools/base.py` (`@register`), `tools/dispatch.py:25` `validate_call`, `safety.FORBIDDEN_ACTIONS` | invented tool → refused + `invented_tool_request` (+2.40); 3 strikes mute the LLM |
| The 8 named tools | `tools/parse_headers.py:30`, `resolve_origin.py:50`, `geolocate_ip.py:37`, `check_tor_exit.py:36`, `extract_urls.py:37`, `check_reputation.py:34`, `static_file_scan.py:53`, `hash_evidence.py:37` | +1 bonus tool `redact_reply.py:40` (fallbacks d/e) |
| Only `static_file_scan` touches file bytes, and only inside the sandbox | `sandbox/docker_runner.py:99` `scan_file` (the sole reader of staged copies) | the source `.eml` is mounted read-only and re-hashed at close-out |
| Docker sandbox: no network except explicit whitelist; read-only mount; container destroyed after each run; REMnux-style static tooling | `sandbox/Dockerfile` (`python:3.12-slim` + `libimage-exiftool-perl`, `libmagic1`, `yara`), `docker_runner.py:122` (`--network none --read-only --tmpfs … --cap-drop ALL --no-new-privileges --memory --cpus --pids-limit --user … --rm`), `_force_destroy` | `--network none` is a *stricter* reading of "explicit whitelist": all network-consuming lookups (GeoIP/reputation) are done by host tools on hashes/IPs, so the sandbox needs zero egress. Documented in README §8. |
| Blockchain evidence log: only `{file_hash, AI_verdict, confidence_score, timestamp, geolocation_summary}` | `blockchain/hashchain.evidence_payload` (+`risk_score`, `origin_source_kind`, `artifact_hashes`) | raw mail/attachments are never sent anywhere |
| …on a local Ganache testnet **or** a simple Python hash-chain fallback | `blockchain/hashchain.py` (A, default, zero-deps) · `blockchain/ganache_logger.py` (B, optional) | `SENTINEL_CHAIN_BACKEND=auto` picks B when the RPC answers, else A, and *records which it used* |
| Transparent about blockchain limits (latency; logging only, never detection) | `_log_to_chain` runs **after** the verdict is displayed; `_try_ganache` is wrapped in a 12 s `run_with_timeout` | README §7 states it; report prints `elapsed` for the chain step |
| Exact system prompt embedded | `prompts/agent_system_prompt.py:9` | `selftest` asserts rules 1–7 text is present; `<EMAIL_DATA>` wrapper at `:51` |

### Safety parameters (non-negotiables) — all eight in code
1. ✅ **Tool whitelist** — `tools/dispatch.py` (`FORBIDDEN_ACTIONS` blocks `shell`/`exec`/`subprocess` names even if a tool were added later).
2. ✅ **Sandbox isolation, network-restricted** — `sandbox/docker_runner.py`; ⚠️ Docker is not installed in this sandbox, so every run here used the labelled fallback `sandbox=subprocess-limited (no docker)` (never presented as Docker).
3. ✅ **Static analysis only** — `sandbox/scanner_script.py` reads bytes: magic-vs-extension, Shannon entropy, OLE/`vbaProject` keyword scan, PDF active content (`/OpenAction`, `/JavaScript`, `/Launch`, `/EmbeddedFile`), PE headers, high-entropy strings, optional oletools/YARA/exiftool if present. No execution, no rendering, no viewer.
4. ✅ **Human gate** — `ui/console.py:199`; fail-closed (timeout or non-`yes` ⇒ DENIED and recorded as `human_denied_scan` + "What was NOT observed").
5. ✅ **Hard 15 s timeout per tool** — `safety.run_with_timeout:193`; `SENTINEL_TOOL_TIMEOUT` / `--timeout`; per-tool overrides (`resolve_origin` 14 s, `static_file_scan` a separately budgeted sandbox run).
6. ✅ **Immutable evidence logging** — `hash_evidence` before analysis → `runs/<case>/evidence.json` + `audit.log`; ledger `evidence/hashchain.jsonl`; re-hash at close-out; drift ⇒ `evidence_integrity_failure` + confidence cap (35 % default).
7. ✅ **Prompt-injection separation** — `net.sanitize_untrusted:294` defangs `</EMAIL_DATA>`/`SYSTEM:`/`[CONFIRM_NEEDED]`/"ignore previous instructions" **without deleting the shape**, so the transcript still proves the attempt (`prompt_injection_attempt` +2.00).
8. ✅ **Kill-switch** — `safety.KillSwitch:42`; aborts the loop, `docker rm -f`s the container, flushes a partial report marked `run was aborted by the kill-switch — evidence is partial by construction`.

### Deliverables
| # | Requested | Status |
|---|---|---|
| 1 | agent controller + live rich terminal UI | ✅ `agent.py` (≈660 lines) + `ui/console.py` |
| 2 | Ollama tool-calling loop | ✅ `llm/ollama_client.py` (native `tool_calls` **and** JSON-object fallback parsers) + `llm/deterministic.py` floor |
| 3 | each tool fully coded & runnable | ✅ 9 modules, each with a real `PARAMS` schema and `llm_hint` |
| 4 | Docker sandbox configuration | ✅ `sandbox/Dockerfile` + runner; ⚠️ `docker build` not runnable here (no Docker in this sandbox) |
| 5 | blockchain evidence logging (Ganache **or** hash-chain) | ✅ both; hash-chain is default and fully exercised |
| 6 | sample `.eml` files: clean, obvious phishing, subtle BEC via Gmail webmail | ✅ those three **plus** a Tor-exit sample (rule 6 demo); generated by `scripts/generate_samples.py` |
| 7 | inline comments explaining each safety measure | ✅ `safety.py` is annotated `#1…#8` per item; tools/runner/config carry `SAFETY #n` comments |
| 8 | step-by-step local setup, no cloud deps except free-tier reputation APIs | ✅ `./scripts/setup.sh` (+ `--with-ollama/--with-sandbox/--with-chain`), `requirements.txt` (2 lines), `pyproject.toml`, `config/default.env.example`, README §3–§4, §10 |

---

## 2. Measured results (this environment, `--demo --no-llm` + local mock GeoIP/reputation)

```
samples/clean_newsletter.eml   → SAFE          risk  23.5/100   confidence 76.5%   exit 0
samples/phishing_obvious.eml   → MALICIOUS     risk  99.0/100   confidence 90.1%   exit 2
samples/gmail_bec_subtle.eml   → SUSPICIOUS    risk  33.1/100   confidence 76.1%   exit 1
samples/tor_exit_legit.eml     → SAFE          risk  23.8/100   confidence 86.3%   exit 0
evidence chain: 4 blocks → ✅ links + hashes consistent
```
* The BEC sample is the honest-degradation showcase: origin ceiling 62–78 %, `origin=…
  kind=…`, "sender mailbox IP unrecoverable by design", and it stays `SUSPICIOUS` — not
  `MALICIOUS` — because conviction requires a strong indicator (`classify`).
* The Tor sample prints `tor_exit ▲ 52` **and** the caveat that anonymization is
  elevated scrutiny, not proof of guilt; it remains `SAFE` (SPF/DKIM/DMARC all pass).
* Verdict → exit code (`0/1/2`) is intentional: `investigate … && alert || escalate` works
  in a mail-transport hook.

Extra proofs run here:
```
$ python -m cybersecurity_agent chain verify      (after editing one block's verdict)
❌ evidence chain: 2 block(s), head a3ebb5c52ea39f7b…
   · block 1 content does not hash to its recorded block_hash (349338509d9b… vs 2d29bb7df7a0…)
     — payload was edited after logging
   first broken index: 1
$ printf "no\n" | … investigate samples/phishing_obvious.eml --offline
[GATE] static_file_scan: DENIED (fail-closed; timeout or non-affirmative answer)
→ verdict still MALICIOUS 99.0 but confidence 68.0% and the report lists
  "static_file_scan skipped by the human gate — no file-structure evidence"
$ python -m cybersecurity_agent analyze-file samples/payloads/macro_dropper.bin
[sentinel] refusing: --confirm is required …                     (exit 2)
$ python -m cybersecurity_agent analyze-file samples/payloads/macro_dropper.bin --confirm
→ flags embedded_macro / suspicious VBA strings / high entropy, without executing anything
$ python -m cybersecurity_agent selftest
→ ✅ all safety invariants hold (9 tools registered, 'shell' refused, timeout raises,
    ledger tamper detected)
$ .venv/bin/python -m pytest tests -q
→ 106 passed in 6.5 s, no network egress needed
```

---

## 3. Decisions a reviewer should be able to argue with

1. **Log-odds fusion instead of a weighted sum.** A weighted mean lets one strong signal be
   diluted, or three soft hints fake a conviction. `fuse()` = `100·σ((Σ wᵢsᵢ − 2.4)/1.8)` with
   multiplicative mitigation, a 15 % floor on positive mass (a clean static scan cannot
   launder a phishing kit), and a capped corroboration bonus.
2. **Confidence is orthogonal to risk.** `confidence_score()` counts *provenance and
   coverage*, never scariness, and is then hard-capped: no origin IP ⇒ ≤58 %; IP but no usable
   GeoIP ⇒ ≤68 %; custody broken ⇒ ≤35 %. Calibrated effect: `phishing_obvious` 90.1 % vs
   `gmail_bec` 76.1 % at *lower* risk but similar evidence quality.
3. **Tor is context, not conviction** — `tor_exit` +2.20 weight, NXDOMAIN ⇒ *no* signal,
   DNS failure ⇒ "unknown" signal; the fixture path is always labelled `simulated` and
   scored lower (52 vs 85) because a fixture proves our code, not the world.
4. **Provider relay IPs are never origin candidates** — recorded as `skipped` with reasons.
5. **We do not hand-roll keccak.** An evidence hash must be byte-identical to Solidity's
   `keccak256`; a from-scratch sponge looks right, passes self-consistency tests, and can be
   silently wrong — so `pure_python_crypto.keccak256` delegates to `pycryptodome` and raises
   `KeccakUnavailable` otherwise (with the honest error text). Pure-Python secp256k1/RLP are
   kept (a bug there fails loudly as a rejected broadcast, not as corrupted evidence) and are
   tested against published vectors: `keccak256("")=c5d246…`, `keccak256("hello")=1c8aff…`,
   privkey `0x46…46` → `0x9d8a…5a4f`, RFC 6979 determinism + low-s, RLP `"dog"/["cat","dog"]/15/1024`.
6. **The contract's ABI is fixed-layout on purpose.** Verdict is a right-padded `bytes32`, not
   `string`, so `getEvidenceAt(seq)` returns 5 static words any reviewer can decode with no ABI
   library — and `tests/test_ganache_logger.py` asserts the `.sol` text, the ABI JSON and the
   logger's selector string never drift apart (that drift is the classic silent on-chain bug).
7. **`--demo`/`--yes` weaken the gate but never hide it** — `gate: auto (demo/--yes)` is in the
   report header, and `--chain-backend`/mock endpoints are echoed too.

---

## 4. Honest limitations (mine, not the concept's)

* ⚠️ **Not exercised here:** a real Ollama model (none installed → every run used the
  deterministic engine, clearly labelled); `docker build`/container run (no Docker);
  oletools/YARA/exiftool sections of the scanner; a real Ganache node and real
  `solc` compilation; live ip-api/ipinfo/AbuseIPDB/VirusTotal/Spamhaus (unreachable from this
  sandbox — exercised instead against `mock-apis`, with fixture answers labelled as such).
* `safety.run_with_timeout` cannot interrupt a *thread*, so a tool that ignores its
  deadline is reported as `timed_out` and its result discarded while the thread finishes in the
  background (documented in `safety.py`). `static_file_scan` avoids the problem by running the
  scanner as a subprocess with `kill()` on timeout.
* Memory-limit parsing in the sandbox fallback handles `512m`/`2g`-style strings only.
* `analyze-file` accepts an extension-less file with an explicit "no canonical magic" note
  rather than refusing — it is a *static* scanner, not a policy engine.
* The hash-chain is *tamper-evident*, not *tamper-proof*: without an externally published head
  hash (`chain anchor`), someone with write access to this disk can rebuild a self-consistent
  chain. The report says this in prose.
* Geolocation is city + ±radius only; `127.0.0.1`/TEST-NET sample IPs yield `unknown` on
  a real network, and the demo requires `--geoip-allow-private` (recorded in the report).
* `redact_reply`'s pixel URL is only a *lead* generator; it is opt-in, and it is never sent
  automatically by anything in this repo.

---

## 5. Files to read, in this order

1. `README.md` — pitch, safety model (§6), exact commands, honest limitations (§14).
2. `docs/ARCHITECTURE.md` — module boundaries/trust model, the three "brains", extension points.
3. `docs/FORENSIC_METHODOLOGY.md` — the full weight table, fusion math, the origin ladder,
   what each report line means, and what "unobserved" implies.
4. `cybersecurity_agent/agent.py` → `tools/dispatch.py` → `risk.py` → `blockchain/hashchain.py`.
5. `tests/` (10 files, 106 tests) — each test name states the claim it defends.
