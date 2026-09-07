# FORENSIC METHODOLOGY — how SENTINEL-IR reaches a verdict, and what it refuses to claim

> Written so that a reviewer can reproduce every number in a `report.md` from the
> evidence it lists. Where the method is weak, that is stated here as well as in the
> report itself.

---

## 0. The honesty contract (read this first)

Three rules dominate every design decision below:

1. **Confidence measures evidence collected, not scariness.** A message can score
   99/100 risk and still report ~55 % confidence (the no-origin ceiling) if we never found
   a traceable IP — see the table in §2.
2. **A degraded path must say it degraded.** Every fallback (fixture DNS, mocked
   GeoIP, offline engine, missing reputation key, denied file scan) prints its
   reason, lowers confidence, and appears in the report's *What was NOT observed*.
3. **"Unknown" is a result.** Geolocation output is always `city + ±radius + %`;
   there is no code path that emits a precise pin. When no source answers, the
   report says `unknown — no usable GeoIP answer`, not the last guess.

---

## 1. Evidence collection order (the pipeline the LLM may not skip)

| # | Tool | What it establishes | Failure mode we handle |
|---|------|--------------------|-----------------------|
| 0 | `hash_evidence` | SHA-256 of the `.eml` **and of every attachment before any analysis touches them** | digest drift ⇒ hard stop: `source digest changed after initial hashing` |
| 1 | `parse_headers` | all `Received:` hops (bottom→top), SPF/DKIM/DMARC verdicts, `client-ip=`, Message-ID host, Date offset | folded headers, missing hops, `=?UTF-8?` encodings |
| 2 | `resolve_origin` | the sender-side IP, **or** the documented fallback ladder + a confidence ceiling | webmail-only chains (see §2) |
| 3 | `geolocate_ip` | 2–3 independent GeoIP answers → consensus city, radius, agreement % | provider disagreement, private IPs, offline |
| 4 | `check_tor_exit` | live Tor DNSEL answer (`127.0.0.2` = listed) | DNS failure ⇒ `unknown`, never `not a Tor exit` |
| 5 | `extract_urls` | visible text **and logo `alt`** vs actual href host, homoglyph/typosquat, IP-literal links, credential forms, BEC vocabulary | obfuscated/relative links, defanged injection text |
| 6 | `check_reputation` | AbuseIPDB / VirusTotal / Spamhaus on IPs, domains and file hashes | no key ⇒ `reputation_skipped` (0 weight, but an *unobserved* line) |
| 7 | `static_file_scan` | **inside the sandbox, after a human `yes`**: magic vs extension, entropy, OLE/macros, PDF active content, EICAR/AV hits | refusal ⇒ `human_denied_scan`, evidence gap recorded, verdict unchanged |
| 8 | `redact_reply` | (optional) a *sanitised* reply draft + tracking-pixel URL for fallback (d) | never sent automatically |

Each step emits `RiskSignal(factor, direction, strength, explanation, source)`. The
score is **recomputed from the whole signal set** after every step (never incremented
by hand), so a late signal can lower an earlier conclusion.

---

## 2. The "Gmail hides the sender IP" ladder

`resolve_origin` walks the layers in this order and *records which layer it landed on*:

```
1  oldest usable Received: hop                   → kind=received_hop            ceiling 82 %
2  Authentication-Results/Received-SPF client-ip= → kind=spf_client_ip           ceiling 78 %
3a lure/infrastructure IP (the phishing server)   → kind=phishing_infrastructure ceiling 62 %
3b Message-ID hostname leak + rDNS               → kind=messageid_rdns          ceiling 34 %
3c timezone / style / pixel findings              → signals only (tz_hint +0.30,
                                                    llm_style_indicator +0.80,
                                                    tracking_pixel_captured +1.60),
                                                    never promoted to an "origin"
4  provider relay hops only, no client-ip=        → kind=webmail_relay_only      status=degraded,
                                                    finding confidence 12 % (not in the ceiling table)
5  nothing usable anywhere                        → kind=unrecovered             ceiling  0 %
```

Two close-out caps (`agent._finalize`) sit *on top* of the table, so a weak provenance can
never produce a confident verdict. The rows below are computed with full tool coverage (10/10
tools), six corroborating signal families, and **`geoloc_confidence = 0`** — i.e. an IP that was
traced but never placed:

| situation | `confidence_score()` | after caps |
|---|---|---|
| no origin IP at all (`unrecovered`) | 55.0 | **55.0** (`min(…, 58.0)` — no-origin rule) |
| relay IP only, nothing learned about it | 67.2 | **67.2** (`min(…, 68.0)` when geolocation confidence ≤ 20 %) |
| lure infrastructure traced, not placed | 77.9 | **68.0** (same geo-confidence cap) |
| lure infrastructure traced *and* placed (geo 95 %) | 90.1 | 90.1 |
| genuine sender-side hop, placed | 96.0 | 96.0 (the function's own ceiling) |

Rules enforced in code, not just in prose:

* Provider relay hops (`Google`/`Microsoft`/`Yahoo` networks) are **skipped as origin
  candidates** and listed in `finding.notes` as skipped — their location describes
  where the provider peered, not where the human sat.
* When the *only* client-ip is in a provider edge network and every hop is a relay, we
  emit `webmail_relay_only`, `status="degraded"`, `confidence 12 %`, and keep the edge
  IP in the record explicitly labelled `ip_role="provider_edge"` / *"context only — not
  attributable to the sender"*.
* The infrastructure fallback (3a) is legitimate but must be *named*: it produces the
  `lure_domain_infra` signal (+1.4 weight) with the explanation "the mailbox IP is
  hidden, the lure host is traceable", and the geolocation ceiling stays at 62 %.
* Confidence is capped twice: at `resolve_origin` time (the ceiling) and at
  `_finalize` time (`no origin IP ⇒ confidence ≤ 58`; `IP found but GeoIP learned
  nothing ⇒ ≤ 68`).

---

## 3. Geolocation: multi-source consensus, not a lookup

Sources (config-driven): `ip-api` (HTTP, keyless), `ipinfo` (HTTPS, optional token),
`maxmind_offline` (local GeoLite2 `.mmdb`, the only one usable fully air-gapped).

For each IP we keep every source that answered and compute:

```
agreement = share of answering sources inside the median distance of the modal city
radius    = median accuracy radius, widened to cover source disagreement (± km)
summary   = "≈ City, CC · radius ±N km · confidence P% · sources: ip-api, ipinfo"
```

* ≥2 sources agree on city → `confidence = 60 + 15·(sources-2)`, capped by the origin ceiling.
* Sources agree on country but not city → city is reported as the *modal* city with
  `confidence ≤ 40` and the report adds "city-level disagreement".
* Only one source answers → `confidence ≤ 35`, labelled "single-source".
* Contradictory countries → **no location claim**: `conflicting sources — not reporting a location`.
* Private/loopback/reserved IPs are refused unless `SENTINEL_GEO_ALLOW_PRIVATE=1`
  (which the demo corpus and CI set, and which the report then states out loud).

---

## 4. Tor: scrutiny, not conviction

`check_tor_exit` queries `<reversed-ip>.ip-port.exitlist.torproject.org` for an A record:

| answer | meaning | our treatment |
|---|---|---|
| `127.0.0.2` | listed exit (all ports incl. 25 → can send mail) | `tor_exit` +2.2 × strength 85 |
| `127.0.0.10` | listed for port 25 only | `tor_exit` +2.2 × strength 62 |
| `NXDOMAIN` | not listed | **no signal** (absence of a hit must not reduce risk either) |
| `SERVFAIL`/timeout/DNS disabled | unknown | `tool_timeout` +0.4 and an "unknown" line |

A demo/CI fixture can substitute for the live query; when it does, `via` contains
`simulated via fixture … (NOT a live DNSEL answer)` and the strength is lowered (52),
because a fixture proves our code path, not the world.

Rule 6 is implemented in the *wording*: the signal explanation always contains
"origin anonymized … elevated scrutiny, NOT proof of guilt". A Tor exit is also never
enough for `MALICIOUS` on its own — see §5.

---

## 5. Score fusion (why not a weighted average)

`risk.fuse()` is a **log-odds** fusion:

```
pos      = Σᵢ  wᵢ · (strengthᵢ / 100)          for wᵢ > 0
mitig    = Πⱼ (1 + wⱼ · strengthⱼ/100)          for wⱼ < 0   (each ≤ 1)
pos      = max(pos · mitig, 0.15 · pos)          ← a clean scan can never launder a kit
pos     *= 1 + 0.05 · (families − 1)            ← corroboration bonus, capped
score    = 100 · σ((pos − 2.4) / 1.8)           ← saturates only when several heavyweights fire
```

Properties we wanted (and unit-test):

* one strong signal ⇒ ~30 (never 100);
* three strong signals ⇒ ~98 (real corroboration);
* any number of soft hints (`urgency_language`, `tz_hint`, `shortener`, `http_url`)
  stays **below** the 65 threshold — no conviction on vibes;
* mitigators (up to −2.6) can move a score but a floor of 15 % of positive mass keeps
  `MALICIOUS` reachable when the positive evidence is heavy.

Verdict thresholds (`classify`): `≥65` **and** at least one strong indicator
(`brand_mismatch`, `spf_fail`, `dmarc_fail`, `homoglyph_domain`, `known_malware_hash`,
`av_detections`, `file_type_mismatch`, `pdf_active_content`, `embedded_macro`,
`credential_harvest_form` at strength ≥ 45) ⇒ `MALICIOUS`; `≥65` without one ⇒
`SUSPICIOUS`; `≥30` ⇒ `SUSPICIOUS`; else `SAFE`.

### Weights (from `risk.FACTOR_WEIGHTS`, strongest first — this block is the dict, not a summary)

```
evidence_integrity_failure  +3.40   origin_webmail_relay        +1.20
known_malware_hash          +3.40   messageid_hostname_leak     +1.00
av_detections               +3.20   spf_none_temperror          +1.00
homoglyph_domain            +3.20   suspicious_tld              +1.00
brand_mismatch              +3.00   urgency_language            +1.00
spf_fail                    +3.00   money_request_context       +0.90
credential_harvest_form     +2.80   http_url                    +0.80
dmarc_fail                  +2.80   human_denied_scan           +0.80
file_type_mismatch          +2.80   llm_style_indicator         +0.80
dkim_fail                   +2.40   secrecy_pressure            +0.80
embedded_macro              +2.40   contact_isolation_request   +0.70
invented_tool_request       +2.40   attachment_present          +0.60
pdf_active_content          +2.20   shortener                   +0.60
tor_exit                    +2.20   tool_timeout                +0.40
abuse_reports               +2.00   tz_hint                     +0.30
high_entropy                +2.00   url_domain_age_unknown      +0.20
prompt_injection_attempt    +2.00   origin_unrecovered           0.00
ip_literal_url              +1.80   reputation_skipped           0.00
reply_to_mismatch           +1.80   sandbox_unavailable          0.00
display_name_spoof          +1.60   clean_static_scan           -0.35
link_text_mismatch          +1.60   arc_pass                    -0.40
spf_soft_fail               +1.60   origin_direct_host          -0.60
tracking_pixel_captured     +1.60   av_clean                    -1.00
attachment_risky_ext        +1.40   brand_match                 -1.00
lure_domain_infra           +1.40   safe_domain_reputation      -1.40
origin_open_proxy           +1.40   auth_pass                   -2.60
new_domain                  +1.20
```

Zero-weight factors are **bookkeeping, not scoring**: they exist so the report can state
what did *not* happen (`reputation_skipped`, `origin_unrecovered`) without the absence
itself moving the number. That distinction is deliberate — a missing API key must not
make an email look safer or more dangerous.

---

## 6. Prompt-injection handling (the email is attacker input)

* The `.eml` body is inserted only inside `<EMAIL_DATA> … </EMAIL_DATA>`, and before it
  reaches the model, `net.sanitize_untrusted()` rewrites the shapes that could break out of
  the data region — fullwidth brackets around control tags (`＜email_data＞`), a marker suffix on
  approval tokens (`[CONFIRM_NEEDED·defanged]`), labelled role lines
  (`From【SYSTEM-lookalike (untrusted)】:`) and `⟦injection-phrase: ignore previous instructions⟧`.
  It **defangs rather than deletes**, so the transcript still proves an attempt was made, and
  `injection_attempts()` turns each hit into a `prompt_injection_attempt` signal (+2.00).
  Over-long bodies are truncated with an explicit
  `…[truncated by agent; N chars withheld — raw bytes remain in the hashed .eml]` marker rather
  than being silently cut.
* Detection of injection phrasing is a **signal** (`prompt_injection_attempt +2.00`),
  never a command: the agent's own text notes it was "defanged, refused, and logged".
* The model cannot execute anything it invents: tool names are matched against
  `tools.REGISTRY`; a non-whitelisted name is refused, recorded as
  `invented_tool_request (+2.40)`, and the deterministic planner resumes the pipeline.
  Three consecutive refused/blank steps ⇒ the LLM is muted for the rest of the run
  (`LLM quiet → deterministic engine` is printed and logged).

---

## 7. Chain of custody

1. `hash_evidence` digests the source file and each staged attachment **before** analysis,
   writing `runs/<case>/evidence_hashes.json`.
2. Any later digest drift is an incident, not a bookkeeping update: the tool refuses
   with `source digest changed after initial hashing … evidence may have been tampered with`.
3. Every verdict is appended to `evidence/hashchain.jsonl` as
   `{index, timestamp, payload, previous_block_hash, nonce, block_hash}` where
   `block_hash = sha256(canonical_json(header incl. payload))` (keys sorted, compact
   separators — so cosmetic re-serialization cannot alter a hash) — rewriting any block
   breaks every later link (`chain verify` proves it in ~1 ms).
4. `chain anchor` prints the head hash to be published elsewhere (git tag, RFC 3161 TSA,
   public chain). **Limit, stated plainly:** the local chain is *tamper-evident*, not
   *tamper-proof* — anyone with write access to this disk can rebuild a self-consistent
   chain unless the head hash is anchored externally.
5. Optionally (`--chain-backend ganache`) the same payload's `keccak256` is mirrored to
   `EvidenceChain.submitEvidence` on a local testnet. Only `fileHash`, `payloadDigest`,
   `verdict`, `confidenceBps` go on-chain — never the mail. If the node is unreachable,
   the run records `skipped: no local testnet … → local hash-chain is the record` and
   the verdict does not move.

### Verification bundle

`chain export --bundle out.json --cases runs/<case>` writes a file a third party can
check with their own tools: payload JSON per case, ledger path + head + link status,
decoded on-chain records, and the four manual verification steps. It contains no email
content by construction (it is a list of digests and verdict metadata).

---

## 8. Sandbox methodology (why the file scan looks the way it does)

* Only `static_file_scan` ever receives attachment bytes, and only inside the container:
  `--network none`, `--read-only`, evidence mounted `:/work:ro`, `--tmpfs /tmp` size-limited,
  `--memory`, `--cpus`, `--pids-limit`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
  `--rm` plus explicit `_force_destroy` after the run.
* Inside, `sandbox/scanner_script.py` is **pure stdlib**: magic-byte sniffing vs declared
  type, Shannon entropy over chunks and whole file, OLE/`vbaProject` keyword scan, PDF
  active-content scan (`/OpenAction`, `/JavaScript`, `/Launch`, `/EmbeddedFile`), PE headers,
  long high-entropy strings, optional oletools/YARA when installed.
* **Nothing is executed, opened, unpacked or rendered.** No `exiftool`/`libreoffice`/`olevba`
  ever touches the file in-process; oletools parses bytes only, and is optional.
* `SENTINEL_SANDBOX_REQUIRED=1` turns a missing Docker into a *refusal* rather than a
  fallback; without it, the fallback (subprocess with rlimits, no network) is used and
  the report line reads `sandbox=subprocess-limited (no docker)`.
* The EICAR test file in `samples/payloads/` proves the AV/magic path end-to-end without
  any real malware; the macro sample is a stub `.docm` with an embedded
  `AutoOpen` string, not a working payload.

---

## 9. Interpreting a report

| Report says | Means |
|---|---|
| `risk 99.0/100 · confidence 90.1%` | many corroborating hard signals *and* a traceable origin |
| `risk 99.0/100 · confidence 68.0%` | strong content/infra evidence, weak origin attribution — do **not** act as if the location is proven |
| `origin=… kind=phishing_infrastructure (ceiling 62%)` | sender IP unrecoverable; we traced the attacker's *server*, not their laptop |
| `geolocation: unknown — no usable GeoIP answer (confidence 6%)` | the IP is not in any provider we reached; no location claim is made |
| `static_file_scan not run — attachment bytes were never inspected` | the verdict rests on headers/URLs/origin only; the attachment is *unassessed*, not *clean* |
| `LLM OFFLINE → deterministic engine` | no local model answered; every conclusion comes from the coded pipeline, nothing is model-authored |

---

## 10. Known limitations (also printed in every report)

* Webmail-only chains cannot yield a sender IP. Anyone claiming a "precise pin" from a
  Gmail `Received:` chain is guessing.
* GeoIP is ISP/registry-dependent: expect city-level, sometimes regional-level error.
* Static analysis ≠ dynamic detonation: malicious files can score clean on magic/entropy.
* Reputation APIs rate-limit, miss novel infrastructure, and disagree with each other;
  we record each provider's answer rather than averaging them into false precision.
* The pixel fallback (d) requires *sending* something to the correspondent — it is
  disabled by default, opt-in, human-gated, and ships pointed at `127.0.0.1`.
* A hash-chain entry proves *this file + this verdict existed at this time*; it proves
  nothing about whether the verdict was *correct*.
