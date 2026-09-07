# 🔎 SENTINEL-IR — the guided demo

One command, no setup beyond the venv, nothing to sign up for:

```bash
./scripts/demo.sh          # ≈5 s · four samples, offline, deterministic engine
./scripts/demo.sh --quick  # two samples, skips the mood gallery and the skin table
```

It needs **no** API keys, **no** network egress (it starts a loopback mock GeoIP/reputation server
and uses the bundled DNS/Tor fixtures), **no** Docker and **no** Ollama. Every investigation prints
its verdict, its confidence and its risk, and the process exit code *is* the verdict
(`0 SAFE · 1 SUSPICIOUS · 2 MALICIOUS`); the script fails loudly if the two ever disagree, so
`./scripts/demo.sh && echo clean` doubles as a smoke test.

What it walks through:

| step | what you see |
|---|---|
| 0 | the loopback fixture endpoints + `selftest` (whitelist, hard timeout, ledger tamper, **display containment**) |
| 1 | all 17 work-status moods drawn side by side, two frames each |
| 2.1–2.4 | the four samples investigated end-to-end, with the cat reacting per event |
| 3 | `runs/<case>/status.jsonl` — the events an external companion would watch, plus a grep proving no case text leaked into it |
| 3b | `sentinel-ir pet` rendering that same case, as a second window would |
| 4 | a care reminder firing mid-run, and where it is recorded (audit log, **not** the forensic report) |
| 5 | the skins (palette only — the art and the numbers cannot change) |
| 6 | the same file with the whole surface on and off: identical verdict, risk, confidence, plan |
| 7 | the evidence ledger verify + the artifact list per case |

> The transcript below is the real output of `./scripts/demo.sh` in this repo on 2026-09-07
> (deterministic engine, mock endpoints on :8099), captured through a pipe — so the UI rendered its
> **non-TTY log**, where every mood change is printed as `[sentinel-cat] …`. In a real terminal you
> get the live `rich` frame instead, redrawn as events arrive (see *Watching it live* at the bottom).

---

### 0 · offline fixture endpoints (mock GeoIP + reputation, loopback only)

```text
reusing the mock server already listening on 127.0.0.1:8099
```

### 0b · selftest — 9-tool whitelist, hard timeout, ledger tamper, display containment

```text
registry  : 9 whitelisted tools → check_reputation, check_tor_exit, extract_urls, geolocate_ip, hash_evidence, parse_headers, redact_reply, resolve_origin, static_file_scan
whitelist : correctly refuses 'shell' / unknown tools
timeout   : ToolTimeoutError raised as expected
fuse      : 81.8 for brand_mismatch+spf_fail
ledger    : append+verify ok | tamper detected: True
pet/hook  : 17 moods, uniform live box=yes, note vocabulary=26 entries, attacker-shaped notes dropped=yes
selftest  : ✅ all safety invariants hold
```

### 1 · the sentinel cat: every work-status reaction, drawn

```text
  watching  watching the mailbox
           /\_/\          /\_/\
          ( o.o )        ( -.- )
           >   <          >   <
           /| |\          /| |\
  thinking  planning the next tool call
            .               .
           /\_/\          /\_/\
          ( ?_? )        ( ?_? )
           >   <          >   <
           /| |\          /| |\
  typing    a whitelisted tool is running
           /\_/\          /\_/\
          ( o.o )        ( o.o )
           >v<            >^<
           /| |\          /| |\
          tap tap         tap tap
  hunting   tracing link and origin infrastructure
           /\_/\          /\_/\
          ( o.o )        ( o.o )
           _  _           _  _
           /| |\~         /| | \
           wiggle        wiggle
  fur       prompt-injection attempt in this message
           /\ /\         /\ /\ /
           /\_/\          /\_/\
          ( O_O )        ( O_O )
           >   <          >   <
           /| |\          /| |\
          fur up          fur up
  bristle   evidence integrity problem — treat this case as contaminated
           ! \ / !       !  \ /  !
           /\_/\          /\_/\
          ( >w< )        ( >w< )
           >   <          >   <
           /| |\          /| |\
          puffed up       puffed up
  steam     a tool hit its hard timeout
            ~   ~         ~   ~
           /\_/\          /\_/\
          ( >_< )        ( >_< )
           >   <          >   <
           /| |\          /| |\
           (slow)         (slow)
  denied    the human denied the file-touching tool
           /\_/\          /\_/\
          ( -_- )        ( -, - )
           >   <          >   <
           /| |\          /| |\
          won't touch     won't touch
  waiting   blocked on you: type 'yes' at the confirmation gate
           /\_/\          /\_/\
          ( o.o )        ( -.- )
           >   ?          >   ?
           /| |\          /| |\
           your call     your call
  tilt      suspicious, and the evidence is thin
           /\_/\          /\_/\
          ( o_o )        ( _o )
           >   <          >   <
           /| |\          /| |\
          hmm?           hmm ?
  hop       verdict: SAFE
            \ /           /|\ /|\
           /\_/\          /\_/\
          ( ^.^ )        ( ^.^ )
          \|/   \|/       >   <
             v             ~ ~
          * meow *        hop!
  arch      verdict: MALICIOUS
            \   /           \ /
           /\_/\          /\_/\
          ( >.< )        ( >.< )
          / |   | \      \ |   | /
           hisss          hisss
          hiss!           HISS!
  flee      kill-switch pressed, tearing down
           /\_/\          /\_/\
          ( o.o )        ( o.o )
           _==_           _===
             ===> flee    ====> flee
  sentry    focus block running — the case has the floor
            t i c k       t o c k
           /\_/\          /\_/\
          ( o.o )        ( o.o )
           >   <          >   <
           /| |\          /| |\
          sentry          sentry
  stretch   stand up: shoulders back, neck roll, 20 seconds
           /\_/\          /\_/\
          ( -.- )        ( -.- )
            \_/           _/\_
          \_|_|_/         /| |\
          stretch         stretch
  water     drink some water
           /\_/\          /\_/\
          ( o.o )        ( ^.^ )
           >   <          >   <
           /| |\          /| |\
           glug...       glug ...
  nap       break time — the mailbox can wait two minutes
               z             zZ
           /\_/\          /\_/\
          ( -.- )        ( -.- )
           >   <          >   <
           /| |\          /| |\
              Zz            zZ
17 moods · hand-written frames · one fixed 13×6 box so the live panel never jumps
no frame contains a single character from the email — that is asserted by a test
```

### 2.1 · investigate samples/clean_newsletter.eml  (deterministic engine, offline, gates auto)

```text
  gauge ░░░░░░░░·░░░░░░░░·░░░░░░░░    0.0/100 · tools 0/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] a whitelisted tool is running
  gauge ██████░░·░░░░░░░░·░░░░░░░░   21.6/100 · tools 1/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
  [sentinel-cat] a whitelisted tool is running
  gauge ██████░░·░░░░░░░░·░░░░░░░░   22.3/100 · tools 2/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
╭────────────────────────────────────────── FINAL VERDICT (rule 7) ──────────────────────────────────────────╮
│ SAFE  ·  confidence 76.5%  ·  risk 23.5/100                                                                │
│ ├── ██████░░·░░░░░░░░·░░░░░░░░   23.5/100  (floors: 30 suspicious · 65 malicious)                          │
│ ├── ↓ SPF, DKIM and DMARC all pass for the From-domain — sender domain was cryptographically attested      │
│ ├── ↑ oldest hop is a Google relay (mx.google.com) — the composing client's IP is not in this header chain │
│ ├── ↑ From-domain sends via Google; the only IP retained is the client-ip from authentication headers      │
│ │   (192.0.2.10) — that is the *connecting machine*, not a guaranteed home line                            │
│ ├── ↑ urgency/threat-of-loss vocabulary in subject/body (soft signal: common in marketing too)             │
   exit=0  →  SAFE  ·  confidence 76.5%  ·  risk 23.5/100
   exit code agrees with the printed verdict ✓
```

### 2.2 · investigate samples/phishing_obvious.eml  (deterministic engine, offline, gates auto)

```text
  [sentinel-cat] prompt-injection attempt in this message
  gauge ░░░░░░░░·░░░░░░░░·░░░░░░░░    0.0/100 · tools 0/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] a whitelisted tool is running
  gauge ████████┼████████┼████████   98.8/100 · tools 1/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
  [sentinel-cat] a whitelisted tool is running
  gauge ████████┼████████┼████████   99.0/100 · tools 2/8
  [sentinel-cat] planning the next tool call
╭────────────────────────────────────────── FINAL VERDICT (rule 7) ──────────────────────────────────────────╮
│ MALICIOUS  ·  confidence 90.1%  ·  risk 99.0/100                                                           │
│ ├── ████████┼████████┼████████   99.0/100  (floors: 30 suspicious · 65 malicious)                          │
│ ├── ↑ look-alike / typosquatted host in at least one link (Unicode homoglyph or digit substitution)        │
│ ├── ↑ SPF=fail — the message failed cryptographic/mailflow authentication                                  │
│ ├── ↑ 2 link(s) advertise a brand whose domain they do not belong to — strong phishing indicator           │
│ ├── ↑ DMARC=fail — the message failed cryptographic/mailflow authentication                                │
│ ├── ↑ password field / credential-harvest URL shape present in the message body                            │
   exit=2  →  MALICIOUS  ·  confidence 90.1%  ·  risk 99.0/100
   exit code agrees with the printed verdict ✓
```

### 2.3 · investigate samples/gmail_bec_subtle.eml  (deterministic engine, offline, gates auto)

```text
  gauge ░░░░░░░░·░░░░░░░░·░░░░░░░░    0.0/100 · tools 0/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] a whitelisted tool is running
  gauge ██████░░·░░░░░░░░·░░░░░░░░   23.4/100 · tools 1/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
  [sentinel-cat] a whitelisted tool is running
  gauge ███████░·░░░░░░░░·░░░░░░░░   28.4/100 · tools 2/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
╭────────────────────────────────────────── FINAL VERDICT (rule 7) ──────────────────────────────────────────╮
│ SUSPICIOUS  ·  confidence 76.1%  ·  risk 33.1/100                                                          │
│ ├── ████████┼░░░░░░░░·░░░░░░░░   33.1/100  (floors: 30 suspicious · 65 malicious)                          │
│ ├── ↑ body matches credential-harvest phrasing (/login?redirect_uri=…, “verify your password”)             │
│ ├── ↑ Reply-To points at outlook.com while From is gmail.com — replies would be diverted                   │
│ ├── ↓ SPF/DKIM/DMARC pass — but on a FREE WEBMAIL domain, which proves only that a real mailbox sent this, │
│ │   not that the request is genuine (classic account-abuse/BEC case)                                       │
│ ├── ↑ sender mailbox IP is hidden but the linked lure host corp-portal-secure.com resolves to 203.0.113.88 │
   exit=1  →  SUSPICIOUS  ·  confidence 76.1%  ·  risk 33.1/100
   exit code agrees with the printed verdict ✓
```

### 2.4 · investigate samples/tor_exit_legit.eml  (deterministic engine, offline, gates auto)

```text
  gauge ░░░░░░░░·░░░░░░░░·░░░░░░░░    0.0/100 · tools 0/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] a whitelisted tool is running
  gauge ░░░░░░░░·░░░░░░░░·░░░░░░░░    0.0/100 · tools 1/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
  [sentinel-cat] a whitelisted tool is running
  gauge ██████░░·░░░░░░░░·░░░░░░░░   21.4/100 · tools 2/8
  [sentinel-cat] planning the next tool call
  [sentinel-cat] tracing link and origin infrastructure
╭────────────────────────────────────────── FINAL VERDICT (rule 7) ──────────────────────────────────────────╮
│ SAFE  ·  confidence 86.3%  ·  risk 23.8/100                                                                │
│ ├── ██████░░·░░░░░░░░·░░░░░░░░   23.8/100  (floors: 30 suspicious · 65 malicious)                          │
│ ├── ↓ SPF, DKIM and DMARC all pass for the From-domain — sender domain was cryptographically attested      │
│ ├── ↑ origin IP 198.51.100.24 is listed as a Tor exit node (simulated via fixture tor_exit_ips.txt (NOT a  │
│ │   live DNSEL answer)) → origin anonymized: the sender's real network is masked by design; elevated       │
│ │   scrutiny, NOT proof of guilt (Tor serves legitimate privacy too)                                       │
│ ├── ↑ message asks the recipient to isolate the thread (no reply / tell nobody) — a pressure tactic,       │
   exit=0  →  SAFE  ·  confidence 86.3%  ·  risk 23.8/100
   exit code agrees with the printed verdict ✓
```

### 3 · runs/<case>/status.jsonl — what an external companion would watch

```text
{"case": "9a55e44201", "mood": "typing", "note": "chain:written", "state": "chain", "ts": "2026-09-07T16:57:39.246+00:00"}
{"case": "9a55e44201", "mood": "watching", "note": "chain:skipped", "state": "chain", "ts": "2026-09-07T16:57:39.246+00:00"}
{"case": "9a55e44201", "confidence": 86.3, "mood": "hop", "note": "verdict-recorded", "risk": 23.8, "state": "verdict", "ts": "2026-09-07T16:57:39.248+00:00", "verdict": "SAFE"}
{"case": "9a55e44201", "risk": 23.8, "state": "closed", "ts": "2026-09-07T16:57:39.251+00:00"}
allowlisted fields · `case` is a digest, not the filename · `note` must be in NOTE_VOCAB
   attacker/case text in the status file: 0 lines
```

### 3b · sentinel-ir pet — the companion rendering that same case

```text
sentinel-cat · watching runs/20260907T165739Z-tor_exit_legit/status.jsonl
─────────────────────────────────────────────────────────
  \ /        
 /\_/\       
( ^.^ )      
\|/   \|/    
   v         
* meow *     
verdict: SAFE · tool check_reputation · risk 23.8/100 · confidence 86.3% · 26 event(s)
note: verdict-recorded
care: next break in 20 min
status hook is an ADVISORY display, not evidence — the verdict of record is runs/<case>/run.json
```

### 4 · care reminders mid-run (intervals compressed so you can actually see one fire)

```text
  [care] drink some water
  [care] drink some water
  [care] 20-20-20: look 6 m away for 20 s
   care notes now in runs/20260907T165739Z-tor_exit_legit-2/: audit.log=3  report.md=0
the 12 ms interval makes it fire on nearly every loop tick — that is the knob working, not a bug
0 in report.md is the point: the forensic transcript stays a document about the email
defaults are eyes=20,stretch=30,water=45 minutes — a 20-second demo never gets nudged
```

### 5 · skins — the 'custom colour' feature, reduced to a palette

```text
  calm           arch → 'red'   hop → 'green'
  colour-blind   arch → 'bold white'   hop → 'blue'
  default        arch → 'bold red'   hop → 'green'
  high-contrast  arch → 'bold red'   hop → 'bold green'
  mono           arch → ''   hop → ''

    \   /      
   /\_/\       
  ( >.< )      
  / |   | \    
   hisss       
  hiss!        
identical art and identical numbers under every skin — colour is a cue, not the finding
```

### 6 · proof the surface cannot move the case: same file, pet on vs pet off

```text
   pet on : SAFE 23.8 86.3 spf_client_ip ['parse_headers', 'extract_urls', 'resolve_origin', 'geolocate_ip', 'check_tor_exit', 'check_reputation']
   pet off: SAFE 23.8 86.3 spf_client_ip ['parse_headers', 'extract_urls', 'resolve_origin', 'geolocate_ip', 'check_tor_exit', 'check_reputation']
identical verdict, risk, confidence, origin kind and executed plan ✓
a cartoon that could change a verdict would not ship
--no-pet --no-status-hook: no panel, no reminders, no status file — nothing else changed
```

### 7 · evidence ledger (chain-of-custody, not detection)

```text
✅ evidence chain: 93 block(s), head fe0392d04d0a315e…
   · 93 block(s) verified, links + hashes consistent

Artifacts for the pet-off case (/home/user/email/runs/20260907T165740Z-tor_exit_legit):
  audit.log evidence.json report.md run.json 
Artifacts for the pet-on case (/home/user/email/runs/20260907T165739Z-tor_exit_legit-3):
  audit.log evidence.json report.md run.json status.jsonl 
report.md (forensic) · run.json (machine) · evidence.json (custody) · audit.log (what happened) · status.jsonl (display)
```
---

## Watching it live, in a real terminal

```bash
python -m cybersecurity_agent mock-apis --port 8099 &
python -m cybersecurity_agent investigate samples/phishing_obvious.eml --demo --no-llm \
      --geo-base-url http://127.0.0.1:8099 --reputation-base-url http://127.0.0.1:8099 \
      --geoip-allow-private
```

The layout exists so one glance answers *is it working, on what, and does it need me*: the cat sits
left of the two bars, its caption carries the mood label + current tool + risk, and a care reminder
appears underneath. This is an actual frame, captured from a pty:

```text
╭─────────────────────────────────────── work-status · running score ────────────────────────────────────────╮
│                ████████┼████████┼████████  risk  99.0/100    confidence 88.0%                              │
│  /\_/\         ████████████████████░░░░░░░░░░░░░░░░░░░░  evidence 4/8 tool results · floors: ≥30           │
│ ( -.- )        SUSPICIOUS, ≥65 MALICIOUS (+1 strong indicator)                                             │
│   \_/          stand up: shoulders back, neck roll, 20 seconds · tool extract_urls · risk 99.0/100         │
│ \_|_|_/                                                                                                    │
│ stretch                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Two properties are load-bearing and both are tested, not eyeballed: every frame of every mood is
padded to the same 13×6 box (so the Live region can never resize mid-run and flicker), and the
caption is built from enums and numbers only — a tool summary, subject or address is never echoed
into this panel, because this panel is a display an attacker's text must not be able to speak
through.

## Poking at it by hand

```bash
# the gate: anything but 'yes' ⇒ DENIED, fail-closed, and the denial is in the report + audit log
printf 'no\n' | SENTINEL_REQUIRE_CONFIRMATION=1 python -m cybersecurity_agent \
    investigate samples/phishing_obvious.eml --no-llm --geoip-allow-private

# a companion following the live case in another terminal
python -m cybersecurity_agent pet --follow --path "$(ls -td runs/*/ | head -1)status.jsonl"

# reminders you can actually see, plus the Pomodoro clock
python -m cybersecurity_agent pet --once --plain --remind "water=0.001" --pomodoro 25,5

# silence, if a cartoon is the last thing you want while reading a real case
python -m cybersecurity_agent investigate samples/phishing_obvious.eml --demo --no-pet --no-status-hook

# the containment check, as part of the standard self-test
python -m cybersecurity_agent selftest | tail -2
```

## What each claim above is backed by

| claim you can see in the transcript | where it is enforced |
|---|---|
| reactions follow real events, never the email | `Agent._react()` is the only writer; `test_frames_never_contain_case_text` renders every frame of all 17 moods |
| the status file cannot be used to talk through the pet | fixed field set + `scrub_note` (shape filter, then `NOTE_VOCAB`); `test_hook_writes_only_allowlisted_fields_and_never_the_case_name` |
| a broken sink must not break a case | `StatusHook._append` swallows `OSError` after one warning; `test_hook_never_raises_on_a_broken_sink` |
| the pet is honest about *now* | transient moods decay to `watching`, the verdict mood is pinned, `waiting` never decays while the gate is open |
| care reminders cannot touch the case | `ui/care.py` imports nothing from the package (AST check) and fires into `audit.log`, never `report.md` |
| skins are cosmetics | `test_skins_change_colour_never_content` — identical art and identical numbers |
| the whole surface is inert | `test_the_pet_cannot_influence_the_case`, plus step 6 above at the CLI level |
| two runs in the same second get separate case dirs | `_case_id()` + `test_two_runs_in_the_same_second_do_not_share_a_case_dir` — the collision that `-3` above shows was found *by writing this demo*, and it was a real custody bug before the fix |

## The suite behind the demo

```bash
.venv/bin/python -m pytest tests -q      # 145 passed in ~6.5 s, no network egress needed

```
