#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SENTINEL-IR guided demo. Everything runs offline against the bundled fixtures
# and a local mock GeoIP/reputation server — no keys, no egress, no stranger's
# IP address is ever touched. The exit code of each investigation IS the verdict
# (0 SAFE · 1 SUSPICIOUS · 2 MALICIOUS), so this script doubles as a smoke test.
#
#   ./scripts/demo.sh              # full guided demo (≈40 s)
#   ./scripts/demo.sh --quick      # two samples, skip the mood gallery + skins
#   PORT=8123 ./scripts/demo.sh    # use a different mock-apis port
#
# In a real terminal you also get the live `rich` UI with the cat animating in
# the running-score panel; piping this to a file works too, because the UI
# degrades to its non-TTY log, which still prints every mood change.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
PORT=${PORT:-8099}
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

export SENTINEL_DNS_FIXTURES=samples/fixtures/dns_fixtures.json
export SENTINEL_TOR_EXIT_FIXTURE=samples/fixtures/tor_exit_ips.txt

step() { printf '\n\033[1;36m── %s\033[0m\n' "$1"; }
note() { printf '\033[2m%s\033[0m\n' "$1"; }
show() { printf '%s\n' "$1" | grep -E "$2" | head -n "${3:-12}" || true; }
count() { local n; n=$(grep -ciE "$1" "$2" 2>/dev/null || true); printf '%s' "${n:-0}"; }
newest_case() { ls -td runs/*/ 2>/dev/null | head -1; }
MOCK_PID=""
cleanup() { if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

VERDICT_RE='(MALICIOUS|SUSPICIOUS|SAFE)  ·  confidence [0-9.]+%  ·  risk [0-9.]+/100'
run_case() {   # $1 = sample stem, rest = extra flags → prints the demo-relevant lines
  local out code v
  set +e
  out=$($PY -m cybersecurity_agent investigate "samples/$1.eml" --demo --no-llm $GEO "${@:2}" 2>&1)
  code=$?
  set -e
  show "$out" "sentinel-cat|gauge" 10
  printf '%s\n' "$out" | sed -n '/FINAL VERDICT/,/^╰/p' | head -8 || true
  v=$(printf '%s' "$out" | grep -oE "$VERDICT_RE" | head -1 || true)
  printf '\033[1m   exit=%s  →  %s\033[0m\n' "$code" "${v:-<no verdict line>}"
  case "$code:$v" in
    0:*SAFE*|1:*SUSPICIOUS*|2:*MALICIOUS*) note "   exit code agrees with the printed verdict ✓" ;;
    *) printf '\033[31m   exit code and verdict disagree — that is a bug\033[0m\n'; exit 1 ;;
  esac
  LAST_OUT="$out"
}

# ── 0 · fixture endpoints ───────────────────────────────────────────────────
step "0 · offline fixture endpoints (mock GeoIP + reputation, loopback only)"
if curl -s -m 2 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
  note "reusing the mock server already listening on 127.0.0.1:${PORT}"
else
  $PY -m cybersecurity_agent mock-apis --port "$PORT" >/dev/null 2>&1 &
  MOCK_PID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -m 1 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 && break
    sleep 0.2
  done
  note "started mock-apis on 127.0.0.1:${PORT} (pid ${MOCK_PID}) — 7 synthetic GeoIP rows"
fi
GEO="--geo-base-url http://127.0.0.1:${PORT} --reputation-base-url http://127.0.0.1:${PORT} --geoip-allow-private"

step "0b · selftest — 9-tool whitelist, hard timeout, ledger tamper, display containment"
$PY -m cybersecurity_agent selftest

# ── 1 · the cast ────────────────────────────────────────────────────────────
if [ "$QUICK" = 0 ]; then
  step "1 · the sentinel cat: every work-status reaction, drawn"
  $PY - <<'PY'
from cybersecurity_agent.ui.pet import MOODS, render_lines

order = ["watching", "thinking", "typing", "hunting", "fur", "bristle", "steam", "denied",
         "waiting", "tilt", "hop", "arch", "flee", "sentry", "stretch", "water", "nap"]
assert set(order) == set(MOODS), "the demo gallery must show every mood, so keep this list in sync"
for mood in order:
    cols = [render_lines(mood, i) for i in range(min(2, len(MOODS[mood]["frames"])))]
    body = "\n".join("  ".join(c[r] for c in cols).rstrip() for r in range(6))
    print(f"  {mood:<9} {MOODS[mood]['label']}")
    print("\n".join("          " + ln for ln in body.splitlines() if ln.strip()))
PY
  note "17 moods · hand-written frames · one fixed 13×6 box so the live panel never jumps"
  note "no frame contains a single character from the email — that is asserted by a test"
fi

# ── 2 · investigate ─────────────────────────────────────────────────────────
SAMPLES="phishing_obvious gmail_bec_subtle"
[ "$QUICK" = 0 ] && SAMPLES="clean_newsletter phishing_obvious gmail_bec_subtle tor_exit_legit"
i=1
for s in $SAMPLES; do
  step "2.$i · investigate samples/${s}.eml  (deterministic engine, offline, gates auto)"
  run_case "$s"
  LAST="$s"
  i=$((i + 1))
done
CASE_DIR=$(newest_case)

# ── 3 · the hook + companion ────────────────────────────────────────────────
step "3 · runs/<case>/status.jsonl — what an external companion would watch"
tail -4 "${CASE_DIR}status.jsonl" || true
note "allowlisted fields · \`case\` is a digest, not the filename · \`note\` must be in NOTE_VOCAB"
leaks=$(count "paypal|dave|@|ignore previous|secure-p0nyail|203\.0\.113" "${CASE_DIR}status.jsonl")
printf '   attacker/case text in the status file: \033[1m%s\033[0m lines\n' "$leaks"
if [ "$leaks" != 0 ]; then printf '\033[31m   containment broken\033[0m\n'; exit 1; fi

step "3b · sentinel-ir pet — the companion rendering that same case"
$PY -m cybersecurity_agent pet --once --plain --tail 3 --path "${CASE_DIR}status.jsonl"

# ── 4 · care ────────────────────────────────────────────────────────────────
step "4 · care reminders mid-run (intervals compressed so you can actually see one fire)"
set +e
out=$($PY -m cybersecurity_agent investigate "samples/${LAST}.eml" --demo --no-llm $GEO \
        --remind "water=0.0002,eyes=0.0005" 2>&1)
set -e
printf '%s\n' "$out" | grep -E "\[care\]" | head -4 || true
CASE_DIR=$(newest_case)
printf '   care notes now in %s: audit.log=%s  report.md=%s\n' "${CASE_DIR}" \
  "$(count "care_reminder" "${CASE_DIR}audit.log")" "$(count "care reminder" "${CASE_DIR}report.md")"
note "the 12 ms interval makes it fire on nearly every loop tick — that is the knob working, not a bug"
note "0 in report.md is the point: the forensic transcript stays a document about the email"
note "defaults are eyes=20,stretch=30,water=45 minutes — a 20-second demo never gets nudged"

# ── 5 · skins ───────────────────────────────────────────────────────────────
if [ "$QUICK" = 0 ]; then
  step "5 · skins — the 'custom colour' feature, reduced to a palette"
  $PY - <<'PY'
from cybersecurity_agent.ui.pet import render_plain, skin_names, style_for
for skin in skin_names():
    print(f"  {skin:<14} arch → '{style_for('arch', skin)}'   hop → '{style_for('hop', skin)}'")
print()
print("  " + render_plain("arch").replace("\n", "\n  "))
PY
  note "identical art and identical numbers under every skin — colour is a cue, not the finding"
fi

# ── 6 · display-only proof ──────────────────────────────────────────────────
step "6 · proof the surface cannot move the case: same file, pet on vs pet off"
set +e
a=$($PY -m cybersecurity_agent investigate "samples/${LAST}.eml" --demo --no-llm $GEO --json 2>&1)
b=$($PY -m cybersecurity_agent investigate "samples/${LAST}.eml" --demo --no-llm $GEO --json --no-pet --no-status-hook 2>&1)
set -e
# Each run reports its own case dir through --json, so two runs inside the same second (case
# ids have second granularity) cannot be confused with each other.
da=$(printf '%s' "$a" | grep -oE '"report": *"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/' | xargs -r dirname || true)
db=$(printf '%s' "$b" | grep -oE '"report": *"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/' | xargs -r dirname || true)
for d in "$da" "$db"; do
  [ -n "$d" ] && [ -f "$d/run.json" ] || { printf '\033[31m   could not locate a case dir for the parity check\033[0m\n'; exit 1; }
done
sum() { $PY -c "import json,sys;d=json.load(open(sys.argv[1]))['verdict'];print(d['verdict'],d['risk'],d['confidence'],d['origin_source_kind'],[r['tool'] for r in json.load(open(sys.argv[1]))['results']])" "$1"; }
pa=$(sum "$da/run.json"); pb=$(sum "$db/run.json")
printf '   pet on : %s\n   pet off: %s\n' "$pa" "$pb"
if [ "$pa" = "$pb" ]; then
  note "identical verdict, risk, confidence, origin kind and executed plan ✓"
  note "a cartoon that could change a verdict would not ship"
else
  printf '\033[31m   they differ — that is a real bug, investigate it\033[0m\n'; exit 1
fi
if [ -f "$da/status.jsonl" ] && [ ! -f "$db/status.jsonl" ]; then
  note "--no-pet --no-status-hook: no panel, no reminders, no status file — nothing else changed"
else
  printf '\033[31m   status file written despite --no-status-hook (%s)\033[0m\n' "$db"; exit 1
fi

# ── 7 · ledger ──────────────────────────────────────────────────────────────
step "7 · evidence ledger (chain-of-custody, not detection)"
$PY -m cybersecurity_agent chain verify | tail -3
printf '\n\033[1mArtifacts for the pet-off case (%s):\033[0m\n  %s\n' "$db" "$(ls "$db" | tr '\n' ' ')"
printf '\033[1mArtifacts for the pet-on case (%s):\033[0m\n  %s\n' "$da" "$(ls "$da" | tr '\n' ' ')"
note "report.md (forensic) · run.json (machine) · evidence.json (custody) · audit.log (what happened) · status.jsonl (display)"
