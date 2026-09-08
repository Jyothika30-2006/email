#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SENTINEL-IR local setup. Nothing here phones home except (optionally) PyPI,
# Ollama's model pull, and the free GeoIP/reputation endpoints you choose to use.
#
#   ./scripts/setup.sh              # venv + core deps + sample corpus + selftest
#   ./scripts/setup.sh --with-ollama [llama3.1:8b]
#   ./scripts/setup.sh --with-sandbox
#   ./scripts/setup.sh --with-chain
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
VENV=.venv
MODE=core

for arg in "$@"; do
  case "$arg" in
    --with-ollama) MODE=ollama ;;
    --with-sandbox) MODE=sandbox ;;
    --with-chain) MODE=chain ;;
    --help|-h) sed -n '2,12p' "$0"; exit 0 ;;
    *) OLLAMA_MODEL="$arg" ;;
  esac
done

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

step "1/6 Python venv ($($PY --version 2>&1))"
if [ ! -d "$VENV" ]; then
  $PY -m venv "$VENV"
fi
VPY="$VENV/bin/python"
"$VPY" -m pip install --upgrade pip -q
ok "venv ready: $VENV"

step "2/6 Core dependencies (rich, dnspython) + this package"
"$VPY" -m pip install -q rich dnspython
"$VPY" -m pip install -q -e .
ok "installed; entry point: $VENV/bin/sentinel-ir"

step "3/6 Test dependencies"
"$VPY" -m pip install -q pytest
ok "pytest"

step "4/6 Sample corpus (4 .eml + attachments + fixtures)"
if [ -d samples ] && ls samples/*.eml >/dev/null 2>&1; then
  ok "samples/ already populated"
else
  "$VPY" scripts/generate_samples.py
  ok "samples/ regenerated"
fi

step "5/6 Optional layers"
case "$MODE" in
  ollama)
    if command -v ollama >/dev/null 2>&1; then
      M="${OLLAMA_MODEL:-llama3.1:8b}"
      warn "ollama found → pulling $M (needs internet once; inference stays local)"
      ollama pull "$M" && ok "model $M ready"
    else
      warn "ollama not installed — install from https://ollama.com, then: ollama pull llama3.1:8b"
      warn "the agent still runs fully: it falls back to the deterministic engine and SAYS so"
    fi
    ;;
  sandbox)
    if command -v docker >/dev/null 2>&1; then
      docker build -t sentinel-sandbox:latest -f cybersecurity_agent/sandbox/Dockerfile cybersecurity_agent/sandbox \
        && ok "sandbox image built (network-less, read-only /work)" \
        || warn "image build failed — static_file_scan will use the subprocess fallback (reported in every run)"
    else
      warn "docker not found. Either install Docker, or run REMnux/Kali in a VM and set:"
      warn "  export SENTINEL_SANDBOX_IMAGE=<your image>   # and keep SENTINEL_SANDBOX_REQUIRED=1"
    fi
    ;;
  chain)
    "$VPY" -m pip install -q pycryptodome && ok "pycryptodome (keccak-256 for the ganache mirror)"
    if command -v ganache >/dev/null 2>&1; then
      ok "ganache present — start it with: ganache --wallet.seed sentinel --chain.chainId 1337"
    else
      warn "ganache not installed (npm i -g ganache). Without it the local hash-chain is used automatically."
    fi
    ./scripts/compile_contract.sh || warn "contract artifact not built — 'chain deploy' needs it (hash-chain does not)"
    ;;
  *)
    warn "optional layers skipped: rerun with --with-ollama / --with-sandbox / --with-chain"
    ;;
esac

step "6/6 Selftest + unit tests"
"$VPY" -m cybersecurity_agent selftest && ok "safety invariants verified"
"$VPY" -m pytest -q || warn "tests failed — check the output above before demoing"

cat <<'EOF'

Next steps
──────────
  source .venv/bin/activate
  cp config/default.env.example config/local.env && $EDITOR config/local.env   # optional
  source config/local.env                                                       # optional

  # live demo, no external services at all:
  python -m cybersecurity_agent mock-apis --port 8099 &
  export SENTINEL_DNS_FIXTURES=samples/fixtures/dns_fixtures.json
  export SENTINEL_TOR_EXIT_FIXTURE=samples/fixtures/tor_exit_ips.txt
  python -m cybersecurity_agent investigate samples/phishing_obvious.eml --demo \
      --geo-base-url http://127.0.0.1:8099 --reputation-base-url http://127.0.0.1:8099 \
      --geoip-allow-private

  # with your local model as the brain (Ollama must be running):
  python -m cybersecurity_agent investigate ~/Downloads/suspicion.eml
EOF
