#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Compile cybersecurity_agent/blockchain/contract/EvidenceChain.sol into
# artifacts/EvidenceChain.json ({"bytecode": "0x…", "abi": […]}), which is what
# `python -m cybersecurity_agent chain deploy` looks for.
#
# Tries, in order: solcjs → solc → forge → npx hardhat. All are optional: with no
# artifact, SENTINEL-IR still logs evidence to the local hash-chain (the default).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=cybersecurity_agent/blockchain/contract/EvidenceChain.sol
OUT=artifacts
mkdir -p "$OUT"

if [ ! -f "$SRC" ]; then
  echo "missing $SRC" >&2; exit 1
fi

emit_solcjs() {
  echo "▶ solcjs"
  ( cd "$(dirname "$SRC")" && solcjs --bin --abi --optimize -o "$OLDPWD/$OUT/.solcjs" "$(basename "$SRC")" )
  local bin abi
  bin=$(ls "$OUT"/.solcjs/*_EvidenceChain.bin | head -1)
  abi=$(ls "$OUT"/.solcjs/*_EvidenceChain.abi | head -1)
  python3 - "$bin" "$abi" "$OUT/EvidenceChain.json" <<'PY'
import json, sys
bin_path, abi_path, out_path = sys.argv[1:4]
code = open(bin_path).read().strip()
abi = json.load(open(abi_path))
json.dump({"bytecode": "0x" + code, "abi": abi, "contract": "EvidenceChain"}, open(out_path, "w"), indent=1)
print("wrote", out_path, f"({len(code)//2} bytes of bytecode)")
PY
}

emit_solc() {
  echo "▶ solc"
  local bin abi
  bin=$(solc --bin --optimize "$SRC" | awk '/======.*EvidenceChain/ {p=1;next} /^======/ {p=0} p && /^[0-9a-fA-F]+$/ {print; exit}')
  abi=$(solc --abi --optimize "$SRC" | awk '/======.*EvidenceChain/ {p=1;next} /^======/ {p=0} p' )
  [ -n "$bin" ] || { echo "solc produced no bytecode"; return 1; }
  python3 - "$bin" "$abi" "$OUT/EvidenceChain.json" <<'PY'
import json, sys
code, abi_text, out_path = sys.argv[1:4]
json.dump({"bytecode": "0x" + code.strip(), "abi": json.loads(abi_text), "contract": "EvidenceChain"},
          open(out_path, "w"), indent=1)
print("wrote", out_path, f"({len(code.strip())//2} bytes of bytecode)")
PY
}

emit_forge() {
  echo "▶ forge (foundry)"
  tmp=$(mktemp -d)
  mkdir -p "$tmp/src" "$tmp/out"
  cp "$SRC" "$tmp/src/EvidenceChain.sol"
  printf '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\noptimize = true\n' > "$tmp/foundry.toml"
  ( cd "$tmp" && forge build --quiet )
  cp "$tmp/out/EvidenceChain.sol/EvidenceChain.json" "$OUT/EvidenceChain.json"
  echo "wrote $OUT/EvidenceChain.json (foundry artifact)"
  rm -rf "$tmp"
}

emit_hardhat() {
  echo "▶ npx hardhat (one-time node_modules download)"
  tmp=$(mktemp -d)
  mkdir -p "$tmp/contracts"
  cp "$SRC" "$tmp/contracts/EvidenceChain.sol"
  cat > "$tmp/hardhat.config.js" <<'JS'
module.exports = { solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } } };
JS
  ( cd "$tmp" && npm init -y >/dev/null 2>&1 \
      && npm i --no-audit --no-fund --silent hardhat@^2.22.0 )
  ( cd "$tmp" && npx hardhat compile --quiet )
  cp "$tmp/artifacts/contracts/EvidenceChain.sol/EvidenceChain.json" "$OUT/EvidenceChain.json"
  echo "wrote $OUT/EvidenceChain.json (hardhat artifact)"
  rm -rf "$tmp"
}

if command -v solcjs >/dev/null 2>&1; then emit_solcjs
elif command -v solc >/dev/null 2>&1; then emit_solc
elif command -v forge >/dev/null 2>&1; then emit_forge
elif command -v npx >/dev/null 2>&1; then emit_hardhat
else
  cat <<EOF
No Solidity compiler found. Pick one (any of these is fine, all offline after install):
  npm i -g solc                       # solcjs
  sudo apt install solc               # or: brew install solc
  curl -L https://foundry.paradigm.xyz | bash && foundryup     # forge
Then rerun: ./scripts/compile_contract.sh

Or skip the on-chain mirror entirely — the default hash-chain evidence log needs no
compiler, no node and no gas:
  python -m cybersecurity_agent chain verify
EOF
  exit 2
fi

echo "✓ artifact ready → python -m cybersecurity_agent chain deploy --help"
