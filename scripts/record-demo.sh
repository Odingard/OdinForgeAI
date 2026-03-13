#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# OdinForge AI — High-Quality Demo GIF Generator
#
# Records the breach chain benchmark running against a live
# target and produces a polished GIF using VHS (Charm).
#
# Prerequisites:
#   - Target running (e.g. BrokenCrystals at http://localhost:3000)
#   - vhs (brew install charmbracelet/tap/vhs)
#
# Usage:
#   ./scripts/record-demo.sh [target-url] [target-name]
#
# Output:
#   assets/odinforge-demo.gif   — ready for README
# ──────────────────────────────────────────────────────────────

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_URL="${1:-http://localhost:3000}"
TARGET_NAME="${2:-broken-crystals}"
TAPE_FILE="assets/demo.tape"
GIF_FILE="assets/odinforge-demo.gif"

# ─── Preflight checks ────────────────────────────────────────

for cmd in vhs npx; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd not found."
    [[ "$cmd" == "vhs" ]] && echo "  brew install charmbracelet/tap/vhs"
    exit 1
  fi
done

if ! curl -sf "$TARGET_URL" >/dev/null 2>&1; then
  echo "ERROR: Target not reachable at $TARGET_URL"
  echo ""
  echo "Start BrokenCrystals:"
  echo "  docker compose -f /tmp/brokencrystals/compose.benchmark.yml up -d"
  echo ""
  echo "Or pass a different target:"
  echo "  ./scripts/record-demo.sh http://localhost:3001 juice-shop"
  exit 1
fi

mkdir -p assets

# ─── Generate tape with correct target ───────────────────────

GENERATED_TAPE=$(mktemp /tmp/odinforge-demo-XXXX.tape)

cat > "$GENERATED_TAPE" <<TAPE
# OdinForge AI — Demo Recording (auto-generated)

Output ${GIF_FILE}

Set Shell "bash"
Set FontSize 14
Set Width 1100
Set Height 650
Set Theme "Monokai"
Set Padding 20
Set TypingSpeed 35ms
Set CursorBlink false

Type "# OdinForge AI — Breach Chain Benchmark"
Enter
Sleep 500ms

Type "npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts ${TARGET_URL} live --target ${TARGET_NAME} --output /tmp/breach-chain-demo.json"
Enter

Sleep 120s

Sleep 5s
TAPE

# ─── Record ───────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════"
echo "  Recording demo: ${TARGET_NAME} @ ${TARGET_URL}"
echo "  Output: ${GIF_FILE}"
echo "═══════════════════════════════════════════════════════"
echo ""

vhs "$GENERATED_TAPE"

rm -f "$GENERATED_TAPE"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Done!"
echo "  GIF: ${GIF_FILE}"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Add to README.md:"
echo '  ![Demo](assets/odinforge-demo.gif)'
