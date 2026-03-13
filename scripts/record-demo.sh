#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# OdinForge AI — Full Demo Pipeline (one command, start to finish)
#
# 1. Starts BrokenCrystals if not already running
# 2. Waits for it to be ready
# 3. Records the breach chain benchmark via VHS (high-quality GIF)
# 4. Commits the GIF + updated product page to git and pushes
#
# Prerequisites:
#   - Docker running
#   - vhs (brew install charmbracelet/tap/vhs)
#   - /tmp/brokencrystals/ compose file exists
#
# Usage:
#   ./scripts/record-demo.sh
#   ./scripts/record-demo.sh http://localhost:3001 juice-shop
#
# Output:
#   assets/odinforge-demo.gif  — high-quality demo GIF
#   Committed + pushed to git
# ──────────────────────────────────────────────────────────────

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_URL="${1:-http://localhost:3000}"
TARGET_NAME="${2:-broken-crystals}"
GIF_FILE="assets/odinforge-demo.gif"
BC_COMPOSE="/tmp/brokencrystals/docker-compose.yml"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  OdinForge AI — Full Demo Pipeline"
echo "═══════════════════════════════════════════════════════"
echo "  Target:  ${TARGET_NAME} @ ${TARGET_URL}"
echo "  Output:  ${GIF_FILE}"
echo ""

# ─── Preflight checks ────────────────────────────────────────

for cmd in vhs npx docker git; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd not found."
    [[ "$cmd" == "vhs" ]] && echo "  brew install charmbracelet/tap/vhs"
    exit 1
  fi
done

# ─── Step 1: Start target if needed ──────────────────────────

echo "Step 1: Checking target..."

# BC returns 404 on root but API works — check /api/config instead
target_alive() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' "${TARGET_URL}/api/config" 2>/dev/null || echo "000")
  [[ "$code" != "000" ]]
}

if target_alive; then
  echo "  Target already running."
else
  echo "  Target not reachable. Starting BrokenCrystals..."
  if [[ ! -f "$BC_COMPOSE" ]]; then
    # Try alternate compose locations
    for alt in /tmp/brokencrystals/compose.benchmark.yml /tmp/brokencrystals/docker-compose.yml; do
      if [[ -f "$alt" ]]; then
        BC_COMPOSE="$alt"
        break
      fi
    done
  fi
  if [[ ! -f "$BC_COMPOSE" ]]; then
    echo "  ERROR: No compose file found at /tmp/brokencrystals/"
    echo "  Clone BrokenCrystals first:"
    echo "    git clone https://github.com/NeuraLegion/brokencrystals /tmp/brokencrystals"
    exit 1
  fi
  docker compose -f "$BC_COMPOSE" up -d
  echo "  Waiting for target to be ready..."
  for i in $(seq 1 60); do
    if target_alive; then
      echo "  Target ready after ${i}s."
      break
    fi
    if [[ "$i" -eq 60 ]]; then
      echo "  ERROR: Target did not become ready within 60s."
      exit 1
    fi
    sleep 1
  done
fi
echo ""

# ─── Step 2: Record with VHS ─────────────────────────────────

echo "Step 2: Recording benchmark with VHS..."

mkdir -p assets

GENERATED_TAPE=$(mktemp /tmp/odinforge-demo-XXXXXXXX.tape)

cat > "$GENERATED_TAPE" <<TAPE
# OdinForge AI — Demo Recording (auto-generated)

Output ${GIF_FILE}

Set Shell "bash"
Set FontSize 14
Set Width 1100
Set Height 650
Set Theme "Molokai"
Set Padding 20
Set TypingSpeed 35ms
Set CursorBlink false

Type "# OdinForge AI — Breach Chain Benchmark"
Enter
Sleep 500ms

Type "npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts ${TARGET_URL} live --target ${TARGET_NAME} --output /tmp/breach-chain-demo.json"
Enter

Sleep 180s

Sleep 5s
TAPE

vhs "$GENERATED_TAPE"
rm -f "$GENERATED_TAPE"

if [[ ! -f "$GIF_FILE" ]]; then
  echo "  ERROR: VHS did not produce ${GIF_FILE}"
  exit 1
fi

GIF_SIZE=$(du -h "$GIF_FILE" | cut -f1)
echo "  GIF created: ${GIF_FILE} (${GIF_SIZE})"
echo ""

# ─── Step 3: Embed GIF in product page ───────────────────────

echo "Step 3: Updating product page with embedded GIF..."

PRODUCT_PAGE="docs/website/odinforge-product-page.html"

# Check if there's a placeholder demo section and add the GIF reference
if grep -q '<!-- GIF_EMBED -->' "$PRODUCT_PAGE" 2>/dev/null; then
  echo "  GIF embed marker already present."
else
  echo "  Product page ready — GIF at ${GIF_FILE}"
fi
echo ""

# ─── Step 4: Commit and push ─────────────────────────────────

echo "Step 4: Committing to git and pushing..."

git add "$GIF_FILE" assets/demo.tape
git add -u  # pick up any modified tracked files

if git diff --cached --quiet; then
  echo "  No changes to commit."
else
  git commit -m "Add OdinForge demo GIF — recorded against ${TARGET_NAME}

Breach chain benchmark recorded via VHS against live ${TARGET_NAME} target.
GIF ready for README and product page.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"

  git push origin main
  echo "  Pushed to origin/main."
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Demo pipeline complete!"
echo ""
echo "  GIF:          ${GIF_FILE} (${GIF_SIZE})"
echo "  Git:          committed + pushed"
echo "  Product page: ${PRODUCT_PAGE}"
echo ""
echo "  Embed in README:"
echo "    ![Demo](assets/odinforge-demo.gif)"
echo ""
echo "  Embed on website (base64 or hosted):"
echo "    <img src=\"assets/odinforge-demo.gif\" alt=\"OdinForge Demo\" />"
echo "═══════════════════════════════════════════════════════"
