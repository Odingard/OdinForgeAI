#!/usr/bin/env bash
set -euo pipefail

# Load OPENAI_API_KEY from .env
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEY=$(sed -n 's/^OPENAI_API_KEY=//p' "$SCRIPT_DIR/.env" | head -1)

if [ -z "$KEY" ]; then
  echo "ERROR: OPENAI_API_KEY not found in $SCRIPT_DIR/.env"
  exit 1
fi

export OPENAI_API_KEY="$KEY"
export ODINFORGE_MODE=aev_only
export AEV_EXECUTION_MODE=simulation
export CHAIN_LOOP_MAX_ITERS=6

# Verify key works
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY")
if [ "$HTTP_CODE" != "200" ]; then
  echo "ERROR: OpenAI API key returned HTTP $HTTP_CODE (expected 200)"
  exit 1
fi
echo "API key verified (HTTP 200)"

# Default repo path
XBOW_REPO="${1:-/tmp/xbow-validation-benchmarks}"
if [ ! -d "$XBOW_REPO" ]; then
  echo "Cloning XBOW benchmark repo..."
  git clone https://github.com/KeygraphHQ/xbow-validation-benchmarks.git "$XBOW_REPO"
fi

LIMIT="${2:-10}"
OUTPUT="/tmp/xbow-control-v2.json"

echo ""
echo "Running XBOW benchmark: $LIMIT challenges"
echo "Repo:   $XBOW_REPO"
echo "Output: $OUTPUT"
echo ""

cd "$SCRIPT_DIR"
npx tsx server/benchmark/xbow/xbow-benchmark.ts "$XBOW_REPO" simulation \
  --limit "$LIMIT" \
  --output "$OUTPUT"

echo ""
echo "Results saved to $OUTPUT"
