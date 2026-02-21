#!/bin/bash
# Records a benchmark run as a terminal GIF for the README.
# Prerequisites: asciinema, agg, Docker (for Juice Shop)
#
# Usage: ./scripts/record-benchmark.sh

set -e

CAST_FILE="docs/assets/benchmark.cast"
GIF_FILE="docs/assets/benchmark.gif"

echo "=== OdinForge Benchmark Recording ==="
echo ""

# Check dependencies
command -v asciinema >/dev/null 2>&1 || { echo "Install asciinema: brew install asciinema"; exit 1; }
command -v agg >/dev/null 2>&1 || { echo "Install agg: brew install agg"; exit 1; }

# Ensure Juice Shop is running
if ! curl -sf http://localhost:3001 > /dev/null 2>&1; then
  echo "Starting Juice Shop..."
  docker rm -f juice-shop 2>/dev/null || true
  docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
  echo "Waiting for Juice Shop to start..."
  npx --yes wait-on@7 -t 120000 http://localhost:3001
fi

echo "Juice Shop is ready."
echo ""
echo "Recording benchmark to $CAST_FILE..."
echo "This will take ~90 seconds."
echo ""

# Record the benchmark run
asciinema rec "$CAST_FILE" \
  --cols 80 \
  --rows 35 \
  --title "OdinForge AI — Exploit Agent Benchmark" \
  --command "npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop --output /tmp/odinforge-benchmark-recording.json"

echo ""
echo "Converting to GIF..."

# Convert to GIF with a dark theme and reasonable speed
agg "$CAST_FILE" "$GIF_FILE" \
  --font-size 14 \
  --speed 2 \
  --theme monokai \
  --cols 80 \
  --rows 35

echo ""
echo "Done!"
echo "  Cast: $CAST_FILE"
echo "  GIF:  $GIF_FILE"
echo ""
echo "Add to README with:"
echo "  ![OdinForge Benchmark](docs/assets/benchmark.gif)"
