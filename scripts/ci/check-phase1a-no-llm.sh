#!/bin/bash
# LLM Boundary Amendment — CI Guard
# Fails the build if any LLM call appears in the active exploit engine.
# Phase 1A is deterministic HTTP execution only. Zero LLM calls allowed.

TARGET="server/services/active-exploit-engine.ts"

if [ ! -f "$TARGET" ]; then
  echo "ERROR: $TARGET not found"
  exit 1
fi

# Match LLM-related imports and API calls
# Patterns: OpenAI/Anthropic imports, chat completion calls, model references
PATTERN='(from ["'"'"']openai|import.*OpenAI|from ["'"'"']anthropic|chat\.completions\.create|gpt-[34]|claude-|ChatCompletion)'

# Collect matches excluding comment lines
TMPFILE=$(mktemp)
grep -nE "$PATTERN" "$TARGET" 2>/dev/null | grep -vE '^\s*//' | grep -vE '^\s*\*' > "$TMPFILE" || true

FORBIDDEN=$(wc -l < "$TMPFILE" | tr -d ' ')

if [ "$FORBIDDEN" -gt 0 ]; then
  echo "FAIL: LLM call detected in $TARGET"
  echo ""
  echo "Phase 1A (Active Exploit Engine) must contain zero LLM calls."
  echo "LLM is a classifier only — it belongs in the micro-agent orchestrator,"
  echo "not in the deterministic HTTP execution engine."
  echo ""
  echo "Matches found:"
  cat "$TMPFILE"
  rm -f "$TMPFILE"
  exit 1
fi

rm -f "$TMPFILE"
echo "PASS: $TARGET is LLM-free"
