#!/usr/bin/env bash
set -euo pipefail

log() { printf "\n\033[1;36m==>\033[0m %s\n" "$*"; }
warn() { printf "\n\033[1;33m[WARN]\033[0m %s\n" "$*"; }
die() { printf "\n\033[1;31m[ERR]\033[0m %s\n" "$*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

DB_CONTAINER_NAME="${DB_CONTAINER_NAME:-odinforge-postgres}"
DB_IMAGE="${DB_IMAGE:-pgvector/pgvector:pg15}"
DB_PORT_HOST="${DB_PORT_HOST:-5433}"
DB_PORT_CONTAINER="${DB_PORT_CONTAINER:-5432}"
DB_USER="${DB_USER:-odinforge}"
DB_PASS="${DB_PASS:-odinforge_dev_password}"
DB_NAME="${DB_NAME:-odinforge}"
DB_VOLUME="${DB_VOLUME:-odinforge_pgdata}"

XBOW_REPO_DIR="${XBOW_REPO_DIR:-/tmp/xbow-repo}"
XBOW_OUTPUT="${XBOW_OUTPUT:-/tmp/xbow-control-10.json}"
XBOW_LIMIT="${XBOW_LIMIT:-10}"
XBOW_TIMEOUT_MS="${XBOW_TIMEOUT_MS:-180000}"
CHAIN_LOOP_MAX_ITERS="${CHAIN_LOOP_MAX_ITERS:-6}"

PROJECT_ROOT="${PROJECT_ROOT:-$(pwd)}"
MIGRATION_FILE="${MIGRATION_FILE:-server/migrations/006_aev_telemetry.sql}"
XBOW_RUNNER="${XBOW_RUNNER:-server/benchmark/xbow/xbow-benchmark.ts}"

wait_for_pg() {
  local tries=60
  local i=0
  while [[ $i -lt $tries ]]; do
    if docker exec "$DB_CONTAINER_NAME" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  return 1
}

need_cmd docker
need_cmd node
need_cmd npx
need_cmd git

log "Preflight: Docker running"
docker info >/dev/null 2>&1 || die "Docker is not running."

log "Preflight: OPENAI_API_KEY present"
[[ -n "${OPENAI_API_KEY:-}" ]] || die "OPENAI_API_KEY is not set. Run: export OPENAI_API_KEY='sk-...'"
echo "$OPENAI_API_KEY" | head -c 8 >/dev/null || true

log "Preflight: required files exist"
[[ -f "$PROJECT_ROOT/$MIGRATION_FILE" ]] || die "Missing migration file: $PROJECT_ROOT/$MIGRATION_FILE"
[[ -f "$PROJECT_ROOT/$XBOW_RUNNER" ]] || die "Missing XBOW runner: $PROJECT_ROOT/$XBOW_RUNNER"

if [[ ! -d "$XBOW_REPO_DIR/.git" ]]; then
  log "Cloning XBOW repo -> $XBOW_REPO_DIR"
  rm -rf "$XBOW_REPO_DIR"
  git clone https://github.com/KeygraphHQ/xbow-validation-benchmarks.git "$XBOW_REPO_DIR"
else
  log "XBOW repo already exists -> $XBOW_REPO_DIR"
fi

log "Recreating $DB_CONTAINER_NAME on host port $DB_PORT_HOST (volume: $DB_VOLUME)"
if docker ps -a --format '{{.Names}}' | grep -qx "$DB_CONTAINER_NAME"; then
  docker stop "$DB_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rm "$DB_CONTAINER_NAME" >/dev/null 2>&1 || true
fi

docker volume inspect "$DB_VOLUME" >/dev/null 2>&1 || docker volume create "$DB_VOLUME" >/dev/null

docker run -d --name "$DB_CONTAINER_NAME" \
  -e POSTGRES_USER="$DB_USER" \
  -e POSTGRES_PASSWORD="$DB_PASS" \
  -e POSTGRES_DB="$DB_NAME" \
  -p "${DB_PORT_HOST}:${DB_PORT_CONTAINER}" \
  -v "${DB_VOLUME}:/var/lib/postgresql/data" \
  "$DB_IMAGE" >/dev/null

log "Waiting for Postgres..."
wait_for_pg || { docker logs --tail 200 "$DB_CONTAINER_NAME" || true; die "Postgres did not become ready"; }
log "Postgres ready."

export DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@localhost:${DB_PORT_HOST}/${DB_NAME}"
log "DATABASE_URL=$DATABASE_URL"

log "Testing DB connection from host via node+pg"
node -e "import('pg').then(async ({default:pg})=>{const c=new pg.Client({connectionString:process.env.DATABASE_URL});await c.connect();const r=await c.query('select 1 as ok');console.log('DB OK:', r.rows);await c.end();}).catch(e=>{console.error('DB FAIL:', e.message||e);process.exit(1);});"

log "Applying telemetry migration inside container"
docker exec -i "$DB_CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" < "$PROJECT_ROOT/$MIGRATION_FILE"

log "Sanity: tsc --noEmit"
npx tsc --noEmit

log "Sanity: vite build"
npx vite build

log "Running XBOW control benchmark (limit=$XBOW_LIMIT) -> $XBOW_OUTPUT"
ODINFORGE_MODE=aev_only \
BENCHMARK_MODE=1 \
CHAIN_LOOP_MAX_ITERS="$CHAIN_LOOP_MAX_ITERS" \
DATABASE_URL="$DATABASE_URL" \
OPENAI_API_KEY="$OPENAI_API_KEY" \
npx tsx "$PROJECT_ROOT/$XBOW_RUNNER" \
  "$XBOW_REPO_DIR" simulation \
  --limit "$XBOW_LIMIT" \
  --output "$XBOW_OUTPUT" \
  --timeout "$XBOW_TIMEOUT_MS"

log "Benchmark complete: $XBOW_OUTPUT"
log "Next commands:"
echo "jq '.telemetry' $XBOW_OUTPUT"
echo "jq '[.results[0], .results[1], .results[2]] | map({challengeId, success, vulnDetected, failureCode, agentTurns, toolCalls, agentRunMs, retryCount})' $XBOW_OUTPUT"
