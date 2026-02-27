#!/bin/bash
# benchmark-vuln-bank.sh — One-command setup and scanning of vuln-bank with OdinForge

set -e

VULN_BANK_DIR="/tmp/vuln-bank"
ODINFORGE_DIR="/Users/dre/prod/OdinForge-AI"
BENCHMARK_RESULTS_DIR="$ODINFORGE_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$BENCHMARK_RESULTS_DIR/vuln-bank_${TIMESTAMP}.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# 1. Setup vuln-bank
# ============================================================================

log_info "Step 1: Setting up vuln-bank..."

if [ -d "$VULN_BANK_DIR" ]; then
  log_info "vuln-bank already cloned, updating..."
  cd "$VULN_BANK_DIR"
  git pull origin main 2>/dev/null || true
else
  log_info "Cloning vuln-bank repository..."
  git clone https://github.com/Commando-X/vuln-bank.git "$VULN_BANK_DIR"
fi

cd "$VULN_BANK_DIR"

# Setup environment
if [ ! -f ".env" ]; then
  cp .env.example .env
  log_info "Created .env file (using defaults)"
fi

# Stop any running instances
log_info "Stopping any existing vuln-bank containers..."
docker-compose down 2>/dev/null || true

# Start fresh
log_info "Starting vuln-bank with Docker Compose..."
docker-compose up -d

# Wait for PostgreSQL to be ready
log_info "Waiting for PostgreSQL to initialize..."
sleep 15

# Health check
MAX_RETRIES=30
RETRY_COUNT=0
while ! curl -s http://localhost:5000 > /dev/null; do
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    log_error "vuln-bank failed to start after ${MAX_RETRIES} seconds"
    docker-compose logs
    exit 1
  fi
  echo -n "."
  sleep 1
done

log_success "vuln-bank is running at http://localhost:5000"

# ============================================================================
# 2. Verify OdinForge environment
# ============================================================================

log_info "Step 2: Verifying OdinForge..."

if [ ! -d "$ODINFORGE_DIR" ]; then
  log_error "OdinForge directory not found: $ODINFORGE_DIR"
  exit 1
fi

cd "$ODINFORGE_DIR"

# Check dependencies
if [ ! -d "node_modules" ]; then
  log_info "Installing OdinForge dependencies..."
  npm install
fi

# Ensure results directory exists
mkdir -p "$BENCHMARK_RESULTS_DIR"

log_success "OdinForge is ready"

# ============================================================================
# 3. Create evaluation and collect results
# ============================================================================

log_info "Step 3: Creating OdinForge evaluation for vuln-bank..."

# First, we need to get a JWT token
# This assumes you have a default admin user set up
# You may need to create one first

log_info "Getting authentication token..."

# For now, we'll use environment variable or create a test evaluation
# In production, integrate with actual OdinForge API

cat > "$BENCHMARK_RESULTS_DIR/evaluation_config_${TIMESTAMP}.json" <<EOF
{
  "assetId": "vuln-bank-benchmark-${TIMESTAMP}",
  "assetType": "web_application",
  "targetUrl": "http://localhost:5000",
  "targetDescription": "vuln-bank: Deliberately vulnerable banking application",
  "executionMode": "safe",
  "scanType": "full_recon",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

log_info "Evaluation config saved to: $BENCHMARK_RESULTS_DIR/evaluation_config_${TIMESTAMP}.json"

# ============================================================================
# 4. Manual scan instructions
# ============================================================================

cat > "$BENCHMARK_RESULTS_DIR/SCAN_INSTRUCTIONS_${TIMESTAMP}.md" <<EOF
# Manual Scan Instructions for vuln-bank Benchmark

vuln-bank is running at: http://localhost:5000

## Step 1: Start OdinForge

In another terminal:
\`\`\`bash
cd $ODINFORGE_DIR
npm run dev
# Server starts at http://localhost:5000
# Client at http://localhost:5173
\`\`\`

## Step 2: Create Evaluation via UI or API

### Option A: Via UI
1. Open http://localhost:5173
2. Login with your credentials
3. Create new evaluation → "Web Application"
4. Target URL: \`http://localhost:5000\`
5. Execution Mode: \`safe\`
6. Run evaluation

### Option B: Via API
First, get a JWT token:
\`\`\`bash
EVAL_CONFIG="$BENCHMARK_RESULTS_DIR/evaluation_config_${TIMESTAMP}.json"

# You'll need to authenticate first
# This example assumes you have admin access
curl -X POST http://localhost:5000/api/evaluations \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -d @\$EVAL_CONFIG
\`\`\`

## Step 3: Monitor Real-Time Results

Watch the evaluation progress via WebSocket in the UI, or check database:
\`\`\`bash
# Check evaluation status in PostgreSQL
psql \$DATABASE_URL -c "SELECT id, status, created_at FROM aev_evaluations ORDER BY created_at DESC LIMIT 1;"

# Check findings
psql \$DATABASE_URL -c "SELECT id, finding_type, severity, asset_id FROM aev_findings WHERE asset_id LIKE 'vuln-bank%' LIMIT 20;"
\`\`\`

## Step 4: Expected Discoveries

OdinForge should find at least:
- **SQL Injection** in login endpoint, various query parameters
- **BOLA/BOPLA** in account/card access endpoints
- **Path Traversal** in file upload functionality
- **Race Conditions** in transfer/balance operations
- **Information Disclosure** in error messages, debug endpoints
- **Weak Authentication** JWT vulnerabilities
- **XSS Vectors** in multiple input fields
- **File Upload Issues** unrestricted uploads, type validation bypass

## Step 5: Export Results

Once evaluation completes, export findings:
\`\`\`bash
# SARIF format (for CI/CD integration)
curl -X GET http://localhost:5000/api/evaluations/{evalId}/export/sarif \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -o "$BENCHMARK_RESULTS_DIR/vuln-bank-${TIMESTAMP}.sarif"

# JSON format
curl -X GET http://localhost:5000/api/evaluations/{evalId}/report \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -o "$BENCHMARK_RESULTS_DIR/vuln-bank-report-${TIMESTAMP}.json"
\`\`\`

## Cleanup

When done:
\`\`\`bash
cd /tmp/vuln-bank
docker-compose down -v

# Optional: remove directory
rm -rf /tmp/vuln-bank
\`\`\`

---

For detailed information, see: $ODINFORGE_DIR/docs/BENCHMARKS_VULN_BANK.md
EOF

log_success "Scan instructions saved to: $BENCHMARK_RESULTS_DIR/SCAN_INSTRUCTIONS_${TIMESTAMP}.md"

# ============================================================================
# 5. Summary
# ============================================================================

echo ""
log_success "vuln-bank benchmark setup complete!"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Open another terminal and start OdinForge:"
echo "   cd $ODINFORGE_DIR && npm run dev"
echo ""
echo "2. Access OdinForge UI:"
echo "   http://localhost:5173"
echo ""
echo "3. vuln-bank is ready at:"
echo "   http://localhost:5000"
echo ""
echo "4. Create a new evaluation targeting: http://localhost:5000"
echo ""
echo "📊 Results will be saved to:"
echo "   $BENCHMARK_RESULTS_DIR/"
echo ""
echo "📄 Configuration:"
echo "   $BENCHMARK_RESULTS_DIR/evaluation_config_${TIMESTAMP}.json"
echo ""
echo "📖 Detailed Instructions:"
echo "   $BENCHMARK_RESULTS_DIR/SCAN_INSTRUCTIONS_${TIMESTAMP}.md"
echo ""

# Display current status
echo "🟢 Current Status:"
docker-compose -f "$VULN_BANK_DIR/docker-compose.yml" ps
