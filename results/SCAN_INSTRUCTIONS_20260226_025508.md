# Manual Scan Instructions for vuln-bank Benchmark

vuln-bank is running at: http://localhost:5000

## Step 1: Start OdinForge

In another terminal:
```bash
cd /Users/dre/prod/OdinForge-AI
npm run dev
# Server starts at http://localhost:5000
# Client at http://localhost:5173
```

## Step 2: Create Evaluation via UI or API

### Option A: Via UI
1. Open http://localhost:5173
2. Login with your credentials
3. Create new evaluation → "Web Application"
4. Target URL: `http://localhost:5000`
5. Execution Mode: `safe`
6. Run evaluation

### Option B: Via API
First, get a JWT token:
```bash
EVAL_CONFIG="/Users/dre/prod/OdinForge-AI/results/evaluation_config_20260226_025508.json"

# You'll need to authenticate first
# This example assumes you have admin access
curl -X POST http://localhost:5000/api/evaluations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d @$EVAL_CONFIG
```

## Step 3: Monitor Real-Time Results

Watch the evaluation progress via WebSocket in the UI, or check database:
```bash
# Check evaluation status in PostgreSQL
psql $DATABASE_URL -c "SELECT id, status, created_at FROM aev_evaluations ORDER BY created_at DESC LIMIT 1;"

# Check findings
psql $DATABASE_URL -c "SELECT id, finding_type, severity, asset_id FROM aev_findings WHERE asset_id LIKE 'vuln-bank%' LIMIT 20;"
```

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
```bash
# SARIF format (for CI/CD integration)
curl -X GET http://localhost:5000/api/evaluations/{evalId}/export/sarif \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o "/Users/dre/prod/OdinForge-AI/results/vuln-bank-20260226_025508.sarif"

# JSON format
curl -X GET http://localhost:5000/api/evaluations/{evalId}/report \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o "/Users/dre/prod/OdinForge-AI/results/vuln-bank-report-20260226_025508.json"
```

## Cleanup

When done:
```bash
cd /tmp/vuln-bank
docker-compose down -v

# Optional: remove directory
rm -rf /tmp/vuln-bank
```

---

For detailed information, see: /Users/dre/prod/OdinForge-AI/docs/BENCHMARKS_VULN_BANK.md
