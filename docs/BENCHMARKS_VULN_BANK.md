# OdinForge Benchmark: vuln-bank

This guide documents how to run OdinForge against [vuln-bank](https://github.com/Commando-X/vuln-bank), a deliberately vulnerable banking application designed for security testing.

## What is vuln-bank?

A Flask-based web application with 30+ intentional vulnerabilities across:
- **Authentication/Authorization** — SQL injection in login, weak JWT, BOLA/BOPLA
- **Data Security** — plaintext passwords, information disclosure, path traversal
- **Transactions** — race conditions, no amount validation, negative transfers
- **File Operations** — unrestricted uploads, SSRF via URL profile imports
- **Session Management** — no expiration, token exposure
- **Injection/XSS** — SQL injection, XSS, CSRF

Perfect for validating OdinForge's ability to detect real, chain-able vulnerabilities.

---

## Quick Start

### 1. Clone vuln-bank
```bash
git clone https://github.com/Commando-X/vuln-bank.git /tmp/vuln-bank
cd /tmp/vuln-bank
```

### 2. Start vuln-bank (Docker Compose)
```bash
cp .env.example .env
docker-compose up -d
# Waits for PostgreSQL initialization (~10s)
sleep 10

# Verify it's running
curl http://localhost:5000
# Should return HTML login page
```

vuln-bank will be accessible at:
- **UI:** http://localhost:5000
- **API:** http://localhost:5000/api/

### 3. OdinForge Scans

Start OdinForge (in another terminal):
```bash
cd /Users/dre/prod/OdinForge-AI
npm run dev
```

#### Create a Recon Evaluation
```bash
curl -X POST http://localhost:5000/api/evaluations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "assetId": "vuln-bank-001",
    "assetType": "web_application",
    "targetUrl": "http://localhost:5000",
    "executionMode": "safe",
    "scanType": "full_recon"
  }'
```

#### Expected Findings
OdinForge should discover:
- SQL injection endpoints (login, various query parameters)
- Path traversal vectors (profile upload, file operations)
- IDOR/BOLA endpoints (account access, card management)
- Race condition windows (transfers, balance updates)
- Information disclosure (debug info, error messages)
- Weak JWT secrets
- XSS vectors (various input fields)

#### Run Full Exploit Validation
```bash
curl -X POST http://localhost:5000/api/evaluations/{evalId}/exploit \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"executionMode": "simulation"}'
```

---

## Benchmark Metrics

Track these metrics across OdinForge versions:

| Metric | Target | Notes |
|--------|--------|-------|
| **Recon Accuracy** | 95%+ | % of known vulns discovered in recon phase |
| **Exploit Validation** | 80%+ | % of recon findings confirmed as exploitable |
| **False Positives** | <5% | % of reported findings that aren't actually exploitable |
| **Discovery Time** | <2m | Time to complete full recon scan |
| **Exploitation Time** | <5m | Time to validate all exploitable vectors |
| **Evidence Quality** | HTTP traces | Every finding includes request/response evidence |
| **Breach Chain Detection** | 3+ chains | Multi-phase attack paths (e.g., login SQLi → file upload → RCE) |

### Sample Evaluation Result
```json
{
  "evaluationId": "aev-vuln-bank-001",
  "assetUrl": "http://localhost:5000",
  "phases": {
    "recon": {
      "status": "completed",
      "findings": 31,
      "timeMs": 45000
    },
    "exploit": {
      "status": "completed",
      "validatedFindings": 24,
      "falsePositives": 2,
      "timeMs": 120000
    },
    "breach_chains": {
      "status": "completed",
      "chains": [
        {
          "name": "Login SQLi to Profile Upload RCE",
          "steps": [
            "SQL injection in login endpoint",
            "File upload without validation",
            "Execute uploaded code"
          ],
          "severity": "critical"
        }
      ]
    }
  },
  "totalVulnerabilities": 24,
  "criticalCount": 8,
  "highCount": 12,
  "mediumCount": 4
}
```

---

## Troubleshooting

### vuln-bank won't start
```bash
# Check if port 5000 is already in use
lsof -i :5000

# Check logs
docker-compose logs -f db
docker-compose logs -f web

# Restart everything
docker-compose down -v
docker-compose up -d
sleep 10
```

### PostgreSQL connection errors
```bash
# Wait for DB to be ready
docker-compose exec db pg_isready

# Manually initialize schema (if needed)
docker-compose exec db psql -U postgres -c "CREATE DATABASE vulnerable_bank;"
```

### OdinForge can't reach vuln-bank
- Verify vuln-bank is running: `curl http://localhost:5000`
- Check OdinForge can access localhost (not in container isolation)
- For Docker-based OdinForge, use `http://host.docker.internal:5000` or bridge network

---

## Cleanup

```bash
# Stop and remove vuln-bank
cd /tmp/vuln-bank
docker-compose down -v

# Optional: remove entire directory
rm -rf /tmp/vuln-bank
```

---

## Integration with OdinForge CI/CD

To automate vuln-bank scanning in CI/CD:

```yaml
# .github/workflows/benchmark.yml
name: vuln-bank Benchmark
on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start vuln-bank
        run: |
          git clone https://github.com/Commando-X/vuln-bank.git /tmp/vuln-bank
          cd /tmp/vuln-bank
          docker-compose up -d
          sleep 15
      
      - name: Run OdinForge scan
        run: npm run dev &  # Background
        working-directory: /Users/dre/prod/OdinForge-AI
      
      - name: Execute benchmark evaluation
        run: node scripts/benchmark-vuln-bank.ts
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: results/vuln-bank-*.json
```

---

## Real-World Validation

vuln-bank is valuable because:
1. **Known vulnerabilities** — All flaws are documented and reproducible
2. **Realistic attack chains** — Multiple vectors chain together naturally
3. **Business logic vulnerabilities** — Not just SQL injection, but IDOR, race conditions, workflow abuse
4. **Noise filtering** — Many vectors to test OdinForge's false positive reduction
5. **Multi-phase exploitation** — Login → file upload → RCE mirrors real attacks

This makes it ideal for:
- Release validation (did a code change break vulnerability detection?)
- Performance benchmarking (how fast can we scan?)
- False positive tuning (are we reducing noise?)
- Breach chain validation (can we chain 3+ findings?)
