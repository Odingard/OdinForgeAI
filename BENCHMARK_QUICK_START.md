# vuln-bank Benchmark Quick Start

**vuln-bank** is now running as a benchmark target for OdinForge. Use it to validate vulnerability detection, chaining, and scoring.

## Status

✅ **vuln-bank is running** at `http://localhost:5000`

```
vuln-bank-db-1    postgres:13     Up 15+ seconds    5432/tcp
vuln-bank-web-1   vuln-bank-web   Up 15+ seconds    5000/tcp, 80/tcp
```

---

## One-Command Benchmark

Start OdinForge in one terminal:
```bash
npm run dev
```

Then in another, run the automated benchmark:
```bash
npm run benchmark:run
```

Results are saved to `results/vuln-bank-benchmark-*.json`

---

## Manual Testing

### 1. Access vuln-bank
- **Web UI:** http://localhost:5000
- **API:** http://localhost:5000/api/

### 2. Create OdinForge Evaluation
- **UI:** http://localhost:5173 → New Evaluation → Target: `http://localhost:5000`
- **Execution Mode:** `safe` (no actual exploitation)
- **Scan Type:** `full_recon` (start with discovery)

### 3. Expected Findings
Within 2-5 minutes, OdinForge should discover:

| Category | Count | Examples |
|----------|-------|----------|
| **SQL Injection** | 5+ | Login, search, transactions |
| **BOLA/BOPLA** | 8+ | Account access, card management |
| **Path Traversal** | 4+ | File upload, profile images |
| **Race Conditions** | 3+ | Transfers, balance updates |
| **Info Disclosure** | 6+ | Error messages, debug endpoints |
| **Weak Auth** | 2+ | JWT secrets, token storage |
| **XSS** | 5+ | Multiple input fields |
| **Unrestricted Upload** | 2+ | File type, size validation |
| **CSRF** | 3+ | State-changing operations |

### 4. Watch Real-Time Progress
In the UI, the attack graph updates in real-time as OdinForge discovers endpoints and chains findings.

---

## Benchmark Scripts

### Setup vuln-bank (one-time)
```bash
npm run benchmark:setup
# Clones repo, starts Docker, initializes DB
```

### Run automated scan
```bash
npm run benchmark:run
# Creates evaluation, polls results, exports JSON
```

### Cleanup
```bash
cd /tmp/vuln-bank && docker-compose down -v
```

---

## Configuration

Environment variables (in `.env`):
```bash
# Optional: point to different OdinForge instance
ODINFORGE_API_URL=http://localhost:5000

# Optional: point to different vuln-bank instance  
VULN_BANK_URL=http://localhost:5000

# Optional: provide JWT token for API access
ODINFORGE_JWT_TOKEN=your_jwt_token_here
```

---

## Performance Targets

Use these as regression tests during development:

| Metric | Target | Current |
|--------|--------|---------|
| **Discovery Time** | <2m | ? |
| **Findings Accuracy** | >90% | ? |
| **False Positive Rate** | <5% | ? |
| **Breach Chain Detection** | 3+ chains | ? |

Run `npm run benchmark:run` to collect baseline data.

---

## What's Running

```
OdinForge         http://localhost:5000 (API)
OdinForge Client  http://localhost:5173 (UI)
vuln-bank         http://localhost:5000 → 5000:5000 (Docker)
vuln-bank DB      PostgreSQL localhost:5432
```

---

## Troubleshooting

### vuln-bank not responding
```bash
docker ps | grep vuln-bank
# If missing, run: npm run benchmark:setup
```

### OdinForge can't reach vuln-bank
```bash
# From OdinForge perspective (may be in Docker)
# Try: http://host.docker.internal:5000 instead
```

### Need to restart everything
```bash
# Stop vuln-bank
cd /tmp/vuln-bank && docker-compose down -v

# Stop OdinForge
# Kill terminal running `npm run dev`

# Start fresh
npm run benchmark:setup  # Terminal 1
npm run dev             # Terminal 2  
npm run benchmark:run   # Terminal 3
```

---

## Learn More

- **Full Benchmark Guide:** [docs/BENCHMARKS_VULN_BANK.md](../docs/BENCHMARKS_VULN_BANK.md)
- **vuln-bank GitHub:** https://github.com/Commando-X/vuln-bank
- **API Reference:** [docs/API_REFERENCE.md](../docs/API_REFERENCE.md)

---

Last updated: Feb 26, 2026
