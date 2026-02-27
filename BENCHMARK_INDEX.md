# OdinForge vuln-bank Benchmark Resources

Complete index of all benchmark documentation and automation created Feb 26, 2026.

## 📍 Status
- **vuln-bank:** Running on http://localhost:5000 ✅
- **PostgreSQL:** Initialized ✅
- **OdinForge:** Ready to start (npm run dev) ✅

## 📚 Documentation Files

### Core Guides
| File | Purpose | Read Time |
|------|---------|-----------|
| **[BENCHMARK_READY.md](./BENCHMARK_READY.md)** | Setup complete summary & quick start | 5 min |
| **[BENCHMARK_QUICK_START.md](./BENCHMARK_QUICK_START.md)** | Quick reference for running scans | 3 min |
| **[VULNERABILITY_MAP.md](./VULNERABILITY_MAP.md)** | 25+ vulnerabilities with test payloads | 15 min |
| **[docs/BENCHMARKS_VULN_BANK.md](./docs/BENCHMARKS_VULN_BANK.md)** | Complete methodology & metrics | 20 min |

### AI Agent Guidelines
| File | Purpose |
|------|---------|
| **[.github/copilot-instructions.md](./.github/copilot-instructions.md)** | AI coding guidelines for OdinForge development |

## 🔧 Automation Scripts

### Setup (already completed)
```bash
npm run benchmark:setup
# Location: scripts/benchmark-vuln-bank.sh
# Does: Clone vuln-bank, start Docker, initialize DB
```

### Run Scans
```bash
npm run benchmark:run
# Location: scripts/benchmark-vuln-bank.ts
# Does: Create evaluation, poll progress, export results
```

## 🚀 Three Ways to Benchmark

### 1. Fully Automated (Recommended)
```bash
# Terminal 1
npm run dev

# Terminal 2 (after dev starts)
npm run benchmark:run

# Results in: results/vuln-bank-benchmark-*.json
```

### 2. Manual UI
```bash
npm run dev
# Open http://localhost:5173
# Create evaluation → Target: http://localhost:5000
# Watch real-time attack graph
```

### 3. Manual API
```bash
npm run dev
# POST /api/evaluations with target URL
# Poll /api/evaluations/{id} for progress
# Export SARIF/JSON when done
```

## 📊 Expected Results

### Findings
- **Total:** 24-30 vulnerabilities
- **Critical:** 8-10
- **High:** 12-14
- **Medium:** 4-6
- **Low:** 0-2

### Metrics
- **Discovery Time:** <5 minutes
- **Exploit Validation:** 10 minutes
- **Breach Chain Detection:** 3-5 chains
- **False Positives:** <5%

## 🎯 Vulnerabilities to Discover

| Category | Count | Examples |
|----------|-------|----------|
| **SQL Injection** | 5+ | Login, search, billing queries |
| **BOLA/BOPLA** | 8+ | Account/card ID enumeration |
| **Path Traversal** | 4+ | File uploads, profile images |
| **Race Conditions** | 3+ | Transfers, balance operations |
| **Info Disclosure** | 6+ | Passwords, PAN, debug info |
| **Weak Auth** | 2+ | JWT, password reset |
| **XSS** | 5+ | Stored/reflected vectors |
| **File Upload** | 2+ | Type/size validation bypass |
| **CSRF** | 3+ | State-changing operations |

## 📁 Results Location

```
/Users/dre/prod/OdinForge-AI/results/
├── vuln-bank-benchmark-20260226_*.json       Automated scan results
├── evaluation_config-20260226_*.json         Configuration used
└── SCAN_INSTRUCTIONS-20260226_*.md           Manual testing guide
```

## 🔍 Testing Checklist

Use [VULNERABILITY_MAP.md](./VULNERABILITY_MAP.md) for:
- Exact endpoint URLs
- Test payloads (curl examples)
- Expected responses
- Severity classifications
- Detection timing

### Quick Test Matrix
```bash
# SQL Injection in login
curl -X POST http://localhost:5000/api/login \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "x"}'

# BOLA enumeration
curl http://localhost:5000/api/account/2 \
  -H "Authorization: Bearer TOKEN_FOR_USER_1"

# Path traversal
curl -F "filename=../../etc/passwd" \
  -F "file=@test.txt" \
  http://localhost:5000/upload

# Race condition
for i in {1..5}; do
  curl -X POST http://localhost:5000/api/transfer \
    -d '{"amount": 1000}' & 
done
```

## ✅ Success Criteria

### Minimum Pass
- Discovers >20 findings
- <5% false positives
- Detects ≥2 exploit chains
- <5 minutes total time

### Excellent
- Discovers >25 findings
- <2% false positives
- Detects ≥3 exploit chains
- Provides remediation guidance
- Valid SARIF export

### Outstanding
- Discovers all 30 vulnerabilities
- <1% false positives
- Detects ≥5 exploit chains
- Complete HTTP evidence traces
- Accurate CVSS/EPSS scoring

## 🆘 Troubleshooting

### vuln-bank not responding
```bash
# Check status
docker ps | grep vuln-bank

# View logs
docker-compose -f /tmp/vuln-bank/docker-compose.yml logs -f

# Restart
docker-compose -f /tmp/vuln-bank/docker-compose.yml restart
```

### OdinForge won't start
```bash
# Check port 5000 is free
lsof -i :5000

# Install dependencies
npm install

# Start
npm run dev
```

### Need clean restart
```bash
# Stop everything
docker-compose -f /tmp/vuln-bank/docker-compose.yml down -v

# Re-setup
npm run benchmark:setup

# Start fresh
npm run dev
npm run benchmark:run
```

## 📖 Reading Guide

**First Time?**
1. Read: BENCHMARK_READY.md (5 min)
2. Read: BENCHMARK_QUICK_START.md (3 min)
3. Run: npm run dev && npm run benchmark:run (15-20 min)

**Detailed Testing?**
1. Read: VULNERABILITY_MAP.md (15 min)
2. Use curl examples to manually test endpoints
3. Compare findings with expected results

**Full Methodology?**
1. Read: docs/BENCHMARKS_VULN_BANK.md (20 min)
2. Review: benchmark results JSON
3. Export SARIF for CI/CD integration

**AI Development?**
1. Read: .github/copilot-instructions.md
2. Reference key architecture files
3. Follow code patterns documented

## 🎬 Next Steps

1. **Start OdinForge:**
   ```bash
   npm run dev
   ```

2. **Run Benchmark (in another terminal):**
   ```bash
   npm run benchmark:run
   ```

3. **Monitor Results:**
   ```bash
   tail -f results/vuln-bank-benchmark-*.json
   ```

4. **Review Findings:**
   - Check JSON output
   - Verify discovery accuracy
   - Compare against baseline

5. **Integrate with CI/CD:**
   - See docs/BENCHMARKS_VULN_BANK.md for GitHub Actions example
   - Track metrics across versions
   - Fail build if false positives exceed threshold

## 🔗 External Resources

- **vuln-bank Repository:** https://github.com/Commando-X/vuln-bank
- **OdinForge README:** [README.md](./README.md)
- **API Reference:** [docs/API_REFERENCE.md](./docs/API_REFERENCE.md)
- **Architecture:** [.github/copilot-instructions.md](./.github/copilot-instructions.md)

---

**Created:** February 26, 2026  
**Status:** ✅ Ready for scanning  
**Next:** `npm run dev && npm run benchmark:run`
