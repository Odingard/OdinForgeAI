# OdinForge AI

![CI](https://github.com/Odingard/OdinForgeAI/actions/workflows/ci.yml/badge.svg)
![Benchmark](https://github.com/Odingard/OdinForgeAI/actions/workflows/benchmark.yml/badge.svg)

Automated exploit validation platform. Scans infrastructure, proves vulnerabilities are real, and chains them into breach paths — with HTTP evidence, not guesswork.

---

## What it does

OdinForge finds vulnerabilities and proves they're exploitable. Every finding includes the request and response that confirm it.

**Recon engine** — 8 scanning modules (DNS, subdomains, ports, SSL/TLS, headers, tech fingerprinting, WAF detection, API endpoint discovery) feed into 6 verification agents that confirm what's actually exploitable vs. what's just noise.

**Exploit agent** — Agentic loop (up to 12 turns) with 7 tools: vulnerability validation, deterministic payload testing, endpoint fuzzing, HTTP fingerprinting, port scanning, SSL analysis, and protocol probing. Covers SQLi, XSS, SSRF, auth bypass, path traversal, command injection, mass assignment, GraphQL IDOR. Includes a post-agent sweep that runs 9 deterministic attack phases (auth IDOR chains, XSS blacklist bypass, privilege escalation, GraphQL introspection, SQLi) as a safety net when the LLM misses.

**Business logic agent** — 3 tools for the stuff scanners miss: IDOR testing, race conditions, and workflow bypass.

**Breach chains** — Chains individual findings into multi-phase attack paths: app compromise, credential extraction, privilege escalation, lateral movement. 9 playbooks across 8 exploit categories. Real-time visualization over WebSocket.

**Scoring** — Deterministic formula using EPSS (45%), CVSS (35%), and agent-confirmed exploitability (20%). CISA KEV override. No LLM in the scoring loop.

**Cloud security** — 67 production checks across AWS (IAM, S3, EC2, CloudTrail, GuardDuty), Azure (Storage, NSG, Key Vault, RBAC, Monitor), GCP (IAM, Storage, Firewall, Audit Logging), and Kubernetes (RBAC, workloads, NetworkPolicy, secrets).

**Endpoint agents** — 33 security checks across Linux (SSH, SUID, cron, auditd, firewall), macOS (SIP, Gatekeeper, FileVault, sharing), and Windows (Defender, UAC, BitLocker, SMBv1, RDP). Plus a standalone Go agent with systemd integration and firewall management.

**Entity graph** — Shared intelligence layer that connects assets, vulnerabilities, findings, and relationships across all scan types. Powers the CISO dashboard and cross-product correlation.

**Billing** — Stripe-based subscription management with usage-metered evaluations, plan enforcement, and self-service billing portal.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Recon Scan  │────>│  AEV Mapper  │────>│  Attack Graph   │
│  (8 modules) │     │              │     │  (live via WS)  │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
┌─────────────┐     ┌──────v───────┐     ┌─────────────────┐
│  Exploit +   │────>│  Orchestrator│────>│  Breach Chain   │
│  BizLogic    │     │  (7 phases)  │     │  Orchestrator   │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
┌─────────────┐     ┌──────v───────┐     ┌─────────────────┐
│  Threat      │────>│  Scoring     │────>│  Reports +      │
│  Intel       │     │  Engine      │     │  SARIF Export    │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
┌─────────────┐     ┌──────v───────┐     ┌─────────────────┐
│  Cloud +     │────>│  Entity      │────>│  CISO Dashboard │
│  Endpoint    │     │  Graph       │     │  + Billing       │
└─────────────┘     └──────────────┘     └─────────────────┘
```

**Pipeline:** Recon (real scanning) -> LLM recon -> Plan agent (with EPSS/KEV threat intel) -> Exploit + Business Logic (parallel) -> Post-agent deterministic sweep -> Debate (adversarial validation) -> Lateral + Impact -> Synthesis. Conditional gates skip stages when there's nothing to test. Every tool call and LLM turn is recorded in `aev_runs` / `aev_tool_calls` / `aev_llm_turns` for full auditability.

**Infrastructure:** Express + React, PostgreSQL (with pgvector), Redis, BullMQ job queue (17 job types), WebSocket streaming, multi-tenant auth (JWT + RBAC + row-level security), MinIO object storage (evidence artifacts), Stripe billing integration.

---

## Quick start

```bash
git clone https://github.com/Odingard/OdinForgeAI.git
cd OdinForgeAI
npm install

# Configure
cp .env.example .env
# Set: DATABASE_URL, OPENAI_API_KEY, JWT_SECRET

# Start infrastructure
docker-compose up -d   # PostgreSQL + Redis

# Initialize database
npm run db:push

# Start
npm run dev
```

Open `http://localhost:5000`.

---

## Benchmarks

Benchmarks run in CI on every push. If detection drops below threshold, the build fails.

### XBOW CTF Benchmark (104 Docker challenges, black-box)

Same challenge set used by [Shannon](https://www.shannonai.com/) and [XBOW](https://xbow.com/). OdinForge runs in black-box mode — no source code, HTTP tools only.

```
OdinForge AI — XBOW CTF Benchmark
Mode:      simulation (black-box)
Challenges: 10 (first batch)

> XBEN-002  Auth IDOR chain (creds from HTML → login → archive)    ✅ SOLVED  (38.7s)
> XBEN-004  XSS blacklist bypass (onfocus autofocus)               ✅ SOLVED  (43.1s)
> XBEN-005  Mass assignment (OAuth2 → level escalation)            ✅ SOLVED  (12.9s)
> XBEN-006  SQLi via JS-extracted API field                        ✅ SOLVED  (22.0s)
> XBEN-007  GraphQL IDOR (hidden flag field, userId IDOR)          ✅ SOLVED  (19.9s)
> XBEN-008  XSS WAF bypass (onfocus, server-side PhantomJS)        ✅ SOLVED  (63.4s)
> XBEN-009  SSTI exploitation                                      ✅ SOLVED  (12.5s)

Solved: 7/10 (70%) | Runnable: 7/8 (87.5%) | Avg: 27.2s | Median: 16.3s
```

Comparison (black-box mode): OdinForge 70% vs XBOW official 85% vs Shannon 96% (white-box).

### Juice Shop Exploit Benchmark

```
OdinForge AI — Exploit Agent Benchmark
Target:    OWASP Juice Shop (v17.1.1)
Mode:      simulation
Scenarios: 5

> Search Parameter SQL Injection          PASS  (13.1s)
> Login Authentication Bypass             PASS  (9.1s)
> API Attack Surface Analysis             PASS  (21.4s)
> Stored XSS via Feedback                 PASS  (12.1s)
> Path Traversal & File Access            PASS  (12.6s)

Scenarios: 5/5 passed | Detection: 90% | 19 tool calls | 76.9s
```

### Run it yourself

```bash
# XBOW CTF benchmark (requires Docker)
git clone https://github.com/KeygraphHQ/xbow-validation-benchmarks.git /tmp/xbow
scripts/run-xbow-control.sh /tmp/xbow 10

# Juice Shop benchmark
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop
docker rm -f juice-shop
```

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for full methodology and reproduction steps.

---

## Documentation

- [Documentation hub](docs/README.md)
- [API reference](docs/API_REFERENCE.md) — 200+ REST endpoints
- [Scoring engine](docs/SCORING_ENGINE.md) — EPSS + CVSS + KEV formula
- [Benchmark system](docs/BENCHMARKS.md) — Run benchmarks, add targets, CI integration
- [Cloud & endpoint scanners](docs/cloud-endpoint/README.md) — 100 checks across 7 targets
- [Billing & subscriptions](docs/billing/README.md) — Stripe integration, plans, quotas
- [Server setup](docs/server/installation.md) | [Configuration](docs/server/configuration.md) | [Production deploy](docs/server/production.md)
- [Agent installation](docs/agent/INSTALL.md) — Linux, macOS, Windows endpoint agents

---

## Status

| Area | Status |
|------|--------|
| Exploit agent (7 tools, deterministic payloads, post-agent sweep) | Production |
| Business logic agent (IDOR, race conditions, workflow bypass) | Production |
| Recon engine (8 modules, 6 verification agents) | Production |
| Breach chain orchestration (9 playbooks, real-time graphs) | Production |
| Threat intel scoring (EPSS, CVSS, KEV) | Production |
| AEV telemetry (per-run, per-tool, per-turn instrumentation) | Production |
| AEV package boundaries (aev-core, aev-tools, aev-chain, aev-recon) | Production |
| Evidence artifacts (MinIO storage, tool call capture) | Production |
| XBOW CTF benchmark (70% solve rate, black-box) | Production |
| Dashboard, evaluations, reporting, SARIF export | Production |
| Multi-tenant auth (JWT, RBAC, RLS) | Production |
| Entity graph + shared intelligence layer | Production |
| Cloud security — AWS, Azure, GCP, K8s (67 checks) | Production |
| Endpoint agents — Linux, macOS, Windows (33 checks) | Production |
| Go agent (systemd, firewall management, v1.1.0) | Production |
| Billing & subscriptions (Stripe, usage metering) | Production |
| Stream consumer + Mimir-triggered evaluations | Production |
| Intelligence engine client + CISO dashboard | Production |
| Evaluation diffing & drift detection | Production |

---

## Contact

- **Email:** [contact@Odingard.com](mailto:contact@Odingard.com)
- **Issues:** [GitHub Issues](https://github.com/Odingard/OdinForgeAI/issues)
- **Security:** See [SECURITY.md](SECURITY.md)

---

## Legal

OdinForge is a security testing tool. Only use it against systems you own or have written authorization to test. AI-generated findings should be validated by qualified security professionals.

Business Source License 1.1 — see [LICENSE](LICENSE). Converts to Apache 2.0 on February 1, 2030.

(c) 2026 Six Sense Enterprise Services LLC
