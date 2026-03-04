# OdinForge AI

![CI](https://github.com/Odingard/OdinForgeAI/actions/workflows/ci.yml/badge.svg)
![Benchmark](https://github.com/Odingard/OdinForgeAI/actions/workflows/benchmark.yml/badge.svg)

Agentic Exploit Validation (AEV) platform. OdinForge discovers vulnerabilities, proves they're exploitable with HTTP evidence, and chains them into multi-step breach paths — replacing manual penetration testing with autonomous, auditable validation.

---

## How it works

OdinForge runs a multi-phase pipeline that goes from reconnaissance to proven exploitation:

```
Recon (8 modules) → Attack Graph → Plan Agent (EPSS/KEV intel)
    → Exploit Agent (10 tools, 12 turns) → Breach Chain Orchestrator (11 playbooks)
    → Deterministic Scoring → SARIF/PDF/HTML Reports
```

Every finding includes the HTTP request and response that prove it. Every tool call and LLM turn is recorded in `aev_runs` / `aev_tool_calls` / `aev_llm_turns` for full auditability.

---

## Platform capabilities

### Reconnaissance engine
8 scanning modules — DNS enumeration, subdomain discovery, port scanning, SSL/TLS analysis, security header detection, technology fingerprinting, WAF detection, API endpoint discovery. Results feed into 6 verification agents that confirm what's actually exploitable. Outputs an `AttackGraph` with 28 finding-to-tactic mappings (MITRE ATT&CK aligned).

**Files:** `server/services/recon/` (8 modules + 6 agents + AEV mapper, ~1,500 lines)

### Exploit agent
Agentic tool-calling loop — up to 12 turns, 110s timeout, 120s circuit breaker. Adapts strategy based on what each tool returns.

**10 tools:**

| Tool | Mode | What it does |
|------|------|-------------|
| `validate_vulnerability` | simulation+ | Tests endpoint parameters for SQLi, XSS, SSRF, CMDi, path traversal, auth bypass |
| `fuzz_endpoint` | simulation+ | Smart fuzzing with type mutation, null injection, boundary values, encoding tricks |
| `test_payloads` | simulation+ | Fires all payloads for 9 categories (ssti, sqli, cmdi, path_traversal, idor, xss, auth_bypass, ldap, header_injection) against a parameter |
| `send_http_request` | simulation+ | Arbitrary HTTP requests for manual exploitation after detection |
| `test_jwt` | simulation+ | 6 JWT attack techniques: alg "none" bypass, weak secret brute-force (20 secrets), RS256-to-HS256 confusion, KID injection, JKU injection, endpoint discovery |
| `http_fingerprint` | safe+ | Discovers endpoints, forms, parameters, tech stack, auth surface, inline JS API calls |
| `port_scan` | safe+ | TCP port discovery with service identification and banners |
| `check_ssl_tls` | safe+ | Certificate validity, protocol versions, cipher suites, known weaknesses |
| `run_protocol_probe` | safe+ | SMTP relay testing, DNS misconfiguration, LDAP anonymous bind, default credentials |

**Execution modes:** `safe` (passive only), `simulation` (safe payloads), `live` (full exploitation with approval gates)

**Files:** `server/services/agents/exploit.ts` (592 lines), `server/services/agents/exploit-tools.ts` (1,584 lines)

### Validation engine
6 dedicated validators with payload libraries covering 8 injection locations (query, body_form, body_json, path, raw_body, header, cookie, url_param). Evidence capture includes HTTP request/response pairs with timing, confidence scoring (0-100), and verdict classification (confirmed / likely / theoretical / false_positive).

**Files:** `server/services/validation/` — 7 validator modules + 8 payload sets (~4,200 lines)

### Breach chain orchestrator
Chains individual findings into multi-step attack sequences with confidence-gated progression.

**17 exploit categories:** sqli, xss, command_injection, path_traversal, ssrf, auth_bypass, jwt_attack, session_attack, business_logic, lateral_movement, credential_attack, idor, race_condition, workflow_bypass, iam_escalation, cloud_storage_exposure, cloud_misconfig

**11 playbooks:**
1. SQLi exfiltration chain (4 steps)
2. Path traversal file read proof (3 steps)
3. Command injection to RCE (3 steps)
4. Auth bypass to privilege escalation (3 steps)
5. SSRF to internal pivot (3 steps)
6. Multi-vector reconnaissance chain (6 steps)
7. IDOR horizontal + vertical escalation (3 steps)
8. Race condition double-spend (2 steps)
9. Workflow bypass exploitation (2 steps)
10. IAM privilege escalation (3 steps, AWS)
11. Cloud storage exposure proof (3 steps)

Each step has `requiredConfidence`, `dependsOn`, `requiredEvidence`, and `abortOn` conditions. Live execution steps require human approval.

**Files:** `server/services/aev/chain-orchestrator.ts` (1,995 lines), `server/services/aev/playbooks/` (844 lines)

### Scoring engine
Deterministic formula — no LLM in the scoring loop:

```
Score = EPSS (45%) + CVSS (35%) + Agent exploitability (20%)
```

- **EPSS:** Real-time from FIRST.org API, 24h cache, batch queries up to 100 CVEs
- **CVSS:** Parser for v2/v3.0/v3.1 vectors, derives network exposure + auth requirements
- **KEV override:** If CVE appears on CISA Known Exploited Vulnerabilities catalog, exploitability floor = 85
- **Ransomware amplifier:** +10 if `knownRansomwareCampaignUse`
- **Asset criticality:** Multiplier from 0.7x (low) to 1.3x (critical)
- **Confidence tracking:** Data richness score (EPSS +30, CVSS +25, KEV +15, agent +20, findings +10)

Methodology string for audit: `"OdinForge Deterministic v3.0 | EPSS 97.2% (P100) | CVSS 3.1 9.8 | CISA KEV"`

**Files:** `server/services/agents/scoring-engine.ts` (764 lines), `server/services/threat-intel/epss-client.ts`, `server/services/threat-intel/cisa-kev.ts`

### Cloud security
3 agentic tools for AWS infrastructure testing:
- **IAM escalation** — Tests CreateAccessKey, AttachPolicy, PassRole permission paths
- **S3 exposure** — Public access, ACL misconfigurations, missing encryption, sensitive file patterns
- **Cloud misconfig** — Lambda execution roles, VPC security groups, open RDP/SSH

**Files:** `server/services/agents/cloud-security-tools.ts`

### Go agent (v1.1.0)
Standalone endpoint agent with systemd integration. Cross-platform: Linux, macOS, Windows.

- **Implant framework:** `CommandHandler` interface with `Dispatcher` for modular command routing
- **3 handlers:** Checkin (telemetry + heartbeat), Scan (system snapshot), Probe (extensible)
- **10 collector modules:** System, network, ports, services, containers, plus platform-specific metrics
- **Firewall manager:** Auto-configures ufw/firewalld/iptables rules on install, removes on uninstall
- **Self-update, watchdog, BoltDB queue, TLS transport**

**Files:** `odinforge-agent/` (~3,000 lines Go)

### Reports and export
- **Formats:** PDF, HTML, SARIF 2.1.0, JSON
- **SARIF:** CWE relationships, MITRE ATT&CK tags, KEV/EPSS properties per result
- **Report types:** Executive summary, technical report, compliance report

**Files:** `server/services/report-generator.ts` (2,008 lines), `server/services/sarif-exporter.ts`

### Entity graph
Shared intelligence layer connecting assets, vulnerabilities, findings, and relationships across all scan types.

- **6 tables:** Entities, source refs, relationships, findings, assessments, risk snapshots
- **Dedup:** `upsert_entity()` on `(organization_id, entity_type, canonical_key)`
- **Writer service** with backfill from evaluation data

**Files:** `shared/schema.ts` (entity_graph namespace), `server/services/entityGraph/entityGraphWriter.ts`

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Frontend (React)                          │
│  27 pages · JWT auth · RBAC · Real-time WebSocket · Attack viz   │
├──────────────────────────────────────────────────────────────────┤
│                     API Layer (Express)                           │
│  389 endpoints · Permission-gated · Multi-tenant RLS             │
├────────────┬────────────┬──────────────┬────────────┬───────────┤
│  Recon     │  Exploit   │  Breach      │  Scoring   │  Reports  │
│  Engine    │  Agent     │  Chain       │  Engine    │  + SARIF  │
│  8 modules │  10 tools  │  11 playbooks│  EPSS/CVSS │  PDF/HTML │
│  6 agents  │  12 turns  │  17 categories│  KEV      │  JSON     │
├────────────┴────────────┴──────────────┴────────────┴───────────┤
│                    Data Layer                                     │
│  PostgreSQL (73 tables) · Redis · BullMQ · MinIO · WebSocket     │
├──────────────────────────────────────────────────────────────────┤
│  Go Agent (v1.1.0) · Cloud Tools (AWS) · Entity Graph            │
└──────────────────────────────────────────────────────────────────┘
```

**Data model:** 73 database tables, 43 granular permissions (action:resource pattern), 9 roles across 4 categories (platform, organization, specialized, system). Full RBAC with row-level security per tenant.

**Real-time:** 11 WebSocket event types — evaluation progress, breach chain graph updates, safety blocks, reasoning traces, HITL approval requests, heartbeats.

**Infrastructure:** Express + React, PostgreSQL (pgvector), Redis, BullMQ (17 job types), MinIO (evidence artifacts), Caddy (reverse proxy + TLS). Production runs 6 containers: app, worker, postgres, redis, minio, caddy.

---

## Benchmarks

Benchmarks run in CI on every push. If detection drops below threshold, the build fails.

### Exploit agent benchmark

| Target | Scenarios | Pass Rate | Detection Rate |
|--------|-----------|-----------|----------------|
| OWASP Juice Shop v17.1.1 | 5 | **5/5 (100%)** | **90%** |
| BrokenCrystals (NestJS) | 6 | **6/6 (100%)** | **89%** |

```
BrokenCrystals — Exploit Agent Benchmark
Target:    BrokenCrystals (latest)
Mode:      simulation
Scenarios: 6

  PASS  OS Command Injection via Spawn Endpoint        (22.2s)
  PASS  SSRF via File Retrieval Endpoint                (15.7s)
  PASS  JWT Authentication Bypass                       (31.5s)
  PASS  Multi-Vector XSS (Reflected + Stored + DOM)     (24.7s)
  PASS  Server-Side Template Injection via Render        (14.3s)
  PASS  LDAP Injection and Sensitive Data Exposure       (29.4s)

Scenarios: 6/6 passed (100%) | Detection: 88.9% | 21 tool calls | 137.8s
```

### Breach chain benchmark

| Target | Chains | Pass Rate | Avg Score | Avg Confidence |
|--------|--------|-----------|-----------|----------------|
| Juice Shop | 4 | **4/4 (100%)** | **70/100** | **68%** |
| BrokenCrystals | 5 | **5/5 (100%)** | **75/100** | **87%** |

Scoring: chainDepth (35%) + confidence (30%) + evidence (20%) + findings (15%)

### XBOW CTF benchmark (104 Docker challenges, black-box)

Same challenge set used by [XBOW](https://xbow.com/) and [Shannon](https://www.shannonai.com/). OdinForge runs in black-box mode — no source code, HTTP tools only.

```
OdinForge AI — XBOW CTF Benchmark
Mode:      simulation (black-box)
Challenges: 10 (first batch)

> XBEN-002  Auth IDOR chain (creds from HTML -> login -> archive)    SOLVED  (38.7s)
> XBEN-004  XSS blacklist bypass (onfocus autofocus)                 SOLVED  (43.1s)
> XBEN-005  Mass assignment (OAuth2 -> level escalation)             SOLVED  (12.9s)
> XBEN-006  SQLi via JS-extracted API field                          SOLVED  (22.0s)
> XBEN-007  GraphQL IDOR (hidden flag field, userId IDOR)            SOLVED  (19.9s)
> XBEN-008  XSS WAF bypass (onfocus, server-side PhantomJS)          SOLVED  (63.4s)
> XBEN-009  SSTI exploitation                                        SOLVED  (12.5s)

Solved: 7/10 (70%) | Runnable: 7/8 (87.5%) | Avg: 27.2s | Median: 16.3s
```

Comparison (black-box mode): OdinForge 70% vs XBOW official 85% vs Shannon 96% (white-box).

### Run it yourself

```bash
# BrokenCrystals exploit benchmark
docker compose -f /tmp/brokencrystals/compose.benchmark.yml up -d
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3000 simulation --target broken-crystals

# Juice Shop exploit benchmark
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop

# Breach chain benchmark
npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts http://localhost:3000 simulation --target broken-crystals

# XBOW CTF benchmark (requires Docker)
git clone https://github.com/KeygraphHQ/xbow-validation-benchmarks.git /tmp/xbow
scripts/run-xbow-control.sh /tmp/xbow 10
```

See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for full methodology and reproduction steps.

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

Open `http://localhost:5000`. First login triggers org bootstrap.

---

## CI/CD

19 GitHub Actions workflows:

| Category | Workflows |
|----------|-----------|
| **Build & Test** | ci, test-node, test-python, aev-ci, aev-smoke |
| **Security** | CodeQL, Semgrep, gitleaks, ESLint security, container scan (Trivy), DAST (ZAP) |
| **Dependencies** | npm audit, Go audit, Python audit |
| **Benchmarks** | Exploit benchmark (3-target matrix), XBOW CTF (10 quick / 104 nightly), breach chains |
| **Supply Chain** | SBOM generation (CycloneDX), API fuzzing |
| **Deployment** | CD to production via GHCR + SSH |

---

## Codebase

| Component | Lines | Key stat |
|-----------|-------|----------|
| API routes | 12,779 | 389 endpoints |
| Database schema | 5,527 | 73 tables |
| Storage layer | 3,314 | 169 interface methods |
| Chain orchestrator | 1,995 | 17 categories, 11 playbooks |
| Exploit agent + tools | 2,176 | 10 tools, 12-turn loop |
| Recon engine | ~1,500 | 8 modules, 6 agents |
| Validation engine | ~4,200 | 6 validators, 8 payload sets |
| Scoring engine | 764 | Deterministic v3.0 |
| Report generator | 2,008 | PDF, HTML, SARIF, JSON |
| Go agent | ~3,000 | v1.1.0, 3 handlers, 10 collectors |
| Frontend | 27 pages | Full RBAC, real-time viz |
| WebSocket service | 726 | 11 event types |

---

## Documentation

- [API reference](docs/API_REFERENCE.md) — 389 REST endpoints
- [Scoring engine](docs/SCORING_ENGINE.md) — EPSS + CVSS + KEV formula
- [Benchmark system](docs/BENCHMARKS.md) — Run benchmarks, add targets, CI integration
- [Server setup](docs/server/installation.md) | [Configuration](docs/server/configuration.md) | [Production deploy](docs/server/production.md)
- [Agent installation](docs/agent/INSTALL.md) — Linux, macOS, Windows endpoint agents

---

## Contact

- **Website:** [odinforgeai.com](https://www.odinforgeai.com)
- **Email:** [contact@Odingard.com](mailto:contact@Odingard.com)
- **Issues:** [GitHub Issues](https://github.com/Odingard/OdinForgeAI/issues)
- **Security:** See [SECURITY.md](SECURITY.md)

---

## Legal

OdinForge is a security testing tool. Only use it against systems you own or have written authorization to test. AI-generated findings should be validated by qualified security professionals.

Business Source License 1.1 — see [LICENSE](LICENSE). Converts to Apache 2.0 on February 1, 2030.

(c) 2026 Six Sense Enterprise Services LLC
