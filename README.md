# OdinForge AI

![Benchmark](https://github.com/OdinGard/OdinForgeAI/actions/workflows/benchmark.yml/badge.svg)
![CI](https://github.com/OdinGard/OdinForgeAI/actions/workflows/ci.yml/badge.svg)

**Autonomous Adversarial Exposure Validation Platform**

OdinForge AI is an enterprise-grade security platform that combines agentic AI reasoning with real offensive security tooling to autonomously validate exploitability, simulate multi-domain breach chains, and continuously assess organizational security posture. It goes beyond scanning by proving whether vulnerabilities lead to full organizational compromise — with HTTP evidence, not speculation.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          OdinForge Platform                              │
├──────────────────────────────────────────────────────────────────────────┤
│  Frontend (React 18 + TypeScript)       │  API Server (Express)          │
│  ├─ Dashboard & Risk Analytics          │  ├─ 200+ REST Endpoints        │
│  ├─ Evaluation Wizard                   │  ├─ WebSocket (Live Events)    │
│  ├─ Attack Graph Visualization (D3.js)  │  ├─ JWT Auth + 67 Permissions  │
│  ├─ Live Breach Chain Graph (Canvas)    │  ├─ Rate Limiting (Redis)      │
│  ├─ Threat Intel Score Panel            │  └─ Multi-Tenant RLS           │
│  ├─ Purple Team Simulations             │                                │
│  ├─ Cloud/K8s Security Views            │                                │
│  └─ Executive Reports & Exports         │                                │
├──────────────────────────────────────────────────────────────────────────┤
│  Worker (BullMQ)                        │  AI Agent Pipeline             │
│  ├─ Decoupled Container                 │  ├─ 8 Specialized Agents       │
│  ├─ 14 Job Types                        │  ├─ Tiered Parallel Execution  │
│  ├─ Priority Scheduling                 │  ├─ Agentic Tool-Calling Loop  │
│  ├─ Auto-Retry + Backoff                │  ├─ Model Router (Alloy)       │
│  └─ Redis Pub/Sub WS Bridge             │  ├─ Adversarial Debate Module  │
│                                         │  └─ Noise Reduction Pipeline   │
├──────────────────────────────────────────────────────────────────────────┤
│  Threat Intelligence                    │  Validation Engines            │
│  ├─ EPSS (FIRST.org, daily updates)     │  ├─ SQLi, XSS, SSRF, CmdInj   │
│  ├─ CVSS v2/v3.x Vector Parsing        │  ├─ Path Traversal, Auth Bypass│
│  ├─ CISA KEV (active exploitation)      │  ├─ API Fuzzing Engine         │
│  ├─ Deterministic Scoring (v3.0)        │  ├─ Protocol Probes            │
│  └─ Asset Criticality Weighting         │  └─ Credential Testing         │
├──────────────────────────────────────────────────────────────────────────┤
│  External Recon                         │  Infrastructure                │
│  ├─ Port Scanning                       │  ├─ Docker (app + worker)      │
│  ├─ SSL/TLS Analysis (A+ → F)          │  ├─ Caddy (TLS, reverse proxy) │
│  ├─ HTTP Fingerprinting                 │  ├─ MinIO (S3 storage)         │
│  ├─ Auth Surface Detection              │  └─ Go Endpoint Agents         │
│  └─ Infrastructure Discovery            │                                │
├──────────────────────────────────────────────────────────────────────────┤
│  Data Layer                             │  Security Services             │
│  ├─ PostgreSQL 15+ (50+ tables, RLS)    │  ├─ Policy Guardian (RAG)      │
│  ├─ pgvector (1536-dim embeddings)      │  ├─ HITL Safety Framework      │
│  ├─ Redis 7+ (queues, cache, pub/sub)   │  ├─ Kill Switch + Auto-Kill    │
│  └─ Drizzle ORM (type-safe migrations)  │  └─ Evidence Chain of Custody  │
├──────────────────────────────────────────────────────────────────────────┤
│  AI Providers                                                            │
│  ├─ OpenAI (GPT-4o)                                                      │
│  ├─ OpenRouter (Claude, Gemini, etc.)                                    │
│  └─ Alloy Rotation (per-turn model selection for exploit diversity)      │
└──────────────────────────────────────────────────────────────────────────┘
```

## Key Features

### Deterministic Threat Intelligence Scoring

OdinForge uses a **deterministic, reproducible scoring formula** — not LLM estimation — to prioritize vulnerabilities. This is the same approach used by Qualys TruRisk, Tenable VPR, and CrowdStrike Falcon Spotlight.

**Scoring Formula (v3.0):**

| Signal | Weight | Source |
|--------|--------|--------|
| EPSS probability | 45% | FIRST.org API (daily updates, 200K+ CVEs) |
| CVSS base score | 35% | Parsed from CVSS v2/v3.x vectors |
| Agent exploitability | 20% | Confirmed via exploit agent tooling |

**Threat Intelligence Signals:**

- **EPSS (Exploit Prediction Scoring System)** — Real-time 30-day exploitation probability from FIRST.org. Batch queries with 24h cache. Free, no auth required.
- **CVSS Vector Parsing** — Full v2.0, v3.0, v3.1 support with base score computation per FIRST.org specification. Extracts attack vector, complexity, privileges, user interaction, scope, and impact.
- **CISA KEV Override** — Binary signal for confirmed active exploitation. Forces minimum exploitability floor of 85 and business impact floor of 70. Ransomware amplifier (+10) for known ransomware campaigns.
- **Asset Criticality** — Multiplier based on asset classification (critical=1.3x, high=1.1x, medium=1.0x, low=0.7x).

**Methodology string (audit-friendly):**
```
OdinForge Deterministic v3.0 | EPSS 97.2% (P100) | CVSS 3.1 9.8 | CISA KEV [Ransomware] | Asset: critical
```

When signals are missing, weights automatically redistribute to available data. Falls back to severity-based heuristic when no external data is available.

### Agentic Exploit Validation

The exploit agent uses a **multi-turn tool-calling loop** — not a single LLM prompt. It reasons about attack vectors, invokes real security tools, analyzes results, adapts strategy, and produces findings backed by actual HTTP evidence.

**6 Security Tools Available to the Agent:**

| Tool | Function | Mode Required |
|------|----------|---------------|
| `validate_vulnerability` | Test SQLi, XSS, SSRF, command injection, path traversal, auth bypass | Simulation+ |
| `fuzz_endpoint` | Smart payload fuzzing (type mutation, boundary, encoding, injection) | Simulation+ |
| `http_fingerprint` | Tech stack, security headers, authentication surface detection | All modes |
| `port_scan` | TCP port scanning with service identification and banners | All modes |
| `check_ssl_tls` | Certificate, protocol, cipher suite, and weakness analysis | All modes |
| `run_protocol_probe` | SMTP relay, DNS misconfig, LDAP anonymous bind, default credentials | All modes |

The agent executes up to 12 reasoning turns, with execution mode gating controlling which tools are available (safe = passive only, simulation/live = full active testing). Findings include `validated: true` with HTTP request/response evidence when tool-confirmed.

### Model-Agnostic AI with Alloy Rotation

The exploit agent supports **multi-model rotation** within a single conversation — alternating between GPT-4o, Claude Sonnet, and Gemini per-turn for exploit diversity. Configurable via environment variables:

- **Single model** (default) — GPT-4o, zero config needed
- **Round-robin** — Alternate models each turn
- **Weighted random (alloy)** — Per-turn probabilistic model selection (default: GPT-4o 40%, Claude Sonnet 40%, Gemini 2.5 Pro 20%)

### Cross-Domain Breach Orchestrator

Chains evaluations across security domains with cumulative context propagation and **real-time progressive visualization**:

| Phase | Description | Delegates To |
|-------|-------------|-------------|
| **Application Compromise** | Exploits app-layer vulnerabilities (logic flaws, CVEs, API abuse) | Agent Orchestrator Pipeline |
| **Credential Extraction** | Harvests credentials from compromised applications | Agent Orchestrator (data exfiltration) |
| **Cloud IAM Escalation** | Escalates privileges via IAM misconfigurations | AWS/Azure/GCP Pentest Services |
| **Container/K8s Breakout** | Exploits RBAC, secrets, and container escape paths | Kubernetes Pentest Service |
| **Lateral Movement** | Pivots across network using harvested credentials | Lateral Movement Service |
| **Impact Assessment** | Aggregates business impact, compliance gaps, and risk scoring | Deterministic Scoring Engine |

Each phase passes a `BreachPhaseContext` (credentials, compromised assets, privilege level, attack path steps) to the next. Safety gates enforce execution mode compliance at every phase transition. Features: pause/resume/abort, real-time WebSocket progress, crash recovery via DB persistence.

**Live Breach Chain Graph:** Canvas-based real-time visualization with spine+satellite layout. Phase nodes form the main arc with individual findings collapsed into parent phases. Color-coded by MITRE ATT&CK tactic, animated particles showing attack progression, and "+N" badges indicating hidden attack chains.

### AI Agent Pipeline

8 specialized agents orchestrated in tiered parallel execution:

```
Tier 1 (Parallel, 30s):    Recon Agent  +  Business Logic Agent
                                │                    │
                                ▼                    ▼
Tier 2 (Parallel, 120s):   Exploit Agent  +  Lateral Agent
                            (agentic loop)
                                │                    │
                                ▼                    ▼
Tier 3 (Parallel, 30s):    Multi-Vector Agent  +  Impact Agent
                                │                    │
                                ▼                    ▼
Synthesis:                  Debate Module → Noise Reduction → Report
```

- **Recon Agent** — Attack surface mapping, technology fingerprinting, entry point discovery
- **Exploit Agent** — Multi-turn tool-calling loop with real HTTP validation (12 turns, 110s timeout)
- **Lateral Agent** — Pivot path discovery, credential reuse analysis, network traversal
- **Business Logic Agent** — IDOR, mass assignment, workflow abuse, payment flow manipulation, state machine violations
- **Multi-Vector Agent** — Cross-domain attack path synthesis, chained exploit assembly
- **Impact Agent** — Financial exposure, compliance mapping, operational consequence modeling
- **Debate Module** — Adversarial attacker-vs-defender AI discourse for confidence calibration
- **Noise Reduction** — Multi-layer filter (reachability, exploitability, environmental, deduplication)

### Active Exploit Engine

Real HTTP-based exploit validation beyond AI simulation:

- **Payload Categories** — SQL injection (error/union/blind), XSS (reflected/stored/DOM), SSRF, path traversal, auth bypass, command injection, IDOR
- **API Fuzzing** — Smart payload generation with type mutation, null injection, boundary values, encoding tricks
- **Protocol Probes** — SMTP open relay, DNS zone transfer, LDAP anonymous bind, default credential testing
- **Response Analysis** — Error pattern matching, reflection detection, timing analysis, status code anomalies
- **Evidence Collection** — Full request/response pairs with confidence scoring and validation verdicts

### Cloud & Infrastructure Security

- **AWS IAM Privilege Escalation** — 10 real escalation path analyses (CreatePolicyVersion, AssumeRole, PassRole, etc.)
- **Azure Pentest Service** — Service principal analysis, RBAC misconfigurations, storage exposure
- **GCP Pentest Service** — IAM bindings, service account key analysis, storage ACLs
- **Kubernetes RBAC Analysis** — 5 escalation vectors (pod exec, secret access, privilege escalation, host mounting, RBAC manipulation)
- **Lateral Movement Engine** — Credential reuse testing, pivot point discovery, network segmentation validation
- **Cloud Asset Discovery** — AWS/Azure/GCP resource enumeration with automatic agent deployment

### Security & Governance

- **JWT Authentication** — Role-based access with 67 granular permissions across 8 roles
- **Multi-Tenancy** — Row-Level Security (RLS) with per-tenant data isolation at the database layer
- **Policy Guardian** — RAG-powered policy enforcement blocking out-of-scope exploits in real-time
- **Safety Framework** — HITL approval for live operations, kill switch, auto-kill on critical findings
- **Execution Modes** — safe (passive only), simulation (safe payloads), live (full exploitation with HITL)
- **Rate Limiting** — Per-endpoint and per-user with Redis-backed sliding windows
- **Audit Trail** — Every action logged with timestamp, actor, IP, severity; CSV export for compliance

### Purple Team Simulations

AI vs AI attack/defense exercises across 5 scenarios (web breach, cloud attack, ransomware, data exfiltration, insider threat) with iterative adversarial learning, real-time MTTD/MTTR metrics, and SIEM-observed detection data.

### Reporting Engine

Dual report generation: V1 template engine (structured, deterministic) and V2 AI narrative engine (consulting-quality prose with financial exposure analysis, 30/60/90-day remediation roadmaps, MITRE ATT&CK mapped attack narratives). Compliance mapping across SOC 2, PCI DSS, HIPAA, GDPR, CCPA, ISO 27001, NIST CSF, and FedRAMP.

## Benchmark Results

OdinForge's exploit agent is continuously benchmarked against real vulnerable applications to measure detection accuracy.

**Latest Results (OWASP Juice Shop v17.1.1):**

| Metric | Result |
|--------|--------|
| Scenarios Passed | 5/5 (100%) |
| Vulnerability Detection Rate | 90% (18/20 expected) |
| Total Tool Calls | 19 |
| Execution Time | 94.5s |

**5 Benchmark Scenarios:**

1. SQL Injection via search parameter
2. Authentication bypass on login
3. Full API attack surface analysis (SQLi, XSS, auth bypass, path traversal, misconfiguration)
4. Stored XSS via feedback submission
5. Path traversal and file access

Benchmarks run automatically in CI on every push to agent/validation code. Results are publicly viewable at `/benchmark`. See the [Benchmark CI workflow](.github/workflows/benchmark.yml) for details.

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, Radix, Recharts, D3.js, Canvas |
| Backend | Express.js, TypeScript, WebSocket (ws) |
| Database | PostgreSQL 15+ with Drizzle ORM, pgvector (1536-dim) |
| Cache/Queue | Redis 7+, BullMQ (14 job types, priority scheduling) |
| AI | OpenAI GPT-4o, OpenRouter (Claude, Gemini), model-agnostic routing, alloy rotation |
| Threat Intel | EPSS (FIRST.org), CVSS v2/v3.x parser, CISA KEV, deterministic scoring v3.0 |
| Validation | Validation engine (6 vuln types), API fuzzer, protocol probes (SMTP/DNS/LDAP/creds) |
| Agents | Go 1.21+ (cross-compiled: linux/mac/windows, amd64/arm64) |
| Auth | JWT with refresh rotation, 67 permissions, 8 roles, RLS multi-tenancy |
| Deployment | Docker (app + worker containers), Caddy, MinIO, DigitalOcean |
| CI/CD | 18 GitHub Actions workflows (SAST, DAST, secret scanning, fuzzing, container scanning, benchmarks) |

## Deployment

### Production Architecture

```
                    ┌─────────────────┐
                    │   Caddy Proxy   │  ← TLS termination, HTTP/2
                    │   (Port 443)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   App Container │  ← Express API + WebSocket + Frontend
                    │   (Port 5000)   │
                    └───┬────┬────┬───┘
                        │    │    │
           ┌────────────┼────┼────┼──────────────┐
           │            │    │    │               │
  ┌────────▼──────┐ ┌──▼────▼──┐ ┌──▼──────────┐ ┌▼───────────────┐
  │  PostgreSQL   │ │  Redis   │ │    MinIO     │ │ Worker Container│
  │  (pgvector)   │ │  (7+)    │ │ (S3 storage) │ │  (BullMQ jobs)  │
  └───────────────┘ └──────────┘ └──────────────┘ └─────────────────┘
```

The app and worker run as **separate containers** sharing the same database, Redis, and MinIO. The worker processes all long-running jobs (evaluations, breach chains, scans, reports) via BullMQ, communicating progress back to the app via Redis pub/sub for WebSocket broadcast.

### Quick Start

```bash
# Clone and install
git clone <repository-url>
cd odinforge
npm install

# Set up environment
cp .env.example .env
# Edit .env: DATABASE_URL, OPENAI_API_KEY, SESSION_SECRET, JWT_SECRET

# Start infrastructure
docker-compose up -d   # PostgreSQL + Redis

# Initialize database
npm run db:push

# Start development server
npm run dev
```

Server runs at `http://localhost:5000` with WebSocket on `/ws`.

### Deploy Agents

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

## API Overview

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threat-intel/epss?cve=CVE-1,CVE-2` | Batch EPSS score lookup (max 100 CVEs) |

### Breach Orchestrator
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/breach-chains` | Create and start a cross-domain breach chain |
| GET | `/api/breach-chains` | List all breach chains (org-filtered) |
| GET | `/api/breach-chains/:id` | Get chain with full phase results and context |
| POST | `/api/breach-chains/:id/resume` | Resume a paused chain |
| POST | `/api/breach-chains/:id/abort` | Abort a running chain |

### Evaluations & Assessments
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/aev/evaluations` | Create an adversarial evaluation |
| GET | `/api/aev/evaluations` | List evaluations |
| POST | `/api/full-assessments` | Launch multi-phase assessment |
| GET | `/api/full-assessments/:id` | Get assessment with attack graph |

### Purple Team Simulations
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/simulations` | Launch AI vs AI purple team simulation |
| GET | `/api/simulations` | List simulations with MTTD/MTTR metrics |
| GET | `/api/simulations/:id` | Get simulation with round-by-round results |

### Agents & Telemetry
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/register` | Register an endpoint agent |
| POST | `/api/agents/:id/telemetry` | Submit agent telemetry |
| GET | `/api/agents` | List all agents |

See full API reference in [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

## CI/CD Pipeline

18 automated workflows covering the full security development lifecycle:

| Category | Workflows |
|----------|-----------|
| **Build & Test** | CI (Node + Go tests), AEV smoke tests, unit tests |
| **SAST** | CodeQL, Semgrep, ESLint security plugin |
| **DAST** | ZAP authenticated full scan, API fuzzing |
| **Supply Chain** | npm audit, Dependabot (npm + Go + Actions), SBOM generation |
| **Container** | Trivy container scanning |
| **Secrets** | Gitleaks secret detection |
| **Benchmark** | Exploit agent accuracy against OWASP Juice Shop (threshold-gated) |
| **Deploy** | Docker build + push to GHCR + SSH deploy + health check |

## Documentation

| Document | Description |
|----------|-------------|
| [Documentation Hub](docs/README.md) | Complete documentation index |
| [Scoring & Threat Intel](docs/SCORING_ENGINE.md) | Deterministic scoring formula, EPSS, CVSS, KEV |
| [Server Installation](docs/server/installation.md) | Deploy the OdinForge server |
| [Server Configuration](docs/server/configuration.md) | Environment variables and settings |
| [Production Deployment](docs/server/production.md) | Docker, Kubernetes, cloud deployment |
| [Agent Installation](docs/agent/INSTALL.md) | Deploy endpoint agents |
| [API Reference](docs/API_REFERENCE.md) | REST API endpoints |
| [Technical White Paper](OdinForge-AI-Technical-White-Paper.md) | Architecture deep-dive |
| [Executive White Paper](OdinForge-AI-White-Sheet.md) | Business capabilities overview |

## License

Business Source License 1.1 (BSL 1.1) — see [LICENSE](LICENSE) for details. Converts to Apache 2.0 on February 1, 2030.

## Support

For support, please contact your OdinForge administrator or open an issue in the repository.
