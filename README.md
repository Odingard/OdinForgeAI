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
│  ├─ Breach Chain Monitor (Live WS)      │  ├─ Rate Limiting (Redis)      │
│  ├─ Purple Team Simulations             │  └─ Multi-Tenant RLS           │
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
│  Validation Engines                     │  External Recon                │
│  ├─ SQLi, XSS, SSRF, Cmd Injection     │  ├─ Port Scanning              │
│  ├─ Path Traversal, Auth Bypass         │  ├─ SSL/TLS Analysis (A+ → F) │
│  ├─ API Fuzzing Engine                  │  ├─ HTTP Fingerprinting        │
│  ├─ Protocol Probes (SMTP/DNS/LDAP)     │  ├─ Auth Surface Detection     │
│  └─ Credential Testing                  │  └─ Infrastructure Discovery   │
├──────────────────────────────────────────────────────────────────────────┤
│  Data Layer                             │  Infrastructure                │
│  ├─ PostgreSQL 15+ (50+ tables, RLS)    │  ├─ Docker (app + worker)      │
│  ├─ pgvector (1536-dim embeddings)      │  ├─ Caddy (TLS, reverse proxy) │
│  ├─ Redis 7+ (queues, cache, pub/sub)   │  ├─ MinIO (S3 storage)         │
│  └─ Drizzle ORM (type-safe migrations)  │  └─ Go Endpoint Agents         │
├──────────────────────────────────────────────────────────────────────────┤
│  AI Providers                           │  Security Services             │
│  ├─ OpenAI (GPT-4o)                     │  ├─ Policy Guardian (RAG)      │
│  ├─ OpenRouter (Claude, Gemini, etc.)   │  ├─ HITL Safety Framework      │
│  └─ Alloy Rotation (per-turn model      │  ├─ Kill Switch + Auto-Kill    │
│     selection for exploit diversity)     │  └─ Evidence Chain of Custody  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Key Features

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
- **Weighted random (alloy)** — Per-turn probabilistic model selection

### Cross-Domain Breach Orchestrator

Chains evaluations across security domains with cumulative context propagation:

| Phase | Description | Delegates To |
|-------|-------------|-------------|
| **Application Compromise** | Exploits app-layer vulnerabilities (logic flaws, CVEs, API abuse) | Agent Orchestrator Pipeline |
| **Credential Extraction** | Harvests credentials from compromised applications | Agent Orchestrator (data exfiltration) |
| **Cloud IAM Escalation** | Escalates privileges via IAM misconfigurations | AWS/Azure/GCP Pentest Services |
| **Container/K8s Breakout** | Exploits RBAC, secrets, and container escape paths | Kubernetes Pentest Service |
| **Lateral Movement** | Pivots across network using harvested credentials | Lateral Movement Service |
| **Impact Assessment** | Aggregates business impact, compliance gaps, and risk scoring | Template-based aggregation |

Each phase passes a `BreachPhaseContext` (credentials, compromised assets, privilege level, attack path steps) to the next. Safety gates enforce execution mode compliance at every phase transition. Features: pause/resume/abort, real-time WebSocket progress, crash recovery via DB persistence.

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

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, Radix, Recharts, D3.js |
| Backend | Express.js, TypeScript, WebSocket (ws) |
| Database | PostgreSQL 15+ with Drizzle ORM, pgvector (1536-dim) |
| Cache/Queue | Redis 7+, BullMQ (14 job types, priority scheduling) |
| AI | OpenAI GPT-4o, OpenRouter (Claude, Gemini), model-agnostic routing, alloy rotation |
| Validation | Validation engine (6 vuln types), API fuzzer, protocol probes (SMTP/DNS/LDAP/creds) |
| Agents | Go 1.21+ (cross-compiled: linux/mac/windows, amd64/arm64) |
| Auth | JWT with refresh rotation, 67 permissions, 8 roles, RLS multi-tenancy |
| Deployment | Docker (app + worker containers), Caddy, MinIO, DigitalOcean |
| CI/CD | 17 GitHub Actions workflows (SAST, DAST, secret scanning, fuzzing, container scanning) |

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

17 automated workflows covering the full security development lifecycle:

| Category | Workflows |
|----------|-----------|
| **Build & Test** | CI (Node + Go tests), AEV smoke tests, unit tests |
| **SAST** | CodeQL, Semgrep, ESLint security plugin |
| **DAST** | ZAP authenticated full scan, API fuzzing |
| **Supply Chain** | npm audit, Dependabot (npm + Go + Actions), SBOM generation |
| **Container** | Trivy container scanning |
| **Secrets** | Gitleaks secret detection |
| **Deploy** | Docker build + push to GHCR + SSH deploy + health check |

## Documentation

| Document | Description |
|----------|-------------|
| [Documentation Hub](docs/README.md) | Complete documentation index |
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
