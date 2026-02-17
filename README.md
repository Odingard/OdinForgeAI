# OdinForge AI

**Adversarial Exposure Validation Platform**

OdinForge AI is an enterprise-grade security platform for autonomous exploit validation, multi-domain breach simulation, and continuous attack surface analysis. It goes beyond single-vector scanning by chaining exploits across application, cloud, container, and network domains — proving not just that vulnerabilities exist, but that they lead to full organizational compromise.

## Key Features

### Core Platform
- **AI-Powered Exploit Validation** — Multi-agent AI pipeline (recon, exploit, policy guardian, lateral movement, debate, impact) autonomously validates security exposures
- **Active Exploit Engine** — Real HTTP payload validation that sends actual exploit payloads against targets (SQLi, XSS, SSRF, path traversal, auth bypass, command injection, IDOR) and analyzes real responses — not just AI simulation
- **Attack Path Visualization** — MITRE ATT&CK mapped attack graphs with interactive kill chain analysis across 14 tactics
- **Purple Team Simulations** — AI vs AI attack/defense exercises with iterative adversarial learning, real-time MTTD/MTTR metrics, and SIEM-observed detection data
- **Endpoint Agents** — Cross-platform Go agents for real-time telemetry, vulnerability scanning, and auto-evaluation triggers
- **Full Assessment Mode** — Multi-phase penetration testing with web app recon, API scanning, auth testing, exploit validation, and remediation verification
- **Executive Reporting** — Professional pentest-quality PDF/CSV reports with business impact analysis, compliance mapping, and remediation guidance including breach chain analysis reports

### Cross-Domain Breach Orchestrator
The competitive differentiator. Chains evaluations across security domains with context propagation between phases:

| Phase | Description | Delegates To |
|-------|-------------|-------------|
| **Application Compromise** | Exploits app-layer vulnerabilities (logic flaws, CVEs, API abuse) | Agent Orchestrator Pipeline |
| **Credential Extraction** | Harvests credentials from compromised applications | Agent Orchestrator (data exfiltration) |
| **Cloud IAM Escalation** | Escalates privileges via IAM misconfigurations | AWS Pentest Service |
| **Container/K8s Breakout** | Exploits RBAC, secrets, and container escape paths | Kubernetes Pentest Service |
| **Lateral Movement** | Pivots across network using harvested credentials | Lateral Movement Service |
| **Impact Assessment** | Aggregates business impact, compliance gaps, and risk scoring | Template-based aggregation |

Each phase passes a `BreachPhaseContext` (credentials, compromised assets, privilege level, attack path steps) to the next. Phase gates ensure logical progression — no cloud escalation without credentials, no K8s breakout without cloud access.

Features: pause/resume/abort, real-time WebSocket progress, unified cross-domain attack graph, per-phase timeout controls, crash recovery via DB persistence.

### Breach Chains UI
Full-featured monitoring interface for cross-domain breach chains:
- **Chain Creation** — Create breach chains with target URL, asset selection, per-phase toggles, execution mode (sequential/opportunistic), and pause-on-critical configuration
- **Real-Time Monitoring** — Live WebSocket-driven progress updates with phase timeline visualization and auto-refreshing status cards
- **Detail View** — 4-tab interface: Overview (metrics + phase timeline), Phase Results (expandable per-phase findings with severity badges), Breach Context (harvested credentials, compromised assets, attack path steps), and Executive Summary
- **Platform Integration** — Breach chain metrics surface across the Dashboard (stat card with active chain glow), Risk Dashboard (consolidated risk strip), Jobs queue (breach_chain job type filter), and Reports (breach chain analysis report type)

### Active Exploit Engine
Real HTTP-based exploit validation that goes beyond AI simulation:
- **Payload Categories** — SQL injection (error-based, union, blind), XSS (reflected, stored, DOM), SSRF (internal network probing), path traversal, authentication bypass, command injection, IDOR
- **Response Analysis** — Analyzes actual HTTP responses for exploit indicators (error patterns, reflection detection, timing analysis, status code anomalies)
- **Confidence Scoring** — Multi-signal confidence scoring based on response characteristics, not just AI judgment
- **Safety Controls** — Respects scope boundaries, rate limits exploit attempts, integrates with Policy Guardian for out-of-scope blocking
- **Evidence Collection** — Captures full request/response pairs as evidence artifacts for audit and reporting

### Cloud & Infrastructure Security
- **AWS IAM Privilege Escalation** — 10 real escalation path analyses (CreatePolicyVersion, AssumeRole, PassRole, etc.)
- **Kubernetes RBAC Analysis** — 5 escalation vectors (pod exec, secret access, privilege escalation, host mounting, RBAC manipulation)
- **Lateral Movement Engine** — Credential reuse testing, pivot point discovery, network segmentation validation
- **Cloud Asset Discovery** — AWS/Azure/GCP resource enumeration with automatic agent deployment

### Security & Governance
- **JWT-Based Authentication** — Role-based access with 67 granular permissions across 8 roles
- **Multi-Tenancy** — Row-Level Security (RLS) with per-tenant data isolation
- **Policy Guardian** — RAG-powered policy enforcement that blocks out-of-scope exploit attempts in real-time
- **Safety Framework** — Human-in-the-loop (HITL) approval for critical operations, safety decisions audit trail
- **Rate Limiting** — Per-endpoint and per-user rate limiting with Redis-backed sliding windows

## Quick Start

### Prerequisites
- **Node.js** 20+
- **PostgreSQL** 15+ (with pgvector extension recommended)
- **Redis** 7+ (for job queues, rate limiting, caching)
- **Go** 1.21+ (for building endpoint agents)
- **OpenAI API Key**

### Deploy the Server

```bash
# Clone and install dependencies
git clone <repository-url>
cd odinforge
npm install

# Set up environment
cp .env.example .env
# Edit .env with your configuration (DATABASE_URL, OPENAI_API_KEY, SESSION_SECRET, etc.)

# Start infrastructure (PostgreSQL + Redis)
docker-compose up -d

# Initialize database
npm run db:push

# Start the server
npm run dev
```

Server runs at `http://localhost:5000` with WebSocket support on `/ws`.

### Deploy Agents

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

Agents auto-register, begin telemetry collection, and trigger evaluations based on discovered vulnerabilities.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        OdinForge Platform                            │
├──────────────────────────────────────────────────────────────────────┤
│  Frontend (React + TypeScript)       │  Backend (Express + TypeScript)│
│  ├─ Dashboard & Risk Analytics       │  ├─ REST API (200+ endpoints) │
│  ├─ Evaluation Wizard                │  ├─ WebSocket Real-time Events│
│  ├─ Attack Graph Visualization       │  ├─ AI Agent Pipeline (8 agents)
│  ├─ Breach Chain Monitor (Live WS)   │  ├─ Breach Orchestrator       │
│  ├─ Purple Team Simulations          │  ├─ Active Exploit Engine     │
│  ├─ Cloud/K8s Security Views         │  ├─ Report Generator (PDF/CSV)│
│  └─ Executive Reports & Exports      │  └─ Job Queue (14 job types)  │
├──────────────────────────────────────────────────────────────────────┤
│  PostgreSQL + pgvector               │  OpenAI Integration           │
│  ├─ 50+ tables with RLS             │  ├─ GPT-4 Multi-Agent Analysis│
│  ├─ Breach chains & phase results    │  ├─ Attack Path Generation    │
│  ├─ Evaluations, findings, evidence  │  ├─ Adversarial Debate Module │
│  └─ Audit logs & compliance          │  └─ Business Impact Narratives│
├──────────────────────────────────────────────────────────────────────┤
│  Redis                               │  Endpoint Agents (Go)         │
│  ├─ Job queues (Bull)                │  ├─ System Telemetry          │
│  ├─ Rate limiting                    │  ├─ Vulnerability Scanning    │
│  └─ Session caching                  │  ├─ Container Detection       │
│                                      │  └─ Auto-Evaluation Triggers  │
├──────────────────────────────────────────────────────────────────────┤
│                     Security Services                                │
│  ├─ AWS IAM Privilege Escalation     ├─ Kubernetes RBAC Analysis     │
│  ├─ Lateral Movement Engine          ├─ Cloud Asset Discovery        │
│  ├─ Active Exploit Engine (HTTP)     ├─ Safety Framework (HITL)      │
│  ├─ Policy Guardian (RAG)            ├─ Multi-Tenant RLS             │
│  └─ Breach Chain Orchestrator        └─ MTTD/MTTR Metrics Engine     │
└──────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React 18, TypeScript, TailwindCSS, shadcn/ui, Recharts, D3.js |
| Backend | Express.js, TypeScript, WebSocket (ws) |
| Database | PostgreSQL 15+ with Drizzle ORM, pgvector |
| Cache/Queue | Redis 7+, Bull job queues |
| AI | OpenAI GPT-4, multi-agent orchestration, adversarial debate |
| Agents | Go 1.21+ (cross-compiled: linux/mac/windows, amd64/arm64) |
| Auth | JWT with role-based permissions, refresh token rotation |
| Security | RLS multi-tenancy, RAG policy enforcement, HITL safety |

## API Overview

### Breach Orchestrator
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/breach-chains` | Create and start a cross-domain breach chain |
| GET | `/api/breach-chains` | List all breach chains (org-filtered) |
| GET | `/api/breach-chains/:id` | Get chain with full phase results and context |
| POST | `/api/breach-chains/:id/resume` | Resume a paused chain |
| POST | `/api/breach-chains/:id/abort` | Abort a running chain |
| DELETE | `/api/breach-chains/:id` | Delete a breach chain |

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
| POST | `/api/agents/:id/commands` | Send command to agent |

See full API reference in [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

## Documentation

| Document | Description |
|----------|-------------|
| [Documentation Hub](docs/README.md) | Complete documentation index |
| [Server Installation](docs/server/installation.md) | Deploy the OdinForge server |
| [Server Configuration](docs/server/configuration.md) | Environment variables and settings |
| [Production Deployment](docs/server/production.md) | Docker, Kubernetes, cloud deployment |
| [Agent Installation](docs/agent/INSTALL.md) | Deploy endpoint agents |
| [API Reference](docs/API_REFERENCE.md) | REST API endpoints |

## License

Business Source License 1.1 (BSL 1.1) — see [LICENSE](LICENSE) for details. Converts to Apache 2.0 on February 1, 2030.

## Support

For support, please contact your OdinForge administrator or open an issue in the repository.
