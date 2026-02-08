# System Architecture

OdinForge AI uses a modern full-stack TypeScript architecture with real-time capabilities and multi-tenant isolation.

## High-Level Overview

```
                                    ┌─────────────────┐
                                    │   Web Browser   │
                                    │   (React SPA)   │
                                    └────────┬────────┘
                                             │
                                    ┌────────▼────────┐
                                    │    Express.js   │
                                    │   API Server    │
                                    │   (Port 5000)   │
                                    └───┬────┬────┬───┘
                                        │    │    │
               ┌────────────────────────┼────┼────┼────────────────────────┐
               │                        │    │    │                        │
      ┌────────▼────────┐     ┌────────▼────▼────┐     ┌─────────▼─────────┐
      │   PostgreSQL    │     │    Job Queue     │     │    WebSocket      │
      │    Database     │     │ (BullMQ + Redis) │     │     Server        │
      └─────────────────┘     └────────┬─────────┘     └───────────────────┘
                                       │
                              ┌────────▼────────┐
                              │   Job Workers   │
                              │  - Evaluation   │
                              │  - Discovery    │
                              │  - Scanning     │
                              │  - Reports      │
                              └─────────────────┘
```

## Core Components

### Frontend (React SPA)

| Component | Technology | Purpose |
|-----------|------------|---------|
| UI Framework | React 18 | Component-based interface |
| Routing | Wouter | Client-side navigation |
| State | TanStack Query | Data fetching and caching |
| Styling | TailwindCSS + shadcn/ui | Modern, accessible design |
| Real-time | WebSocket | Live updates for scans and evaluations |

### Backend Services

| Service | Description |
|---------|-------------|
| **AEV Engine** | AI-powered vulnerability analysis orchestrator |
| **Agent Orchestrator** | Coordinates multi-agent AI pipeline |
| **AI Simulation** | Manages Attacker vs Defender simulations |
| **Cloud Integration** | AWS, Azure, GCP asset discovery and deployment |
| **Report Generator** | Executive, technical, and compliance reports |
| **Governance Enforcement** | Safety controls, kill switch, scope rules |

### AI Agent Pipeline

The AEV engine uses a multi-agent architecture:

```
Input Exposure
      │
      ▼
┌───────────────┐
│  Recon Agent  │ ─── Maps attack surface
└───────┬───────┘
        ▼
┌───────────────┐
│ Exploit Agent │ ─── Analyzes exploitation methods
└───────┬───────┘
        ▼
┌───────────────┐
│Lateral Agent  │ ─── Discovers lateral movement paths
└───────┬───────┘
        ▼
┌───────────────┐
│Business Logic │ ─── Detects workflow abuse patterns
│    Agent      │
└───────┬───────┘
        ▼
┌───────────────┐
│ Multi-Vector  │ ─── Combines attack techniques
│    Agent      │
└───────┬───────┘
        ▼
┌───────────────┐
│ Impact Agent  │ ─── Assesses business consequences
└───────┬───────┘
        ▼
┌───────────────┐
│  Synthesizer  │ ─── Consolidates findings
└───────┬───────┘
        ▼
Final AEV Result
```

### Job Queue System

BullMQ with Redis handles asynchronous processing:

| Job Type | Description |
|----------|-------------|
| `evaluation` | AEV analysis pipeline |
| `cloud_discovery` | Cloud asset enumeration |
| `network_scan` | Port scanning and service detection |
| `external_recon` | Internet-facing asset reconnaissance |
| `exploit_validation` | Live payload-based validation |
| `report_generation` | PDF/CSV/JSON report creation |
| `ai_simulation` | Purple team AI simulations |
| `agent_deployment` | Remote agent installation |

### Database Schema

Key tables:

| Table | Purpose |
|-------|---------|
| `aevEvaluations` | Vulnerability evaluations |
| `aevResults` | Analysis results per evaluation |
| `endpointAgents` | Registered security agents |
| `discoveredAssets` | Cloud and network assets |
| `cloudConnections` | Cloud provider integrations |
| `aiSimulations` | AI vs AI simulation records |
| `tenants` | Multi-tenant organizations |

### Multi-Tenant Architecture

```
┌─────────────────────────────────────────────┐
│                Tenant Layer                 │
├─────────────────────────────────────────────┤
│  Tenant A           │  Tenant B             │
│  ├─ Org 1          │  ├─ Org 3             │
│  │  ├─ Users       │  │  ├─ Users          │
│  │  ├─ Assets      │  │  ├─ Assets         │
│  │  └─ Agents      │  │  └─ Agents         │
│  └─ Org 2          │  └─ Org 4             │
└─────────────────────────────────────────────┘
```

Features:
- Tenant isolation at database level
- Organization-scoped operations
- IP allowlisting per tenant
- Feature limits and quotas
- Hierarchical tenant structure

### Real-Time Communication

WebSocket channels:
- `evaluation:${id}` - Evaluation progress updates
- `simulation:${id}` - Simulation round updates
- `discovery:${connectionId}` - Cloud discovery progress
- `assets:${orgId}` - Asset change notifications
- `auto-deploy:${orgId}` - Agent deployment status

### Security Architecture

| Layer | Implementation |
|-------|----------------|
| Authentication | OIDC + Session-based |
| Authorization | Role-based with org scoping |
| Agent Auth | API keys with bcrypt hashing + mTLS support |
| API Security | Rate limiting, CORS, CSP headers |
| Data Protection | Encrypted credentials, tenant isolation |

## External Dependencies

| Service | Purpose |
|---------|---------|
| PostgreSQL | Primary database |
| Redis | Job queue and caching |
| OpenAI API | AI analysis engine |
| AWS SDK | EC2, RDS, Lambda, S3 discovery |
| Azure SDK | VM, SQL, Resource discovery |
| GCP SDK | Compute, Resource Manager discovery |
