# OdinForge AI Platform

## Overview
OdinForge AI (Adversarial Exposure Validation) is a next-generation AI-powered security platform for autonomous exploit validation and attack simulation. It analyzes security exposures (CVEs, misconfigurations, network vulnerabilities), determines exploitability using AI, constructs attack paths via MITRE ATT&CK, assesses business impact, and generates remediation recommendations. The platform features a full-stack TypeScript architecture with a React frontend, Express backend, PostgreSQL, and real-time WebSocket communication. It includes an AI vs AI simulation system for purple team exercises and a comprehensive multi-system penetration testing capability.

## User Preferences
Preferred communication style: Simple, everyday language.

## Documentation Structure
All documentation is consolidated under the `docs/` directory:

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Platform overview and quick start |
| [docs/README.md](docs/README.md) | Documentation hub and navigation |
| [docs/server/installation.md](docs/server/installation.md) | Server deployment (local, Docker, K8s) |
| [docs/server/configuration.md](docs/server/configuration.md) | Environment variables and settings |
| [docs/server/production.md](docs/server/production.md) | Production deployment and cloud platforms |
| [docs/agent/README.md](docs/agent/README.md) | Endpoint agent overview |
| [docs/agent/INSTALL.md](docs/agent/INSTALL.md) | Agent installation for all platforms |
| [docs/api/reference.md](docs/api/reference.md) | REST API documentation |

## System Architecture
### Frontend
- **Framework**: React 18 with TypeScript, Wouter for routing.
- **State Management**: TanStack React Query for server state.
- **Styling**: Tailwind CSS with shadcn/ui (New York style), dark/light mode.
- **Real-time**: WebSocket for live evaluation progress.
- **Components**: Dashboard for evaluation statistics, Guided Evaluation Wizard, evaluation table, risk dashboard, reports, batch jobs.
- **Evaluation Wizard**: Guides non-technical users with 8 infrastructure categories, smart priority calculation, and auto-generated descriptions for AI analysis.

### Backend
- **Framework**: Express.js with TypeScript.
- **Real-time**: WebSocket server for progress events.
- **Core Services**:
    - **AEV Service**: AI analysis using OpenAI.
    - **Agent Orchestrator**: Coordinates AI agents for evaluations.
    - **Defender Agent**: AI for attack detection and response.
    - **AI Simulation Orchestrator**: Manages AI vs AI simulations with iterative attack/defense cycles.
    - **Report Generator**: Creates executive, technical, and compliance reports.
    - **mTLS Auth Service**: Certificate management for agent authentication.
    - **JWT Auth Service**: JWT token management with multi-tenant support.
    - **Unified Auth Service**: Integrates API keys, mTLS, and JWT.

### AI vs AI Simulation System
- Features Attacker AI and Defender AI for purple team exercises.
- Configurable iterative rounds with actionable recommendations.

### Full Assessment System
- Multi-phase penetration testing (reconnaissance, vulnerability analysis, attack synthesis, lateral movement, impact assessment).
- Generates cross-system attack graphs and AI-powered analysis for unified attack paths.
- Provides real-time progress updates and prioritized remediation.
- **Business Impact Analysis**: Formatted display showing risk levels, data at risk, operational/financial impact, and regulatory implications.
- **Lateral Movement Analysis**: Visual display of movement paths with source/target systems, likelihood ratings, and prerequisites.

### Data Storage
- **Database**: PostgreSQL with Drizzle ORM.
- **Schema**: Shared `shared/schema.ts` defining tables for users, evaluations, results, reports, agents, and simulations.

### Endpoint Agent System
- Live agent deployment for real-time monitoring.
- Features agent registration, telemetry ingestion, auto-evaluation triggers for critical findings, and deduplication.
- **Go Agent**: `odinforge-agent/` for system telemetry, offline resilience, secure transmission (mTLS, SPKI pinning), and auto-registration.
- **Real-time Status**: Agent status calculated dynamically based on heartbeat age (online <2min, stale 2-10min, offline >10min).
- **Force Check-in**: On-demand refresh of agent data via WebSocket broadcast.

### AI Integration
- Uses OpenAI API for analyzing security exposures, determining exploitability, and generating attack paths and remediation.

### Enhanced Reporting System
- Comprehensive, logic-based reporting (not AI-templated).
- **Vulnerability Catalog**: Maps exposure types to detailed metadata, MITRE ATT&CK, CWE IDs, and remediation guidance.
- **Kill Chain Visualization**: Maps attack paths to MITRE ATT&CK phases, generates ASCII and PDF-exportable diagrams.
- **Report Logic Engine**: Computes executive summaries, technical reports, and compliance assessments from actual data.

### Design System
- Custom guidelines blending Material Design with cyber-security aesthetics.
- Typography: Inter, JetBrains Mono.
- Color scheme: Dark-first with cyan/blue accents.
- Data-dense layouts for security professionals.

## External Dependencies
### Database
- **PostgreSQL**: Primary data store.
- **Drizzle ORM**: Type-safe database queries.
- **connect-pg-simple**: PostgreSQL session store.

### AI Services
- **OpenAI API**: Core AI analysis engine.

### Frontend Libraries
- **shadcn/ui**: Accessible React components.
- **TanStack React Query**: Data fetching and caching.
- **Lucide React**: Icon library.
- **date-fns**: Date utilities.

### Development Tools
- **Vite**: Frontend build tool.
- **tsx**: TypeScript execution.
- **Drizzle Kit**: Database migration.

### Real-time Communication
- **ws**: Server-side WebSocket library.
- Native WebSocket API on client.