# OdinForge AI Platform

## Overview

OdinForge AI (Adversarial Exposure Validation) is a next-generation AI-powered security platform that performs autonomous exploit validation and attack simulation. The platform analyzes security exposures (CVEs, misconfigurations, behavioral anomalies, network vulnerabilities) and uses AI to determine exploitability, construct attack paths using MITRE ATT&CK techniques, assess business impact, and generate remediation recommendations.

The application follows a full-stack TypeScript architecture with a React frontend, Express backend, PostgreSQL database, and real-time WebSocket communication for live evaluation progress updates.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Routing**: Wouter (lightweight React router)
- **State Management**: TanStack React Query for server state, local React state for UI
- **Styling**: Tailwind CSS with shadcn/ui component library (New York style)
- **Theme**: Dark/light mode support with cyber-security aesthetics
- **Real-time Updates**: WebSocket connection for live evaluation progress

The frontend is organized around a dashboard-centric design with:
- Main dashboard showing evaluation statistics and active assessments
- **Guided Evaluation Wizard** for non-technical users with 8 infrastructure categories (Web Servers, Databases, Cloud Storage, Containers, Network, Identity, Email, Applications)
- Evaluation table with filtering and sorting capabilities
- Detail views for individual evaluation results including attack path visualization
- Modal-based workflows for creating new evaluations and viewing progress
- Risk Dashboard with interactive visualizations (attack graphs, heatmaps, gauges)
- Reports page for generating executive, technical, and compliance reports
- Batch Jobs page for parallel security assessments

### Evaluation Wizard System
The platform includes a guided wizard (`client/src/components/EvaluationWizard.tsx`) for non-technical administrators:
- **Templates** (`client/src/lib/evaluation-templates.ts`): 8 infrastructure categories with specific types, versions, and configuration questions
- **Smart Priority Calculation**: Layered risk scoring considers internet exposure, data sensitivity, patch status, authentication methods, and risk factor combinations
- **Auto-generated Descriptions**: Converts wizard answers into structured technical descriptions for AI analysis
- **Dual Paths**: Dashboard offers both "Guided Wizard" (template-based) and "Quick Evaluation" (manual entry) options

### Backend Architecture
- **Framework**: Express.js with TypeScript
- **Build Tool**: Vite for frontend, esbuild for server bundling
- **API Design**: RESTful endpoints under `/api/` prefix
- **Real-time**: WebSocket server on `/ws` path for progress events

Key backend services:
- **AEV Service** (`server/services/aev.ts`): Core AI analysis using OpenAI API to evaluate security exposures
- **WebSocket Service** (`server/services/websocket.ts`): Broadcasts evaluation progress and completion events
- **Storage Layer** (`server/storage.ts`): Database abstraction using Drizzle ORM
- **Report Generator** (`server/services/report-generator.ts`): Generates executive, technical, and compliance reports
- **Agent Orchestrator** (`server/services/agents/orchestrator.ts`): Coordinates AI agent workflow for evaluations with adversary profile support
- **Defender Agent** (`server/services/agents/defender.ts`): AI agent for detecting attacks, recommending responses, and assessing control effectiveness
- **AI Simulation Orchestrator** (`server/services/agents/ai-simulation.ts`): Runs AI vs AI simulations with iterative attack/defense cycles and purple team feedback
- **mTLS Auth Service** (`server/services/mtls-auth.ts`): Certificate generation, validation, rotation, and revocation for agent authentication
- **JWT Auth Service** (`server/services/jwt-auth.ts`): JWT token management with multi-tenant support and scope-based authorization
- **Unified Auth Service** (`server/services/unified-auth.ts`): Unified authentication middleware supporting API keys, mTLS certificates, and JWT tokens

### AI vs AI Simulation System
The platform includes an AI vs AI simulation capability for purple team exercises:
- **Attacker AI**: Uses the orchestrator's multi-agent system (recon, exploit, lateral, business logic, multi-vector agents)
- **Defender AI**: Detects attacks, recommends responses, assesses defensive control effectiveness
- **Iterative Rounds**: Configurable number of attack/defense cycles
- **Purple Team Feedback**: Generates actionable recommendations based on simulation results
- **Frontend Page**: `/simulations` route with simulation creation, progress tracking, and result visualization

### Data Storage
- **Database**: PostgreSQL with Drizzle ORM
- **Schema Location**: `shared/schema.ts` (shared between frontend and backend)
- **Key Tables**:
  - `users`: Basic user authentication
  - `aev_evaluations`: Stores evaluation requests with asset info, exposure type, priority
  - `aev_results`: Stores AI analysis results including exploitability scores, attack paths, recommendations
  - `reports`: Stores generated reports (executive, technical, compliance)
  - `batch_jobs`: Tracks batch evaluation jobs with progress and results
  - `scheduled_scans`: Stores scheduled scan configurations
  - `evaluation_history`: Tracks historical evaluation snapshots for drift detection
  - `endpoint_agents`: Tracks deployed endpoint agents with hashed API keys and metadata
  - `agent_telemetry`: Stores system info, metrics, and security findings from agents
  - `agent_findings`: Individual security findings detected by agents with auto-evaluation triggers
  - `ai_simulations`: Tracks AI vs AI simulation sessions with attacker/defender results
  - `purple_team_findings`: Stores purple team findings and recommendations from simulations

### Endpoint Agent System
The platform includes a live agent deployment system for real-time security monitoring:
- **Agent Registration**: Agents register via `/api/agents/register` and receive a one-time API key (bcrypt hashed for storage)
- **Telemetry Ingestion**: Agents send system data and security findings via `/api/agents/telemetry`
- **Auto-evaluation Triggers**: Critical/high severity findings automatically create AEV evaluations
- **Deduplication**: Findings are deduplicated using composite keys (findingType|title|affectedComponent)

**Security Features**:
- API keys hashed with bcrypt before storage (plaintext only shown once at registration)
- Zod validation on all agent API endpoints
- HTTPS enforcement with optional mTLS and SPKI pinning

### Go Agent Deployment
The platform includes a production-ready Go agent (`odinforge-agent/`) with comprehensive deployment options:

**Agent Features**:
- Collects system telemetry (CPU, memory, disk, network)
- Offline resilience using BoltDB queue for buffering
- Batched HTTPS transmission with optional mTLS and SPKI pinning
- Stable agent ID based on hostname+OS+arch hash

**Self-Install CLI**:
```bash
# Auto-detect environment and install
sudo ./odinforge-agent install --server-url https://server.com --api-key KEY

# Check installation status
./odinforge-agent status

# Uninstall
sudo ./odinforge-agent uninstall
```

**Deployment Options** (`odinforge-agent/deploy/`):
- **Docker**: `docker-compose.yml` with volume mounts and environment configuration
- **Kubernetes**: DaemonSet/Deployment manifests with ConfigMap, Secret, and PVC
- **Linux systemd**: Service unit with security hardening (ProtectSystem, NoNewPrivileges, etc.)
- **macOS launchd**: Plist template for daemon installation

**Environment Detection**:
The installer auto-detects: Docker containers, Kubernetes pods, systemd (Linux), launchd (macOS), Windows services

### AI Integration
- **Provider**: OpenAI API (configurable via environment variables)
- **Purpose**: Analyzes security exposures to determine exploitability, construct attack paths, assess impact, and generate remediation steps
- **Configuration**: `AI_INTEGRATIONS_OPENAI_API_KEY` and `AI_INTEGRATIONS_OPENAI_BASE_URL` environment variables

### Design System
The platform follows custom design guidelines (`design_guidelines.md`) combining Material Design component structure with cyber-security aesthetics:
- Typography: Inter for UI, JetBrains Mono for technical data
- Color scheme: Dark-first with cyan/blue accent gradients for security branding
- Data-dense layouts optimized for security professionals

## External Dependencies

### Database
- **PostgreSQL**: Primary data store (requires `DATABASE_URL` environment variable)
- **Drizzle ORM**: Type-safe database queries and migrations
- **connect-pg-simple**: PostgreSQL session store

### AI Services
- **OpenAI API**: Powers the AEV analysis engine for exploit validation
  - Requires `AI_INTEGRATIONS_OPENAI_API_KEY`
  - Optional `AI_INTEGRATIONS_OPENAI_BASE_URL` for custom endpoints

### Frontend Libraries
- **shadcn/ui**: Pre-built accessible React components (Radix UI primitives)
- **TanStack React Query**: Data fetching and caching
- **Lucide React**: Icon library
- **date-fns**: Date formatting utilities

### Development Tools
- **Vite**: Frontend development server and build tool
- **tsx**: TypeScript execution for development
- **Drizzle Kit**: Database migration tooling

### Real-time Communication
- **ws**: WebSocket library for server-side real-time communication
- Native WebSocket API on client for receiving evaluation progress updates

## Production Hardening

### Rate Limiting
- Sliding window algorithm with per-endpoint configurations
- Default limits: Auth (10 req/15min), API (100 req/min), Agent telemetry (1000 req/min)
- Strict limits for heavy operations: Simulations (3 req/5min), Reports (5 req/min)
- Response headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After

### Database Optimization
- 37 performance indexes created at startup (server/db-indexes.ts)
- Covers: evaluations, results, agents, findings, telemetry, reports, simulations, authorization logs
- Indexes created via pg client during application startup

### WebSocket Scaling
- Connection limits: 1000 global, 50 per IP
- Heartbeat monitoring: 30s ping interval, 60s timeout
- Automatic cleanup of stale connections
- Message queuing: 100 messages max per client

### Production Environment Variables
- `NODE_ENV=production` - Enables production mode
- `WS_REQUIRE_AUTH=true` - Enables JWT authentication for WebSocket connections (enabled by default in production; set to "false" only for demo/testing)
- `SESSION_SECRET` - Required for JWT signing (minimum 32 characters recommended)

### Load Testing
- Load test script at `scripts/load-test.ts`
- Usage: `npx tsx scripts/load-test.ts [concurrency] [requestsPerEndpoint]`
- Example: `npx tsx scripts/load-test.ts 10 100` (10 concurrent, 100 requests each)
- Metrics: latency percentiles (P50/P95/P99), throughput, rate limit detection