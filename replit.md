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

### Multi-Tenant Isolation
- **Tenants Table**: Core tenant management with tier-based feature limits, IP allowlisting, and hierarchical multi-tenancy support.
- **Tenant Middleware** (`server/middleware/tenant.ts`): Extracts tenant context from session/headers, validates tenant status, enforces IP allowlists.
- **Tenant Context**: Every request includes `TenantContext` with tenantId, organizationId, tier, and enabled features.
- **Feature Gating**: `requireTier()` and `requireFeature()` middleware enforce feature access based on tenant configuration.
- **Default Tenant**: System seeds a "default" tenant on startup with enterprise-level access for development/single-tenant deployments.

### Scheduled Scan Scheduler
- **Automatic Execution**: node-cron scheduler checks for due scans every minute.
- **Scan Frequencies**: Supports once, daily, weekly, monthly, and quarterly schedules.
- **Next Run Calculation**: Automatically computes nextRunAt based on frequency and time settings.
- **Batch Job Creation**: Due scans create batch jobs with all configured assets.
- **Manual Trigger**: `POST /api/scheduled-scans/:id/trigger` for on-demand execution.
- **One-time Scans**: Automatically disabled after execution.

### Job Queue Infrastructure
- **BullMQ Integration**: Redis-backed job queue with in-memory fallback when Redis is unavailable.
- **Job Types**: Evaluation, network scan, cloud discovery, external recon, report generation, AI simulation, and more.
- **API Routes**: `/api/jobs/*` endpoints for job submission, status, and management.
- **Graceful Degradation**: Queue service automatically detects Redis availability and falls back to in-memory processing.
- **Database Persistence**: All scan/validation results persisted to dedicated tables (apiScanResults, authScanResults, exploitValidationResults, remediationResults).
- **Registered Handlers** (12 total):
  - `network_scan`: Real TCP port scanning with banner grabbing and vulnerability detection.
  - `cloud_discovery`: Multi-cloud asset discovery (AWS/Azure/GCP) via CloudIntegrationService.
  - `external_recon`: External reconnaissance using fullRecon service (port scan, SSL check, HTTP fingerprinting, DNS enumeration).
  - `report_generation`: Report generation via ReportGenerator (executive, technical, compliance reports).
  - `ai_simulation`: AI vs AI purple team simulations via runAISimulation with iterative attack/defense rounds.
  - `evaluation`: Single AI-powered security evaluation using agent orchestrator with multi-agent analysis.
  - `full_assessment`: Multi-phase penetration testing across multiple systems with unified attack graphs.
  - `exploit_validation`: Safe exploit verification for security findings with configurable safe/live modes.
  - `api_scan`: API endpoint security testing (authentication, injection, authorization vulnerabilities).
  - `auth_scan`: Authentication/authorization testing (credential handling, session management, bypass vectors).
  - `remediation`: Remediation workflow management with action execution and verification.
  - `agent_deployment`: Cloud-based agent deployment automation (AWS/Azure/GCP instance targeting).

### Live Network Testing (Phase 2A Complete)
- **Real TCP Port Scanning**: Uses Node.js net module for actual network connectivity testing.
- **Banner Grabbing**: Captures service banners from open ports for fingerprinting.
- **Service Detection**: Identifies running services (SSH, HTTP, FTP, etc.) from banners.
- **Vulnerability Pattern Matching**: Detects known vulnerable versions and misconfigurations.
- **Job Handler**: `network-scan-handler.ts` processes scan jobs via the queue system.
- **Database Persistence**: Scan results stored in `liveScanResults` table with organization scoping.
- **REST API**: `/api/scans` endpoints for submitting scans and retrieving results with tenant isolation.
- **Secure WebSocket Progress**: Tenant-scoped channels (`network-scan:${tenantId}:${organizationId}:${scanId}`) with server-side subscription authorization.
- **Failure Visibility**: WebSocket events include `phase: "error"` for failed scans/targets.

### Endpoint Agent System
- Live agent deployment for real-time monitoring.
- Features agent registration, telemetry ingestion, auto-evaluation triggers for critical findings, and deduplication.
- **Go Agent**: Pre-compiled binaries in `public/agents/` for Linux, Windows, macOS (amd64/arm64).
- **Real-time Status**: Agent status calculated dynamically based on heartbeat age (online <2min, stale 2-10min, offline >10min).
- **Force Check-in**: On-demand refresh of agent data via WebSocket broadcast.
- **Platform Validation**: Cross-platform data contamination prevention - telemetry rejected if reported OS doesn't match registered agent platform.

### Validation Agent Heartbeat System
- **Heartbeat Tracker** (`server/services/agents/heartbeat-tracker.ts`): Tracks progress of long-running AI validation agents.
- **Stall Detection**: Agents marked stalled after 5 minutes without progress updates.
- **Automatic Recovery**: Stalled agents trigger automatic retries (up to 2 retries, 3 total attempts).
- **Timeout Mechanism**: `runWithStallTimeout` races agent execution against a stall timer, enabling retry when hung.
- **WebSocket Events**: Broadcasts `agent_stall_detected`, `agent_recovery_attempt`, and `agent_recovery_failed` for real-time monitoring.
- **Integration**: All orchestrator agent calls wrapped with `runWithHeartbeat` for automatic stall handling.

### Cloud Agent Deployment
- **AWS**: Uses SSM Run Command to install agents on EC2 instances. Requires `ssm:SendCommand` permission and SSM Agent on instances.
- **Azure**: Uses VM Run Command to install agents on Azure VMs. Requires `Microsoft.Compute/virtualMachines/runCommand/action` permission.
- **GCP**: Uses startup script metadata to install agents on next instance reboot. Requires `compute.instances.setMetadata` permission.
- **Pre-registration**: Agents are pre-registered in pending state before cloud deployment, appearing immediately in the Agents list.
- **Status Tracking**: Deployment status tracked per cloud asset (pending, deploying, success, failed).

### AEV Evidence Collection (Phase 1 Complete)
- **Database Schema**: `validationEvidenceArtifacts` table stores raw HTTP request/response, timing data, verdict classifications, and tenant scoping.
- **ValidationVerdict Types**: `confirmed`, `likely`, `theoretical`, `false_positive`, `error` - with confidence scoring (0-100).
- **ValidatingHttpClient** (`server/services/validation/validating-http-client.ts`): Wraps fetch to capture full request/response with timing, sanitizes sensitive headers, truncates large bodies. Provides `saveEvidence()` method for consistent artifact creation.
- **EvidenceStorageService** (`server/services/validation/evidence-storage-service.ts`): Manages evidence persistence with retention policies (default 90 days), per-evaluation artifact limits (max 100), automatic cleanup of theoretical/false-positive findings.
- **Tenant Isolation**: All evidence queries enforce organizationId at storage layer for cross-tenant protection.
- **Scan Handler Integration**:
  - `api-scan-handler.ts`: Captures HTTP evidence for up to 5 critical/high severity API vulnerabilities using ValidatingHttpClient.saveEvidence() with full ValidationContext (tenantId, organizationId, evaluationId, scanId, findingId).
  - `auth-scan-handler.ts`: Captures authentication test evidence for critical/high severity issues with proper context linking.
- **Report Integration**: Technical reports now include raw evidence artifacts matched to evaluation findings via evaluationId, enabling full audit trail in generated reports.
- **API Endpoints**:
  - `GET /api/evidence` - List evidence artifacts for organization
  - `GET /api/evidence/summary` - Statistics (counts by verdict, total size)
  - `GET /api/evidence/:id` - Get single artifact with org verification
  - `GET /api/evaluations/:evaluationId/evidence` - Evidence by evaluation
  - `GET /api/findings/:findingId/evidence` - Evidence by finding
  - `DELETE /api/evidence/:id` - Delete artifact with org verification
  - `POST /api/evidence/cleanup` - Trigger retention policy cleanup

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