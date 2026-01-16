# OdinForge AI Platform

## Overview
OdinForge AI (Adversarial Exposure Validation) is a next-generation AI-powered security platform designed for autonomous exploit validation and attack simulation. Its core purpose is to analyze security exposures, determine exploitability using AI, construct attack paths via MITRE ATT&CK, assess business impact, and generate remediation recommendations. The platform aims to provide comprehensive multi-system penetration testing capabilities and an AI vs AI simulation system for purple team exercises, enabling organizations to proactively strengthen their security posture against evolving threats.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture
### Core Platform
The platform uses a full-stack TypeScript architecture. The frontend is built with React 18, utilizing Wouter for routing, TanStack React Query for state management, and Tailwind CSS with shadcn/ui for styling, supporting dark/light modes. Real-time communication is handled via WebSockets for live progress updates.

The backend is built with Express.js and TypeScript, also leveraging WebSockets. Key services include:
- **AEV Service**: AI analysis using OpenAI.
- **Agent Orchestrator**: Coordinates AI agents for evaluations.
- **AI Simulation Orchestrator**: Manages AI vs AI simulations with iterative attack/defense cycles.
- **Report Generator**: Creates executive, technical, and compliance reports.
- **Auth Services**: mTLS Auth Service for agent authentication and JWT Auth Service for user authentication, integrated into a Unified Auth Service supporting multi-tenancy.

### AI vs AI Simulation System
This system features Attacker AI and Defender AI for purple team exercises, offering configurable iterative rounds with actionable recommendations.

**Quick-Start Templates**: The Simulations page (`/simulations`) provides 5 pre-configured templates for one-click simulation launch:
1. **Web Application Breach**: SQL injection, XSS, and authentication bypass attacks
2. **Cloud Infrastructure Attack**: Cloud misconfigurations, IAM weaknesses, container escapes
3. **Ransomware Simulation**: Lateral movement, data encryption tactics
4. **Data Exfiltration**: Sensitive data theft via multiple exfiltration channels
5. **Insider Threat**: Privilege abuse and credential misuse from internal actors

**Evaluation-to-Simulation Flow**: Completed evaluations show a "Start AI Simulation" button that navigates to `/simulations` with pre-filled parameters (`assetId`, `exposureType`, `priority`, `fromEvaluation`) for seamless workflow continuation.

### Full Assessment System
Provides multi-phase penetration testing, including reconnaissance, vulnerability analysis, attack synthesis, lateral movement, and impact assessment. It generates cross-system attack graphs and AI-powered analysis for unified attack paths, delivering real-time progress and prioritized remediation. This includes Business Impact Analysis and Lateral Movement Analysis.

### Data Storage
PostgreSQL serves as the primary data store, with Drizzle ORM for type-safe database interactions. The schema defines tables for users, evaluations, results, reports, agents, and simulations.

### Multi-Tenant Isolation
The system supports multi-tenancy with a `Tenants` table for managing organizations, tier-based feature limits, IP allowlisting, and hierarchical multi-tenancy. A tenant middleware extracts context, validates status, and enforces IP allowlists, ensuring feature gating based on tenant configuration.

### Job Queue Infrastructure
Utilizes BullMQ with a Redis-backed job queue, featuring an in-memory fallback. It supports various job types such as evaluation, network scan, cloud discovery, external recon, report generation, and AI simulation. All scan and validation results are persisted to dedicated database tables. Job handlers include `network_scan`, `cloud_discovery`, `external_recon`, `report_generation`, `ai_simulation`, `evaluation`, `full_assessment`, `exploit_validation`, `api_scan`, `auth_scan`, `remediation`, and `agent_deployment`.

### Live Network Testing
This feature provides real TCP port scanning with banner grabbing, service detection, and vulnerability pattern matching. Results are stored in the `liveScanResults` table and accessible via a REST API with tenant isolation. Secure WebSocket channels provide real-time progress updates.

### External Reconnaissance (6-Section Structure)
Provides comprehensive internet-facing asset scanning with direct integration into autonomous exploit chaining logic. The system is organized into 6 sections:

1. **Network Exposure**: Open ports, high-risk services (FTP, Telnet, SMB, RDP, VNC), database exposure, version disclosure
2. **Transport Security**: TLS grading (A+ to F), HSTS configuration, forward secrecy, certificate transparency, downgrade risks
3. **Application Identity**: Technologies detected, frameworks, CMS, web server, WAF detection, security headers present/missing
4. **Authentication Surface**: Login pages, admin panels (protected/unprotected), OAuth endpoints, password reset forms, API authentication methods
5. **DNS & Infrastructure**: Hosting/CDN providers, DNS configuration, mail security (SPF/DMARC), shadow assets
6. **Attack Readiness Summary**: Overall exposure score, risk level, category scores, AEV next-actions with MITRE ATT&CK IDs, prioritized remediations

Each finding includes exploit chain signals with:
- Exploit type and MITRE ATT&CK technique ID
- Chain position (initial_access, execution, persistence, privilege_escalation, lateral_movement)
- Required execution mode (observe, passive, active, exploit)
- Confidence score (0-100)

UI accessible via `/recon` with 7 tabs: Summary (default), Network, Transport, App, Auth, Infra, Findings.

### Endpoint Agent System
Supports live agent deployment for real-time monitoring, including agent registration, telemetry ingestion, auto-evaluation triggers, and deduplication. Pre-compiled Go agents are provided for multiple platforms. Agent status is dynamically calculated based on heartbeat, with support for force check-ins and cross-platform data validation.

**Agent Registration Token System**: Supports single-use registration tokens as a secure alternative to embedding permanent tokens. Admins can generate time-limited, one-time tokens via `/api/agents/registration-tokens` that are consumed after successful agent registration. Tokens are stored as SHA256 hashes with configurable expiration (default 24 hours).

**Zero-Interaction Agent Installation**: Only 2 deployment methods are supported for simplicity:

1. **Host Install** (Linux/Windows): The `POST /api/agents/install-command` endpoint generates a one-liner command with embedded server URL and single-use token. Scripts (`odinforge-agent/install.sh` and `install.ps1`) support CLI args (`--server-url`, `--api-key`, `--tenant-id`, `--dry-run`, `--force`), commands (`install|uninstall|status`), and automatic service installation with security hardening.

2. **Container Install** (Docker/Kubernetes): Docker deployment via `docker run` with environment variables (`ODINFORGE_SERVER_URL`, `ODINFORGE_API_KEY`, `ODINFORGE_TENANT_ID`). Kubernetes deployment via Helm chart at `odinforge-agent/deploy/helm/` with DaemonSet, RBAC, ServiceAccount, and optional mTLS configuration in `values.yaml`.

### Validation Agent Heartbeat System
Tracks the progress of long-running AI validation agents, detecting and recovering from stalled agents through retries and timeouts. WebSocket events provide real-time monitoring of agent status.

### Cloud Agent Deployment
Facilitates agent deployment on AWS (SSM Run Command), Azure (VM Run Command), and GCP (startup script metadata). Agents are pre-registered in a pending state, and deployment status is tracked per cloud asset.

### Coverage Autopilot
A hands-off agent onboarding system for deploying agents at scale across infrastructure. Available as a tab in the Agents page (`/agents`).

**Enrollment Tokens**: Short-lived (60-minute TTL) single-use tokens for bulk agent deployment. Stored as SHA256 hashes with only the last 6 characters visible for identification.
- `POST /api/enrollment/token` - Create enrollment token
- `GET /api/enrollment/tokens` - List active tokens
- `DELETE /api/enrollment/tokens/:id` - Revoke token

**Bootstrap Commands**: Platform-specific installation commands generated via `GET /api/bootstrap?token=<token>`:
- Host Install: Linux/Windows one-liner commands
- Cloud User-Data: AWS, Azure VMSS, GCP startup scripts (both Linux/Windows)
- Kubernetes: Raw DaemonSet manifest with placeholder substitution (`public/k8s/odinforge-agent-daemonset.yaml`)

**Coverage Metrics**: `GET /api/coverage` returns asset vs agent coverage stats with per-provider breakdowns (AWS, Azure, GCP).

**UI Component**: `CoverageAutopilot.tsx` displays coverage metrics, token generation, and tabbed bootstrap scripts with copy-to-clipboard functionality.

### AEV Evidence Collection
Stores raw HTTP request/response, timing data, and verdict classifications (`confirmed`, `likely`, `theoretical`, `false_positive`, `error`) in a `validationEvidenceArtifacts` table. A `ValidatingHttpClient` captures evidence, and an `EvidenceStorageService` manages persistence, retention policies, and automatic cleanup, ensuring tenant isolation.

### AEV Safe Validation Primitives (Phase 2 & 3 Complete)
- **Payload Library**: Comprehensive categorized payloads for SQL Injection, XSS, Command Injection, Path Traversal, SSRF, Auth Bypass with risk levels and indicators.
- **All 6 Validation Modules Implemented**:
  - `SqliValidator`: Error-based, time-based, boolean-based detection with DB fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
  - `XssValidator`: Reflected and DOM-based XSS detection with encoding analysis.
  - `AuthBypassValidator`: SQLi bypass, header manipulation, path bypass techniques.
  - `CommandInjectionValidator`: Blind time-based (sleep/ping) and error-based (id, whoami) with Unix/Windows OS detection.
  - `PathTraversalValidator`: File disclosure detection for Unix/Windows system files, config files, Base64 content.
  - `SsrfValidator`: Cloud metadata (AWS/Azure/GCP), localhost bypass, internal service detection.
- **ValidationEngine**: Unified coordinator for all 6 validators with evidence capture integration and configurable timeouts.
- **Exploit Validation Handler**: Runs live payload-based validation when `safeMode=false` with targetUrl, supports all 6 vulnerability types.

### Enhanced Reporting System
Provides comprehensive, logic-based reporting, including a vulnerability catalog, kill chain visualization mapping to MITRE ATT&CK, and a report logic engine for generating executive summaries, technical reports, and compliance assessments from actual data.

### Design System
Follows custom guidelines blending Material Design with cyber-security aesthetics, using Inter and JetBrains Mono fonts, a dark-first color scheme with cyan/blue accents, and data-dense layouts.

## External Dependencies
### Database
- **PostgreSQL**: Primary relational database.
- **Drizzle ORM**: TypeScript ORM for database interaction.
- **connect-pg-simple**: PostgreSQL session store.

### AI Services
- **OpenAI API**: Used for core AI analysis.

### Frontend Libraries
- **shadcn/ui**: Accessible React component library.
- **TanStack React Query**: Data fetching, caching, and synchronization.
- **Lucide React**: Icon library.
- **date-fns**: JavaScript date utility library.

### Development Tools
- **Vite**: Frontend build tool.
- **tsx**: TypeScript execution environment.
- **Drizzle Kit**: Database migration tool.

### Real-time Communication
- **ws**: WebSocket server library.
- Native WebSocket API on client-side.