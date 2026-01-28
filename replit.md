# OdinForge AI Platform

## Overview
OdinForge AI is an AI-powered security platform for autonomous exploit validation and attack simulation. It identifies security exposures, assesses exploitability using AI, constructs attack paths aligned with MITRE ATT&CK, evaluates business impact, and provides remediation recommendations. The platform offers multi-system penetration testing and an AI vs AI simulation system for purple team exercises, aiming to enhance security posture against evolving threats.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture
The platform utilizes a full-stack TypeScript architecture. The frontend is built with React 18, Wouter for routing, TanStack React Query for state management, and Tailwind CSS with shadcn/ui for styling, supporting dark/light modes. Real-time communication is handled via WebSockets. The backend uses Express.js and TypeScript, also with WebSockets, and includes services for AI analysis (AEV), Agent Orchestration, AI Simulation, Report Generation, and a Unified Auth Service supporting mTLS and JWT for multi-tenancy.

**Key Features:**

*   **AI vs AI Simulation System**: Features Attacker AI and Defender AI for purple team exercises with configurable iterative rounds and quick-start templates.
*   **Full Assessment System**: Provides multi-phase penetration testing, generating cross-system attack graphs and AI-powered analysis for unified attack paths, including Business Impact Analysis and Lateral Movement Analysis.
*   **Enhanced Web Application Mode**: Offers web app reconnaissance, parallel agent dispatch for various vulnerability types, and LLM validation to filter false positives.
*   **Multi-Tenant Isolation**: Supports multi-tenancy with a `Tenants` table for managing organizations, feature limits, and hierarchical multi-tenancy.
*   **Job Queue Infrastructure**: Uses BullMQ with a Redis-backed job queue for asynchronous tasks like evaluation, scanning, and report generation.
*   **Live Network Testing & External Reconnaissance**: Provides real TCP port scanning with banner grabbing and service detection, along with comprehensive internet-facing asset scanning across multiple security dimensions.
*   **Endpoint Agent System**: Supports live agent deployment for monitoring, telemetry, auto-evaluation triggers, and secure registration across multiple platforms.
*   **Validation Agent Heartbeat System**: Monitors and recovers stalled long-running AI validation agents.
*   **Cloud Agent Deployment**: Facilitates agent deployment on AWS, Azure, and GCP via cloud APIs or SSH.
*   **Cloud IAM Security Scanning**: Analyzes IAM configurations for security risks across AWS, Azure, and GCP, detecting critical issues.
*   **Coverage Autopilot**: A system for bulk agent deployment using short-lived enrollment tokens and platform-specific bootstrap commands.
*   **AEV Evidence Collection & Safe Validation Primitives**: Stores raw HTTP request/response data and verdict classifications, and includes a comprehensive categorized payload library.
*   **Governance & Safety Controls Enforcement**: Centralized controls including a kill switch, execution modes (Safe, Simulate, Live), and scope rules are enforced before job execution.
*   **Enhanced Reporting System**: Provides comprehensive, logic-based reporting with a vulnerability catalog, kill chain visualization (MITRE ATT&CK), and a report logic engine.
*   **API Security Testing**: Comprehensive API security testing with schema-aware fuzzing, authentication flow testing, and anomaly detection.
*   **OAuth/SAML Security Testing**: Focuses on security testing for JWT tokens, OAuth redirects, and SAML flows.
*   **Container/Kubernetes Security**: Analyzes container and Kubernetes manifests for security issues, aligning with CIS Kubernetes Benchmark Controls.
*   **Exploit Execution Sandbox**: Isolated environments for live exploit testing with configurable modes, payload execution, state snapshots, and evidence capture.
*   **Live Lateral Movement Testing**: Simulates credential reuse, pass-the-hash/ticket, and pivot point discovery across 10 lateral movement techniques, mapped to MITRE ATT&CK.
*   **Cloud Penetration Testing**: Full cloud security testing for AWS, Azure, and GCP, including IAM analysis, storage security, network exposure, secrets management, compute vulnerabilities, and AI-powered remediation.
*   **Compliance Reporting System**: Multi-framework compliance assessment and reporting supporting NIST 800-53, PCI-DSS 4.0, SOC 2, and HIPAA.
*   **Container Security Testing**: Advanced container escape detection and Kubernetes abuse testing.
*   **Business Logic Fuzzing Engine**: Workflow fuzzing with race condition detection, transaction manipulation testing, authentication bypass chain detection, and state violation detection.
*   **Remediation Automation**: Infrastructure-as-Code fix generation for Terraform, CloudFormation, and Kubernetes manifests, and code patch suggestions for vulnerabilities.
*   **Tool Integration**: Integration with Metasploit Framework and Nuclei for exploit execution and vulnerability scanning.
*   **Session Replay System**: Full exploit session recording with forensic-quality evidence collection, including event timelines, attack path visualization, and network traffic capture.
*   **RAG-Enhanced Policy Enforcement**: Vector-based Rules of Engagement (RoE) context injection into all AI agents to prevent hallucination and enforce organizational security policies.
*   **PolicyGuardian Check-Loop**: Synchronous policy validation for agent actions before commitment to final results, using RAG-enhanced policy search for ALLOW/DENY/MODIFY decisions.
*   **AI Debate Module for False Positive Detection**: Multi-model adversarial validation system using a CriticAgent to challenge ExploitAgent findings before final scoring, integrating a structured challenge-response protocol.
*   **Real-Time Reasoning Trace View**: Streams agent Chain of Thought to the UI via WebSocket during evaluation execution. Features terminal-style display with color-coded agents (PolicyGuardian in gold/yellow, ExploitAgent in red, CriticAgent in cyan, etc.), auto-scroll with pause-on-hover, and live indicator for active evaluations.

**UI/UX Design**:
The design system follows custom guidelines blending Material Design with cyber-security aesthetics, using Inter and JetBrains Mono fonts, a dark-first color scheme with cyan/blue accents, and data-dense layouts.

## External Dependencies
*   **PostgreSQL**: Primary relational database.
*   **Drizzle ORM**: TypeScript ORM for database interaction.
*   **OpenAI API**: Used for core AI analysis.
*   **shadcn/ui**: Accessible React component library.
*   **TanStack React Query**: Data fetching, caching, and synchronization.
*   **ws**: WebSocket server library for real-time communication.
*   **BullMQ**: Job queue library.
*   **Redis**: Backing store for BullMQ.
*   **OpenRouter**: For alternative LLM models (e.g., Llama-3, DeepSeek) used by CriticAgent.

## Recent Changes

**January 2026 - Multi-Tenant Row-Level Security (RLS)**
- Implemented PostgreSQL Row-Level Security policies on 52 tenant-sensitive tables
- RLS policies enforce strict tenant isolation at the database level using `app.current_organization_id` session variable
- Security model: DENY by default when org context is unset (fail-closed); requires explicit bypass for system operations
- Tenant context middleware (`server/middleware/tenant.ts`) sets RLS context per-request; fails request with 500 if context setup fails
- JWT auth middleware (`server/services/ui-auth.ts`) extracts organizationId from tokens and sets RLS context
- Background job handlers (evaluation, AI simulation, report generation, full assessment, cloud discovery) set/clear tenant context for job duration
- Admin bypass mode via `app.rls_bypass='true'` flag with helper functions: `withRLSBypass()`, `enableRLSBypass()`, `disableRLSBypass()`
- Three tables skipped (no organization_id column): `aev_results`, `evaluation_history`, `ui_refresh_tokens`
- RLS initialization logs on startup showing protected tables count

**January 2026 - RuntimeGuard Human-in-the-Loop Approval System**
- Added `hitl_approval_requests` table for tracking pending/approved/rejected command approvals
- Implemented `RuntimeGuard` service with forbidden command pattern detection (rm -rf, DROP TABLE, etc.)
- RAG-based policy search to identify blacklisted targets and forbidden commands from security_policies
- HITL approval workflow blocks orchestrator execution until security admin approves high-risk commands
- Server-side signature generation using HMAC with HITL_SIGNING_SECRET (required in production)
- WebSocket events: `hitl_approval_required` and `hitl_approval_response` for real-time notifications
- API endpoints: GET /api/hitl/pending, GET /api/hitl/evaluation/:id, POST /api/hitl/:id/approve, POST /api/hitl/:id/reject
- RBAC: Approve/reject requires security_admin or org_owner roles; viewing allows security_analyst
- PolicyGuardian integration via checkActionWithRuntimeGuard() and executeWithApproval()

**January 2026 - Forensic Audit Logging System**
- Added `audit_logs` and `forensic_exports` tables for comprehensive agent activity tracking
- Implemented `AuditLogger` service with methods for logging agent decisions, LLM prompts/responses, command outputs, policy checks, and evidence artifacts
- Created `EvidenceStorageService` using Replit Object Storage for screenshots (PNG) and network captures (PCAP)
- Built `ForensicExportService` with AES-256-GCM encryption (scrypt key derivation) for secure export bundling
- Added RBAC-protected API endpoints for forensic export creation/download (requires security_admin, org_owner, or security_analyst roles)
- Orchestrator enhanced to create audit logs at evaluation start with unique executionId
- Encryption format: salt (32 bytes) + IV (16 bytes) + authTag (16 bytes) + ciphertext

**January 2026 - Real-Time Reasoning Trace View**
- Added `ReasoningTracePanel` component with terminal-style UI displaying agent Chain of Thought
- Implemented WebSocket events: `reasoning_trace` and `shared_memory_update`
- Enhanced orchestrator to emit reasoning traces during agent execution phases
- Color-coded agent entries: PolicyGuardian (gold), ExploitAgent (red), CriticAgent (cyan), ReconAgent (blue), LateralAgent (purple), BusinessLogicAgent (orange), ImpactAgent (pink), DebateModule (emerald), Orchestrator (gray)
- Auto-scroll with pause-on-hover functionality and live indicator for active evaluations

**January 2026 - Cloud Agent Deployment Consistency**
- Centralized deployment configuration in `DEPLOYMENT_CONFIG` constant:
  - `COMMAND_TIMEOUT_MS: 300000` (5 minutes for command execution)
  - `POLL_INTERVAL_MS: 5000` (5 seconds between status checks)
  - `VM_RESET_TIMEOUT_MS: 120000` (2 minutes for VM reset)
  - `TOKEN_EXPIRY_MS: 3600000` (1 hour for registration tokens)
- Added SSH deployment fallback for all cloud providers via `deployViaSSHWithCredential()`
- Multi-tenant security: SSH credential ownership validated against organizationId before use
- Agent binaries stored in Object Storage at `/public/agents/` for production accessibility
- Deployment methods by provider:
  - AWS: SSM Run Command (immediate) or SSH if credentials provided
  - Azure: VM Run Command (immediate) or SSH if credentials provided  
  - GCP: SSH if credentials provided, otherwise startup-script + VM reset

## WebSocket Events

The platform uses WebSocket for real-time communication. Key event types:

| Event Type | Description | Payload |
|------------|-------------|---------|
| `aev_progress` | Evaluation progress updates | evaluationId, agentName, stage, progress, message |
| `aev_complete` | Evaluation completion | evaluationId, status |
| `reasoning_trace` | Agent Chain of Thought stream | evaluationId, agentId, agentName, content, metadata |
| `shared_memory_update` | Agent shared memory changes | evaluationId, key, value, agentName |

**Channel Subscription Pattern:**
- Clients subscribe to `evaluation:${evaluationId}` to receive updates for specific evaluations
- WebSocket server broadcasts to all subscribers on matching channels

## Environment Separation

OdinForge supports strict development vs production environment separation using Replit's infrastructure.

### Environment Detection
The platform automatically detects the environment using these signals:
- `REPLIT_DEPLOYMENT=1` → Production
- `REPLIT_DEPLOYMENT_PREVIEW=1` → Preview (deployment testing)
- Otherwise → Development

### Database Separation
- **Development database**: Free, for experimentation and testing
- **Production database**: Automatically created on publish (PostgreSQL 16 on Neon)
- Schema changes should be validated in dev before publishing
- Use deployment previews to test changes before affecting production

### Migration Commands
Run these commands to manage database schema:
```bash
npx tsx scripts/db-migrate.ts generate [name]  # Generate migration from schema changes
npx tsx scripts/db-migrate.ts push             # Push to dev database
npx tsx scripts/db-migrate.ts validate         # Validate schema consistency
npx tsx scripts/db-migrate.ts status           # Show migration status
```

### Pre-Deployment Validation
Run validation before publishing:
```bash
npx tsx scripts/pre-deploy-validate.ts
```
This checks TypeScript types and Drizzle schema before deployment.

### Environment-Specific Secrets
Secrets can be scoped by environment. The system looks for:
1. `{SECRET_NAME}_PRODUCTION`, `{SECRET_NAME}_PREVIEW`, or `{SECRET_NAME}_DEVELOPMENT` (environment-specific)
2. `{SECRET_NAME}` (fallback)

Key secrets:
- `DATABASE_URL` - Automatically set by Replit for each environment
- `OPENAI_API_KEY` - AI integration key
- `REDIS_URL` - Queue backend connection