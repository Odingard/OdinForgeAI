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

### Endpoint Agent System
Supports live agent deployment for real-time monitoring, including agent registration, telemetry ingestion, auto-evaluation triggers, and deduplication. Pre-compiled Go agents are provided for multiple platforms. Agent status is dynamically calculated based on heartbeat, with support for force check-ins and cross-platform data validation.

**Agent Registration Token System**: Supports single-use registration tokens as a secure alternative to embedding permanent tokens. Admins can generate time-limited, one-time tokens via `/api/agents/registration-tokens` that are consumed after successful agent registration. Tokens are stored as SHA256 hashes with configurable expiration (default 24 hours). Install scripts can optionally have tokens embedded via `?token=` query parameter.

### Validation Agent Heartbeat System
Tracks the progress of long-running AI validation agents, detecting and recovering from stalled agents through retries and timeouts. WebSocket events provide real-time monitoring of agent status.

### Cloud Agent Deployment
Facilitates agent deployment on AWS (SSM Run Command), Azure (VM Run Command), and GCP (startup script metadata). Agents are pre-registered in a pending state, and deployment status is tracked per cloud asset.

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