# OdinForge AI Platform

## Overview
OdinForge AI (Adversarial Exposure Validation) is an AI-powered security platform designed for autonomous exploit validation and attack simulation. It identifies security exposures, assesses exploitability using AI, constructs attack paths aligned with MITRE ATT&CK, evaluates business impact, and provides remediation recommendations. The platform offers multi-system penetration testing and an AI vs AI simulation system for purple team exercises, aiming to enhance security posture against evolving threats.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture
The platform utilizes a full-stack TypeScript architecture. The frontend is built with React 18, Wouter for routing, TanStack React Query for state management, and Tailwind CSS with shadcn/ui for styling, supporting dark/light modes. Real-time communication is handled via WebSockets. The backend uses Express.js and TypeScript, also with WebSockets, and includes services for AI analysis (AEV), Agent Orchestration, AI Simulation, Report Generation, and a Unified Auth Service supporting mTLS and JWT for multi-tenancy.

**Key Features:**

*   **AI vs AI Simulation System**: Features Attacker AI and Defender AI for purple team exercises with configurable iterative rounds and quick-start templates for common attack scenarios.
*   **Full Assessment System**: Provides multi-phase penetration testing (reconnaissance, vulnerability analysis, attack synthesis, lateral movement, impact assessment), generating cross-system attack graphs and AI-powered analysis for unified attack paths. Includes Business Impact Analysis and Lateral Movement Analysis.
*   **Enhanced Web Application Mode**: Offers web app reconnaissance, parallel agent dispatch for various vulnerability types (SQLi, XSS, etc.), and LLM validation to filter false positives.
*   **Multi-Tenant Isolation**: Supports multi-tenancy with a `Tenants` table for managing organizations, feature limits, and hierarchical multi-tenancy, enforced via middleware.
*   **Job Queue Infrastructure**: Uses BullMQ with a Redis-backed job queue for handling various asynchronous tasks like evaluation, scanning, and report generation.
*   **Live Network Testing & External Reconnaissance**: Provides real TCP port scanning with banner grabbing and service detection, along with comprehensive internet-facing asset scanning across multiple security dimensions (Network Exposure, Transport Security, Application Identity, etc.). Includes both Domain Scan and Web App Scan modes.
*   **Endpoint Agent System**: Supports live agent deployment for monitoring, telemetry, auto-evaluation triggers, and secure registration across multiple platforms (host, cloud, Kubernetes).
*   **Validation Agent Heartbeat System**: Monitors and recovers stalled long-running AI validation agents.
*   **Cloud Agent Deployment**: Facilitates agent deployment on AWS, Azure, and GCP via cloud APIs or SSH.
*   **Cloud IAM Security Scanning**: Analyzes IAM configurations for security risks across AWS, Azure, and GCP, detecting critical issues like old access keys, dangerous permissions, and public access.
*   **Coverage Autopilot**: A system for bulk agent deployment using short-lived enrollment tokens and platform-specific bootstrap commands.
*   **AEV Evidence Collection & Safe Validation Primitives**: Stores raw HTTP request/response data and verdict classifications, and includes a comprehensive categorized payload library for various validation modules.
*   **Governance & Safety Controls Enforcement**: Centralized controls including a kill switch, execution modes (Safe, Simulate, Live), and scope rules (allow/block IP addresses, hostnames, etc.) are enforced before job execution.
*   **Enhanced Reporting System**: Provides comprehensive, logic-based reporting with a vulnerability catalog, kill chain visualization (MITRE ATT&CK), and a report logic engine for generating various report types.
*   **API Security Testing (Phase 2)**: Comprehensive API security testing with schema-aware fuzzing, authentication flow testing, and anomaly detection.
*   **OAuth/SAML Security Testing (Phase 2)**: Focuses on security testing for JWT tokens, OAuth redirects, and SAML flows, addressing known vulnerabilities and MITRE ATT&CK mappings.
*   **Container/Kubernetes Security (Phase 2)**: Analyzes container and Kubernetes manifests for security issues, including privileged containers, dangerous capabilities, RBAC misconfigurations, and Dockerfile vulnerabilities, aligning with CIS Kubernetes Benchmark Controls.
*   **Exploit Execution Sandbox (Phase 3)**: Isolated environments for live exploit testing with configurable modes (safe, simulation, live), payload execution, state snapshots, and evidence capture.
*   **Live Lateral Movement Testing (Phase 3)**: Simulates credential reuse, pass-the-hash/ticket, and pivot point discovery across 10 lateral movement techniques, mapped to MITRE ATT&CK.

### Additional Phase 1-3 Features (January 2026)

*   **Cloud Penetration Testing (P1)**: Full cloud security testing for AWS, Azure, and GCP including IAM analysis, storage security, network exposure, secrets management, compute vulnerabilities, and AI-powered remediation. Detects misconfigurations, overly permissive policies, unencrypted resources, and generates detailed attack paths with MITRE ATT&CK mappings.

*   **Compliance Reporting System (P1)**: Multi-framework compliance assessment and reporting supporting NIST 800-53, PCI-DSS 4.0, SOC 2, and HIPAA. Generates comprehensive reports with control mappings, gap analysis, remediation recommendations, and executive summaries. Export to HTML, CSV, and JSON formats with evidence collection.

*   **Container Security Testing (P2)**: Advanced container escape detection identifying 8 escape vectors (privileged containers, Docker socket mounts, CAP_SYS_ADMIN/PTRACE abuse, host namespace access, sensitive host mounts). Kubernetes abuse testing covering API abuse vectors, RBAC escalation paths, network policy analysis, and secret exposure detection.

*   **Business Logic Fuzzing Engine (P2)**: Workflow fuzzing with race condition detection for financial systems (double spending, coupon multi-use, inventory oversell), transaction manipulation testing (price/quantity/ID tampering), authentication bypass chain detection (step skipping, token reuse, forced browsing), and state violation detection.

*   **Remediation Automation (P2)**: Infrastructure-as-Code fix generation for Terraform, CloudFormation, and Kubernetes manifests. Includes templates for S3 public access, IAM admin policies, security groups, encryption, privileged containers, network policies, and RBAC. Code patch suggestions for SQL injection, XSS, path traversal, and deserialization vulnerabilities. Batch remediation and PR creation capabilities.

*   **Tool Integration - Metasploit (P3)**: Integration with Metasploit Framework for exploit execution. Supports 5 exploit modules (EternalBlue MS17-010, Apache Struts2, WebLogic, Tomcat Manager, Jenkins Script Console) with session management, command execution, and MITRE ATT&CK mappings.

*   **Tool Integration - Nuclei (P3)**: Nuclei template execution for vulnerability scanning. 10 built-in templates covering critical CVEs (Log4Shell CVE-2021-44228, Confluence CVE-2023-22515, ScreenConnect CVE-2024-1708) and misconfigurations (Git exposure, .env disclosure, Spring Actuator). Severity filtering, tag-based selection, and remediation recommendations.

*   **Session Replay System (P3)**: Full exploit session recording with forensic-quality evidence collection. Features include:
    - Event timeline with 5 attack phases (recon/scanning/enumeration/exploitation/post-exploitation)
    - Attack path visualization with MITRE ATT&CK technique mappings
    - Network traffic capture and visualization with node-edge graphs
    - Evidence chain reconstruction with integrity hashes
    - Session playback with speed control and event filtering
    - Finding correlation with CVE references

*   **RAG-Enhanced Policy Enforcement (January 2026)**: Vector-based Rules of Engagement (RoE) context injection into all AI agents to prevent hallucination and enforce organizational security policies:
    - Policy context fetched via semantic search at orchestrator startup
    - Injected into system prompts for all 7 agents (Recon, Exploit, Lateral, Business Logic, Impact, Defender, AI Simulation)
    - Three execution modes (Safe, Simulation, Live) with mode-specific constraints
    - Multi-tenant support with organizationId-scoped policy retrieval
    - Graceful fallback to default policy reminders if RAG fetch fails
    - Action validation API for runtime policy compliance checks
    - Key files: `server/services/agents/policy-context.ts`, `server/services/rag/policy-search.ts`

*   **PolicyGuardian Check-Loop (January 2026)**: Synchronous policy validation for agent actions before commitment to final results:
    - PolicyGuardian service validates each agent action with ALLOW/DENY/MODIFY decisions using RAG-enhanced policy search
    - Check-loop in Orchestrator filters ExploitAgent chains and LateralAgent paths before committing to OrchestratorResult
    - DENY blocks the planned action and logs it; MODIFY substitutes a safer alternative marked as [MODIFIED]
    - SafetyDecision tracking with timestamps, reasoning, and policy references for audit trail
    - Real-time WebSocket notifications via safety_block events to evaluation channels (tenant-scoped)
    - Safety decisions included in Synthesizer final reports for compliance documentation
    - Graceful degradation: safe mode defaults to DENY on policy check errors; other modes allow on error
    - Key files: `server/services/agents/policy-guardian.ts`, `server/services/agents/orchestrator.ts`
    - **ARCHITECTURAL CONSTRAINT**: Exploit and Lateral agents are plan-only generators (no real action execution); PolicyGuardian gates planned findings before final commit
    - **Database Persistence**: safety_decisions table stores audit trail with 4 indexes (evaluation, organization, decision, created)
    - **API Endpoints**: GET /api/evaluations/:id/safety-decisions (tenant-scoped), GET /api/safety-decisions (with filters), GET /api/safety-decisions/stats
    - **Frontend**: SafetyDecisionsPanel component displays blocked/modified actions with collapsible details, integrated in EvaluationDetail

**UI/UX Design**:
The design system follows custom guidelines blending Material Design with cyber-security aesthetics, using Inter and JetBrains Mono fonts, a dark-first color scheme with cyan/blue accents, and data-dense layouts.

## External Dependencies
*   **PostgreSQL**: Primary relational database.
*   **Drizzle ORM**: TypeScript ORM for database interaction.
*   **OpenAI API**: Used for core AI analysis.
*   **shadcn/ui**: Accessible React component library.
*   **TanStack React Query**: Data fetching, caching, and synchronization.
*   **ws**: WebSocket server library for real-time communication.

## API Endpoints Summary

### Tool Integration
- `GET /api/tools/metasploit/modules` - List Metasploit exploit modules
- `GET /api/tools/metasploit/modules/search?query=` - Search modules by CVE/name
- `POST /api/tools/metasploit/exploit` - Execute an exploit against a target
- `GET /api/tools/metasploit/sessions` - List active exploit sessions
- `POST /api/tools/metasploit/sessions/:id/exec` - Run commands in session
- `GET /api/tools/nuclei/templates` - List Nuclei vulnerability templates
- `POST /api/tools/nuclei/scan` - Run Nuclei scan against target

### Session Replay
- `POST /api/sessions/create` - Create new exploit session
- `GET /api/sessions` - List all sessions
- `GET /api/sessions/:id` - Get session details
- `POST /api/sessions/:id/stop` - Stop recording session
- `POST /api/sessions/:id/events` - Add event to session
- `GET /api/sessions/:id/playback` - Get session playback data
- `GET /api/sessions/:id/network` - Get network visualization
- `GET /api/sessions/:id/evidence-chain` - Get evidence chain
- `POST /api/sessions/simulate` - Create simulated demo session

### Container Security
- `POST /api/container-security/escape-detection` - Detect container escape vectors
- `POST /api/container-security/kubernetes/pentest` - Run K8s penetration test
- `POST /api/container-security/kubernetes/rbac-analysis` - Analyze RBAC configurations
- `POST /api/container-security/kubernetes/network-policy-analysis` - Analyze network policies

### Business Logic Fuzzing
- `POST /api/business-logic/fuzz-workflow` - Fuzz a business workflow
- `POST /api/business-logic/race-detection` - Detect race conditions
- `POST /api/business-logic/transaction-manipulation` - Test transaction tampering
- `POST /api/business-logic/auth-bypass` - Test authentication bypasses

### Remediation Automation
- `POST /api/remediation/iac-fix` - Generate IaC security fix
- `POST /api/remediation/code-patch` - Generate code security patch
- `POST /api/remediation/batch` - Generate batch remediations
- `POST /api/remediation/create-pr` - Create PR with security fixes

### Cloud Penetration Testing
- `POST /api/cloud-pentest/aws/full-assessment` - Full AWS security assessment
- `POST /api/cloud-pentest/azure/full-assessment` - Full Azure security assessment
- `POST /api/cloud-pentest/gcp/full-assessment` - Full GCP security assessment

### Compliance Reporting
- `POST /api/compliance/assess` - Run compliance assessment
- `GET /api/compliance/reports` - List compliance reports
- `GET /api/compliance/reports/:id` - Get report details
- `GET /api/compliance/reports/:id/export` - Export report (HTML/CSV/JSON)
