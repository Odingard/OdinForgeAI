# OdinForge AI Platform

## Overview
OdinForge AI (Adversarial Exposure Validation) is an AI-powered security platform for autonomous exploit validation and attack simulation. It analyzes security exposures, determines exploitability using AI, constructs attack paths via MITRE ATT&CK, assesses business impact, and generates remediation recommendations. The platform provides multi-system penetration testing and an AI vs AI simulation system for purple team exercises, aiming to strengthen security posture against evolving threats.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture
### Core Platform
The platform uses a full-stack TypeScript architecture. The frontend is built with React 18, Wouter for routing, TanStack React Query for state management, and Tailwind CSS with shadcn/ui for styling, supporting dark/light modes. Real-time communication uses WebSockets.

The backend uses Express.js and TypeScript, also with WebSockets. Key services include AEV for AI analysis, Agent Orchestrator, AI Simulation Orchestrator, Report Generator, and a Unified Auth Service supporting mTLS and JWT for multi-tenancy.

### AI vs AI Simulation System
This system features Attacker AI and Defender AI for purple team exercises with configurable iterative rounds. It includes quick-start templates for common attack scenarios (e.g., Web Application Breach, Cloud Infrastructure Attack, Ransomware Simulation, Data Exfiltration, Insider Threat) and allows launching simulations directly from completed evaluations with pre-filled parameters.

### Full Assessment System
Provides multi-phase penetration testing (reconnaissance, vulnerability analysis, attack synthesis, lateral movement, impact assessment), generating cross-system attack graphs and AI-powered analysis for unified attack paths, real-time progress, and prioritized remediation. It includes Business Impact Analysis and Lateral Movement Analysis.

An enhanced web application mode includes:
- **Web App Reconnaissance**: Crawls target URLs, discovers endpoints, detects technologies, analyzes security headers, and uses AI to prioritize attack surface.
- **Parallel Agent Dispatch**: Concurrently spawns specialized validation agents for SQLi, XSS, Auth Bypass, Command Injection, Path Traversal, and SSRF, using LLM validation to filter false positives.

### Data Storage
PostgreSQL is the primary data store, with Drizzle ORM for type-safe interactions.

### Multi-Tenant Isolation
The system supports multi-tenancy with a `Tenants` table for managing organizations, feature limits, IP allowlisting, and hierarchical multi-tenancy, enforced via middleware.

### Job Queue Infrastructure
BullMQ with a Redis-backed job queue (in-memory fallback) handles various job types like evaluation, network scan, cloud discovery, external recon, report generation, and AI simulation.

### Live Network Testing
Provides real TCP port scanning with banner grabbing, service detection, and vulnerability pattern matching. Results are tenant-isolated and accessible via REST API and WebSockets.

### External Reconnaissance
Offers comprehensive internet-facing asset scanning with a 6-section structure: Network Exposure, Transport Security, Application Identity, Authentication Surface, DNS & Infrastructure, and Attack Readiness Summary. Each finding includes exploit chain signals with type, MITRE ATT&CK ID, chain position, execution mode, and confidence score.

The External Reconnaissance page includes two scanning modes:
- **Domain Scan**: Traditional reconnaissance for domains/IPs with port scanning, SSL checks, HTTP fingerprinting, and DNS enumeration.
- **Web App Scan**: Standalone web application vulnerability testing with:
  - Target URL input for direct web app testing
  - Configurable parallel validation agents (up to 6 concurrent)
  - Vulnerability types: SQLi, XSS, Auth Bypass, Command Injection, Path Traversal, SSRF
  - LLM-powered false positive filtering
  - Real-time progress tracking via WebSocket
  - Displays reconnaissance results (endpoints, technologies, attack surface metrics) and validated findings with severity, CVSS, confidence, evidence, and recommendations

### Endpoint Agent System
Supports live agent deployment for monitoring, including registration, telemetry, auto-evaluation triggers, and deduplication. Pre-compiled Go agents are provided for multiple platforms. A registration token system enables secure, single-use token-based agent registration. Simple zero-interaction installation methods are provided for host and container environments (Docker/Kubernetes).

### Validation Agent Heartbeat System
Monitors long-running AI validation agents, detecting and recovering from stalled agents via retries and timeouts, with real-time status updates via WebSockets.

### Cloud Agent Deployment
Facilitates agent deployment on AWS, Azure, and GCP, tracking deployment status per cloud asset. Supports two deployment methods:
- **Cloud API Deployment**: Uses native cloud provider APIs (SSM, Run Command, etc.) for agent installation
- **SSH-Based Deployment**: Direct SSH connection using password or private key authentication with sudo support

### Cloud IAM Security Scanning
Analyzes identity and access management configurations for security risks across all major cloud providers. Access via the Infrastructure page cloud connection dropdown menu ("Scan IAM") with visual findings display.

- **AWS IAM Scanning**: Detects old access keys (90+ days), inactive users/keys, administrator access, dangerous permissions (PassRole, AssumeRole, CreateAccessKey, etc.), wildcard trust policies, and full-access patterns. Scans user/role attached policies, inline policies, customer-managed policies, and group-inherited policies.
- **Azure IAM Scanning**: Detects Owner/Contributor/User Access Administrator roles at subscription level, custom roles with wildcard permissions, and service principals with elevated privileges. Scans role assignments across all subscriptions.
- **GCP IAM Scanning**: Detects Owner/Editor/Security Admin roles at project level, public access bindings (allUsers/allAuthenticatedUsers), service account privilege escalation risks (serviceAccountKeyAdmin, serviceAccountTokenCreator), and dangerous IAM bindings.

**Severity levels**:
- Critical: Admin access, full wildcard access (*:* on *), public access
- High: Dangerous permissions on wildcard resources, privilege escalation risk
- Medium: High-risk actions on specific resources, inactive keys
- Low: Informational findings

**IAM Findings UI**: Displays findings in a modal with severity-based color coding, summary statistics by provider, and actionable recommendations for each finding.

### Coverage Autopilot
A hands-off system for bulk agent deployment using short-lived enrollment tokens and platform-specific bootstrap commands (host, cloud user-data, Kubernetes DaemonSet). It provides coverage metrics for assets versus agents.

### AEV Evidence Collection
Stores raw HTTP request/response, timing data, and verdict classifications in a `validationEvidenceArtifacts` table. An `EvidenceStorageService` manages persistence, retention, and cleanup with tenant isolation.

### AEV Safe Validation Primitives
Includes a comprehensive categorized payload library and implemented validation modules for SQL Injection, XSS, Auth Bypass, Command Injection, Path Traversal, and SSRF. A `ValidationEngine` coordinates these with evidence capture, and an Exploit Validation Handler runs live payload-based validation.

### Governance & Safety Controls Enforcement
Centralized controls enforced via a `GovernanceEnforcementService`:
- **Kill Switch**: Halts all security operations organization-wide.
- **Execution Modes**: Defines levels of operation (Safe, Simulate, Live) with progressively more intrusive actions and target restrictions.
- **Scope Rules**: Allow/Block rules for IP addresses, hostnames, CIDR ranges, and regex patterns.
All job handlers validate governance before execution, logging blocked operations for audit. Settings are cached with invalidation on change.

### Enhanced Reporting System
Provides comprehensive, logic-based reporting including a vulnerability catalog, kill chain visualization mapping to MITRE ATT&CK, and a report logic engine for generating executive summaries, technical reports, and compliance assessments.

### Design System
Follows custom guidelines blending Material Design with cyber-security aesthetics, using Inter and JetBrains Mono fonts, a dark-first color scheme with cyan/blue accents, and data-dense layouts.

## External Dependencies
### Database
- **PostgreSQL**: Primary relational database.
- **Drizzle ORM**: TypeScript ORM for database interaction.

### AI Services
- **OpenAI API**: Used for core AI analysis.

### Frontend Libraries
- **shadcn/ui**: Accessible React component library.
- **TanStack React Query**: Data fetching, caching, and synchronization.

### Real-time Communication
- **ws**: WebSocket server library.