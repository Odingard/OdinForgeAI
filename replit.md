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

**UI/UX Design**:
The design system follows custom guidelines blending Material Design with cyber-security aesthetics, using Inter and JetBrains Mono fonts, a dark-first color scheme with cyan/blue accents, and data-dense layouts.

## External Dependencies
*   **PostgreSQL**: Primary relational database.
*   **Drizzle ORM**: TypeScript ORM for database interaction.
*   **OpenAI API**: Used for core AI analysis.
*   **shadcn/ui**: Accessible React component library.
*   **TanStack React Query**: Data fetching, caching, and synchronization.
*   **ws**: WebSocket server library for real-time communication.