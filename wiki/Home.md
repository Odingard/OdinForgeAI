# Welcome to OdinForge AI

**OdinForge AI** is an AI-powered Adversarial Exposure Validation (AEV) platform for autonomous exploit validation and attack simulation. It combines real security scanning with AI-powered analysis to identify, validate, and prioritize security vulnerabilities.

## What is AEV?

Adversarial Exposure Validation goes beyond traditional vulnerability scanning by:
- **Validating exploitability** - Testing if vulnerabilities can actually be exploited
- **Mapping attack paths** - Using MITRE ATT&CK framework to show how attackers chain vulnerabilities
- **Assessing business impact** - Understanding the real-world consequences of successful attacks
- **Generating remediation** - Providing actionable fixes prioritized by risk

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **AEV Engine** | AI-powered analysis of vulnerabilities with real exploit validation |
| **Cloud Discovery** | Automatic asset discovery for AWS, Azure, and GCP |
| **Web App Scanning** | Parallel vulnerability testing with SQLi, XSS, SSRF, and more |
| **AI vs AI Simulation** | Purple team exercises with Attacker AI vs Defender AI |
| **Endpoint Agents** | Cross-platform agents for real-time security telemetry |
| **Coverage Autopilot** | Automatic agent deployment across your infrastructure |
| **Governance Controls** | Kill switch, execution modes, and scope rules for safety |
| **Operations Dashboard** | System health, job monitoring, audit logs, and real-time metrics |
| **Compliance Tracking** | SOC2, ISO27001, NIST, PCI-DSS, HIPAA, and GDPR frameworks |
| **Evidence Management** | Secure storage with chain of custody and forensic exports |

## Quick Navigation

### Getting Started
- [[Getting-Started]] - Quick start guide for new users
- [[Architecture]] - System design and components

### Core Features
- [[Features]] - Complete feature overview
- [[Web-App-Scanning]] - Web application security testing
- [[AI-Simulation]] - AI vs AI purple team exercises
- [[Cloud-Integration]] - AWS, Azure, and GCP setup

### Operations
- [[Governance]] - Safety controls and execution modes
- [[Agent-Deployment]] - Endpoint agent installation

### Reference
- [[API-Reference]] - REST API documentation
- [[Configuration]] - Environment variables and settings

## Technology Stack

- **Frontend**: React 18, TailwindCSS, shadcn/ui
- **Backend**: Express.js, TypeScript, WebSockets
- **Database**: PostgreSQL with Drizzle ORM
- **AI**: OpenAI GPT-4 for analysis
- **Queue**: BullMQ with Redis
- **Agents**: Go-based cross-platform binaries

## Support

For issues and feature requests, open an issue in the GitHub repository.
