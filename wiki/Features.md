# Feature Overview

Complete list of OdinForge AI capabilities organized by category.

## AEV (Adversarial Exposure Validation)

### Exposure Types

**Traditional Vulnerabilities**
- CVE Exploitation Analysis
- Configuration Weakness Detection
- Behavioral Anomaly Detection
- Network Vulnerability Assessment

**Cloud & IAM**
- Cloud Misconfiguration Detection
- IAM Privilege Abuse Analysis
- SaaS Permission Misuse Detection
- Shadow Admin Discovery

**Business Logic**
- API Sequence Abuse Detection
- Payment Flow Bypass Detection
- Subscription Bypass Detection
- State Machine Violation Detection
- Privilege Boundary Violation Detection
- Workflow Desynchronization Detection
- Order Lifecycle Abuse Detection

### AI Agent Pipeline

| Agent | Function |
|-------|----------|
| Recon Agent | Maps attack surface and entry points |
| Exploit Agent | Analyzes exploitation techniques |
| Lateral Movement Agent | Discovers paths between systems |
| Business Logic Agent | Detects workflow abuse patterns |
| Multi-Vector Agent | Combines multiple attack techniques |
| Impact Agent | Assesses business consequences |
| Synthesizer Agent | Consolidates all findings |
| Graph Synthesizer | Creates attack path visualization |
| Scoring Engine | Calculates intelligent risk scores |

### Adversary Profiles

Configurable attacker personas that modify AI behavior:

| Profile | Characteristics |
|---------|-----------------|
| Script Kiddie | Low sophistication, uses public tools |
| Organized Crime | Moderate resources, financially motivated |
| Nation State | Advanced TTPs, high stealth and persistence |
| Insider Threat | Internal access, knows systems |
| APT Group | Advanced persistent threat, targeted attacks |

## Web Application Security

### Scanning Modes

**Domain Scan**
- Port scanning and service detection
- SSL/TLS certificate analysis
- HTTP fingerprinting
- DNS enumeration
- Technology detection

**Web App Scan**
- Target URL vulnerability testing
- Parallel validation agents (up to 6 concurrent)
- Real-time progress via WebSocket
- LLM-powered false positive filtering

### Vulnerability Types

| Type | Description |
|------|-------------|
| SQL Injection | Database query manipulation |
| XSS | Cross-site scripting attacks |
| Auth Bypass | Authentication circumvention |
| Command Injection | OS command execution |
| Path Traversal | Directory traversal attacks |
| SSRF | Server-side request forgery |

### Evidence Collection

- Raw HTTP request/response capture
- Timing data for timing-based attacks
- Verdict classifications with confidence scores
- Tenant-isolated evidence storage

## Cloud Integration

### Supported Providers

| Provider | Asset Types |
|----------|-------------|
| AWS | EC2, RDS, Lambda, S3, VPCs, Security Groups |
| Azure | VMs, SQL Databases, Resource Groups |
| GCP | Compute Engine, Cloud SQL, Projects |

### Features

- Automatic asset discovery
- Real-time sync with cloud changes
- Credential encryption and secure storage
- Multi-region support
- WebSocket updates during discovery

## Endpoint Agent System

### Agent Capabilities

- System telemetry collection (CPU, memory, disk)
- Open port and service detection
- Container runtime awareness (Docker, K8s)
- Security finding ingestion
- Auto-evaluation triggers for critical findings

### Supported Platforms

| Platform | Architectures |
|----------|---------------|
| Linux | amd64, arm64 |
| macOS | Intel, Apple Silicon |
| Windows | x64 |
| Docker | All Linux architectures |
| Kubernetes | DaemonSet deployment |

### Installation Methods

- One-line curl/PowerShell scripts
- Docker Compose
- Kubernetes DaemonSet
- Manual binary deployment

## Coverage Autopilot

Automated agent deployment system:

- Short-lived enrollment tokens
- Platform-specific bootstrap commands
- Coverage metrics (assets vs agents)
- Governance integration for safety
- Auto-deploy on cloud discovery

## AI vs AI Simulation

Purple team exercises with AI adversaries:

### Components

| Component | Role |
|-----------|------|
| Attacker AI | Uses full agent pipeline to attack |
| Defender AI | Detects attacks and recommends responses |
| Orchestrator | Manages iterative attack/defense rounds |

### Features

- Configurable simulation rounds (1-10)
- Quick-start templates for common scenarios
- Launch from completed evaluations
- Performance metrics for both sides
- Purple team recommendations

### Scenario Templates

- Web Application Breach
- Cloud Infrastructure Attack
- Ransomware Simulation
- Data Exfiltration
- Insider Threat

## Governance & Safety Controls

### Kill Switch

Emergency halt for all security operations organization-wide.

### Execution Modes

| Mode | Description |
|------|-------------|
| Safe | Read-only reconnaissance, no active testing |
| Simulate | Simulated attacks with no real payloads |
| Live | Full active testing with real payloads |

### Scope Rules

- IP address allow/block lists
- Hostname patterns
- CIDR range restrictions
- Regex-based rules

### Enforcement

- All job handlers validate governance before execution
- Blocked operations logged for audit
- Settings cached with invalidation on change

## Reporting

### Report Types

| Type | Audience |
|------|----------|
| Executive Summary | C-level, non-technical stakeholders |
| Technical Report | Security engineers and developers |
| Compliance Assessment | Auditors and compliance teams |

### Export Formats

- PDF with visualizations
- CSV for data analysis
- JSON for integrations

### Visualizations

- Attack path graphs (MITRE ATT&CK aligned)
- Risk heatmaps (exploitability x impact)
- Time-to-compromise metrics
- Kill chain visualization

## Multi-Tenancy

- Tenant and organization hierarchy
- Feature limits per tenant
- IP allowlisting
- Data isolation at database level
- Scoped API access
