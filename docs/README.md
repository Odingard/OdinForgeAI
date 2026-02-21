# OdinForge Documentation

Welcome to the OdinForge AI documentation. This guide covers installation, configuration, and operation of the OdinForge Adversarial Exposure Validation platform.

## Table of Contents

### Getting Started
- [Platform Overview](#platform-overview)
- [Quick Start Guide](#quick-start)
- [System Requirements](#system-requirements)

### Server Deployment
- [Installation Guide](server/installation.md) - Local development and server setup
- [Configuration Reference](server/configuration.md) - Environment variables and settings
- [Production Deployment](server/production.md) - Docker, Kubernetes, cloud platforms

### Agent Deployment
- [Agent Overview](agent/README.md) - Endpoint agent architecture
- [Agent Installation](agent/INSTALL.md) - Detailed installation for all platforms
- [Enterprise Agent Deployment](ENTERPRISE_AGENT_DEPLOYMENT.md) - Cloud-based provisioning and automation

### API Reference
- [API Reference](API_REFERENCE.md) - Complete API endpoint documentation
- [API Naming Conventions](API_NAMING_CONVENTIONS.md) - REST API style guide

### Scoring & Threat Intelligence
- [Scoring Engine & Threat Intel](SCORING_ENGINE.md) - Deterministic scoring formula, EPSS, CVSS, CISA KEV integration

### Architecture & Design
- [Design System](DESIGN_SYSTEM.md) - Afterglow UI design system and patterns
- [Testing Guide](TESTING_GUIDE.md) - Vitest integration testing
- [Adversary Simulation Enhancement](ADVERSARY_SIMULATION_ENHANCEMENT.md) - Future release: ATT&CK technique execution engine

### Additional Resources
- [Getting Started Guide](../wiki/Getting-Started.md) - Quick start walkthrough
- [Security Policies](../policies/rules_of_engagement.md) - Rules of engagement

---

## Platform Overview

OdinForge AI is an enterprise security platform that automates exploit validation and attack simulation. It combines AI-powered analysis with real-time endpoint telemetry to provide comprehensive security assessments.

### Core Capabilities

| Capability | Description |
|------------|-------------|
| **Exposure Analysis** | Analyze CVEs, misconfigurations, and vulnerabilities for exploitability |
| **Threat Intel Scoring** | Deterministic scoring with EPSS, CVSS, CISA KEV, and asset criticality |
| **Attack Path Mapping** | Generate MITRE ATT&CK aligned attack graphs with live visualization |
| **Breach Chain Orchestration** | Cross-domain attack chains with real-time WebSocket progress |
| **AI Simulations** | Run AI vs AI purple team exercises |
| **Endpoint Monitoring** | Deploy agents for real-time security telemetry |
| **Benchmark Testing** | Continuous exploit agent validation against OWASP targets |
| **Executive Reporting** | Generate PDF reports with business impact analysis |

### Architecture Components

1. **Web Application** - React frontend with Express backend, live breach chain visualization
2. **AI Engine** - 8-agent pipeline with multi-model alloy rotation (GPT-4o, Claude, Gemini)
3. **Threat Intel** - EPSS, CVSS v2/v3.x, CISA KEV, deterministic scoring v3.0
4. **Exploit Agent** - Multi-turn tool-calling loop with 6 security tools and HTTP evidence
5. **Database** - PostgreSQL 15+ with 50+ tables, RLS, pgvector embeddings
6. **Endpoint Agents** - Go-based agents for Linux, macOS, Windows

---

## Quick Start

### 1. Deploy the Server

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Initialize database
npm run db:push

# Start server
npm run dev
```

### 2. Access the Dashboard

Open `http://localhost:5000` in your browser.

### 3. Deploy Agents

From the Agents page, copy the installation command for your target platform.

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
```

**Windows:**
```powershell
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

### 4. Run Your First Evaluation

1. Navigate to **Evaluations** in the sidebar
2. Click **New Evaluation**
3. Select an exposure type and target
4. Start the AI-powered analysis

---

## System Requirements

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 50+ GB |
| Node.js | 20.x | 20.x LTS |
| PostgreSQL | 14.x | 16.x |

### Agent Requirements

| Platform | Architecture | Requirements |
|----------|--------------|--------------|
| Linux | amd64, arm64 | glibc 2.17+ |
| macOS | amd64, arm64 | macOS 10.15+ |
| Windows | amd64 | Windows 10+ |

### Network Requirements

| Port | Service | Direction |
|------|---------|-----------|
| 5000 | Web UI / API | Inbound |
| 443 | Agent communication (HTTPS) | Inbound |
| 5432 | PostgreSQL | Internal |

---

## Documentation Structure

```
docs/
├── README.md                      # This file
├── SCORING_ENGINE.md              # Deterministic scoring, EPSS, CVSS, KEV
├── API_REFERENCE.md               # Complete API documentation
├── API_NAMING_CONVENTIONS.md      # REST API style guide
├── DESIGN_SYSTEM.md               # Afterglow UI design system
├── ENTERPRISE_AGENT_DEPLOYMENT.md # Enterprise agent provisioning
├── TESTING_GUIDE.md               # Integration testing guide
├── ADVERSARY_SIMULATION_ENHANCEMENT.md  # Future: ATT&CK execution engine
├── server/
│   ├── installation.md            # Server setup guide
│   ├── configuration.md           # Environment and settings
│   └── production.md              # Production deployment
└── agent/
    ├── README.md                  # Agent architecture
    └── INSTALL.md                 # Agent installation
```

---

## Getting Help

- Check the [Configuration Guide](server/configuration.md) for environment setup
- Review [Production Deployment](server/production.md) for scaling guidance
- Open an issue in the repository for bugs or feature requests
