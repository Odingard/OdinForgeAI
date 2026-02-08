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

### API Reference
- [REST API](api/reference.md) - Core API endpoints and authentication
- [Advanced Features API](API_DOCUMENTATION.md) - Cloud pentest, compliance, container security, and advanced features

### Architecture & Design
- [System Architecture](../wiki/Architecture.md) - Platform architecture and components
- [Design Guidelines](design-guidelines.md) - UI/UX design system and patterns
- [Features Overview](../wiki/Features.md) - Platform capabilities and features

### Additional Resources
- [Implementation Status](implementation-gaps.md) - Feature implementation tracking
- [Getting Started Guide](../wiki/Getting-Started.md) - Quick start walkthrough
- [Security Policies](../policies/rules_of_engagement.md) - Rules of engagement

---

## Platform Overview

OdinForge AI is an enterprise security platform that automates exploit validation and attack simulation. It combines AI-powered analysis with real-time endpoint telemetry to provide comprehensive security assessments.

### Core Capabilities

| Capability | Description |
|------------|-------------|
| **Exposure Analysis** | Analyze CVEs, misconfigurations, and vulnerabilities for exploitability |
| **Attack Path Mapping** | Generate MITRE ATT&CK aligned attack graphs |
| **AI Simulations** | Run AI vs AI purple team exercises |
| **Endpoint Monitoring** | Deploy agents for real-time security telemetry |
| **Executive Reporting** | Generate PDF reports with business impact analysis |

### Architecture Components

1. **Web Application** - React frontend with Express backend
2. **AI Engine** - Multi-agent pipeline using OpenAI GPT-4
3. **Database** - PostgreSQL for evaluations, agents, and findings
4. **Endpoint Agents** - Go-based agents for Linux, macOS, Windows

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
├── README.md              # This file
├── server/
│   ├── installation.md    # Server setup guide
│   ├── configuration.md   # Environment and settings
│   └── production.md      # Production deployment
├── agent/
│   ├── README.md          # Agent architecture
│   └── INSTALL.md         # Agent installation
└── api/
    └── reference.md       # API documentation
```

---

## Getting Help

- Check the [Configuration Guide](server/configuration.md) for environment setup
- Review [Production Deployment](server/production.md) for scaling guidance
- Open an issue in the repository for bugs or feature requests
