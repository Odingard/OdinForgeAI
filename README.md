# OdinForge AI

**Adversarial Exposure Validation Platform**

OdinForge AI is an enterprise-grade security platform for autonomous exploit validation and attack simulation. It analyzes security exposures (CVEs, misconfigurations, network vulnerabilities), determines exploitability using AI, constructs attack paths via MITRE ATT&CK, assesses business impact, and generates remediation recommendations.

## Key Features

- **AI-Powered Analysis** - Autonomous exploit validation using multi-agent AI pipeline
- **Attack Path Visualization** - MITRE ATT&CK mapped attack graphs with kill chain analysis
- **Purple Team Simulations** - AI vs AI attack/defense exercises with iterative learning
- **Endpoint Agents** - Cross-platform agents for real-time telemetry and security findings
- **Full Assessment Mode** - Multi-phase penetration testing across infrastructure
- **Executive Reporting** - PDF/CSV reports with business impact and remediation guidance

## Quick Start

### Deploy the Server

```bash
# Clone and install dependencies
git clone <repository-url>
cd odinforge
npm install

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
npm run db:push

# Start the server
npm run dev
```

Server runs at `http://localhost:5000`

### Deploy Agents

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

## Documentation

| Document | Description |
|----------|-------------|
| [Documentation Hub](docs/README.md) | Complete documentation index |
| [Server Installation](docs/server/installation.md) | Deploy the OdinForge server |
| [Server Configuration](docs/server/configuration.md) | Environment variables and settings |
| [Production Deployment](docs/server/production.md) | Docker, Kubernetes, cloud deployment |
| [Agent Installation](docs/agent/INSTALL.md) | Deploy endpoint agents |
| [API Reference](docs/api/reference.md) | REST API endpoints |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     OdinForge Platform                      │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React)          │  Backend (Express)             │
│  - Dashboard               │  - REST API                    │
│  - Evaluation Wizard       │  - WebSocket Events            │
│  - Risk Dashboard          │  - AI Agent Pipeline           │
│  - Reports & Exports       │  - Report Generator            │
├─────────────────────────────────────────────────────────────┤
│  PostgreSQL Database       │  OpenAI Integration            │
│  - Evaluations             │  - GPT-4 Analysis              │
│  - Agents & Telemetry      │  - Attack Path Generation      │
│  - Reports & Findings      │  - Remediation Recommendations │
├─────────────────────────────────────────────────────────────┤
│                    Endpoint Agents (Go)                     │
│  - System Telemetry        │  - Security Findings           │
│  - Container Detection     │  - Auto-Evaluation Triggers    │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React, TypeScript, TailwindCSS, shadcn/ui |
| Backend | Express.js, TypeScript, WebSocket |
| Database | PostgreSQL with Drizzle ORM |
| AI | OpenAI GPT-4 |
| Agents | Go (cross-compiled for Linux, macOS, Windows) |

## Requirements

- **Node.js** 20+
- **PostgreSQL** 14+
- **Go** 1.21+ (for building agents)
- **OpenAI API Key**

## License

Proprietary - All rights reserved

## Support

For support, please contact your OdinForge administrator or open an issue in the repository.
