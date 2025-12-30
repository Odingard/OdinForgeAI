# OdinForge Security Agent

A lightweight, cross-platform security agent for the OdinForge Adversarial Exposure Validation (AEV) platform. The agent collects system telemetry, security findings, and enables real-time endpoint monitoring.

## Features

- **Cross-Platform**: Supports Linux, macOS, Windows, Docker, and Kubernetes
- **Container-Aware**: Automatic detection of Docker, Kubernetes, containerd, podman, and LXC
- **Lightweight**: Minimal resource footprint with configurable collection intervals
- **Offline Resilient**: Queues telemetry locally when disconnected, syncs when restored
- **Secure**: TLS encryption, token-based authentication

## Quick Start

### One-Line Installation

**macOS/Linux:**
```bash
# Interactive (prompts for server URL and token)
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash

# Non-interactive (provide values via environment)
curl -sSL https://YOUR_SERVER/api/agents/install.sh | SERVER_URL=https://YOUR_SERVER TOKEN=YOUR_TOKEN sudo -E bash
```

**Windows (PowerShell as Administrator):**
```powershell
# Interactive
irm https://YOUR_SERVER/api/agents/install.ps1 | iex

# Non-interactive
$env:SERVER_URL="https://YOUR_SERVER"; $env:TOKEN="YOUR_TOKEN"; irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

For complete installation instructions including manual installation, Docker, and Kubernetes deployment, see **[INSTALL.md](INSTALL.md)**.

## Supported Platforms

| Platform | Architecture | Binary |
|----------|--------------|--------|
| Linux | x86_64 | `odinforge-agent-linux-amd64` |
| Linux | ARM64 | `odinforge-agent-linux-arm64` |
| macOS | Intel | `odinforge-agent-darwin-amd64` |
| macOS | Apple Silicon | `odinforge-agent-darwin-arm64` |
| Windows | x64 | `odinforge-agent-windows-amd64.exe` |

## Telemetry Collected

- **System Info**: Hostname, OS, architecture, kernel version
- **Resource Metrics**: CPU, memory, and disk usage
- **Network**: Open ports and listening services
- **Services**: Running system services and their status
- **Container Info**: Runtime, container ID, pod metadata (Kubernetes)

## Configuration

The agent is configured via environment variables:

| Variable | Alternative | Description | Default |
|----------|-------------|-------------|---------|
| `ODINFORGE_SERVER_URL` | `SERVER_URL` | OdinForge server URL | Required |
| `ODINFORGE_TOKEN` | `TOKEN` | Registration token | Required |
| `ODINFORGE_INTERVAL` | `INTERVAL` | Collection interval (seconds) | `60` |
| `STATELESS` | - | Use ephemeral paths (for containers) | `false` |

### File-Based Token Storage

On persistent systems, the token can be stored in a file:
- **Linux/macOS**: `/etc/odinforge/api_key`
- **Windows**: `C:\ProgramData\OdinForge\api_key`

## Building from Source

```bash
cd odinforge-agent

# Build for current platform
go build -o odinforge-agent ./cmd/agent/

# Build static binary for containers (Alpine/musl compatible)
CGO_ENABLED=0 go build -ldflags="-s -w" -o odinforge-agent ./cmd/agent/

# Cross-compile for all platforms
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o odinforge-agent-linux-amd64 ./cmd/agent/
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o odinforge-agent-linux-arm64 ./cmd/agent/
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o odinforge-agent-darwin-amd64 ./cmd/agent/
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o odinforge-agent-darwin-arm64 ./cmd/agent/
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o odinforge-agent-windows-amd64.exe ./cmd/agent/
```

## Docker

```bash
# Build the container image
docker build -t odinforge/agent:latest .

# Run the agent
docker run -d \
  --name odinforge-agent \
  --privileged \
  --pid=host \
  --network=host \
  -e SERVER_URL=https://YOUR_SERVER \
  -e TOKEN=YOUR_TOKEN \
  -e STATELESS=true \
  -v /proc:/host/proc:ro \
  odinforge/agent:latest
```

## Project Structure

```
odinforge-agent/
├── cmd/agent/          # Main entry point
├── internal/
│   ├── collector/      # System telemetry collectors
│   │   ├── system.go       # System info collection
│   │   ├── metrics_linux.go    # Linux CPU/memory/disk
│   │   ├── metrics_darwin.go   # macOS CPU/memory/disk
│   │   ├── metrics_windows.go  # Windows CPU/memory/disk
│   │   ├── ports.go        # Open ports detection
│   │   ├── services.go     # Running services
│   │   └── container.go    # Container runtime detection
│   ├── config/         # Configuration handling
│   ├── queue/          # Offline queue storage
│   └── sender/         # Server communication
├── kubernetes/         # Kubernetes DaemonSet manifest
├── Dockerfile          # Container image build
├── docker-compose.yml  # Docker Compose deployment
├── INSTALL.md          # Comprehensive installation guide
└── README.md           # This file
```

## License

Proprietary - OdinForge Security Platform
