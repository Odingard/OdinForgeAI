# Agent Deployment

OdinForge AI uses lightweight, cross-platform agents to collect security telemetry from your infrastructure.

## Agent Overview

The OdinForge agent is a Go-based binary that:
- Collects system telemetry (CPU, memory, disk, network)
- Monitors open ports and running services
- Detects container environments (Docker, Kubernetes)
- Reports security findings to the server
- Triggers automatic evaluations for critical findings

## Supported Platforms

| Platform | Architecture | Binary |
|----------|--------------|--------|
| Linux | x86_64 | `odinforge-agent-linux-amd64` |
| Linux | ARM64 | `odinforge-agent-linux-arm64` |
| macOS | Intel | `odinforge-agent-darwin-amd64` |
| macOS | Apple Silicon | `odinforge-agent-darwin-arm64` |
| Windows | x64 | `odinforge-agent-windows-amd64.exe` |

## Quick Installation

### Generate Registration Token

1. Go to **Agents** in the sidebar
2. Click **Create Token**
3. Copy the generated token (single-use)

### One-Line Install

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | \
  SERVER_URL=https://YOUR_SERVER TOKEN=YOUR_TOKEN sudo -E bash
```

**Windows (PowerShell as Admin):**
```powershell
$env:SERVER_URL="https://YOUR_SERVER"
$env:TOKEN="YOUR_TOKEN"
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

## Installation Methods

### Linux - systemd

```bash
# Download binary
curl -LO https://YOUR_SERVER/api/agents/download?platform=linux-amd64
chmod +x odinforge-agent-linux-amd64
sudo mv odinforge-agent-linux-amd64 /usr/local/bin/odinforge-agent

# Create config
sudo mkdir -p /etc/odinforge
echo "YOUR_TOKEN" | sudo tee /etc/odinforge/api_key

# Create systemd service
sudo tee /etc/systemd/system/odinforge-agent.service << EOF
[Unit]
Description=OdinForge Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/odinforge-agent
Environment=ODINFORGE_SERVER_URL=https://YOUR_SERVER
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable odinforge-agent
sudo systemctl start odinforge-agent
```

### macOS - launchd

```bash
# Download binary
curl -LO https://YOUR_SERVER/api/agents/download?platform=darwin-arm64
chmod +x odinforge-agent-darwin-arm64
sudo mv odinforge-agent-darwin-arm64 /usr/local/bin/odinforge-agent

# Create config
sudo mkdir -p /etc/odinforge
echo "YOUR_TOKEN" | sudo tee /etc/odinforge/api_key

# Create launchd plist
sudo tee /Library/LaunchDaemons/com.odinforge.agent.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.odinforge.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/odinforge-agent</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ODINFORGE_SERVER_URL</key>
        <string>https://YOUR_SERVER</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Start service
sudo launchctl load /Library/LaunchDaemons/com.odinforge.agent.plist
```

### Windows - Service

```powershell
# Download binary
Invoke-WebRequest -Uri "https://YOUR_SERVER/api/agents/download?platform=windows-amd64" `
  -OutFile "C:\Program Files\OdinForge\odinforge-agent.exe"

# Create config directory
New-Item -ItemType Directory -Path "C:\ProgramData\OdinForge" -Force
"YOUR_TOKEN" | Out-File -FilePath "C:\ProgramData\OdinForge\api_key" -Encoding UTF8

# Register as service (using NSSM or sc.exe)
sc.exe create OdinForgeAgent binPath= "C:\Program Files\OdinForge\odinforge-agent.exe" start= auto
sc.exe start OdinForgeAgent
```

### Docker

```bash
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

### Docker Compose

```yaml
version: '3.8'
services:
  odinforge-agent:
    image: odinforge/agent:latest
    privileged: true
    pid: host
    network_mode: host
    environment:
      - SERVER_URL=https://YOUR_SERVER
      - TOKEN=YOUR_TOKEN
      - STATELESS=true
    volumes:
      - /proc:/host/proc:ro
    restart: unless-stopped
```

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: odinforge-agent
  namespace: odinforge
spec:
  selector:
    matchLabels:
      app: odinforge-agent
  template:
    metadata:
      labels:
        app: odinforge-agent
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: agent
          image: odinforge/agent:latest
          securityContext:
            privileged: true
          env:
            - name: SERVER_URL
              value: "https://YOUR_SERVER"
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: odinforge-agent
                  key: token
            - name: STATELESS
              value: "true"
          volumeMounts:
            - name: proc
              mountPath: /host/proc
              readOnly: true
      volumes:
        - name: proc
          hostPath:
            path: /proc
```

## Configuration

### Environment Variables

| Variable | Alternative | Description | Default |
|----------|-------------|-------------|---------|
| `ODINFORGE_SERVER_URL` | `SERVER_URL` | Server URL | Required |
| `ODINFORGE_TOKEN` | `TOKEN` | Registration token | Required |
| `ODINFORGE_INTERVAL` | `INTERVAL` | Collection interval (seconds) | 60 |
| `STATELESS` | - | Ephemeral mode for containers | false |

### File-Based Token

Instead of environment variable, store token in file:
- Linux/macOS: `/etc/odinforge/api_key`
- Windows: `C:\ProgramData\OdinForge\api_key`

## Telemetry Collected

| Type | Data |
|------|------|
| System Info | Hostname, OS, architecture, kernel version |
| Resources | CPU, memory, disk usage |
| Network | Open ports, listening services |
| Services | Running system services and status |
| Container | Runtime, container ID, pod metadata |

## Agent Management

### Viewing Agents

1. Go to **Agents** in sidebar
2. See all registered agents with:
   - Status (Online/Offline)
   - Last heartbeat time
   - Platform and hostname
   - Findings count

### Agent Details

Click on an agent to see:
- System information
- Recent telemetry
- Security findings
- Connected evaluations

### Agent Actions

| Action | Description |
|--------|-------------|
| Refresh | Request immediate telemetry |
| Evaluate | Trigger AEV evaluation |
| Revoke | Revoke agent credentials |
| Delete | Remove agent from inventory |

## Automatic Evaluations

Agents can trigger evaluations automatically:

1. Agent detects critical finding
2. Finding sent to server
3. Server checks governance
4. Evaluation created if authorized
5. Results linked to agent

### Finding Types

- Critical vulnerabilities detected
- Suspicious services running
- Unusual network activity
- Configuration issues

## Security

### Authentication

- Token-based registration (single-use tokens)
- API key stored with bcrypt hashing
- Optional mTLS certificate authentication

### Communication

- TLS encryption for all traffic
- Certificate pinning available
- Offline resilience with local queue

### Credential Management

- Tokens revocable from UI
- Bulk credential rotation
- Audit logging for all auth events

## Troubleshooting

### Agent Not Connecting

| Issue | Solution |
|-------|----------|
| Network blocked | Check firewall for port 443/5000 |
| Invalid token | Generate new token |
| DNS issues | Use IP address instead |
| TLS errors | Check certificate validity |

### Agent Offline

| Issue | Solution |
|-------|----------|
| Service stopped | Restart agent service |
| Resource exhaustion | Check CPU/memory usage |
| Network outage | Agent queues locally, syncs when restored |

### Missing Telemetry

| Issue | Solution |
|-------|----------|
| Permission denied | Run with elevated privileges |
| Interval too long | Decrease INTERVAL setting |
| Container mode | Ensure STATELESS=true for containers |
