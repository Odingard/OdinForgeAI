# OdinForge Agent Installation Guide

This guide covers installation and deployment of the OdinForge endpoint agent across all supported platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [macOS Installation](#macos-installation)
- [Linux Installation](#linux-installation)
- [Windows Installation](#windows-installation)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## Prerequisites

Before installing the agent, ensure you have:

1. **OdinForge Server URL** - The base URL of your OdinForge platform (e.g., `https://odinforge.example.com`)
2. **Agent Registration Token** - Obtain from the OdinForge dashboard under **Agents > Install Agent**
3. **Administrative privileges** on the target system

---

## Quick Start

### One-Line Installers

**macOS/Linux:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | SERVER_URL=https://YOUR_SERVER TOKEN=YOUR_TOKEN sudo -E bash
```

**Windows (PowerShell as Administrator):**
```powershell
$env:SERVER_URL="https://YOUR_SERVER"; $env:TOKEN="YOUR_TOKEN"; irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

If you omit the environment variables, the installer will prompt for them interactively.

---

## macOS Installation

### Automatic Installation (Recommended)

1. Open Terminal
2. Run the installer:
   ```bash
   curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
   ```
3. The agent will automatically register and start collecting telemetry

### Manual Installation

1. Download the agent binary:
   ```bash
   # For Apple Silicon (M1/M2/M3)
   curl -o /usr/local/bin/odinforge-agent https://YOUR_SERVER/agents/odinforge-agent-darwin-arm64
   
   # For Intel Macs
   curl -o /usr/local/bin/odinforge-agent https://YOUR_SERVER/agents/odinforge-agent-darwin-amd64
   
   chmod +x /usr/local/bin/odinforge-agent
   ```

2. Create the configuration directory:
   ```bash
   sudo mkdir -p /etc/odinforge
   ```

3. Store the API key:
   ```bash
   echo "YOUR_REGISTRATION_TOKEN" | sudo tee /etc/odinforge/api_key > /dev/null
   sudo chmod 600 /etc/odinforge/api_key
   ```

4. Create the launchd service file:
   ```bash
   sudo tee /Library/LaunchDaemons/com.odinforge.agent.plist > /dev/null << 'EOF'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>StandardOutPath</key>
       <string>/var/log/odinforge-agent.log</string>
       <key>StandardErrorPath</key>
       <string>/var/log/odinforge-agent.error.log</string>
   </dict>
   </plist>
   EOF
   ```

5. Start the agent:
   ```bash
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.odinforge.agent.plist
   ```

### Verify Installation (macOS)

```bash
# Check service status
sudo launchctl print system/com.odinforge.agent

# View logs
tail -f /var/log/odinforge-agent.log
```

---

## Linux Installation

### Automatic Installation (Recommended)

1. Run the installer:
   ```bash
   curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
   ```

### Manual Installation

1. Download the agent binary:
   ```bash
   # For x86_64 (most servers)
   sudo curl -o /usr/local/bin/odinforge-agent https://YOUR_SERVER/agents/odinforge-agent-linux-amd64
   
   # For ARM64 (Raspberry Pi, AWS Graviton, etc.)
   sudo curl -o /usr/local/bin/odinforge-agent https://YOUR_SERVER/agents/odinforge-agent-linux-arm64
   
   sudo chmod +x /usr/local/bin/odinforge-agent
   ```

2. Create the configuration directory:
   ```bash
   sudo mkdir -p /etc/odinforge
   ```

3. Store the API key:
   ```bash
   echo "YOUR_REGISTRATION_TOKEN" | sudo tee /etc/odinforge/api_key > /dev/null
   sudo chmod 600 /etc/odinforge/api_key
   ```

4. Create the systemd service file:
   ```bash
   sudo tee /etc/systemd/system/odinforge-agent.service > /dev/null << 'EOF'
   [Unit]
   Description=OdinForge Security Agent
   After=network.target
   
   [Service]
   Type=simple
   ExecStart=/usr/local/bin/odinforge-agent
   Environment=ODINFORGE_SERVER_URL=https://YOUR_SERVER
   Restart=always
   RestartSec=10
   User=root
   
   [Install]
   WantedBy=multi-user.target
   EOF
   ```

5. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable odinforge-agent
   sudo systemctl start odinforge-agent
   ```

### Verify Installation (Linux)

```bash
# Check service status
sudo systemctl status odinforge-agent

# View logs
sudo journalctl -u odinforge-agent -f
```

---

## Windows Installation

### Automatic Installation (Recommended)

1. Open PowerShell as Administrator
2. Run:
   ```powershell
   irm https://YOUR_SERVER/api/agents/install.ps1 | iex
   ```

### Manual Installation

1. Create installation directories:
   ```powershell
   New-Item -ItemType Directory -Force -Path "C:\Program Files\OdinForge"
   New-Item -ItemType Directory -Force -Path "C:\ProgramData\OdinForge"
   ```

2. Download the agent:
   ```powershell
   Invoke-WebRequest -Uri "https://YOUR_SERVER/agents/odinforge-agent-windows-amd64.exe" -OutFile "C:\Program Files\OdinForge\odinforge-agent.exe"
   ```

3. Store the API key:
   ```powershell
   "YOUR_REGISTRATION_TOKEN" | Out-File -FilePath "C:\ProgramData\OdinForge\api_key" -Encoding ASCII -NoNewline
   ```

4. Install as a Windows service:
   ```powershell
   # Using sc.exe
   sc.exe create OdinForgeAgent binPath= "C:\Program Files\OdinForge\odinforge-agent.exe" start= auto
   sc.exe description OdinForgeAgent "OdinForge Security Agent - Endpoint telemetry and security monitoring"
   
   # Set environment variable
   [Environment]::SetEnvironmentVariable("ODINFORGE_SERVER_URL", "https://YOUR_SERVER", "Machine")
   
   # Start the service
   sc.exe start OdinForgeAgent
   ```

### Verify Installation (Windows)

```powershell
# Check service status
Get-Service OdinForgeAgent

# View event logs
Get-EventLog -LogName Application -Source OdinForgeAgent -Newest 20
```

---

## Docker Deployment

### Using Docker Run

```bash
docker run -d \
  --name odinforge-agent \
  --restart unless-stopped \
  --privileged \
  --pid=host \
  --network=host \
  -e SERVER_URL=https://YOUR_SERVER \
  -e TOKEN=YOUR_REGISTRATION_TOKEN \
  -e INTERVAL=60 \
  -e STATELESS=true \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  odinforge/agent:latest
```

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  odinforge-agent:
    image: odinforge/agent:latest
    container_name: odinforge-agent
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    environment:
      - SERVER_URL=https://YOUR_SERVER
      - TOKEN=YOUR_REGISTRATION_TOKEN
      - INTERVAL=60
      - STATELESS=true
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
```

Start with:
```bash
docker-compose up -d
```

### Building the Container Image

```bash
cd odinforge-agent
docker build -t odinforge/agent:latest .
```

### Container Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_URL` | OdinForge server URL | Required |
| `TOKEN` | Agent registration token | Required |
| `INTERVAL` | Telemetry collection interval (seconds) | `60` |
| `STATELESS` | Use ephemeral storage paths | `false` |

---

## Kubernetes Deployment

### DaemonSet Deployment (Recommended)

This deploys the agent to every node in your cluster.

1. Download and customize the manifest:
   ```bash
   curl -o daemonset.yaml https://YOUR_SERVER/agents/kubernetes/daemonset.yaml
   
   # Edit the ConfigMap to set your server URL
   # Replace "https://YOUR_ODINFORGE_SERVER" with your actual server URL
   vim daemonset.yaml
   ```

2. Apply the manifest (creates namespace, ConfigMap, ServiceAccount, and DaemonSet):
   ```bash
   kubectl apply -f daemonset.yaml
   ```

3. Create the secret with your registration token:
   ```bash
   kubectl create secret generic odinforge-agent \
     --namespace odinforge \
     --from-literal=token=YOUR_REGISTRATION_TOKEN
   ```

4. Restart the DaemonSet to pick up the secret:
   ```bash
   kubectl rollout restart daemonset/odinforge-agent -n odinforge
   ```

### DaemonSet Manifest

Save as `kubernetes/daemonset.yaml`:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: odinforge-agent
  namespace: odinforge
  labels:
    app: odinforge-agent
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
        imagePullPolicy: Always
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
        - name: INTERVAL
          value: "60"
        - name: STATELESS
          value: "true"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: docker-sock
          mountPath: /var/run/docker.sock
          readOnly: true
        resources:
          limits:
            memory: 128Mi
            cpu: 100m
          requests:
            memory: 64Mi
            cpu: 50m
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
```

### Verify Kubernetes Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n odinforge

# Check pods on each node
kubectl get pods -n odinforge -o wide

# View agent logs
kubectl logs -n odinforge -l app=odinforge-agent --tail=50
```

---

## Configuration Reference

### Environment Variables

The agent supports the following environment variables:

| Variable | Alternative | Description | Default |
|----------|-------------|-------------|---------|
| `ODINFORGE_SERVER_URL` | `SERVER_URL` | OdinForge server base URL | Required |
| `ODINFORGE_TOKEN` | `TOKEN` | Agent registration token | Read from `/etc/odinforge/api_key` |
| `ODINFORGE_INTERVAL` | `INTERVAL` | Collection interval in seconds | `60` |
| `STATELESS` | - | Use temp paths for ephemeral containers | `false` |

### File Paths

| Platform | API Key Location | Log Location |
|----------|-----------------|--------------|
| macOS | `/etc/odinforge/api_key` | `/var/log/odinforge-agent.log` |
| Linux | `/etc/odinforge/api_key` | `journalctl -u odinforge-agent` |
| Windows | `C:\ProgramData\OdinForge\api_key` | Event Viewer |
| Container | Environment variable | stdout |

---

## Troubleshooting

### Agent Not Connecting

1. Verify the server URL is correct and reachable:
   ```bash
   curl -I https://YOUR_SERVER/api/health
   ```

2. Check the registration token is valid

3. Verify firewall allows outbound HTTPS (port 443)

### High CPU Usage

Increase the collection interval:
```bash
# Linux
sudo systemctl edit odinforge-agent
# Add: Environment=ODINFORGE_INTERVAL=120

# macOS - edit /Library/LaunchDaemons/com.odinforge.agent.plist
```

### Container Detection Not Working

Ensure the agent has access to:
- `/proc` filesystem (read-only)
- Docker socket (`/var/run/docker.sock`) if using Docker
- Kubernetes downward API for pod metadata

### Permission Denied Errors

The agent requires root/administrator privileges for:
- Reading network connections (`/proc/net/tcp`)
- Accessing service status
- Container runtime socket access

---

## Uninstallation

### macOS

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.odinforge.agent.plist
sudo rm /Library/LaunchDaemons/com.odinforge.agent.plist
sudo rm /usr/local/bin/odinforge-agent
sudo rm -rf /etc/odinforge
```

### Linux

```bash
sudo systemctl stop odinforge-agent
sudo systemctl disable odinforge-agent
sudo rm /etc/systemd/system/odinforge-agent.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/odinforge-agent
sudo rm -rf /etc/odinforge
```

### Windows

```powershell
sc.exe stop OdinForgeAgent
sc.exe delete OdinForgeAgent
Remove-Item -Recurse -Force "C:\Program Files\OdinForge"
Remove-Item -Recurse -Force "C:\ProgramData\OdinForge"
```

### Kubernetes

```bash
kubectl delete daemonset odinforge-agent -n odinforge
kubectl delete secret odinforge-agent -n odinforge
kubectl delete namespace odinforge
```

### Docker

```bash
docker stop odinforge-agent
docker rm odinforge-agent
```

---

## Support

For issues or questions:
- Check the [Troubleshooting](#troubleshooting) section
- View agent logs for detailed error messages
- Contact your OdinForge administrator
