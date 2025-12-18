# OdinForge Agent Deployment Guide

This guide covers deploying the OdinForge Security Agent across different environments.

## Quick Start

### Automatic Installation (Recommended)

The agent includes a self-installer that auto-detects your environment:

```bash
# Linux/macOS (interactive)
sudo ./odinforge-agent install

# Linux/macOS (non-interactive)
sudo ./odinforge-agent install \
  --server-url https://your-odinforge-server.com \
  --api-key YOUR_API_KEY

# Windows (run as Administrator)
.\odinforge-agent.exe install --server-url https://your-odinforge-server.com --api-key YOUR_KEY
```

### Check Status

```bash
./odinforge-agent status
```

### Uninstall

```bash
sudo ./odinforge-agent uninstall
```

---

## Manual Deployment Options

### Docker

1. Navigate to the Docker deployment directory:
   ```bash
   cd deploy/docker
   ```

2. Copy and configure the environment file:
   ```bash
   cp .env.example .env
   # Edit .env with your server URL and API key
   ```

3. Start the agent:
   ```bash
   docker-compose up -d
   ```

4. View logs:
   ```bash
   docker-compose logs -f
   ```

### Kubernetes

Choose between DaemonSet (one agent per node) or Deployment (single agent):

1. Create the namespace:
   ```bash
   kubectl apply -f deploy/kubernetes/namespace.yaml
   ```

2. Configure secrets (edit with your API key):
   ```bash
   # Edit deploy/kubernetes/secret.yaml with your API key
   kubectl apply -f deploy/kubernetes/secret.yaml
   ```

3. Configure the server URL:
   ```bash
   # Edit deploy/kubernetes/daemonset.yaml or deployment.yaml
   # Update the odinforge-agent-env ConfigMap with your server URL
   ```

4. Deploy:
   ```bash
   # For per-node monitoring (recommended):
   kubectl apply -f deploy/kubernetes/daemonset.yaml

   # OR for single-instance:
   kubectl apply -f deploy/kubernetes/deployment.yaml
   ```

5. Verify:
   ```bash
   kubectl get pods -n odinforge
   kubectl logs -n odinforge -l app.kubernetes.io/name=odinforge-agent
   ```

### Linux (systemd)

1. Copy the binary:
   ```bash
   sudo cp odinforge-agent /usr/local/bin/
   sudo chmod +x /usr/local/bin/odinforge-agent
   ```

2. Create configuration directory:
   ```bash
   sudo mkdir -p /etc/odinforge /var/lib/odinforge-agent
   ```

3. Copy and edit configuration:
   ```bash
   sudo cp deploy/config.yaml.example /etc/odinforge/agent.yaml
   sudo cp deploy/systemd/agent.env.example /etc/odinforge/agent.env
   # Edit both files with your settings
   ```

4. Create service user:
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin odinforge
   sudo chown -R odinforge:odinforge /var/lib/odinforge-agent
   ```

5. Install and enable service:
   ```bash
   sudo cp deploy/systemd/odinforge-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable odinforge-agent
   sudo systemctl start odinforge-agent
   ```

6. Check status:
   ```bash
   sudo systemctl status odinforge-agent
   sudo journalctl -u odinforge-agent -f
   ```

### macOS (launchd)

1. Copy the binary:
   ```bash
   sudo cp odinforge-agent /usr/local/bin/
   sudo chmod +x /usr/local/bin/odinforge-agent
   ```

2. Create directories:
   ```bash
   sudo mkdir -p /etc/odinforge /var/lib/odinforge-agent /var/log/odinforge-agent
   ```

3. Copy and edit configuration:
   ```bash
   sudo cp deploy/config.yaml.example /etc/odinforge/agent.yaml
   # Edit with your settings
   ```

4. Edit and install the plist:
   ```bash
   # Edit deploy/launchd/com.odinforge.agent.plist with your server URL and API key
   sudo cp deploy/launchd/com.odinforge.agent.plist /Library/LaunchDaemons/
   ```

5. Load and start:
   ```bash
   sudo launchctl load /Library/LaunchDaemons/com.odinforge.agent.plist
   ```

6. Check status:
   ```bash
   sudo launchctl list | grep odinforge
   tail -f /var/log/odinforge-agent/agent.log
   ```

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ODINFORGE_SERVER_URL` | OdinForge server URL | Required |
| `ODINFORGE_API_KEY` | API key from Agents page | Required |
| `ODINFORGE_TENANT_ID` | Tenant/Organization ID | `default` |
| `ODINFORGE_AUTH_MODE` | Authentication mode (`api_key` or `mtls`) | `api_key` |
| `ODINFORGE_TELEMETRY_INTERVAL` | Telemetry collection interval | `5m` |
| `ODINFORGE_HEARTBEAT_INTERVAL` | Heartbeat interval | `1m` |
| `ODINFORGE_BATCH_SIZE` | Events per batch | `50` |
| `ODINFORGE_COMPRESS` | Enable gzip compression | `true` |
| `ODINFORGE_REQUIRE_HTTPS` | Require HTTPS connections | `true` |
| `ODINFORGE_VERIFY_TLS` | Verify TLS certificates | `true` |
| `ODINFORGE_QUEUE_PATH` | Path to offline queue database | `./agent.queue.db` |

### mTLS Authentication

For mTLS authentication instead of API keys:

1. Set `ODINFORGE_AUTH_MODE=mtls`
2. Configure certificate paths:
   - `ODINFORGE_MTLS_CERT`: Path to agent certificate
   - `ODINFORGE_MTLS_KEY`: Path to agent private key
   - `ODINFORGE_CA_CERT`: Path to CA certificate (optional)

---

## Troubleshooting

### Agent won't start

1. Check logs:
   - Linux: `journalctl -u odinforge-agent -n 50`
   - macOS: `tail -50 /var/log/odinforge-agent/agent.log`
   - Docker: `docker-compose logs odinforge-agent`

2. Verify configuration:
   - Ensure server URL is accessible
   - Verify API key is correct
   - Check file permissions on config and data directories

### Connection issues

1. Test connectivity:
   ```bash
   curl -v https://your-odinforge-server.com/api/health
   ```

2. Check firewall rules allow outbound HTTPS (port 443)

3. If using a proxy, configure via environment variables

### High resource usage

1. Adjust collection intervals (increase `ODINFORGE_TELEMETRY_INTERVAL`)
2. Reduce batch size if memory constrained
3. Check the resource limits in systemd/docker configuration

---

## Security Recommendations

1. **Use HTTPS**: Always use HTTPS in production (`ODINFORGE_REQUIRE_HTTPS=true`)
2. **Protect credentials**: Keep API keys in environment files with restricted permissions (0600)
3. **Run as non-root**: The systemd service runs as a dedicated `odinforge` user
4. **Enable TLS verification**: Keep `ODINFORGE_VERIFY_TLS=true` in production
5. **Consider mTLS**: For high-security environments, use mutual TLS instead of API keys
