# Enterprise Agent Deployment Guide

## Overview

This guide provides the **production-ready, enterprise-grade** agent deployment workflow for OdinForge AI. Follow these steps once, and agents will work reliably without constant intervention.

## Quick Start (3 Steps)

### 1. Provision an Agent

Use the API to provision a new agent and get installation credentials:

```bash
curl -X POST http://localhost:5000/api/agents/provision \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "prod-web-01",
    "platform": "linux",
    "architecture": "x86_64",
    "environment": "production",
    "tags": ["web-server", "critical"]
  }'
```

**Response:**
```json
{
  "success": true,
  "agentId": "agent-abc123",
  "apiKey": "odin_agent_1a2b3c4d5e6f...",
  "installCommand": "export ODINFORGE_SERVER=... curl -sSL ...",
  "configFile": "[server]\nurl = ...",
  "warning": "Store the API key securely - it cannot be retrieved again"
}
```

⚠️ **CRITICAL**: Save the `apiKey` immediately - it's shown **only once**.

### 2. Deploy the Agent

**Option A: One-Line Install (Recommended)**

Copy the `installCommand` from the response and run it on your target system:

```bash
# The command looks like this:
export ODINFORGE_SERVER="https://odinforge.example.com"
export ODINFORGE_AGENT_ID="agent-abc123"
export ODINFORGE_API_KEY="odin_agent_1a2b3c4d5e6f..."
curl -sSL https://odinforge.example.com/api/agents/install.sh | bash
```

**Option B: Manual Install**

1. Download the agent binary for your platform
2. Create `/etc/odinforge/agent.conf` with the `configFile` content
3. Start the agent service

### 3. Verify Agent Health

```bash
curl http://localhost:5000/api/agents/agent-abc123/health
```

**Healthy Response:**
```json
{
  "agentId": "agent-abc123",
  "isHealthy": true,
  "lastHeartbeat": "2026-02-08T00:30:00.000Z",
  "lastTelemetry": "2026-02-08T00:30:00.000Z",
  "uptimeSeconds": 3600,
  "issues": [],
  "recommendations": []
}
```

---

## Enterprise Features

### Health Monitoring

**Check All Agents:**
```bash
curl http://localhost:5000/api/agents/health/summary
```

Response shows:
- Total agents
- Healthy count
- Unhealthy count
- Detailed health status per agent

**Auto-Recovery:**

If an agent becomes unhealthy:
```bash
curl -X POST http://localhost:5000/api/agents/agent-abc123/recover
```

The system will:
1. Check agent health status
2. Mark stale agents for redeployment
3. Provide recovery recommendations

### API Key Rotation

For security best practices, rotate agent API keys periodically:

```bash
curl -X POST http://localhost:5000/api/agents/agent-abc123/rotate-key \
  -H "X-Admin-Key: your-admin-key"
```

**Response:**
```json
{
  "success": true,
  "newApiKey": "odin_agent_7g8h9i0j...",
  "configFile": "[server]\nurl = ...",
  "warning": "Update the agent configuration immediately. The old key is now invalid."
}
```

**Update Agent:**
1. SSH to the agent's system
2. Update `/etc/odinforge/agent.conf` with new config
3. Restart the agent: `systemctl restart odinforge-agent`

---

## Production Deployment Patterns

### Pattern 1: AWS Auto-Deploy (Recommended for AWS)

**Prerequisites:**
- AWS Systems Manager (SSM) enabled on EC2 instances
- IAM permissions for `ssm:SendCommand`

**Deploy:**
1. Provision agent via API (stores in database)
2. Use AWS Systems Manager Run Command:

```bash
aws ssm send-command \
  --instance-ids i-1234567890abcdef \
  --document-name "AWS-RunShellScript" \
  --parameters commands="[
    'export ODINFORGE_SERVER=https://odinforge.example.com',
    'export ODINFORGE_AGENT_ID=agent-abc123',
    'export ODINFORGE_API_KEY=odin_agent_...',
    'curl -sSL https://odinforge.example.com/api/agents/install.sh | bash'
  ]"
```

### Pattern 2: Ansible/Terraform Deployment

**Terraform Example:**

```hcl
resource "null_resource" "deploy_odinforge_agent" {
  count = length(aws_instance.servers)

  provisioner "remote-exec" {
    connection {
      host = aws_instance.servers[count.index].public_ip
      type = "ssh"
      user = "ubuntu"
    }

    inline = [
      "export ODINFORGE_SERVER=${var.odinforge_server}",
      "export ODINFORGE_AGENT_ID=${var.odinforge_agent_id}",
      "export ODINFORGE_API_KEY=${var.odinforge_api_key}",
      "curl -sSL ${var.odinforge_server}/api/agents/install.sh | sudo bash"
    ]
  }
}
```

**Ansible Playbook:**

```yaml
- name: Deploy OdinForge Agent
  hosts: all
  vars:
    odinforge_server: "https://odinforge.example.com"
    odinforge_agent_id: "{{ agent_id }}"
    odinforge_api_key: "{{ agent_api_key }}"
  tasks:
    - name: Install OdinForge Agent
      shell: |
        export ODINFORGE_SERVER="{{ odinforge_server }}"
        export ODINFORGE_AGENT_ID="{{ odinforge_agent_id }}"
        export ODINFORGE_API_KEY="{{ odinforge_api_key }}"
        curl -sSL {{ odinforge_server }}/api/agents/install.sh | bash
      become: yes
```

### Pattern 3: Kubernetes DaemonSet

For containerized environments:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: odinforge-agent
  namespace: security
spec:
  selector:
    matchLabels:
      app: odinforge-agent
  template:
    metadata:
      labels:
        app: odinforge-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: agent
        image: odinforge/agent:latest
        env:
        - name: ODINFORGE_SERVER
          value: "https://odinforge.example.com"
        - name: ODINFORGE_AGENT_ID
          valueFrom:
            secretKeyRef:
              name: odinforge-agent-creds
              key: agent-id
        - name: ODINFORGE_API_KEY
          valueFrom:
            secretKeyRef:
              name: odinforge-agent-creds
              key: api-key
        securityContext:
          privileged: true
```

---

## Troubleshooting

### Agent Not Connecting

**Check 1: Verify API Key**
```bash
# Test authentication
curl -H "X-API-Key: odin_agent_..." \
  http://localhost:5000/api/agents/heartbeat
```

If you get 401, the API key is invalid. Provision a new agent or rotate the key.

**Check 2: Network Connectivity**
```bash
# From agent system
curl -v http://localhost:5000/api/agents/heartbeat
```

If connection fails, check:
- Firewall rules
- DNS resolution
- Server URL in agent config

**Check 3: Agent Logs**
```bash
# Linux/macOS
tail -f /var/log/odinforge-agent/agent.log

# Or via journald
journalctl -u odinforge-agent -f

# Windows
Get-Content C:\ProgramData\OdinForge\logs\agent.log -Tail 50 -Wait
```

### Health Check Shows Issues

Run the health endpoint and follow recommendations:

```bash
curl http://localhost:5000/api/agents/agent-abc123/health | jq
```

Common issues:
- **No heartbeat**: Agent not running → restart agent service
- **No telemetry**: Agent configuration issue → check agent.conf
- **No version**: Agent failed to initialize → redeploy agent

### Auto-Recovery Failed

If auto-recovery doesn't resolve the issue:

1. **Delete the phantom agent:**
   ```bash
   curl -X DELETE http://localhost:5000/api/agents/agent-abc123
   ```

2. **Provision a new agent:**
   ```bash
   curl -X POST http://localhost:5000/api/agents/provision ...
   ```

3. **Deploy with new credentials**

---

## Security Best Practices

1. **Rotate API Keys Regularly**
   - Recommended: Every 90 days
   - After security incidents: Immediately
   - Use automated rotation scripts

2. **Store API Keys Securely**
   - Use secrets managers (AWS Secrets Manager, HashiCorp Vault)
   - Never commit API keys to version control
   - Use encrypted config management (Ansible Vault, encrypted Terraform vars)

3. **Monitor Agent Health**
   - Set up alerts for unhealthy agents
   - Review health summary daily
   - Automate recovery for critical agents

4. **Limit Agent Permissions**
   - Agents only need network access to OdinForge server
   - No outbound internet required (except to OdinForge)
   - Run agents with minimal privileges where possible

5. **Audit Agent Activity**
   - Review audit logs regularly
   - Monitor for unexpected agent registrations
   - Alert on API key rotation events

---

## API Reference

### Provision Agent
**POST** `/api/agents/provision`

**Request:**
```json
{
  "hostname": "string (required)",
  "platform": "linux|windows|darwin (required)",
  "architecture": "string (required)",
  "organizationId": "string (optional, default: 'default')",
  "environment": "string (optional, default: 'production')",
  "tags": ["string"] (optional)
}
```

**Response:**
```json
{
  "success": true,
  "agentId": "string",
  "apiKey": "string (ONE-TIME)",
  "installCommand": "string",
  "configFile": "string"
}
```

### Check Agent Health
**GET** `/api/agents/:id/health`

**Response:**
```json
{
  "agentId": "string",
  "isHealthy": boolean,
  "lastHeartbeat": "ISO 8601 date | null",
  "lastTelemetry": "ISO 8601 date | null",
  "uptimeSeconds": number,
  "issues": ["string"],
  "recommendations": ["string"]
}
```

### Check All Agents Health
**GET** `/api/agents/health/summary`

**Response:**
```json
{
  "healthy": number,
  "unhealthy": number,
  "total": number,
  "details": [AgentHealthStatus]
}
```

### Auto-Recover Agent
**POST** `/api/agents/:id/recover`

**Response:**
```json
{
  "success": boolean,
  "message": "string"
}
```

### Rotate API Key
**POST** `/api/agents/:id/rotate-key`

**Response:**
```json
{
  "success": true,
  "newApiKey": "string (ONE-TIME)",
  "configFile": "string"
}
```

---

## Support

For issues with agent deployment:
1. Check the troubleshooting section above
2. Review agent logs
3. Run health checks
4. Open an issue in the GitHub repository with:
   - Agent platform and version
   - Health check output
   - Relevant agent logs

---

## Summary: Enterprise Deployment Checklist

- [ ] Set `ODINFORGE_SERVER_URL` environment variable on server
- [ ] Provision agent via `/api/agents/provision` endpoint
- [ ] Save API key securely (shown only once!)
- [ ] Deploy agent using install command or IaC tool
- [ ] Verify health with `/api/agents/:id/health`
- [ ] Set up health monitoring alerts
- [ ] Configure API key rotation schedule
- [ ] Document deployment in runbook

**Your agents will now work reliably without constant intervention.** ✅
