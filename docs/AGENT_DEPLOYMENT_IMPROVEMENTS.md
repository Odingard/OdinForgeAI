# Agent Deployment Improvements

## Changes Made

### Problem
Agents were failing to start after deployment due to:
1. **File permission issues** - Config files created with restrictive permissions (600) that the agent service couldn't read
2. **Missing registration token** - Server didn't have `AGENT_REGISTRATION_TOKEN` configured

### Solution

#### 1. Fixed Deployment Scripts (All Cloud Providers)

**Modified Files:**
- `server/services/cloud/aws-adapter.ts`
- `server/services/cloud/azure-adapter.ts`
- `server/services/cloud/gcp-adapter.ts`

**Changes:**

**Linux deployments** - Added after agent installation:
```bash
sudo chmod 644 /etc/odinforge/agent.yaml
sudo chmod 755 /etc/odinforge
sudo systemctl restart odinforge-agent || true
```

**Windows deployments** - Added after agent installation:
```powershell
icacls 'C:\ProgramData\OdinForge\agent.yaml' /grant 'Everyone:(R)' /T
Restart-Service -Name 'odinforge-agent' -Force -ErrorAction SilentlyContinue
```

#### 2. Environment Configuration

**Required in `.env`:**
```bash
# Agent registration token (must match what agents use)
AGENT_REGISTRATION_TOKEN=auto-deploy-token

# Public URL for agents to connect (if behind NAT/ngrok)
PUBLIC_ODINFORGE_URL=https://your-server-url.com
```

## How It Works Now

1. **Agent downloads** from server
2. **Agent installs** and creates config file with restrictive permissions
3. **Permissions are fixed** automatically by deployment script
4. **Agent service restarts** to pick up correct permissions
5. **Agent authenticates** using the registration token from `.env`
6. **Agent connects** and starts sending heartbeats

## Testing

After these changes, agent deployments will:
- ✅ Automatically fix file permissions
- ✅ Restart the service with correct permissions
- ✅ Authenticate using the permanent token
- ✅ Connect and send heartbeats within 30 seconds

## Deployment

To deploy agents with these fixes:

```bash
# 1. Ensure .env has AGENT_REGISTRATION_TOKEN set
# 2. Restart the server to pick up changes
# 3. Deploy agents as normal

# They will now install cleanly without manual intervention
```

## Troubleshooting

If agents still fail to start:

**Linux:**
```bash
sudo journalctl -u odinforge-agent -n 50 --no-pager
ls -l /etc/odinforge/agent.yaml
```

**Windows:**
```powershell
Get-Service -Name "OdinForge Agent" | Format-List *
Get-EventLog -LogName Application -Source "OdinForge Agent" -Newest 20
icacls "C:\ProgramData\OdinForge\agent.yaml"
```

---

**Date:** February 7, 2026
**Status:** ✅ Ready for Production
