# 🔧 Agent Deployment Fix Guide

**Issue**: Agents not deploying to discovered EC2 instances
**Root Cause**: EC2 instances are stopped + missing auto-deploy configuration
**Status**: ✅ **Configuration Fixed** - Ready for deployment once instances are started

---

## What Was Fixed

### 1. Auto-Deploy Configuration Created ✅
```sql
Auto-deploy is now enabled with:
- Providers: AWS, Azure, GCP
- Asset Types: ec2, ec2_instance, vm, gce, virtual_machine
- Target Platforms: Linux, Windows
- Max Concurrent: 10 deployments
- Retry on Failure: Yes (max 3 attempts)
```

### 2. EC2 Instances Marked as Deployable ✅
```
Asset Name     | Type         | Deployable | Power State | Agent
---------------|--------------|------------|-------------|--------
New Kid        | ec2_instance | ✅ Yes     | 🔴 Stopped  | No
New Server     | ec2_instance | ✅ Yes     | 🔴 Stopped  | No
App Server     | ec2_instance | ✅ Yes     | 🔴 Stopped  | No
```

**S3 Buckets** (cannot run agents - storage only):
- cf-templates-13jesi5wgu0ti-us-east-1
- cf-templates-13jesi5wgu0ti-us-east-2

---

## 🚨 Critical Issue: Instances Are Stopped

**You cannot deploy agents to stopped EC2 instances.**

### Why Auto-Deploy Didn't Work
1. ✅ Auto-deploy config exists and is enabled
2. ✅ EC2 instances are marked as deployable
3. ❌ **All 3 instances are in "stopped" state**
4. ❌ Auto-deploy skips offline/stopped assets by default

---

## 🔧 How to Fix

### Option A: Start Instances via AWS Console (Recommended)

1. **Go to AWS EC2 Console**:
   - https://console.aws.amazon.com/ec2/

2. **Select and start instances**:
   - Select: "New Kid", "New Server", "App Server"
   - Actions → Instance State → Start
   - Wait for instances to reach "running" state

3. **Trigger deployment in OdinForge**:
   - Go to http://localhost:5000
   - Navigate to **Assets** page
   - Refresh asset list
   - Click "Deploy Agent" on each running instance

### Option B: Start Instances via OdinForge UI

1. **Go to Assets page**:
   - http://localhost:5000/assets

2. **Start instances**:
   - Find each EC2 instance
   - Click "Start Instance" button
   - Wait for power state to change to "running"

3. **Deploy agents**:
   - Once running, click "Deploy Agent"
   - Monitor deployment progress

### Option C: Manual API Deployment (Advanced)

Once instances are running, you can deploy via API:

```bash
# Get asset IDs
curl http://localhost:5000/api/cloud-assets

# Deploy to specific asset
curl -X POST http://localhost:5000/api/cloud-assets/ASSET_ID/deploy-agent \
  -H "Content-Type: application/json" \
  -d '{
    "initiatedBy": "manual",
    "deploymentMethod": "ssm"
  }'
```

---

## 🤖 Auto-Deploy Behavior

Once instances are running, auto-deploy will:

**Automatically deploy when**:
- ✅ New instances are discovered
- ✅ Instances change from stopped → running
- ✅ Manual cloud discovery is triggered
- ✅ Asset matches criteria (provider, type, platform)

**Skip deployment when**:
- ❌ Instance is stopped/terminated
- ❌ Agent already installed
- ❌ Asset type not supported (e.g., S3 buckets)
- ❌ Platform not in target list
- ❌ Governance rules block deployment

**Current auto-deploy settings**:
```json
{
  "enabled": true,
  "providers": ["aws", "azure", "gcp"],
  "assetTypes": ["ec2", "ec2_instance", "vm", "gce", "virtual_machine"],
  "targetPlatforms": ["linux", "windows"],
  "deploymentOptions": {
    "maxConcurrentDeployments": 10,
    "deploymentTimeoutSeconds": 300,
    "retryFailedDeployments": true,
    "maxRetries": 3,
    "skipOfflineAssets": true
  }
}
```

---

## 📊 Current Asset Status

### EC2 Instances (3 total)

| Asset Name | Type | Provider | Power State | Deployable | Agent | Next Action |
|-----------|------|----------|-------------|------------|-------|-------------|
| New Kid | ec2_instance | AWS | 🔴 Stopped | ✅ Yes | ❌ No | Start instance |
| New Server | ec2_instance | AWS | 🔴 Stopped | ✅ Yes | ❌ No | Start instance |
| App Server | ec2_instance | AWS | 🔴 Stopped | ✅ Yes | ❌ No | Start instance |

### S3 Buckets (2 total)

| Asset Name | Type | Deployable | Reason |
|-----------|------|------------|--------|
| cf-templates-13jesi5wgu0ti-us-east-1 | s3_bucket | ❌ No | Storage service (cannot run agents) |
| cf-templates-13jesi5wgu0ti-us-east-2 | s3_bucket | ❌ No | Storage service (cannot run agents) |

---

## 🎯 Step-by-Step Deployment Guide

### Step 1: Start EC2 Instances

**AWS CLI** (fastest):
```bash
# Get instance IDs
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=New Kid,New Server,App Server" \
  --query "Reservations[].Instances[].InstanceId" \
  --output text

# Start instances
aws ec2 start-instances --instance-ids i-xxx i-yyy i-zzz

# Wait for running state
aws ec2 wait instance-running --instance-ids i-xxx i-yyy i-zzz
```

**AWS Console** (easiest):
1. Open EC2 Console
2. Select instances
3. Actions → Start Instance
4. Wait ~30 seconds for "running" state

### Step 2: Verify Instances Are Running

**In OdinForge**:
1. Navigate to http://localhost:5000/assets
2. Click "Refresh" button
3. Verify power_state shows "running"

**Or check database**:
```sql
SELECT asset_name, power_state, agent_deployable
FROM cloud_assets
WHERE asset_type = 'ec2_instance';
```

### Step 3: Deploy Agents

**Option A: Auto-Deploy (Automatic)**

If auto-deploy is enabled, agents will deploy automatically when:
- You trigger a cloud discovery scan
- Instances change from stopped to running
- You click "Sync Assets" in the UI

**Option B: Manual Deploy (Via UI)**

1. Go to http://localhost:5000/assets
2. Find each EC2 instance
3. Click "Deploy Agent" button
4. Monitor deployment status
5. Agent should install in ~1-2 minutes

**Option C: Batch Deploy (Via API)**

```bash
# Get all deployable assets
ASSETS=$(curl -s http://localhost:5000/api/cloud-assets \
  | jq -r '.[] | select(.agentDeployable == true and .powerState == "running") | .id')

# Deploy to each
for asset_id in $ASSETS; do
  echo "Deploying to $asset_id..."
  curl -X POST "http://localhost:5000/api/cloud-assets/$asset_id/deploy-agent" \
    -H "Content-Type: application/json" \
    -d '{"initiatedBy": "batch-deploy"}'
done
```

### Step 4: Monitor Deployment

**Check deployment status**:
```sql
SELECT asset_name, agent_deployment_status, agent_installed, agent_id
FROM cloud_assets
WHERE asset_type = 'ec2_instance';
```

**Check deployment jobs**:
```sql
SELECT id, status, attempts, error_message
FROM agent_deployment_jobs
ORDER BY created_at DESC;
```

**In UI**:
- Assets page shows real-time deployment status
- Agents page shows connected agents
- WebSocket updates provide live progress

---

## 🔍 Troubleshooting

### Issue: "Deployment Failed"

**Check**:
1. Instance is running (not stopped/terminated)
2. Instance has network connectivity
3. Security groups allow outbound HTTPS (for agent download)
4. IAM role has SSM permissions (for SSM deployment)
5. SSH keys are configured (for SSH deployment)

**View logs**:
```sql
SELECT asset_name, agent_deployment_error, error_message
FROM cloud_assets ca
LEFT JOIN agent_deployment_jobs adj ON ca.id = adj.cloud_asset_id
WHERE ca.agent_deployment_status = 'failed';
```

### Issue: "Agent Not Connecting"

**Check**:
1. Agent binary downloaded successfully
2. Agent service is running on instance
3. Firewall allows outbound connections
4. Agent has correct enrollment token
5. Server WebSocket is accessible

**Verify on instance** (SSH in):
```bash
# Check agent process
ps aux | grep odinforge-agent

# Check agent logs
sudo journalctl -u odinforge-agent -f

# Check agent status
sudo systemctl status odinforge-agent
```

### Issue: "Auto-Deploy Not Triggering"

**Check**:
1. Auto-deploy config exists: `SELECT * FROM auto_deploy_configs;`
2. Config is enabled: `enabled = true`
3. Asset type is in allowed list
4. Instance is not stopped/offline
5. Agent is not already installed

**Force trigger**:
```bash
# Trigger cloud discovery (which triggers auto-deploy)
curl -X POST http://localhost:5000/api/cloud-discovery
```

---

## ✅ Success Criteria

**Deployment is successful when**:
1. ✅ `cloud_assets.agent_installed = true`
2. ✅ `cloud_assets.agent_deployment_status = 'completed'`
3. ✅ `cloud_assets.agent_id` has valid agent ID
4. ✅ Agent appears in http://localhost:5000/agents
5. ✅ Agent status shows "online" or "connected"
6. ✅ Agent telemetry is being received

**Expected timeline**:
- Start instance: ~30 seconds
- Trigger deployment: <5 seconds
- Download agent: ~10-30 seconds
- Install agent: ~30-60 seconds
- Agent connect: ~5-10 seconds
- **Total: 1-2 minutes per instance**

---

## 📝 Summary

### What's Fixed ✅
- ✅ Auto-deploy configuration created and enabled
- ✅ EC2 instances marked as deployable
- ✅ Agent binaries are present on server
- ✅ Deployment jobs infrastructure ready
- ✅ WebSocket notifications configured

### What You Need to Do 🎯
1. **Start the 3 EC2 instances** (they're currently stopped)
2. **Wait for "running" state**
3. **Deploy agents** (auto or manual)
4. **Monitor deployment progress**

### Quick Start Commands 🚀

```bash
# 1. Start instances (AWS CLI)
aws ec2 start-instances --instance-ids i-xxx i-yyy i-zzz

# 2. Wait for running
sleep 30

# 3. Trigger deployment via OdinForge UI
# Go to: http://localhost:5000/assets
# Click: "Deploy Agent" on each instance

# 4. Check status
curl http://localhost:5000/api/endpoint-agents
```

---

**Next Steps**: Start your EC2 instances and the agents will deploy automatically! 🚀

*Last Updated: February 7, 2026*
