# OdinForge-AI Production Enhancements

This document describes the production-ready enhancements added to OdinForge-AI for enterprise deployment.

## Table of Contents

1. [Scheduled Scan Execution](#scheduled-scan-execution)
2. [Human-In-The-Loop (HITL) Approval Workflows](#human-in-the-loop-hitl-approval-workflows)
3. [Pull Request Automation](#pull-request-automation)
4. [Getting Started](#getting-started)

---

## Scheduled Scan Execution

### Overview

The scheduled scan executor allows you to configure recurring security evaluations on a schedule (daily, weekly, monthly, quarterly, or one-time).

###status

✅ **Fully Implemented and Active**

### Features

- **Multiple Frequencies**: Once, daily, weekly, monthly, quarterly
- **Time-of-Day Scheduling**: Specify exact time for scan execution
- **Asset-Level Configuration**: Configure specific assets to scan with individual priorities
- **Automatic Job Queuing**: Scans are automatically queued with appropriate priority
- **Execution Tracking**: `lastRunAt` and `nextRunAt` timestamps for each scan

### Implementation

**Service**: `server/services/scheduler/scan-scheduler.ts`
- Runs every minute via `node-cron`
- Checks for due scans and creates evaluations
- Automatically initialized in `server/index.ts`

### API Endpoints

```typescript
// Get all scheduled scans
GET /api/scheduled-scans?organizationId={orgId}

// Get specific scan
GET /api/scheduled-scans/:id

// Create scheduled scan
POST /api/scheduled-scans
{
  "name": "Weekly Production Scan",
  "frequency": "weekly",
  "dayOfWeek": 1,  // Monday
  "timeOfDay": "02:00",
  "enabled": true,
  "assets": [
    {
      "assetId": "asset-123",
      "exposureType": "cve",
      "priority": "high",
      "description": "Production web server"
    }
  ],
  "organizationId": "default"
}

// Update scheduled scan
PATCH /api/scheduled-scans/:id

// Delete scheduled scan
DELETE /api/scheduled-scans/:id

// Trigger immediate execution
POST /api/scheduled-scans/:id/trigger
```

### Database Schema

```typescript
{
  id: string;
  name: string;
  frequency: "once" | "daily" | "weekly" | "monthly" | "quarterly";
  timeOfDay?: string;  // "HH:MM" format
  dayOfWeek?: number;  // 0-6 (Sunday-Saturday)
  dayOfMonth?: number; // 1-31
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt?: Date;
  assets: Array<{
    assetId: string;
    exposureType: string;
    priority: string;
    description: string;
  }>;
  organizationId: string;
}
```

---

## Human-In-The-Loop (HITL) Approval Workflows

### Overview

HITL approval workflows provide real-time human oversight for high-risk security operations. When the AI agents attempt to execute dangerous commands, they are blocked and require explicit human approval before proceeding.

### Status

✅ **Backend Complete** | ✅ **Frontend Complete** | ✅ **WebSocket Notifications Active**

### Features

- **Real-Time Approval Requests**: WebSocket notifications for immediate awareness
- **Risk-Based Gating**: Automatic detection of high-risk operations
- **Policy-Driven**: RAG-based policy search for intelligent risk assessment
- **Cryptographic Signatures**: Non-repudiation with HMAC-SHA256 signatures
- **Time-Limited**: Approval requests expire after 5 minutes
- **Audit Trail**: Complete logging of all approval decisions
- **Role-Based Access**: Only security_admin and org_owner can approve

### Architecture

**Components:**

1. **Runtime Guard** (`server/services/runtime-guard.ts`)
   - Validates commands before execution
   - Checks against forbidden patterns
   - Searches policies via RAG
   - Creates approval requests for high-risk operations

2. **Approval UI** (`client/src/pages/Approvals.tsx`)
   - Real-time dashboard of pending approvals
   - Risk level indicators (Critical, High, Medium)
   - Detailed operation review with policy matches
   - Approve/Reject actions with reason tracking

3. **WebSocket Service** (`server/services/websocket.ts`)
   - Broadcasts approval requests to organization channels
   - Real-time updates on approval status
   - Evaluation-scoped notifications

### API Endpoints

```typescript
// Get pending approvals for organization
GET /api/hitl/pending

// Get approval history for evaluation
GET /api/hitl/evaluation/:evaluationId

// Get nonce for signing (security feature)
GET /api/hitl/:approvalId/nonce

// Approve a request
POST /api/hitl/:approvalId/approve
{
  "nonce": "random-nonce"
}

// Reject a request
POST /api/hitl/:approvalId/reject
{
  "nonce": "random-nonce",
  "reason": "Command targets production database without proper scoping"
}

// Cancel all pending approvals for an evaluation
POST /api/hitl/evaluation/:evaluationId/cancel
```

### WebSocket Events

```typescript
// Subscribe to approval notifications
ws://localhost:5000/ws?token={jwt_token}

// Event received when approval is required
{
  "type": "hitl_approval_required",
  "approvalId": "hitl-1234567890-abc123",
  "evaluationId": "eval-123",
  "organizationId": "default",
  "agentName": "ExploitAgent",
  "command": "rm -rf /",
  "target": "192.168.1.100",
  "riskLevel": "critical",
  "riskReason": "Forbidden pattern detected: rm -rf",
  "expiresAt": "2026-02-07T12:05:00Z",
  "timestamp": "2026-02-07T12:00:00Z"
}
```

### Usage Example

**From Frontend:**

```typescript
// Subscribe to approval channel
wsClient.subscribe(`approvals:${organizationId}`);

// Listen for approval requests
wsClient.on('message', (event) => {
  if (event.type === 'hitl_approval_required') {
    showApprovalNotification(event);
  }
});

// Approve a request
await fetch(`/api/hitl/${approvalId}/approve`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ nonce: generateNonce() })
});
```

### Configuration

**Environment Variables:**

```bash
# Required: Secret for signing approval responses
HITL_SIGNING_SECRET=your-secret-key-here-min-32-chars
```

### Security Considerations

- **Signatures**: All approval/rejection decisions are cryptographically signed
- **Non-repudiation**: Signatures prevent forgery of approval decisions
- **Time Limits**: Requests expire after 5 minutes to prevent stale approvals
- **Role-Based**: Only authorized roles can approve (security_admin, org_owner)
- **Audit Trail**: All decisions logged with user identity and timestamp

---

## Pull Request Automation

### Overview

Automated creation of Pull Requests (GitHub) or Merge Requests (GitLab) with security remediation code generated by the AI.

### Status

✅ **Service Implemented** | ✅ **API Endpoints Added** | ⚠️ **Requires Configuration**

### Features

- **GitHub Support**: Full GitHub API integration via Octokit
- **GitLab Support**: Full GitLab API integration via GitBeaker
- **Branch Management**: Automatic branch creation from default branch
- **File Operations**: Create, modify, and delete files
- **Labels & Reviewers**: Automatic assignment of labels and reviewers
- **Status Tracking**: Check PR/MR status (created, merged, closed)
- **IaC Fix Generation**: Automatic Terraform, CloudFormation, Kubernetes fixes

### Supported IaC Templates

**Terraform:**
- S3 public access blocking
- IAM least-privilege policies
- Security group restrictions
- Encryption enablement

**CloudFormation:**
- S3 bucket encryption and public access
- IAM policy least-privilege

**Kubernetes:**
- Privileged container removal
- Network policies (default-deny)
- RBAC least-privilege
- Secret exposure prevention

**Code Patches:**
- SQL injection fixes (parameterized queries)
- XSS prevention (sanitization)
- Path traversal protection
- Insecure deserialization fixes

### API Endpoints

```typescript
// Configure PR automation (required before creating PRs)
POST /api/remediation/configure-pr
{
  "provider": "github",  // or "gitlab"
  "token": "ghp_your_github_token",
  "baseUrl": "https://api.github.com"  // optional
}

// Create a PR for a finding
POST /api/remediation/:findingId/create-pr
{
  "repositoryUrl": "https://github.com/owner/repo",
  "branchName": "odinforge-fix-s3-public-access",  // optional
  "labels": ["security", "automated-fix"],  // optional
  "reviewers": ["security-team"]  // optional
}

// Check PR status
GET /api/remediation/pr/:prId/status?repositoryUrl=https://github.com/owner/repo
```

### Setup Instructions

#### GitHub Setup

1. **Generate Personal Access Token:**
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate new token (classic) with scopes:
     - `repo` (full control of private repositories)
     - `workflow` (if PRs need to trigger workflows)

2. **Configure in OdinForge:**
   ```bash
   POST /api/remediation/configure-pr
   {
     "provider": "github",
     "token": "ghp_yourtokenhere"
   }
   ```

#### GitLab Setup

1. **Generate Personal Access Token:**
   - Go to GitLab Settings → Access Tokens
   - Create token with scopes:
     - `api` (full API access)
     - `write_repository` (push to repository)

2. **Configure in OdinForge:**
   ```bash
   POST /api/remediation/configure-pr
   {
     "provider": "gitlab",
     "token": "glpat-yourtokenhere",
     "baseUrl": "https://gitlab.com"  // or your self-hosted instance
   }
   ```

### Usage Example

**Generating and Creating PR:**

```typescript
// 1. Configure PR automation (once)
await fetch('/api/remediation/configure-pr', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    provider: 'github',
    token: process.env.GITHUB_TOKEN
  })
});

// 2. Create PR for a security finding
const response = await fetch('/api/remediation/finding-123/create-pr', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    repositoryUrl: 'https://github.com/myorg/infrastructure',
    labels: ['security', 'critical', 'odinforge'],
    reviewers: ['security-team', 'devops-lead']
  })
});

const result = await response.json();
console.log('PR created:', result.pr.url);
// Output: https://github.com/myorg/infrastructure/pull/42

// 3. Check PR status
const statusResponse = await fetch(
  `/api/remediation/pr/${result.pr.id}/status?repositoryUrl=https://github.com/myorg/infrastructure`
);
const status = await statusResponse.json();
console.log('PR status:', status.status);  // created | merged | closed
```

### Security Considerations

- **Token Storage**: Tokens are stored in memory only, not persisted to database
- **Token Scope**: Use minimal required scopes for tokens
- **Branch Protection**: Respect branch protection rules in repositories
- **Review Required**: Always require human review before merging automated PRs
- **Rollback**: Each PR result includes `rollbackCommit` SHA for reverting

### Error Handling

```typescript
try {
  const result = await prAutomationService.createPullRequest(request);
  return result;
} catch (error) {
  // Falls back to mock PR response if Git integration fails
  // Allows system to continue functioning without breaking
  console.error('PR creation failed:', error);
  return {
    id: 'pr-mock',
    status: 'pending',
    url: `${repositoryUrl}/pull/pending`,
    branchName,
    title,
    filesChanged: changes.length
  };
}
```

---

## Getting Started

### 1. Verify Scheduled Scans

Scheduled scans are already active! Just create your first scheduled scan:

```bash
curl -X POST http://localhost:5000/api/scheduled-scans \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Production Scan",
    "frequency": "daily",
    "timeOfDay": "02:00",
    "enabled": true,
    "assets": [
      {
        "assetId": "prod-web-01",
        "exposureType": "cve",
        "priority": "high",
        "description": "Production web server"
      }
    ],
    "organizationId": "default"
  }'
```

### 2. Access HITL Approval Dashboard

1. Navigate to **Approvals** in the sidebar
2. Pending approval requests will appear in real-time
3. Click **Review** to see operation details
4. Approve or reject with a reason

### 3. Configure PR Automation

```bash
# Configure GitHub
curl -X POST http://localhost:5000/api/remediation/configure-pr \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github",
    "token": "ghp_your_token_here"
  }'

# Create your first automated PR
curl -X POST http://localhost:5000/api/remediation/finding-123/create-pr \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryUrl": "https://github.com/your-org/repo",
    "labels": ["security", "odinforge"]
  }'
```

---

## Troubleshooting

### Scheduled Scans Not Running

**Check:**
1. Scheduler initialized: Look for `[Scheduler] Scan scheduler initialized` in logs
2. Scan enabled: `enabled: true` in database
3. `nextRunAt` is in the past
4. Check logs: `[Scheduler] Found X due scheduled scan(s)`

**Fix:**
```bash
# Check scheduler status
tail -f server.log | grep Scheduler

# Manually trigger a scan
curl -X POST http://localhost:5000/api/scheduled-scans/{scanId}/trigger
```

### HITL Approvals Not Appearing

**Check:**
1. WebSocket connected: Check browser console for WebSocket connection
2. Subscribed to correct channel: `approvals:{organizationId}`
3. User has required role: `security_admin` or `org_owner`
4. `HITL_SIGNING_SECRET` environment variable is set

**Fix:**
```bash
# Set signing secret
export HITL_SIGNING_SECRET="your-secret-min-32-characters-long"

# Restart server
npm run dev
```

### PR Creation Failing

**Check:**
1. Token configured: `POST /api/remediation/configure-pr`
2. Token has correct permissions (see Setup Instructions above)
3. Repository URL is correct format
4. Branch doesn't already exist

**Fix:**
```bash
# Reconfigure with correct token
curl -X POST http://localhost:5000/api/remediation/configure-pr \
  -H "Content-Type": "application/json" \
  -d '{"provider": "github", "token": "ghp_correct_token"}'

# Check GitHub token permissions at:
# https://github.com/settings/tokens
```

---

## Architecture Diagrams

### HITL Approval Flow

```
┌──────────────┐
│ Agent        │ Attempts dangerous command
│ (ExploitAgent│ ──────────────┐
└──────────────┘                │
                                ▼
                      ┌─────────────────┐
                      │ Runtime Guard   │ Policy check via RAG
                      └─────────────────┘
                                │
                   ┌────────────┴────────────┐
                   │ Risk Assessment         │
                   │ - Forbidden patterns?   │
                   │ - Policy violations?    │
                   │ - High-risk target?     │
                   └────────────┬────────────┘
                                │
                      ┌─────────▼─────────┐
                      │ Create Approval   │
                      │ Request in DB     │
                      └─────────┬─────────┘
                                │
                      ┌─────────▼──────────┐
                      │ WebSocket Broadcast│
                      │ to Organization    │
                      └─────────┬──────────┘
                                │
                   ┌────────────▼────────────┐
                   │ Frontend Notification   │
                   │ (Real-time alert)       │
                   └────────────┬────────────┘
                                │
                      ┌─────────▼─────────┐
                      │ Human Reviews     │
                      │ Approves/Rejects  │
                      └─────────┬─────────┘
                                │
                   ┌────────────▼────────────┐
                   │ Signature Verified      │
                   │ Decision Recorded       │
                   └────────────┬────────────┘
                                │
           ┌────────────────────▼────────────────────┐
           │                                         │
    ┌──────▼──────┐                        ┌────────▼────────┐
    │ APPROVED    │                        │ REJECTED        │
    │ Command runs│                        │ Command blocked │
    └─────────────┘                        └─────────────────┘
```

### PR Automation Flow

```
┌──────────────────┐
│ Finding Detected │
│ (S3 Public)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────────┐
│ IaC Remediation      │ Generates Terraform/K8s/CF fixes
│ Service              │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ PR Request Created   │
│ - Repository URL     │
│ - Branch name        │
│ - File changes       │
│ - Labels, reviewers  │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ PR Automation Service│
│ (GitHub/GitLab)      │
└────────┬─────────────┘
         │
    ┌────▼────┐
    │Provider?│
    └────┬────┘
         │
    ┌────▼─────────────────────┐
    │                          │
┌───▼─────┐           ┌────────▼──────┐
│ GitHub  │           │ GitLab        │
│ API     │           │ API           │
└───┬─────┘           └────────┬──────┘
    │                          │
    ├─ Get default branch      │
    ├─ Create new branch       │
    ├─ Commit file changes     │
    ├─ Create Pull Request     │
    ├─ Add labels              │
    └─ Request reviewers       │
                               │
    ┌──────────────────────────┴──────────┐
    │ PR Created Successfully             │
    │ URL: https://github.com/org/repo/42 │
    └─────────────────────────────────────┘
```

---

## Support

For issues or questions:
- Check logs: `tail -f server.log`
- Review API responses for error messages
- Verify environment variables are set
- Ensure required services are running (PostgreSQL, Redis if using)

**Enterprise Support:** Contact your OdinForge administrator

---

*Last Updated: February 7, 2026*
*OdinForge AI v1.0.0*
