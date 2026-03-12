# OdinForge AEV — Incident Response Runbook

> Internal procedures for handling production incidents.
> Version: 1.0 | Status: Production

## Rollback Triggers

Immediately rollback if ANY of the following are observed:

1. Any engagement claims "pivot established" without `result.success == true`
2. Any engagement completes in under 2 minutes on a non-trivial target
3. Any credential appears in plaintext in any log stream
4. Any customer engagement finding fails to reconstruct from replay manifest
5. Evidence quality gate reports 0% pass rate on a real engagement

## Rollback Procedure

### Step 1: Halt All Running Engagements

```bash
# On production server
ssh root@24.199.95.237

# List running containers
docker ps

# Stop the app container (halts all engagements)
cd /opt/odinforge
docker compose -f docker-compose.prod.yml stop app
```

### Step 2: Deploy Previous Image

```bash
# List available images
docker images | grep odinforge

# Tag the known-good image
docker tag odinforge-app:<previous-tag> odinforge-app:latest

# Restart with previous image
APP_IMAGE=odinforge-app:latest docker compose -f docker-compose.prod.yml up -d --force-recreate --no-build app
```

### Step 3: Verify Rollback

```bash
# Health check (must use docker exec — port 5000 not exposed to host)
docker exec odinforge-app curl -s http://localhost:5000/healthz

# Verify the correct version is running
docker exec odinforge-app cat /app/package.json | grep version
```

### Step 4: Database Schema Rollback (if needed)

```bash
# Only if the failing deploy included schema migrations
docker exec -it odinforge-postgres psql -U odinforge -d odinforge

# Check current schema state
SELECT * FROM drizzle_migrations ORDER BY created_at DESC LIMIT 5;

# Rollback is manual — contact engineering lead before dropping columns
```

### Step 5: Notify Affected Customers

Template:
```
Subject: OdinForge AEV — Service Incident [INCIDENT-ID]

We identified an issue with engagement processing that may have
affected results generated between [START_TIME] and [END_TIME].

Status: Resolved — previous known-good version restored.
Impact: Engagements during this window should be re-run.
Next: Post-mortem findings will be shared within 48 hours.
```

## Severity Levels

| Level | Definition | Response Time | Rollback? |
|-------|-----------|---------------|-----------|
| SEV-1 | False evidence in customer reports | Immediate | Yes |
| SEV-2 | Plaintext credentials in logs | Immediate | Yes |
| SEV-3 | Engagement failures > 50% rate | 30 minutes | Evaluate |
| SEV-4 | Feature degradation (non-critical) | 2 hours | No |

## Post-Mortem Requirements

Required within 48 hours of any SEV-1 or SEV-2 incident:

1. **Timeline**: When was the issue introduced, detected, and resolved?
2. **Root cause**: What specific code/config change caused the incident?
3. **Impact**: How many engagements/customers were affected?
4. **Detection**: How was the issue detected? Could it have been caught earlier?
5. **Remediation**: What was done to fix it?
6. **Prevention**: What changes will prevent recurrence?

## Monitoring Alerts

### Engagement Failure Rate
- **Threshold**: > 3 failures in 10 minutes
- **Channel**: Slack `#odinforge-alerts`
- **Action**: Check logs, review recent deploys

### Duration Anomaly
- **Threshold**: Engagement completes in < 120 seconds
- **Channel**: Slack `#odinforge-alerts` + structured log warning
- **Action**: Review phase evidence quality

### Credential Leak Detection
- **Threshold**: Any match of credential patterns in log output
- **Channel**: Slack `#odinforge-security` (immediate)
- **Action**: SEV-2 — halt and rollback

### SLA Breach
- **Threshold**: Breach chain SLA deadline passed without remediation
- **Channel**: Slack via `SLACK_ALERT_WEBHOOK`
- **Action**: Notify account team

## Contact

- **On-call engineering**: Check Slack `#odinforge-oncall`
- **Production server**: `ssh root@24.199.95.237`
- **Application logs**: `docker logs odinforge-app --tail 500 -f`
- **Database**: `docker exec -it odinforge-postgres psql -U odinforge -d odinforge`
