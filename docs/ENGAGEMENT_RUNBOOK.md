# OdinForge AEV — Engagement Runbook

> Operational procedures for running customer-facing breach chain engagements.
> Version: 1.0 | Status: Production

## Pre-Engagement Checklist

- [ ] Target scope confirmed in writing (domains, IP ranges, cloud accounts)
- [ ] Authorization letter on file (signed by asset owner)
- [ ] Engagement configuration reviewed:
  - Execution mode: `safe` / `simulation` / `live`
  - Enabled phases (default: all 6)
  - Adversary profile selected
  - Phase/total timeouts configured
  - `pauseOnCritical` enabled for first engagement per customer
- [ ] Customer notified of engagement window
- [ ] Production environment health verified (`GET /healthz` returns 200)
- [ ] Database backup taken before first-ever engagement

## Starting an Engagement

### Via API

```bash
curl -X POST https://www.odinforgeai.com/api/breach-chains \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Customer Corp — Q1 Assessment",
    "assetIds": ["https://target.example.com"],
    "config": {
      "enabledPhases": [
        "application_compromise",
        "credential_extraction",
        "cloud_iam_escalation",
        "container_k8s_breakout",
        "lateral_movement",
        "impact_assessment"
      ],
      "executionMode": "live",
      "requireMinConfidence": 0.6,
      "requireCredentialForCloud": true,
      "requireCloudAccessForK8s": true,
      "phaseTimeoutMs": 600000,
      "totalTimeoutMs": 3600000,
      "pauseOnCritical": true
    }
  }'
```

### Via UI

1. Navigate to Breach Chains page
2. Click "New Breach Chain"
3. Enter target scope and configuration
4. Click "Start Engagement"

## During the Engagement

### Monitoring

- Watch WebSocket feed for `breach_chain_graph_update` events
- Check progress via `GET /api/breach-chains/:id`
- If `pauseOnCritical` is enabled, engagement will pause on CRITICAL findings
  - Review the finding before resuming
  - Resume via `POST /api/breach-chains/:id/resume`

### Expected Durations

| Environment | Expected Duration | Red Flag |
|-------------|------------------|----------|
| Full scope (web + cloud + network) | 5–15 minutes | Under 2 minutes |
| Web-only (phases 1-2) | 3–8 minutes | Under 1 minute |
| Cloud-only (phases 3-4) | 2–5 minutes | Under 30 seconds |

Engagements completing under 2 minutes trigger a `DURATION WARNING` in logs.

### Abort Procedure

If the engagement must be stopped immediately:
```bash
curl -X POST https://www.odinforgeai.com/api/breach-chains/:id/abort \
  -H "Authorization: Bearer <token>"
```

## Post-Engagement

### Review Outputs

1. **Evidence Quality**: `GET /api/breach-chains/:id/evidence-quality`
   - Verify pass rate (target: 80%+ PROVEN or CORROBORATED)
   - Review any INFERRED findings — flag for manual validation

2. **Detection Rules**: `GET /api/breach-chains/:id/detection-rules`
   - Deliver Sigma/YARA/Splunk rules to customer SOC
   - Verify MITRE ATT&CK tags are correct

3. **Reachability Chain**: `GET /api/breach-chains/:id/reachability`
   - Review hop-by-hop breakdown
   - Confirm all pivots are backed by real authentication evidence

4. **Replay Manifest**: `GET /api/breach-chains/:id/replay`
   - Available for customer training/tabletop exercises
   - Export: `GET /api/breach-chains/:id/replay/export?format=json`

### Generate Customer Report

```bash
# PDF-ready replay report
curl https://www.odinforgeai.com/api/breach-chains/:id/replay/export \
  -H "Authorization: Bearer <token>" \
  -o replay-report.md

# Full breach chain report
curl -X POST https://www.odinforgeai.com/api/reports \
  -H "Authorization: Bearer <token>" \
  -d '{ "type": "executive", "breachChainId": "<chain-id>" }'
```

### Delivery to Customer

- [ ] Executive summary reviewed for accuracy
- [ ] All INFERRED findings labeled as such in the report
- [ ] Detection rules packaged (Sigma YAML + YARA + Splunk SPL)
- [ ] Reachability chain graph included (DOT or D3 visualization)
- [ ] Evidence artifacts available for customer inspection
- [ ] Engagement replay available if customer requested

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Engagement stuck at 0% | Target unreachable or invalid | Check target URL resolves; verify not localhost |
| Phase 2 returns 0 credentials | Phase 1A found no exploitable vulns | Expected on hardened targets — report accurately |
| Phase 5 times out | Too many hosts in pivot queue | Reduce `maxLateralMovementDepth` in config |
| "Circuit open" errors | OpenAI rate limited | Wait for circuit breaker reset (60s); or use fallback |
| Engagement under 2 minutes | Simulated instead of real execution | Review phase evidence; check execution mode is `live` |
