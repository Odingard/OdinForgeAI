# Governance & Safety Controls

OdinForge AI includes comprehensive governance controls to ensure safe and authorized security testing.

## Overview

Governance controls prevent unauthorized or unsafe operations:

| Control | Purpose |
|---------|---------|
| Kill Switch | Emergency halt all operations |
| Execution Mode | Control testing intensity |
| Scope Rules | Define allowed targets |
| Audit Logging | Track all operations |

All security operations validate governance before execution.

## Kill Switch

### What It Does

The kill switch immediately halts all security operations:
- Stops running evaluations
- Cancels pending scans
- Halts agent deployments
- Blocks new operations

### When to Use

- Security incident during testing
- Unexpected behavior observed
- Emergency maintenance required
- Compliance requirement

### How to Use

1. Go to **Governance** in sidebar
2. Click **Activate Kill Switch**
3. Confirm activation
4. All operations stop immediately

### Deactivating

1. Go to **Governance**
2. Click **Deactivate Kill Switch**
3. Provide reason for deactivation
4. Operations resume

## Execution Modes

### Available Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Safe** | Read-only reconnaissance, no active testing | Initial setup, passive monitoring |
| **Simulate** | Simulated attacks, no real payloads | Training, demonstrations |
| **Live** | Full active testing with real payloads | Production security testing |

### Mode Behaviors

**Safe Mode:**
- Port scanning allowed
- No vulnerability testing
- No exploit validation
- No agent deployment actions

**Simulate Mode:**
- All reconnaissance allowed
- Vulnerability detection allowed
- No actual exploitation
- Simulated payloads only

**Live Mode:**
- Full reconnaissance
- Active vulnerability testing
- Real exploit validation payloads
- Full agent deployment capabilities

### Changing Modes

1. Go to **Governance**
2. Select desired **Execution Mode**
3. Save changes
4. Mode applies to all new operations

## Scope Rules

### Rule Types

| Type | Description | Example |
|------|-------------|---------|
| **IP Address** | Single IP allow/block | `192.168.1.100` |
| **CIDR Range** | Network range | `10.0.0.0/8` |
| **Hostname** | DNS name pattern | `*.example.com` |
| **Regex** | Regular expression | `prod-.*\.internal` |

### Creating Rules

1. Go to **Governance**
2. Click **Add Scope Rule**
3. Configure:
   - Rule type (IP, CIDR, Hostname, Regex)
   - Action (Allow or Block)
   - Pattern value
   - Description
4. Save rule

### Rule Priority

Rules evaluated in order:
1. Block rules checked first
2. Allow rules checked second
3. Default action if no match (configurable)

### Examples

**Allow only production subnet:**
```
Type: CIDR
Action: Allow
Value: 10.10.0.0/16
```

**Block critical infrastructure:**
```
Type: Hostname
Action: Block
Value: *.critical.internal
```

**Allow specific web apps:**
```
Type: Regex
Action: Allow
Value: https://app[0-9]+\.example\.com.*
```

## Audit Logging

### What's Logged

Every operation records:
- Timestamp
- User/system initiating action
- Target of operation
- Action attempted
- Result (allowed/blocked)
- Governance reason if blocked

### Viewing Logs

1. Go to **Governance**
2. Select **Audit Logs** tab
3. Filter by:
   - Date range
   - User
   - Action type
   - Status (allowed/blocked)

### Log Retention

- Logs retained for 90 days (default)
- Configurable retention period
- Export for long-term storage

## Rate Limiting

### Limits

| Operation | Default Limit |
|-----------|---------------|
| Evaluations per hour | 100 |
| Scans per hour | 50 |
| API requests per minute | 1000 |
| WebSocket connections | 100 |

### Per-Organization

Limits apply per organization:
- Each org has independent quotas
- Limits configurable per tenant
- Warnings at 80% utilization

## Best Practices

### Before Testing

1. **Set appropriate mode** - Start with Safe, progress to Live
2. **Define scope rules** - Allow only authorized targets
3. **Document authorization** - Record testing approval
4. **Notify stakeholders** - Inform operations teams

### During Testing

1. **Monitor governance logs** - Watch for blocked operations
2. **Keep kill switch accessible** - Know how to stop quickly
3. **Review scope violations** - Investigate blocked operations
4. **Track rate limits** - Avoid hitting quotas

### After Testing

1. **Review audit logs** - Document all activities
2. **Export logs** - Archive for compliance
3. **Update scope rules** - Refine based on experience
4. **Reset mode if needed** - Return to Safe if appropriate

## Compliance Integration

### Reporting

- Governance settings included in compliance reports
- Audit logs exportable for auditors
- Scope rules documented automatically

### Evidence

For each security test:
- Authorization verification recorded
- Scope validation logged
- Execution mode documented
- All operations traceable

## Troubleshooting

### Operation Blocked

If operations are blocked:
1. Check current execution mode
2. Verify target is in allowed scope
3. Review kill switch status
4. Check rate limits

### Cannot Change Settings

If settings won't update:
1. Verify admin permissions
2. Check for active operations
3. Review error messages
4. Contact administrator

### Audit Logs Missing

If logs seem incomplete:
1. Check date range filter
2. Verify log retention settings
3. Check user filter
4. Export and search externally
