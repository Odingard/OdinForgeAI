# Task 06 — Cloud Security & Endpoint Agents

Production-grade cloud scanning and endpoint security checks for OdinForge.
All findings normalize to the same schema as existing AEV findings and write to the entity graph.

---

## Architecture

```
CloudScanner (abstract base)
├── AwsScanner   — 24 checks (IAM, S3, EC2, CloudTrail, GuardDuty)
├── AzureScanner — 17 checks (Storage, NSG, Key Vault, RBAC, Monitor)
├── GcpScanner   — 12 checks (IAM, Storage, Firewall, Audit Logging)
└── K8sScanner   — 14 checks (RBAC, Workloads, NetworkPolicy, Secrets)

EndpointAgent (abstract base)
├── LinuxAgent   — 11 checks (SSH, SUID, cron, auditd, firewall)
├── MacOsAgent   — 11 checks (SIP, Gatekeeper, FileVault, sharing)
└── WindowsAgent — 11 checks (Defender, UAC, BitLocker, SMBv1, RDP)
```

**Total: 100 security checks** across 7 targets.

---

## Files

### Cloud Scanners
| File | Purpose |
|------|---------|
| `server/services/cloud/base/CloudScanner.ts` | Abstract base: retry w/ backoff, normalization, error isolation |
| `server/services/cloud/AwsScanner.ts` | AWS security checks |
| `server/services/cloud/AzureScanner.ts` | Azure security checks |
| `server/services/cloud/GcpScanner.ts` | GCP security checks |
| `server/services/cloud/K8sScanner.ts` | Kubernetes security checks |
| `server/services/cloud/cloudScanOrchestrator.ts` | Factory, BullMQ handler, queue helper |

### Endpoint Agents
| File | Purpose |
|------|---------|
| `server/services/endpoint/EndpointAgent.ts` | Abstract base: check isolation, command exec |
| `server/services/endpoint/LinuxAgent.ts` | Linux endpoint security checks |
| `server/services/endpoint/MacOsAgent.ts` | macOS endpoint security checks |
| `server/services/endpoint/WindowsAgent.ts` | Windows endpoint security checks |
| `server/services/endpoint/endpointAgentOrchestrator.ts` | Factory, BullMQ handler, HTTP reporter, CLI |

### Queue Integration
| File | Change |
|------|--------|
| `server/services/queue/job-types.ts` | Added `cloud_scan`, `endpoint_scan` job types + schemas |
| `server/services/queue/handlers/cloud-scan-handler.ts` | BullMQ handler for cloud scans |
| `server/services/queue/handlers/endpoint-scan-handler.ts` | BullMQ handler for endpoint scans |
| `server/services/queue/handlers/index.ts` | Registered both handlers (17 total) |

### Entity Graph
| File | Change |
|------|--------|
| `server/services/entityGraph/entityGraphWriter.ts` | Added `writeFinding()` method for scanners |

---

## Dependencies Added

```bash
@aws-sdk/client-cloudtrail  @aws-sdk/client-guardduty
@azure/arm-storage  @azure/arm-network  @azure/arm-keyvault  @azure/arm-monitor
googleapis
@kubernetes/client-node
```

(Existing: `@aws-sdk/client-iam`, `@aws-sdk/client-s3`, `@aws-sdk/client-ec2`, `@azure/identity`, `@azure/arm-subscriptions`, `@azure/arm-authorization`)

---

## Check Coverage

### AWS (24 checks)
- Root account MFA + access keys
- IAM password policy strength
- IAM users: access key age (>90d), console access without MFA
- S3: public access block, bucket encryption, versioning
- EC2 security groups: wide-open inbound (0.0.0.0/0) by region
- CloudTrail: multi-region logging
- GuardDuty: enabled in region

### Azure (17 checks)
- Storage: public blob access, HTTPS-only, TLS 1.2 minimum
- NSG: unrestricted inbound rules across all resource groups
- Key Vault: soft delete, purge protection, network access
- RBAC: Owner role assignment count
- Monitor: activity log alert configuration

### GCP (12 checks)
- Service account key age (>90d)
- Primitive roles (Owner/Editor) with external members
- GCS: public IAM bindings, Uniform Bucket-Level Access
- Firewall: 0.0.0.0/0 ingress on high-risk ports
- Data access audit logging (DATA_READ + DATA_WRITE)

### Kubernetes (14 checks)
- ClusterRoleBindings granting cluster-admin to non-system subjects
- ClusterRoles with wildcard permissions
- Workloads: hostPID, hostNetwork, privileged containers, runAsRoot
- Namespaces without NetworkPolicy
- Secrets hardcoded as env vars
- Default namespace usage

### Linux (11 checks)
- Empty/missing passwords, extra UID 0 accounts
- SSH: PermitRootLogin, PasswordAuthentication
- Sudoers NOPASSWD entries
- Unexpected SUID binaries
- World-writable files in system dirs
- High-risk services on 0.0.0.0
- Suspicious cron jobs
- auditd, host firewall, pending updates

### macOS (11 checks)
- SIP, Gatekeeper, FileVault
- Firewall + stealth mode
- Guest user, Remote Login, Screen Sharing
- Screen lock delay, startup items
- Software updates, file sharing

### Windows (11 checks)
- Defender: enabled, real-time, signature age
- UAC: enabled, consent behavior
- BitLocker, SMBv1, RDP+NLA
- Firewall profiles, guest account
- Local admin count, scheduled tasks
- Windows Updates, PowerShell logging

---

## Standalone Endpoint Agent

```bash
# Run on target endpoint
ODINFORGE_URL=https://app.odinforge.com \
AGENT_TOKEN=agt_xxx \
ORGANIZATION_ID=org_xxx \
EVALUATION_ID=eval_xxx \
node dist/endpointAgentOrchestrator.js
```

Agent auto-detects OS, runs all checks, posts results back to OdinForge.
