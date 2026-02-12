# Adversary Simulation Enhancement Plan

> **Status:** Planning — Future Release
> **Priority:** Strategic Enhancement
> **Scope:** Go Agent Executor + Server Orchestration + Detection Validation
> **Prerequisites:** P0/P1 Agent Deployment (complete), stable SIEM integration

---

## Executive Summary

OdinForge currently validates exposures through AI-simulated attack/defense rounds and an active exploit engine targeting web application vectors. The Go agent collects telemetry and runs network probes but has no technique execution capability. This enhancement adds a full ATT&CK technique execution engine to the Go agent — covering EDR validation, Active Directory enumeration, credential harvesting, and stealth operations — turning OdinForge from a vulnerability validator into a complete adversarial exposure validation platform that rivals commercial BAS tools while staying within authorized AEV boundaries.

**Key differentiators over existing tools:**
- **vs BloodHound/SharpView:** Real-time AD enumeration with stealth controls (jitter, LDAP paging, encrypted channels) — not just graph queries
- **vs Shannon/Atomic Red Team:** AI-adaptive technique selection based on detection feedback, not static playbooks
- **vs MDSec/Cobalt Strike:** Legitimate AEV with approval gating, audit trails, and automatic rollback — not an offensive C2
- **vs CrowdStrike/SentinelOne validation:** Validates YOUR controls with YOUR techniques, correlates with YOUR SIEM data

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    SERVER (Orchestration)                     │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Technique     │  │ Stealth      │  │ Detection         │  │
│  │ Scheduler     │  │ Policy       │  │ Correlation       │  │
│  │ (ATT&CK map) │  │ Engine       │  │ Engine            │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘  │
│         │                  │                    │              │
│  ┌──────▼──────────────────▼────────────────────▼──────────┐  │
│  │              Campaign Orchestrator                       │  │
│  │  (sequences techniques, manages approval gates,          │  │
│  │   dispatches to agents, collects results)                │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         │ Commands via /api/agents/{id}/cmds  │
└─────────────────────────┼─────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    GO AGENT (Execution)                       │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Executor      │  │ Stealth      │  │ Evidence          │  │
│  │ Engine        │  │ Controller   │  │ Collector         │  │
│  │ (techniques)  │  │ (jitter,     │  │ (screenshots,     │  │
│  │               │  │  evasion)    │  │  artifacts)       │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘  │
│         │                  │                    │              │
│  ┌──────▼──────────────────▼────────────────────▼──────────┐  │
│  │              Technique Router                            │  │
│  │  (ATT&CK ID → handler, safety checks,                   │  │
│  │   cleanup registration, result reporting)                │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Go Agent Executor Engine

### 1.1 New Package: `internal/executor`

The executor package is the core runtime for ATT&CK technique execution on the agent.

**File structure:**
```
odinforge-agent/internal/executor/
├── executor.go          # TechniqueRouter, safety checks, cleanup registry
├── technique.go         # Technique interface, TechniqueResult, Evidence types
├── stealth.go           # StealthController (jitter, process hollowing avoidance)
├── cleanup.go           # CleanupRegistry (rollback on abort/failure)
├── evidence.go          # EvidenceCollector (screenshots, file hashes, memory dumps)
├── techniques/
│   ├── discovery/       # T1087, T1082, T1046, T1135, T1016, T1049, T1007
│   ├── credential/      # T1003, T1552, T1555, T1110, T1558
│   ├── lateral/         # T1021, T1550, T1047, T1569
│   ├── persistence/     # T1547, T1136, T1053, T1543
│   ├── evasion/         # T1070, T1036, T1562, T1027
│   ├── privesc/         # T1068, T1548, T1134, T1574
│   ├── collection/      # T1560, T1005, T1039, T1114
│   └── exfiltration/    # T1048, T1041, T1567
```

**Core interfaces:**

```go
// Technique is the interface every ATT&CK technique handler implements.
type Technique interface {
    // ID returns the MITRE ATT&CK technique ID (e.g., "T1087.001")
    ID() string

    // Name returns human-readable name
    Name() string

    // Tactics returns applicable ATT&CK tactics
    Tactics() []string

    // RequiredPrivilege returns minimum privilege level needed
    RequiredPrivilege() PrivilegeLevel

    // Platform returns supported platforms
    Platform() []Platform // windows, linux, darwin

    // Execute runs the technique with given parameters
    Execute(ctx context.Context, params TechniqueParams) TechniqueResult

    // Cleanup reverses any changes made during execution
    Cleanup(ctx context.Context) error

    // DetectionSurface returns what EDR/SIEM signatures this technique triggers
    DetectionSurface() []DetectionSignature
}

type TechniqueParams struct {
    Target       string            // target host/domain/path
    Credentials  []Credential      // available credentials from prior techniques
    StealthLevel StealthLevel      // ghost, quiet, normal, loud
    Timeout      time.Duration
    DryRun       bool              // validate without executing
    Custom       map[string]string // technique-specific parameters
}

type TechniqueResult struct {
    TechniqueID   string
    Success       bool
    Confidence    int // 0-100
    Evidence      []Evidence
    Artifacts     []Artifact        // files created, registry keys modified
    Credentials   []Credential      // harvested credentials
    Findings      []Finding         // discovered hosts, users, shares
    CleanupStatus CleanupStatus     // pending, completed, failed, not_needed
    DetectionRisk DetectionRiskScore
    Duration      time.Duration
    Error         string
}
```

### 1.2 Command Channel Extension

Add `execute_technique` command type to the existing command polling loop.

**In `cmd/agent/main.go`, extend the command switch:**

```go
case "execute_technique":
    result, cleanupFn = executeATTCKTechnique(ctx, cfg, payload, stealthCtrl)
    // Register cleanup for abort scenarios
    if cleanupFn != nil {
        cleanupRegistry.Register(cmd.ID, cleanupFn)
    }
case "abort_technique":
    // Trigger cleanup for a running or completed technique
    cleanupRegistry.Execute(payload["command_id"].(string))
case "campaign_step":
    // Execute a step within a multi-technique campaign
    result = executeCampaignStep(ctx, cfg, payload, stealthCtrl, evidenceCollector)
```

**Command payload structure:**

```json
{
  "command_type": "execute_technique",
  "payload": {
    "technique_id": "T1087.002",
    "campaign_id": "camp_abc123",
    "step_index": 2,
    "stealth_level": "quiet",
    "target": "dc01.corp.local",
    "timeout_seconds": 120,
    "dry_run": false,
    "credentials": [
      {"type": "password", "username": "svc_backup", "value": "...encrypted..."}
    ],
    "params": {
      "search_base": "DC=corp,DC=local",
      "search_scope": "subtree"
    }
  }
}
```

### 1.3 Safety Architecture

Every technique execution goes through a safety pipeline:

1. **Platform check** — technique supports current OS
2. **Privilege check** — current process has required privilege level
3. **Stealth validation** — technique compatible with requested stealth level
4. **DryRun gate** — if dry_run=true, return expected behavior without executing
5. **Cleanup registration** — register rollback before execution
6. **Execution timeout** — hard kill after timeout + cleanup trigger
7. **Evidence collection** — capture proof of execution for audit trail
8. **Cleanup execution** — automatic rollback unless explicitly retained

**Abort handling:** Server can send `abort_technique` at any time. The cleanup registry ensures all modifications are reversed within 30 seconds.

---

## Phase 2: ATT&CK Technique Library

### 2.1 Discovery Techniques (Priority: Highest)

These replace and exceed BloodHound/SharpView capabilities with stealth controls.

| Technique | MITRE ID | Description | Stealth Impact |
|-----------|----------|-------------|----------------|
| AD User Enumeration | T1087.002 | LDAP queries for all domain users, groups, memberships | Paged LDAP (500/page), jittered queries |
| AD Group Enumeration | T1069.002 | Enumerate privileged groups (Domain Admins, Enterprise Admins) | Single targeted query vs full dump |
| Domain Trust Discovery | T1482 | Map inter-domain and inter-forest trusts | Read-only LDAP, no NLTEST |
| Network Share Discovery | T1135 | Enumerate SMB shares on discovered hosts | Sequential not parallel, random order |
| System Info Discovery | T1082 | OS version, patch level, installed software | Local WMI/registry only |
| Network Service Scanning | T1046 | Port scan + service fingerprinting | SYN scan, randomized ports, jitter |
| Permission Groups | T1069.001 | Local group membership enumeration | WMI queries, not net localgroup |
| Remote System Discovery | T1018 | DNS/LDAP-based host discovery | DNS queries (low noise) vs ARP scan (high noise) |
| Account Discovery | T1087.001 | Local user enumeration | Registry reads vs net user |
| GPO Enumeration | T1615 | Group Policy Objects affecting security | LDAP read of GPO containers |
| SPN Discovery | T1558.003 | Kerberoastable service accounts | Standard TGS requests (blends with normal Kerberos traffic) |

**AD Enumeration Detail (T1087.002 + T1069.002 + T1482):**

```go
// ADEnumerator provides comprehensive Active Directory reconnaissance
// with configurable stealth levels.
type ADEnumerator struct {
    ldapConn   *ldap.Conn
    domain     string
    searchBase string
    stealth    StealthLevel
    pageSize   int // 500 for quiet, 1000 for normal, 5000 for loud
    jitter     JitterConfig
}

// EnumerateUsers returns all domain users with key attributes.
// At ghost level: queries only privileged accounts
// At quiet level: paged LDAP with 2-5s jitter between pages
// At normal level: full enumeration with 100ms jitter
// At loud level: parallel queries, no jitter
func (e *ADEnumerator) EnumerateUsers(ctx context.Context) ([]ADUser, error)

// EnumeratePrivilegedPaths finds attack paths to Domain Admin.
// Analyzes: group nesting, delegation rights, ACL abuse paths,
// unconstrained delegation, AS-REP roastable accounts.
func (e *ADEnumerator) EnumeratePrivilegedPaths(ctx context.Context) ([]AttackPath, error)

// MapTrusts discovers domain and forest trust relationships.
func (e *ADEnumerator) MapTrusts(ctx context.Context) ([]DomainTrust, error)
```

**Key advantage over BloodHound:** Real-time execution with configurable stealth vs. static ingest-and-graph. OdinForge can enumerate ONLY the paths relevant to the current campaign target instead of dumping the entire directory.

### 2.2 Credential Access Techniques

| Technique | MITRE ID | Description | Platform |
|-----------|----------|-------------|----------|
| LSASS Memory Dump | T1003.001 | Extract credentials from LSASS process memory | Windows |
| SAM Database | T1003.002 | Extract local password hashes from SAM | Windows |
| NTDS.dit Extraction | T1003.003 | Domain controller AD database extraction | Windows (DC) |
| LSA Secrets | T1003.004 | Extract cached domain credentials | Windows |
| DCSync | T1003.006 | Replicate AD password data via DRSUAPI | Windows |
| Kerberoasting | T1558.003 | Request TGS tickets for offline cracking | Windows |
| AS-REP Roasting | T1558.004 | Request AS-REP for accounts without pre-auth | Windows |
| Credential Files | T1552.001 | Search filesystem for credential files | All |
| Browser Credentials | T1555.003 | Extract saved browser passwords/cookies | All |
| SSH Key Discovery | T1552.004 | Find private SSH keys | Linux/macOS |

**LSASS Dump Implementation Strategy (T1003.001):**

Multiple methods ranked by stealth:

1. **Ghost:** `MiniDumpWriteDump` via direct syscall (no API hooking visible to EDR)
2. **Quiet:** In-memory minidump using `NtReadVirtualMemory` (no file written to disk)
3. **Normal:** `procdump.exe` (legitimate Microsoft tool, commonly whitelisted)
4. **Loud:** `comsvcs.dll` MiniDump via `rundll32` (detectable but reliable)

The agent selects method based on stealth level and detects which approach works on the target system. Evidence collected includes hash count and types (NTLM, Kerberos TGT) without storing actual credential material on disk.

### 2.3 Defense Evasion Techniques

| Technique | MITRE ID | Description | Purpose |
|-----------|----------|-------------|---------|
| Indicator Removal | T1070.001 | Clear specific event log entries | Remove technique execution traces |
| Timestomp | T1070.006 | Modify file timestamps | Hide dropped files |
| Masquerading | T1036.005 | Rename process/file to look legitimate | Evade process-name-based detection |
| Disable Security Tools | T1562.001 | Attempt to disable AV/EDR (validation only) | Validate EDR tamper protection |
| Process Injection | T1055.012 | Inject into legitimate process | Evade process-based allowlisting |
| AMSI Bypass | T1562.001 | Test AMSI bypass techniques | Validate AMSI enforcement |

**EDR Validation Model:**

The evasion techniques are specifically designed to TEST defensive controls, not bypass them for offensive purposes:

```go
type EDRValidationResult struct {
    EDRProduct      string   // Detected EDR product name
    Version         string   // EDR version
    TamperProtected bool     // Could we disable it?
    HooksBypass     bool     // Could we unhook user-mode hooks?
    AMSIEnforced    bool     // Is AMSI active and blocking?
    ETWBlindSpots   []string // Event sources we could suppress
    DetectionDelay  time.Duration // How long before EDR alerted
    AlertGenerated  bool     // Did EDR generate an alert?
    AlertSeverity   string   // What severity was assigned?
    Techniques      []TechniqueValidation // Per-technique detection results
}
```

Each evasion technique runs, then the system checks via SIEM integration whether the EDR detected it, how long detection took, and what alert was generated. This creates a defensive control validation report.

### 2.4 Privilege Escalation Techniques

| Technique | MITRE ID | Description | Platform |
|-----------|----------|-------------|----------|
| Exploitation for Privesc | T1068 | Known CVE exploitation for local privesc | All |
| Sudo Abuse | T1548.003 | Misconfigured sudo rules | Linux/macOS |
| SUID/SGID Abuse | T1548.001 | Exploitable SUID binaries | Linux |
| Token Manipulation | T1134.001 | Impersonate privileged token | Windows |
| DLL Hijacking | T1574.001 | Plant DLL in search path | Windows |
| Unquoted Service Path | T1574.009 | Exploit unquoted Windows service paths | Windows |
| Scheduled Task Abuse | T1053.005 | Create/modify scheduled tasks | Windows |
| Cron Job Abuse | T1053.003 | Writable cron scripts | Linux |

### 2.5 Lateral Movement Techniques

Extends the existing server-side lateral movement service with agent-side execution.

| Technique | MITRE ID | Description |
|-----------|----------|-------------|
| Remote Services (SSH) | T1021.004 | SSH with discovered credentials |
| Remote Services (RDP) | T1021.001 | RDP with discovered credentials |
| Remote Services (SMB) | T1021.002 | SMB with discovered credentials |
| Pass the Hash | T1550.002 | NTLM hash authentication |
| Pass the Ticket | T1550.003 | Kerberos ticket replay |
| WMI Execution | T1047 | Remote command execution via WMI |
| PsExec-style | T1569.002 | Remote service creation + execution |
| SSH Hijacking | T1563.001 | Hijack existing SSH sessions |

---

## Phase 3: Stealth Controller

### 3.1 Stealth Levels

Four levels with progressively more noise:

| Level | Jitter | Concurrency | Techniques Available | Network Signature | Detection Risk |
|-------|--------|-------------|---------------------|-------------------|----------------|
| **Ghost** | 5-30s between actions | 1 at a time | Discovery + credential files only | Mimics normal user traffic | Minimal |
| **Quiet** | 2-5s between actions | 2 concurrent | All discovery + credential access | Low-volume, spaced queries | Low |
| **Normal** | 100-500ms | 5 concurrent | All techniques | Standard scanning patterns | Medium |
| **Loud** | None | 10 concurrent | All techniques | High-volume, rapid execution | High |

### 3.2 Stealth Mechanisms

```go
type StealthController struct {
    level         StealthLevel
    jitter        JitterConfig
    processName   string        // masquerade as this process
    parentPID     int           // PPID spoofing target
    networkMask   NetworkMask   // traffic shaping config
    timeWindow    TimeWindow    // only execute during business hours
}

// ApplyJitter sleeps for a randomized duration based on stealth level.
// Uses crypto/rand for unpredictable timing.
func (s *StealthController) ApplyJitter(ctx context.Context) error

// ShouldExecute checks if current time is within allowed execution window
// and if the technique is compatible with the current stealth level.
func (s *StealthController) ShouldExecute(t Technique) (bool, string)

// WrapProcess applies process-level stealth (masquerading, PPID spoofing)
// before technique execution. Cleaned up automatically.
func (s *StealthController) WrapProcess(ctx context.Context) (cleanup func(), err error)
```

### 3.3 Anti-Detection Patterns

- **LDAP query spacing:** At ghost level, AD queries are spaced 5-30s apart with page sizes of 100 to mimic admin tooling
- **DNS resolution:** Resolve targets via DNS before port scanning (matches normal application behavior)
- **Process lineage:** Executor runs under a legitimate parent process to avoid anomalous process tree alerts
- **Network timing:** TCP connections use realistic timing (SYN → data → FIN, not instant bursts)
- **Log correlation avoidance:** At ghost/quiet levels, techniques that generate Windows Event Log entries are rate-limited to avoid volume-based SIEM rules
- **Memory-only execution:** At ghost level, no files are written to disk — all technique output stays in memory and is reported via the command channel

---

## Phase 4: Server-Side Campaign Orchestrator

### 4.1 Campaign Model

A campaign is an ordered sequence of ATT&CK techniques that models a realistic adversary operation.

```typescript
interface Campaign {
  id: string;
  name: string;
  organizationId: string;
  adversaryProfile: AdversaryProfile; // APT29, FIN7, custom, etc.
  objective: CampaignObjective;       // data_exfiltration, ransomware, espionage
  stealthLevel: StealthLevel;
  executionMode: ExecutionMode;       // safe, simulation, live
  approvalStatus: ApprovalStatus;
  phases: CampaignPhase[];
  agentIds: string[];                 // which agents participate
  detectionCorrelation: boolean;      // auto-check SIEM after each step
  maxDuration: number;                // campaign timeout (minutes)
  abortConditions: AbortCondition[];  // auto-abort triggers
}

interface CampaignPhase {
  name: string;                       // "Initial Access", "Credential Harvesting"
  techniques: CampaignTechnique[];
  gateCondition: GateCondition;       // what must succeed before next phase
  rollbackOnFailure: boolean;
}

interface CampaignTechnique {
  techniqueId: string;                // "T1087.002"
  agentId: string;                    // which agent executes this
  target: string;
  params: Record<string, string>;
  dependsOn: string[];                // technique IDs that must complete first
  requiredConfidence: number;         // min confidence from dependencies
  stealthOverride?: StealthLevel;     // override campaign default for this step
}
```

### 4.2 Adversary Profiles

Pre-built technique sequences modeled after real threat actors:

| Profile | Kill Chain Focus | Key Techniques | Stealth Default |
|---------|-----------------|----------------|-----------------|
| **APT29 (Cozy Bear)** | Long-term espionage | Spearphishing → token theft → cloud persistence → data staging | Ghost |
| **APT28 (Fancy Bear)** | Credential theft + lateral | Credential phishing → pass-the-hash → DC compromise → exfil | Quiet |
| **FIN7** | Financial data theft | Web exploit → privesc → lateral movement → POS malware | Quiet |
| **Ransomware Operator** | Rapid domain compromise | RDP brute → AD enum → GPO abuse → mass encryption | Loud |
| **Insider Threat** | Data exfiltration | No initial access needed → discovery → collection → exfil | Ghost |
| **Custom** | User-defined | Select techniques from library | User-defined |

### 4.3 AI-Adaptive Technique Selection

The server-side AI can dynamically modify campaign execution based on results:

```typescript
interface AdaptiveDecision {
  // After each technique completes, AI evaluates:
  observedDefenses: string[];         // what security controls were detected
  detectionStatus: DetectionStatus;   // was the technique detected by SIEM?
  alternativeTechniques: string[];    // AI-suggested alternatives if detected
  recommendedStealthAdjustment: StealthLevel;
  shouldContinue: boolean;
  reasoning: string;
}
```

**Decision flow:**
1. Technique executes on agent → result reported to server
2. Server queries SIEM for detection alerts (existing SIEM integration)
3. AI evaluates: was the technique detected? How quickly?
4. If detected AND stealth is important: AI suggests alternative technique or stealth upgrade
5. If not detected: AI continues with next planned technique
6. Campaign report shows detection gaps — which techniques evaded controls

This is the core differentiator vs. static BAS tools: **the campaign adapts to the target environment's defenses in real time.**

---

## Phase 5: Detection Correlation & Reporting

### 5.1 Per-Technique Detection Validation

After each technique executes, the existing SIEM integration queries for matching alerts:

```typescript
interface TechniqueDetectionResult {
  techniqueId: string;              // "T1087.002"
  techniqueName: string;           // "Domain Account Discovery"
  executed: boolean;
  executionTimestamp: Date;
  detected: boolean;
  detectionTimestamp?: Date;
  mttdSeconds?: number;            // time to detect
  alertDetails: {
    siem: string;                  // "elastic", "splunk", "sentinel"
    ruleId: string;
    ruleName: string;
    severity: string;
    rawAlert: object;
  }[];
  edrDetected: boolean;            // agent-side EDR detection check
  edrProduct?: string;
  edrAlertSeverity?: string;
  controlsValidated: string[];     // which security controls responded
  gaps: string[];                  // expected controls that didn't fire
}
```

### 5.2 Campaign Report

```typescript
interface CampaignReport {
  campaign: Campaign;
  executionSummary: {
    totalTechniques: number;
    executed: number;
    succeeded: number;
    detected: number;
    detectionRate: number;          // succeeded-and-detected / executed
    averageMTTD: number;            // seconds
    killChainDepth: number;         // how far the attack progressed (1-14)
    objectiveAchieved: boolean;
  };
  detectionGaps: DetectionGap[];    // techniques that succeeded undetected
  controlEffectiveness: {
    edr: { tested: number; detected: number; rate: number };
    siem: { tested: number; detected: number; rate: number };
    network: { tested: number; detected: number; rate: number };
    identity: { tested: number; detected: number; rate: number };
  };
  recommendations: Recommendation[];
  attackGraph: AttackGraph;          // visual kill chain with detection overlay
  complianceMapping: ComplianceMapping; // NIST, CIS, MITRE coverage
}
```

### 5.3 Detection Gap Analysis

When a technique succeeds but is NOT detected, the system generates actionable remediation:

```typescript
interface DetectionGap {
  techniqueId: string;
  techniqueName: string;
  attackPhase: string;
  expectedDetectionSource: string;  // "EDR process monitoring", "SIEM auth logs"
  recommendation: string;           // "Enable Sysmon EventID 10 for LSASS access"
  siemRuleTemplate?: string;        // Ready-to-import SIEM detection rule
  priority: "critical" | "high" | "medium" | "low";
  references: string[];             // MITRE, vendor documentation links
}
```

---

## Phase 6: UI Integration

### 6.1 Campaign Builder Page

New page at `/campaigns` with:

- **Campaign wizard:** Select adversary profile → customize techniques → set stealth → assign agents → request approval
- **Technique library browser:** Filterable by ATT&CK tactic, platform, stealth compatibility, required privilege
- **Campaign timeline:** Real-time view of executing campaign with technique status, detection indicators
- **Live agent feed:** Stream technique results as they complete

### 6.2 Detection Dashboard Enhancements

Extend existing risk dashboard with:

- **Control validation heatmap:** ATT&CK matrix colored by detection rate (red=0%, yellow=50%, green=100%)
- **MTTD trending:** Per-technique detection time over multiple campaign runs
- **EDR scorecard:** Per-EDR-product detection rates across all tested techniques
- **Gap priority queue:** Ordered list of undetected techniques with remediation guidance

### 6.3 Campaign Reports Page

- Executive PDF export with detection coverage summary
- Technical detail export with full technique logs and evidence
- Compliance mapping (NIST CSF, CIS Controls, MITRE D3FEND)
- Trend comparison: campaign N vs campaign N-1

---

## Implementation Order

### Sprint 1: Agent Executor Foundation
1. Create `internal/executor/` package with `Technique` interface, `TechniqueRouter`, `SafetyPipeline`
2. Add `execute_technique` and `abort_technique` command types to `main.go`
3. Implement `StealthController` with jitter and stealth level enforcement
4. Implement `CleanupRegistry` for automatic rollback
5. Implement `EvidenceCollector` for proof-of-execution capture

### Sprint 2: Discovery Techniques
1. Implement T1087.002 (AD User Enumeration) with full stealth levels
2. Implement T1069.002 (AD Group Enumeration)
3. Implement T1482 (Domain Trust Discovery)
4. Implement T1135 (Network Share Discovery)
5. Implement T1046 (Network Service Scanning) — extend existing port scanner
6. Implement T1082 (System Info Discovery) — extend existing collector
7. Wire discovery techniques to server-side technique scheduler

### Sprint 3: Credential Access
1. Implement T1003.001 (LSASS Dump) with multi-method stealth selection
2. Implement T1558.003 (Kerberoasting)
3. Implement T1558.004 (AS-REP Roasting)
4. Implement T1552.001 (Credential Files) and T1552.004 (SSH Keys)
5. Implement credential passing between techniques (output → input chain)

### Sprint 4: Evasion & Privesc
1. Implement T1562.001 (Disable Security Tools — validation mode)
2. Implement T1055.012 (Process Injection)
3. Implement T1548.003 (Sudo Abuse) and T1548.001 (SUID Abuse)
4. Implement T1134.001 (Token Manipulation)
5. EDR validation reporting (detect → report → correlate)

### Sprint 5: Campaign Orchestrator
1. Build server-side `CampaignOrchestrator` service
2. Implement adversary profiles (APT29, APT28, FIN7, Ransomware, Insider)
3. Integrate AI-adaptive technique selection with existing AI simulation
4. Wire SIEM detection correlation after each technique
5. Build campaign report generation

### Sprint 6: UI & Reports
1. Campaign builder page with technique library browser
2. Campaign execution timeline (real-time)
3. Detection heatmap (ATT&CK matrix overlay)
4. Campaign report PDF export
5. EDR scorecard dashboard

---

## Security & Compliance Guardrails

### Execution Mode Gating

All adversary simulation techniques are subject to the existing execution mode system:

| Technique Category | Safe Mode | Simulation Mode | Live Mode |
|-------------------|-----------|-----------------|-----------|
| Discovery (AD enum, port scan) | Read-only queries | Full enumeration | Full enumeration |
| Credential Access | File search only | Memory dump (no exfil) | Full extraction |
| Defense Evasion | Dry-run validation | Non-destructive tests | Full evasion attempts |
| Privilege Escalation | Misconfiguration detection | Exploit validation | Full exploitation |
| Lateral Movement | Credential validation | Single hop | Multi-hop chains |
| Collection/Exfil | List target files | Sample extraction | Full data staging |

### Approval Requirements

| Campaign Type | Required Approval |
|--------------|-------------------|
| Discovery-only (safe mode) | Manager |
| Credential access (simulation) | Security Lead |
| Full kill chain (simulation) | CISO |
| Any technique (live mode) | CISO + Legal |
| Custom campaign | Matches highest-risk technique |

### Audit Trail

Every technique execution is logged with:
- Technique ID, parameters, stealth level
- Start/end timestamps
- Full evidence package (sanitized — no raw credentials stored)
- Cleanup status and verification
- Detection correlation results
- Approving user and approval timestamp
- Campaign context (which campaign, which phase)

### Credential Handling

- Harvested credentials are hashed before storage (prove extraction capability without storing plaintext)
- Raw credential material is held in agent memory only during campaign execution
- Credentials are zeroed from memory after campaign completes or aborts
- Evidence shows "extracted N NTLM hashes from LSASS" not the actual hashes
- Credential files discovered are logged by path and type, not content

---

## Integration Points with Existing Systems

### Existing System → Enhancement

| Existing Component | Integration |
|-------------------|-------------|
| **Command Channel** (sender.go) | Add `execute_technique`, `abort_technique`, `campaign_step` command types |
| **Prober** (prober.go) | Discovery techniques extend probing with AD-specific protocols |
| **Collector** (collector.go) | EDR detection results feed into telemetry stream |
| **AI Simulation** (ai-simulation.ts) | Campaign AI uses simulation results to adapt technique selection |
| **Breach Chains** (breach-orchestrator.ts) | Campaigns are the agent-executed counterpart to server-simulated breach chains |
| **Kill Chain Graph** (kill-chain-graph.ts) | Campaign results map directly to kill chain visualization |
| **SIEM Integration** (siem-integration/) | Post-technique detection queries (already built) |
| **Execution Modes** (execution-modes.ts) | Campaign techniques gated by mode (already built) |
| **Metrics Calculator** (metrics-calculator.ts) | Campaign detection rates feed into defensive posture scoring |
| **Playbook System** (playbooks/) | Campaigns extend playbooks with agent-side execution |
| **Lateral Movement** (lateral-movement-service.ts) | Agent-side lateral techniques replace server-side simulation |

### No Changes Required

- `shared/schema.ts` — campaign tables will be added but existing tables unchanged
- `server/storage.ts` — new CRUD methods for campaigns, no existing method changes
- `server/services/ui-auth.ts` — new permissions added to existing permission system
- Existing agent deployment, registration, and update flows are unaffected

---

## New Dependencies

### Go Agent
- `github.com/go-ldap/ldap/v3` — LDAP client for AD enumeration
- `golang.org/x/sys/windows` — Windows syscalls for credential access
- `github.com/hirochachacha/go-smb2` — SMB2/3 client for share enumeration and lateral movement
- No other new dependencies — SSH is already available via stdlib

### Server (Node.js)
- No new npm dependencies — campaign orchestration uses existing infrastructure

---

## Success Metrics

| Metric | Target |
|--------|--------|
| ATT&CK technique coverage | 40+ techniques across 10+ tactics |
| Detection correlation accuracy | >95% (technique → SIEM alert matching) |
| Campaign execution reliability | >99% completion rate (no orphaned state) |
| Cleanup success rate | 100% (all modifications reversed) |
| MTTD measurement accuracy | <5s variance from actual detection time |
| Stealth level effectiveness | Ghost level undetected by default EDR rules |
| Campaign report generation | <30s for full report with detection analysis |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Agent crash during technique execution | Cleanup registry persisted to BoltDB; on restart, pending cleanups execute first |
| Network partition during campaign | Agent queues results locally; resumes reporting on reconnect |
| EDR kills agent process | Agent self-update can redeploy; cleanup commands sent to fallback agent |
| Credential material exposure | Memory-only handling, zeroed after campaign, evidence uses hashes only |
| Unauthorized campaign execution | Multi-level approval gating, execution mode enforcement, audit trail |
| Technique causes system instability | Dry-run mode validates before execution; timeout + cleanup on any failure |
| Regulatory/legal concerns | BSL license restricts unauthorized use; campaigns require explicit approval chain |
