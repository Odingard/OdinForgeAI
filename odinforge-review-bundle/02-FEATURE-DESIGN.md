# OdinForge-AI — Feature Design (2026-03-22)

## Core Subsystems

### 1. 6-Phase Breach Chain Engine
**File**: `server/services/breach-orchestrator.ts`

Executes a full adversarial assessment in 6 phases:
1. **Application Compromise** — Initial vulnerability confirmation via active exploit engine
2. **Credential Extraction** — Regex + JWT token extraction from Phase 1 evidence, probes common leakage paths (/.env, /.git/config, /actuator/env, etc.)
3. **Cloud IAM Escalation** — AWS credential analysis via pentest service, privilege escalation path testing
4. **Container/K8s Breakout** — K8s API abuse vectors, RBAC escalation, secret exposure
5. **Lateral Movement** — Adjacent service probing on common ports (8080, 8443, 3000, 5000, etc.)
6. **Impact Assessment** — Synthesis phase, requires ≥2 confirmed phases for cross-domain narrative

**State machine**: Phase 1 → Phase 2 (sequential), Phases 3-5 (concurrent), Phase 6 (synthesis gate).

### 2. Agent Mesh v1 (TCG-Orchestrated)
**Path**: `server/services/aev/`

4 specialized agents coordinated via Task Coordination Graph (DAG):
- **ReconAgent** — Subdomain discovery, port scanning, tech detection. No dependencies.
- **ScanAgent** — Up to 300 concurrent micro-agents. Waits for `target.discovered`.
- **ExploitAgent** — Full 6-phase breach chain. Waits for `vuln.confirmed`.
- **ReportAgent** — Continuous listener, writes engagement package as events arrive.

**AgentEventBus**: Evidence-gated pub/sub. Events like `vuln.confirmed`, `breach.confirmed`, `credential.extracted` require sealed RealHttpEvidence. Bus rejects unsigned findings.

**Dynamic adaptation**: New subdomain discovered → TCG creates new SCAN + EXPLOIT nodes at runtime.

### 3. Exploit Agent
**File**: `server/services/agents/exploit.ts` (800+ lines)

- 12-turn agentic loop with payload generation & validation
- 40+ HTTP/protocol exploit tools (`exploit-tools.ts`, 3,800+ lines)
- 9 payload categories: SQLi, XSS, SSRF, command injection, path traversal, auth bypass, IDOR, JWT abuse, API abuse
- 6 JWT attack techniques: none-algorithm, weak secret brute force, expired token acceptance, claim injection, KID injection, token analysis

### 4. Evidence System (ADR-001)
**Files**: `server/lib/real-finding.ts`, `server/lib/real-evidence.ts`, `server/services/evidence-quality-gate.ts`

- `RealFinding.fromHttpEvidence()` — requires real evidence array, throws if empty
- `RealHttpEvidence` — statusCode > 0, non-empty body, source = "real_http_response"
- Evidence Quality Gate classifies:
  - **PROVEN** — Real HTTP response or real protocol auth success → passes to customer
  - **CORROBORATED** — Real attempt with failure or active exploit engine evidence → passes to customer
  - **INFERRED** — LLM reasoning only → suppressed from customer output
  - **UNVERIFIABLE** — Insufficient evidence → suppressed from customer output
- Report Integrity Filter strips INFERRED/UNVERIFIABLE before customer delivery

### 5. Scoring v3.0 (Deterministic)
**File**: `server/services/agents/scoring-engine.ts`

```
exploitabilityScore = EPSS(45%) + CVSS(35%) + Agent(20%) + criticalCount*5 + highCount*2
```
- KEV override: floor at 85
- Ransomware amplifier: +10
- Risk ranks: info → low → medium → high → critical → emergency
- Business impact: priority multiplier × asset criticality multiplier

### 6. Engagement Package (ADR-005)
**Path**: `server/services/engagement/`

5 mandatory sealed deliverables per engagement:
1. **CISO PDF** — Risk grade A-F, breach narrative, business impact, compliance
2. **Engineer PDF** — Chain trace, HTTP evidence, 12 remediation templates, repro CURL commands
3. **Evidence JSON** — All PROVEN/CORROBORATED findings with audit summary
4. **Defender's Mirror** — Auto-generated Sigma/YARA/Splunk rules per confirmed finding
5. **Breach Chain Replay** — Self-contained interactive HTML visualization

Package seal: SHA-256 hashes per component, deactivates per-engagement API keys, includes 90-day re-engagement offer at 20% discount.

### 7. Recon v2.0
**Path**: `server/services/recon/` (18 files)

5-phase subdomain discovery:
1. Passive DNS aggregation
2. Brute force (optional)
3. Permutation generation
4. Alive check (HTTPS probe)
5. Dedup + IP resolution

Additional: Port scanning, tech fingerprinting (Wappalyzer-style), WAF detection, secret extraction, header security analysis, SSL/TLS analysis.

MITRE ATT&CK mapped per phase (T1190 through T1560).

### 8. Additive Live Graph Model (NEW — 2026-03-22)
**Files**: `server/lib/breach-event-emitter.ts`, `client/src/lib/breach-events.ts`, `client/src/hooks/useBreachChainUpdates.ts`, `client/src/components/LiveBreachChainGraph.tsx`

Replaces snapshot-based graph updates with additive event-driven model:
- `BreachEventEmitter` on server emits typed events (node_added, edge_added, surface_signal, reasoning, phase_transition)
- Frontend accumulates nodes/edges/signals incrementally via WebSocket
- Graph only grows — never resets mid-engagement
- Canvas-rendered force-directed layout with phase spine + satellite nodes

### 9. Continuous Exposure v3.0
**File**: `server/services/breach-chain/continuous-exposure.ts`

- Scheduled breach chain re-runs
- SLA tracking per finding
- Risk snapshots over time
- Slack alert integration

### 10. Go Agent v1.1.0
**Path**: `odinforge-agent/`

Multi-platform implant (linux/darwin/windows × amd64/arm64):
- BoltDB-backed durable event queue
- HTTPS telemetry upload with TLS validation
- Auto-registration with per-engagement API keys
- Command dispatch: force_checkin, run_scan, validation_probe
- Collectors: config files, open ports, network interfaces, containers, system metrics
- Credential probing: LDAP, Kerberos, NTLM handshakes

### 11. Cloud Security
**Path**: `server/services/cloud/`, `server/services/cloud-pentest/`

- AWS Scanner (IAM, S3, RDS, EC2, Secrets, Lambda) — 600+ lines
- Azure Scanner (RBAC, Key Vault, Blobs, VMs) — 500+ lines
- GCP Scanner (IAM, Buckets, VMs, Secrets) — 450+ lines
- Kubernetes Scanner + Container Escape Testing — 600+ lines each
- Penetration testing services per cloud provider

### 12. Auth & Multi-Tenancy
- JWT via UIAuthProvider → uiAuthMiddleware → requirePermission()
- 67 granular permissions, 8 roles
- Row-Level Security via withTenantContext()
- Rate limiting: 6 limiters (api, auth, evaluation, report, simulation, batch)
- Subscription enforcement (Stripe integration)

### 13. Frontend
**Tech stack**: React 18 + TypeScript + Vite + Tailwind CSS + Radix UI + Recharts + Framer Motion

Key pages: BreachChains (102KB), Infrastructure (124KB), Reports (99KB), Agents (75KB), SecurityTesting (70KB), FullAssessment (54KB)

Visualizations: LiveBreachChainGraph (80KB canvas-rendered), AttackGraphVisualizer, AnimatedAttackGraph, CredentialWeb, AttackHeatmap, NetworkTopologyGraph, ChainComparison

Design system: "Falcon" — custom CSS variables, glow cards, holographic cards, cyber toasts

### 14. CLI v1
**File**: `cli/odinforge.ts`

```
odinforge scan <target> --mode [live|simulation|safe] --phases 1,2,3,4,5,6
odinforge status <chain-id>
odinforge report <chain-id> --component [ciso|engineer|evidence|defenders-mirror|replay]
odinforge package <chain-id> --seal
odinforge keys <chain-id> --create|--list|--revoke <key-id>
```

### 15. Benchmarks
- **Exploit Agent**: Juice Shop, DVWA, WebGoat — pass rate + detection rate CI gates
- **XBOW**: 104 real CTF challenges — 10 quick (per PR), all 104 nightly (4 parallel chunks)
- **Breach Chain**: Multi-phase depth, confidence, evidence quality per target
