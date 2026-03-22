# OdinForge AEV — Agent Architecture v2.0

## Pipeline Overview

```
Engagement Payload
       |
       v
  [Step 1: Entry]
  assetId, exposureType, executionMode, organizationId, scenario, priority
       |
       v
  [Step 2: Reconnaissance]
  RECON_AGENT (single-shot LLM call)
  Inputs: asset metadata, adversary profile, execution mode, ground-truth
          scan data, external recon (ports, SSL, HTTP fingerprint, auth
          surface, attack readiness scores)
  Output: ReconFindings (expanded schema — see below)
  Stores: memory.recon
       |
       v
  [Logic_Recon_Success Gate]  ──── FAIL ──── Pipeline stops
       |
      PASS
       |
       v
  [Step 3: Exploitation & Validation — PARALLEL THREADS]
  ┌────────────────────────────────────────────────────┐
  │ Thread A: EXPLOIT_AGENT (multi-turn, real payloads)│
  │ Thread B: BUSINESS_LOGIC_AGENT (IDOR, access ctrl) │
  │ Thread C: MULTI_VECTOR_AGENT (cloud, SSRF, JWT)    │
  │                                                    │
  │ POLICY_GUARDIAN_EXPLOIT: validates all findings     │
  │ BEFORE they are written to memory                  │
  └────────────────────────────────────────────────────┘
  All threads share read-only memory.recon (frozen copy)
  Threads never write to each other — output merges after Promise.all
       |
       v
  [POLICY_GUARDIAN_EXPLOIT validation]
  Blocks out-of-scope, blocks destructive in safe mode,
  strips EvidenceContract-violating findings
       |
       v
  [Debate Module + Noise Reduction]
       |
       v
  [Logic_Exploit_Confirmed Gate]  ──── FAIL ──── Skip to Synthesis
       |
      PASS
       |
       v
  [Step 4: Lateral Move & Impact]
  LATERAL_MOVEMENT_AGENT — only if credentials/pivot points confirmed
  IMPACT_AGENT — blast radius, compliance scope, record counts
       |
       v
  [Step 5: Reporting & Remediation]
  SYNTHESIZER_AGENT — assembles breach narrative
  REMEDIATION_ENGINE — Sigma rules, fix recommendations, Defender's Mirror
       |
       v
  [Finalization]
  Attack graph, deterministic scoring, evidence packaging
```

## File References

| File | Role |
|------|------|
| `server/services/agents/types.ts` | All agent types: `ReconFindings` (expanded), `ExploitFindings`, `AgentMemory`, `SafetyDecision`, etc. |
| `server/services/agents/orchestrator.ts` | Master pipeline: wires recon, parallel threads, gates, debate, synthesis |
| `server/services/agents/exploit.ts` | Thread A: multi-turn agentic exploit agent (12 turns, 165s timeout) |
| `server/services/agents/synthesizer.ts` | Step 5: assembles all agent findings into final assessment |
| `server/services/agents/pipeline-gates.ts` | `gateReconSuccess()` and `gateExploitConfirmed()` — pipeline decision points |
| `server/services/agents/policy-guardian.ts` | `POLICY_GUARDIAN_EXPLOIT` — validates exploit findings before memory write |
| `server/services/agents/grab-banner.ts` | Worker-container: TCP banner grab (pure TS, no LLM) |
| `server/services/agents/index.ts` | Public exports for the agents module |
| `server/services/agents/debate-module.ts` | Adversarial validation (Llama 3.3 70B critic) |
| `server/services/agents/noise-reduction.ts` | Swiss Cheese 4-layer noise filter |
| `server/services/agents/circuit-breaker.ts` | Per-provider circuit breaker |
| `server/services/agents/exploit-tools.ts` | Tool definitions for exploit agent (SQLi, XSS, SSRF, etc.) |
| `server/services/agents/scoring-engine.ts` | Deterministic scoring v3.0 |
| `server/services/evidence-quality-gate.ts` | EvidenceContract classification: PROVEN/CORROBORATED/INFERRED/UNVERIFIABLE |
| `server/services/breach-orchestrator.ts` | Cross-domain breach chain (6 phases) — calls `runAgentOrchestrator` in Phase 1 |
| `server/services/active-exploit-engine.ts` | Active exploitation engine with real payload firing |

## ReconFindings Schema (Expanded)

```typescript
interface ReconFindings {
  // Original fields
  attackSurface: string[];
  entryPoints: string[];
  apiEndpoints: string[];
  authMechanisms: string[];
  technologies: string[];
  potentialVulnerabilities: string[];

  // New fields (v2.0)
  resolvedIp: string;
  openPorts: number[];
  bannerData: Record<string, BannerInfo>;
  httpFingerprint: HttpFingerprint;
  attackReadinessScore: number;       // 0-100
  externalReconSource: "live" | "cached" | "none";
}

interface BannerInfo {
  service: string;
  version: string | null;
  banner: string | null;
}

interface HttpFingerprint {
  server: string | null;
  framework: string | null;
  cdn: string | null;
  waf: string | null;
}
```

## Pipeline Gates

### Logic_Recon_Success

- Location: `pipeline-gates.ts` > `gateReconSuccess()`
- When: After Step 2, before Step 3
- Pass condition: At least one entry point, API endpoint, or meaningful attack surface
- Fail action: Pipeline stops, no exploitation attempted
- EvidenceContract: Recon cannot be purely empty

### Logic_Exploit_Confirmed

- Location: `pipeline-gates.ts` > `gateExploitConfirmed()`
- When: After Step 3 (all threads + debate + noise reduction), before Step 4
- Pass condition: At least one finding across threads A/B/C with real evidence
  - Exploit chains: `validated === true` or `validationConfidence >= 50`
  - Business logic: authorization bypass or race condition detected
  - Multi-vector: critical/high severity IAM/cloud finding
- Fail action: Skip lateral movement and impact — proceed directly to synthesis
- EvidenceContract: Pure LLM-inferred findings (no `evidence[]`, no `validated`) do not count

## Worker-Container vs Worker-Agent Separation

| Layer | Description | LLM? | Example |
|-------|-------------|------|---------|
| Worker-container | Pure code execution — runs real tools | No | `grabBanner()`, `test_payloads`, `http_fingerprint` |
| Worker-agent | Reads container result, reasons, decides next action | Yes | Exploit agent's multi-turn loop |
| Selector-agent | Decides which worker to run based on memory state | Yes | Plan agent (future), exploit agent turn logic |
| Guard-agent | Validates output is legitimate before downstream pass | No | `POLICY_GUARDIAN_EXPLOIT` |

## POLICY_GUARDIAN_EXPLOIT

- Location: `policy-guardian.ts` > `validateExploitFindings()`
- Runs: After all three Step 3 threads complete, BEFORE findings are written to `memory.exploit`
- Rules enforced:
  1. **Execution mode gating** — safe mode blocks active exploitation (RCE, reverse shells)
  2. **Sensitive target protection** — production databases, CI/CD, IAM root require live mode
  3. **Scope enforcement** — blocks findings targeting out-of-scope assets (when scope patterns configured)
  4. **EvidenceContract enforcement** — modifies findings that have no real evidence backing (LLM-only)
- Outputs: Filtered `ExploitFindings` + `SafetyDecision[]` audit trail

## Parallel Thread Execution (Step 3)

All three threads run concurrently via `Promise.all`:

```typescript
const readOnlyRecon = Object.freeze({ ...memory.recon });

const [exploitResult, blResult, mvResult] = await Promise.all([
  threadAPromise,  // EXPLOIT_AGENT
  threadBPromise,  // BUSINESS_LOGIC_AGENT
  threadCPromise,  // MULTI_VECTOR_AGENT
]);
```

Invariants:
- Each thread receives a frozen copy of `memory.recon` (read-only)
- Threads never write to shared memory or each other's findings
- Results are merged only after all threads complete
- POLICY_GUARDIAN_EXPLOIT runs after merge, before memory write

## grabBanner Worker-Container

- Location: `grab-banner.ts`
- Function: `grabBanner(host, port)` / `grabBanners(host, ports[])`
- Protocol: Raw TCP socket with 2-second timeout
- Returns: `{ port, service, banner, versionInfo }`
- Feeds into: `ReconFindings.bannerData`
- LLM calls: None (pure TypeScript worker-container)

## Critical Rules

1. **Never generate findings via LLM** — all findings must come from real HTTP evidence (EvidenceContract)
2. **Worker-containers are pure TypeScript** — no LLM calls in `grabBanner`, `test_payloads`, etc.
3. **Guard/policy checks run BEFORE memory write** — `POLICY_GUARDIAN_EXPLOIT` filters findings before `memory.exploit` assignment
4. **Parallel threads share read-only recon** — frozen copy, no cross-thread writes
5. **TypeScript strict mode** — no `any` without justification
6. **Breach orchestrator untouched** — agent architecture additions are purely additive
