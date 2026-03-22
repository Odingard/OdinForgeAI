# OdinForge AEV — Agent Architecture Upgrade Prompt

Paste the entire block below into VS Code Claude.

---

```
I'm sharing my OdinForge AEV codebase. I want you to read the core agent files, then implement the architectural improvements described below.

## READ THESE FILES FIRST

Read all of these in full before writing any code:

1. /Users/dre/prod/OdinForge-AI/server/services/agents/types.ts
2. /Users/dre/prod/OdinForge-AI/server/services/agents/orchestrator.ts
3. /Users/dre/prod/OdinForge-AI/server/services/agents/exploit.ts
4. /Users/dre/prod/OdinForge-AI/server/services/agents/synthesizer.ts
5. /Users/dre/prod/OdinForge-AI/server/services/agents/index.ts
6. /Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts
7. /Users/dre/prod/OdinForge-AI/server/services/recon-report-generator.ts
8. /Users/dre/prod/OdinForge-AI/server/services/active-exploit-engine.ts

---

## ARCHITECTURE I WANT TO IMPLEMENT

Based on a visual agent workflow I reviewed, here is the target architecture:

### Agent pipeline (in order)

Step 1 — Entry:
  Engagement payload arrives with: assetId, exposureType, executionMode (safe/simulation/live), organizationId, scenario, priority

Step 2 — Reconnaissance:
  RECON_AGENT
  - Single-shot LLM call (NOT multi-turn)
  - Inputs: asset metadata, adversary profile, execution mode, ground-truth scan data, external recon (port scans, SSL, HTTP fingerprinting, auth surface, attack readiness scores)
  - Output: ReconFindings — attackSurface[], entryPoints[], apiEndpoints[], authMechanisms[], technologies[], potentialVulnerabilities[], resolvedIp, openPorts[], bannerData{}, httpFingerprint, authReadinessScore
  - Stores result in memory.recon for downstream agents

Step 3 — Exploitation & Validation (parallel threads off recon):
  Thread A — EXPLOIT_AGENT: multi-turn, looks at entry points, fires real payloads
  Thread B — BUSINESS_LOGIC_AGENT: checks IDOR, access control, logic flaws
  Thread C — MULTI_VECTOR_AGENT: checks for exposed cloud keys, SSRF to IMDS, JWT issues
  POLICY_GUARDIAN_EXPLOIT: Guard node that runs alongside all three — checks every proposed action is within scope and execution mode constraints before it fires

Step 4 — Lateral Move & Impact:
  LATERAL_MOVEMENT_AGENT — only runs if Step 3 confirmed credentials or pivot points
  IMPACT_AGENT — blast radius, compliance scope, record counts

Step 5 — Reporting & Remediation:
  SYNTHESIZER_AGENT — assembles all phase results into a coherent breach narrative
  REMEDIATION_ENGINE — generates Sigma rules, fix recommendations, Defender's Mirror output

### Logic routing between steps:
  Logic_Recon_Success: pass/fail gate — if recon found no entry points, chain stops here
  Logic_Exploit_Confirmed: if any Thread A/B/C agent confirmed a finding, proceed to Step 4
  Both gates must check EvidenceContract compliance — no synthetic findings pass through

### Worker-container vs Worker-agent separation:
  Worker-containers: pure code execution — runs real tools (port scans, TCP banner grab, HTTP requests, payload dispatch), returns raw result, NO LLM involved
  Worker-agents: reads the worker-container result, reasons about it, decides what to do next
  Selector-agent: decides which worker to run next based on current memory state
  Guard-agent: validates that the output is legitimate before it passes downstream

### ReconFindings schema — EXPAND this from the current thin version:
  Current schema only has: attackSurface[], entryPoints[], technologies[]
  Required additions:
    resolvedIp: string
    openPorts: number[]
    bannerData: Record<string, { service: string; version: string | null; banner: string | null }>
    httpFingerprint: { server: string | null; framework: string | null; cdn: string | null; waf: string | null }
    authMechanisms: string[]
    apiEndpoints: string[]
    potentialVulnerabilities: string[]
    attackReadinessScore: number  // 0-100
    externalReconSource: "live" | "cached" | "none"

### grabBanner implementation:
  If it doesn't exist yet, add this to the recon worker-container:
  - Raw TCP socket connection to target host + port
  - 2 second timeout
  - Reads initial broadcast bytes (service banner)
  - Returns DatabaseFingerprint: { port, service, banner, versionInfo }
  - This feeds into ReconFindings.bannerData

---

## WHAT I WANT YOU TO DO

1. Read all 8 files listed above
2. Map what currently exists against the architecture above — tell me what's already there, what's missing, what's misaligned
3. Write the gap-fill code:
   a. Expand ReconFindings type in types.ts with the new fields
   b. Add grabBanner function to recon worker (or active-exploit-engine.ts if that's where scanning lives)
   c. Add Logic_Recon_Success gate function — checks EvidenceContract, returns pass/fail
   d. Add Logic_Exploit_Confirmed gate function — checks if any real confirmed findings exist before allowing Step 4
   e. Wire POLICY_GUARDIAN_EXPLOIT as a validation step inside the exploit phase that blocks out-of-scope actions
   f. Add parallel thread execution to Step 3 — EXPLOIT_AGENT, BUSINESS_LOGIC_AGENT, MULTI_VECTOR_AGENT run concurrently via Promise.all, not sequentially
4. After writing code, run: npx tsc --noEmit and fix any errors
5. Produce a single AGENTS_ARCH.md file at /Users/dre/prod/OdinForge-AI/server/services/agents/AGENTS_ARCH.md documenting the final architecture with file references

## RULES

- Never generate findings via LLM — all findings must come from real HTTP evidence (EvidenceContract)
- Worker-containers must be pure TypeScript functions with no LLM calls
- Guard/policy checks must run BEFORE findings are written to memory
- Parallel threads in Step 3 must share a read-only copy of memory.recon, never write to each other
- TypeScript strict mode — no `any` without justification
- Do not break existing breach-orchestrator.ts phase loop — add to it, don't replace it
```
