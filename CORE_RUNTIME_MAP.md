Perfect. Now I have all the information needed. Let me generate the comprehensive Core Runtime Map:

## CORE RUNTIME MAP: OdinForge-AI Breach Chain Execution

This is the complete call graph from scan trigger to sealed engagement package, with every function call, file, and storage write in execution order.

---

## PATH 1: SCAN TRIGGER → CHAIN CREATION

**Route Entry Point**
- **File**: `/Users/dre/prod/OdinForge-AI/server/routes.ts:7686`
- **Handler**: `POST /api/breach-chains`
- **Middleware Stack**:
  - `evaluationRateLimiter` (rate limit check)
  - `uiAuthMiddleware` (lines 206-251) → verifies JWT, sets `req.uiUser`, calls `setTenantContext()`, updates `lastActivityAt`
  - `requirePermission("evaluations:create")` (checks role permissions from DB)

**Route Handler: lines 7686–7768**
1. Parse request body: `name, description, assetIds, targetDomains, config`
2. Validate `assetIds` is non-empty array
3. Extract `orgId` from `req.uiUser?.organizationId || "default"`
4. **Governance Check** (line 7697):
   - Import `governanceEnforcement` from `./services/governance/governance-enforcement`
   - Call `governanceEnforcement.canStartOperation(orgId, "breach_chain", primaryTarget, executionMode)`
   - Return 403 if blocked
5. Normalize execution mode to "safe" | "simulation" | "live" (line 7710)
6. Build default config (lines 7712–7729):
   - Set `enabledPhases`: all 6 phases by default
   - Set `requireMinConfidence: 30`, `requireCredentialForCloud: true`, etc.
   - Apply per-phase timeout (default 900s), total timeout (default 3600s)
7. **Database Write #1**: `storage.createBreachChain()` (line 7731)
   - **File**: `/Users/dre/prod/OdinForge-AI/server/storage.ts:1894`
   - Generates ID: `bc-${uuid.slice(0, 8)}`
   - Insert into `breachChains` table:
     - `id, name, organizationId, description, assetIds, targetDomains, config, status: "pending", progress: 0, currentPhase: null, phaseResults: [], startedAt: new Date()`
   - Returns created chain object
8. **Fire and Forget** (line 7755):
   - Call `runBreachChain(chain.id)` (no await — returns immediately)
   - Catches error silently in background
9. Return 200 JSON response with `chainId, message, phases`

---

## PATH 2: BREACH ORCHESTRATOR (SEQUENTIAL PATH ONLY)

### Entry Point: `runBreachChain()`

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:239`

**Initialization (lines 239–266)**
1. Fetch chain: `chain = await storage.getBreachChain(chainId)` (storage.ts:1916)
2. Validate live target: `validateLiveTarget(chain)` (lines 168–183)
   - Check `assetIds[0]` is not empty/localhost/127.0.0.1
   - Throw if invalid
3. Create engagement logger: `engagementLogger(chainId)`
4. Extract config: `config = chain.config as BreachChainConfig`
5. Record start time: `startTime = Date.now()`
6. **Database Write #2**: `storage.updateBreachChain(chainId, { status: "running", startedAt: new Date() })` (storage.ts:1935)
   - Updates `status` to "running"
   - Sets `startedAt` timestamp
7. Broadcast progress: `broadcastBreachProgress(chainId, "starting", 0, "...")` (line 267)
   - **File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:3544`
   - Calls `wsService.broadcastToChannel("breach_chain:{chainId}", { type: "breach_chain_progress", ... })`
8. Check AGENT_MESH flag: `isAgentMeshEnabled()` (line 270)
   - If TRUE: delegate to `AgentMeshOrchestrator` (different path — skipped here, SEQUENTIAL ONLY)
   - If FALSE: continue to sequential path below

**Sequential Path (lines 425–851)**

### Context & Emitter Initialization (lines 425–483)
1. Initialize or restore context (lines 426–433):
   - `context: BreachPhaseContext` from `chain.currentContext` or fresh object
   - Fields: `credentials: [], compromisedAssets: [], attackPathSteps: [], evidenceArtifacts: [], currentPrivilegeLevel: "none", domainsCompromised: []`
2. Restore phase results: `phaseResults = chain.phaseResults as BreachPhaseResult[]`
3. Track completed phases: `completedPhases = Set(phaseResults where status === "completed")`
4. Filter enabled phases: `enabledPhases = PHASE_ORDER.filter(p => config.enabledPhases.includes(p))`
5. Initialize GTM v1.0 feature instances (lines 445–448):
   - `replayRecorder = new ReplayRecorder(chainId)`
   - `defendersMirror = new DefendersMirror()`
   - `reachabilityBuilder = new ReachabilityChainBuilder()`
6. Create breach event emitter (line 453):
   - `breachEmitter = createBreachEventEmitter(chainId)`
   - **File**: `/Users/dre/prod/OdinForge-AI/server/lib/breach-event-emitter.ts:1`
   - Emitter is stored in module-level store: `chainEmitterStore.set(chainId, breachEmitter)`
7. Emit skeleton phase spine nodes (lines 458–483):
   - For each phase (0–5):
     - Call `breachEmitter.nodeAdded({ kind: "phase_spine", phase: phaseId, ... })`
     - Returns `nodeId`, stored in `spineNodeIds[phaseId]`
     - Wire spine edges: `breachEmitter.edgeAdded(prevNodeId, nodeId, false)`
8. Record engagement start: `recordEngagementStart()` (line 486) — Prometheus metric

### Phase Execution Loop (lines 488–850)

**For each phase in enabledPhases:**

```
FOR phaseName IN enabledPhases {
  // Skip already completed phases (resume path)
  IF completedPhases.has(phaseName) CONTINUE

  // Re-check abort status (line 494)
  currentChain = await storage.getBreachChain(chainId)
  IF currentChain.status === "aborted" {
    broadcastBreachProgress(..., "aborted")
    RETURN
  }

  // Check total timeout (line 501)
  IF Date.now() - startTime > config.totalTimeoutMs {
    await storage.updateBreachChain(chainId, {
      status: "failed",
      currentContext: context,
      phaseResults,
    })
    broadcastBreachProgress(..., "timeout")
    RETURN
  }

  // Safety gate check (line 512)
  gateResult = checkPhaseGate(phaseName, context, config)
  IF NOT gateResult.pass {
    // Create skipped phase result
    skipResult: BreachPhaseResult = {
      phaseName, status: "skipped",
      startedAt: now, completedAt: now,
      inputContext: {...}, outputContext: context,
      findings: [], error: gateResult.reason
    }
    phaseResults.push(skipResult)
    await storage.updateBreachChain(chainId, {
      phaseResults, currentContext: context
    })
    broadcastBreachProgress(..., phaseName, ..., "Skipped: {reason}")
    CONTINUE
  }

  // Update current phase (line 541)
  phaseDef = PHASE_DEFINITIONS[phaseName]
  await storage.updateBreachChain(chainId, {
    currentPhase: phaseName,
    progress: phaseDef.progressRange[0]
  })
  broadcastBreachProgress(chainId, phaseName, progressRange[0], "Starting...")

  // Record replay start (line 553)
  replayRecorder.recordPhaseStart(phaseName, chain.assetIds?.[0])

  // Get phase executor (line 556)
  executor = getPhaseExecutor(phaseName)

  // Execute phase with timeout (lines 557–560)
  phaseResult = await Promise.race([
    executor(chain, context, onProgress),
    phaseTimeout(config.phaseTimeoutMs, phaseName)
  ])

  phaseResults.push(phaseResult)

  // Merge output context (lines 566–583)
  IF phaseResult.status === "completed" {
    context = mergeContexts(context, phaseResult.outputContext)
    
    // Publish newly discovered credentials to CredentialBus
    FOR cred OF phaseResult.outputContext.credentials {
      getCredentialBus().publish(chainId, {
        id: cred.id,
        engagementId: chainId,
        username: cred.username || cred.type,
        hash: cred.valueHash,
        privilegeTier: ...,
        sourceSystem: cred.source || phaseName,
        sourceNodeId: ...,
        sourceTactic: phaseDef.displayName,
        discoveredAt: cred.discoveredAt || now
      })
    }
  }

  // Record replay completion (line 586)
  replayRecorder.recordPhaseComplete(phaseName, chain.assetIds?.[0], phaseResult.findings.length)

  // GTM v1.0: Evidence Quality Gate (line 600)
  evaluatedFindings: EvaluatedFinding[] = phaseResult.findings.map(f => ({ ...f, source: phaseName }))
  qualityVerdict = evidenceQualityGate.evaluateBatch(evaluatedFindings)
  // Returns: { passed: [...], failed: [...], summary: { proven, corroborated, inferred, unverifiable, ... } }

  // GTM v1.0: Defender's Mirror — generate detection rules (lines 603–620)
  phaseEvidence: AttackEvidence[] = phaseResult.findings
    .filter(f => f.severity === "critical" || f.severity === "high")
    .map(f => ({ id: f.id, engagementId: chainId, phase: phaseName, ... }))
  
  FOR each f IN phaseEvidence {
    call defendersMirror.generateFromEvidence(evidence)
  }

  // Emit phase transition event (lines 629–653)
  IF phaseResult.status === "completed" AND spineNodeIds[phaseName] {
    breachEmitter.phaseTransition(
      fromPhase: previousPhase || null,
      toPhase: phaseName,
      phaseIndex: ...,
      findingCount: phaseResult.findings.length,
      credentialCount: phaseResult.outputContext.credentials.length
    )
  }

  // Record phase metrics (line 590)
  recordPhaseMetric(phaseName, phaseElapsed, phaseResult.status === "completed")
  IF phaseResult.outputContext?.credentials?.length {
    recordCredentialHarvested(phaseResult.outputContext.credentials.length)
  }

  // Broadcast phase complete (lines 654–675)
  broadcastBreachProgress(..., phaseName, ..., "Phase complete")
}
// END FOR
```

### Phase Executor Dispatch (line 556)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:1443`

```
function getPhaseExecutor(phaseName: BreachPhaseName): PhaseExecutor {
  SWITCH phaseName {
    CASE "application_compromise": RETURN executeApplicationCompromise
    CASE "credential_extraction": RETURN executeCredentialExtraction
    CASE "cloud_iam_escalation": RETURN executeCloudIAMEscalation
    CASE "container_k8s_breakout": RETURN executeContainerK8sBreakout
    CASE "lateral_movement": RETURN executeLateralMovement
    CASE "impact_assessment": RETURN executeImpactAssessment
  }
}
```

---

### PHASE 1: APPLICATION COMPROMISE (lines 1464–2042)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:1464`

**Executor**: `executeApplicationCompromise(chain, context, onProgress)`

**For each assetId in chain.assetIds:**

1. **Phase 1A: Run Active Exploit Engine** (lines 1479–1616)
   - Resolve asset URL: `targetUrl = await resolveAssetUrl(assetId)`
   - Create exploit target: `exploitTarget = { baseUrl, assetId, scope: { exposureTypes: [...], ... }, ... }`
   - Call active exploit engine (line 1511):
     ```
     activeExploitResult = await runActiveExploitEngine(
       exploitTarget,
       (phase, progress, detail) => onProgress(...),
       (kind, label, detail) => emitter.surfaceSignal(...)
     )
     ```
     - **File**: `/Users/dre/prod/OdinForge-AI/server/services/active-exploit-engine.ts`
     - Returns: `ActiveExploitResult { crawl: { endpoints: [...] }, validated: ExploitAttempt[], summary: { totalEndpoints, totalAttempts, totalValidated, totalCredentials, attackPathsFound }, durationMs }`
   - Store raw validated attempts for Phase 2 (lines 1534–1535):
     - `phase1AEvidenceStore.set(chainId, [...existingEvidence, ...activeExploitResult.validated])`
   - Map to breach phase format: `mapped = mapToBreachPhaseContext(activeExploitResult)`
   - Merge validated credentials (lines 1541–1551):
     - For each credential from `mapped.credentials`:
       - Create: `BreachCredential { id, type, valueHash, source: "active_exploit_engine", accessLevel, validatedTargets: [targetUrl], discoveredAt }`
       - Push to `newCredentials`
   - Merge compromised assets (lines 1554–1568):
     - For each asset from `mapped.compromisedAssets`:
       - Create: `CompromisedAsset { id, assetId, assetType: "application", name, accessLevel, compromisedBy: "application_compromise", accessMethod, timestamp }`
       - Dedup by assetId
   - Store validated findings (lines 1570–1595):
     - For each finding from `mapped.findings`:
       - Create finding: `{ id, severity, title, description, technique, source: "active_exploit_engine", evidenceQuality: "proven" }`
       - Push to `findings`
       - Emit reasoning event via emitter: `phase1Emitter.reasoning(phaseName, agentId, decision, rationale, outcome, { techniqueTried })`

2. **Phase 1B: Parallel Micro-Agent Dispatch** (lines 1619–1710)
   - Create MicroAgentOrchestrator (lines 1633–1637):
     ```
     microOrchestrator = new MicroAgentOrchestrator({
       maxConcurrent: 50,
       payloadTimeoutMs: 6000,
       targetRequestsPerSecond: 50
     })
     ```
   - Build agent specs (line 1639):
     ```
     agentSpecs = microOrchestrator.buildAgentSpecs(
       activeExploitResult.crawl.endpoints,
       exploitTarget.scope.exposureTypes,
       chainId,
       targetUrl
     )
     ```
   - Dispatch agents (line 1650):
     ```
     microResults = await microOrchestrator.dispatch(agentSpecs,
       (completed, total, result) => {
         onProgress(...)
         wsService.broadcastToChannel(..., {
           type: "breach_chain_agent_dispatch",
           chainId, completed, total, agentId, ...
         })
       }
     )
     ```
   - For each micro-agent result:
     - Extract findings, credentials, assets
     - Merge into `findings, newCredentials, newAssets`
   - Record dispatch summary: `microDispatchSummary = { completedAgents, failedAgents, findings, ... }`

3. **Phase 1C: Agent Orchestrator Fallback** (lines 1712–1810)
   - If micro-agent results were insufficient, fall back to LLM agent:
     ```
     agentResult = await runAgentOrchestrator({
       chainId, target: targetUrl, ...
     })
     ```
     - **File**: `/Users/dre/prod/OdinForge-AI/server/services/agents/orchestrator.ts`
     - Returns: `OrchestratorResult { findings, credentials, success, duration }`
   - Merge agent results into phase findings

4. **Build Phase Result** (line 1810):
   ```
   return buildPhaseResult("application_compromise", startTime, context, {
     credentials: newCredentials,
     assets: newAssets,
     findings,
     evaluationIds,
     subAgentRuns,
     agentDispatchSummary: microDispatchSummary,
     domain: "application"
   })
   ```
   - Returns: `BreachPhaseResult { phaseName, status, startedAt, completedAt, inputContext, outputContext: mergedContext, findings, ... }`

---

### PHASE 2: CREDENTIAL EXTRACTION (lines 2046–2156)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:2046`

**Executor**: `executeCredentialExtraction(chain, context, onProgress)`

1. **Step 1: Carry forward Phase 1A credentials** (lines 2057–2065)
   - Filter credentials already extracted: `activeCredentials = context.credentials.filter(c => c.source === "active_exploit_engine")`
   - If found, update progress

2. **Step 2: Parse Phase 1A HTTP response bodies** (lines 2067–2136)
   - Read phase 1A evidence: `phase1Attempts = phase1AEvidenceStore.get(chainId) || []`
   - For each attempt:
     - Extract body: `body = attempt.response.body`
     - Extract headers: `headers = attempt.response.headers`
     - For each `CREDENTIAL_PATTERNS` (regex patterns for passwords, API keys, tokens, etc.):
       - Perform `target.matchAll(pattern.pattern)`
       - For each match:
         - Extract plaintext: `plaintext = match[1] || match[0]`
         - Create credential via `credentialStore.create({ type, plaintext, source: "credential_extraction", context, accessLevel })`
         - Create `BreachCredential { id, type, valueHash, source: "credential_extraction", accessLevel, validatedTargets: [url], discoveredAt }`
         - Dedup against existing credentials by hash
         - Push to `newCredentials`
         - Create finding: `{ id, severity: (admin ? "critical" : "high"), title: "Credential Extracted: {type}", description: ..., technique: "T1552", source: "credential_extraction", evidenceQuality: "proven", statusCode, responseBody }`
         - Push to `findings`
   - Clear Phase 1A evidence (line 2133): `phase1AEvidenceStore.delete(chainId)`

3. **Step 3: LLM Fallback (Disabled per ADR-001)** (lines 2138–2147)
   - ADR-001 prohibits synthetic credential generation
   - If zero credentials extracted and zero phase 1 attempts, log info and continue with zero credentials
   - Downstream phases gate on this (requireCredentialForCloud, requireCloudAccessForK8s)

4. **Build Phase Result** (line 2149):
   ```
   return buildPhaseResult("credential_extraction", startTime, context, {
     credentials: newCredentials,
     assets: [],
     findings,
     evaluationIds: [],
     domain: "credentials"
   })
   ```

---

### PHASE 3: CLOUD IAM ESCALATION (lines 2162–2353)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:2162`

**Executor**: `executeCloudIAMEscalation(chain, context, onProgress)`

1. **Filter confirmed cloud credentials** (lines 2174–2184)
   - Extract cloud-type credentials: `cloudCreds = context.credentials.filter(c => ["api_key", "iam_role", "service_account", "token"].includes(c.type))`
   - Filter only confirmed: `confirmedCloudCreds = cloudCreds.filter(c => c.source === "active_exploit_engine" || "application_compromise" || "credential_extraction")`

2. **Analyze IAM privilege escalation** (lines 2186–2240)
   - If `confirmedCloudCreds.length > 0`:
     - Build permission set from credential metadata: `inferredPermissions = confirmedCloudCreds.flatMap(c => { if c.type === "iam_role" return ["iam:*", ...]; ... })`
     - Call AWS pentest service (line 2198):
       ```
       iamResult = await awsPentestService.analyzeIAMPrivilegeEscalation(
         inferredPermissions,
         confirmedCloudCreds[0]?.username,
         ...
       )
       ```
       - **File**: `/Users/dre/prod/OdinForge-AI/server/services/cloud-pentest/aws-pentest-service.ts`
       - Returns: `{ escalationPaths: [...{ name, description, steps, impact, mitreId }], riskScore }`
     - For each escalation path:
       - Create finding: `{ id, severity: (impact === "critical" ? "critical" : ...), title: "IAM Privilege Escalation: {name}", description: ..., source: "cloud_iam_escalation", evidenceQuality: "corroborated" }`
       - Create elevated credential: `{ id, type: "iam_role", username: "escalated-{name}", valueHash, source: "cloud_iam_escalation", accessLevel: (impact === "critical" ? "cloud_admin" : "admin"), validatedTargets: ["aws-iam"], discoveredAt }`
       - Push to `newCredentials`
     - If paths found, create compromised asset: `{ id, assetId: "aws-iam", assetType: "iam_principal", name: "AWS IAM (escalated)", accessLevel: (riskScore >= 80 ? "admin" : "user"), compromisedBy: "cloud_iam_escalation", ... }`
     - Push to `newAssets`

3. **Build Phase Result** (line 2352):
   ```
   return buildPhaseResult("cloud_iam_escalation", startTime, context, {
     credentials: newCredentials,
     assets: newAssets,
     findings,
     evaluationIds: [],
     domain: "cloud"
   })
   ```

---

### PHASE 4: CONTAINER/K8S BREAKOUT (lines 2354–2713)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:2354`

**Executor**: `executeContainerK8sBreakout(chain, context, onProgress)`

1. **Filter confirmed K8s access credentials** (lines 2363–2375)
   - Extract K8s-type credentials: `k8sCreds = context.credentials.filter(c => ["k8s_token", "service_account"].includes(c.type))`
   - Filter only confirmed: `confirmedK8sCreds = k8sCreds.filter(c => c.source in CONFIRMED_SOURCES)`

2. **Analyze Kubernetes API abuse** (lines 2377–2500)
   - If `confirmedK8sCreds.length > 0`:
     - Call Kubernetes pentest service (line 2388):
       ```
       k8sResult = await kubernetesPentestService.analyzeK8sPrivilegeEscalation(
         confirmedK8sCreds[0]?.valueHash,
         chain.id
       )
       ```
       - **File**: `/Users/dre/prod/OdinForge-AI/server/services/container-security/kubernetes-pentest-service.ts`
       - Returns: `{ escapePaths: [...{ technique, impact, evidence }], riskScore }`
     - For each escape path:
       - Create finding: `{ id, severity, title: "K8s Escape: {technique}", source: "container_k8s_breakout", evidenceQuality: "corroborated" }`
       - Create escaped asset: `{ id, assetId: "k8s-node", assetType: "container", name, accessLevel, compromisedBy: "container_k8s_breakout", ... }`

3. **Build Phase Result** (line 2712):
   ```
   return buildPhaseResult("container_k8s_breakout", startTime, context, {
     credentials: newCredentials,
     assets: newAssets,
     findings,
     evaluationIds: [],
     domain: "container"
   })
   ```

---

### PHASE 5: LATERAL MOVEMENT (lines 2714–2853)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:2714`

**Executor**: `executeLateralMovement(chain, context, onProgress)`

1. **Drain PivotQueue for credential reuse attacks** (lines 2728–2840)
   - Initialize PivotQueue: `pivotQueue = new PivotQueue(context.credentials)`
   - Dispatch lateral movement sub-agents:
     ```
     FOR pivotHop IN pivotQueue {
       subAgent = new LateralMovementSubAgent(pivotHop)
       nodeResult = await subAgent.execute()
     }
     ```
     - **File**: `/Users/dre/prod/OdinForge-AI/server/services/aev/pivot-queue.ts`
     - Each sub-agent attempts real network auth (SMB, SSH, RDP, WinRM, LDAP)
   - For each node result:
     - Create findings from pivot findings: `{ id, severity, title, source: "lateral_movement", evidenceQuality: (authResult === "success" ? "proven" : "corroborated"), statusCode, responseBody }`
     - Push to `findings`
     - If auth succeeded, create compromised asset: `{ id, assetId: host, assetType: "server", accessLevel, compromisedBy: "lateral_movement", accessMethod: technique, ... }`
     - Harvest new credentials at node and push to `newCredentials`

2. **Build Phase Result** (line 2846):
   ```
   return buildPhaseResult("lateral_movement", startTime, context, {
     credentials: newCredentials,
     assets: newAssets,
     findings,
     evaluationIds: [],
     domain: "network"
   })
   ```

---

### PHASE 6: IMPACT ASSESSMENT (lines 2859–2926)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:2859`

**Executor**: `executeImpactAssessment(chain, context, onProgress)`

1. **Aggregate breach impact** (lines 2865–2926)
   - Extract totals from context:
     - `totalFindings = context.attackPathSteps.length`
     - `uniqueDomains = context.domainsCompromised.length`
     - `maxPrivilege = context.currentPrivilegeLevel`
     - `totalAssets = context.compromisedAssets.length`
     - `totalCreds = context.credentials.length`
   - If `uniqueDomains >= 3`:
     - Create SYNTHESIS finding: `{ id, severity: "critical", title: "[SYNTHESIS] Multi-Domain Breach", description: "Attacker achieved access across {domains}...", source: "impact_synthesis", evidenceQuality: "inferred" }`
   - If `maxPrivilege === "cloud_admin" || "domain_admin"`:
     - Create SYNTHESIS finding: `{ id, severity: "critical", title: "[SYNTHESIS] Administrative Privilege Achieved", source: "impact_synthesis", evidenceQuality: "inferred" }`
   - If `totalAssets >= 5`:
     - Create SYNTHESIS finding: `{ id, severity: "high", title: "[SYNTHESIS] Large-Scale Infrastructure Compromise", source: "impact_synthesis", evidenceQuality: "inferred" }`

2. **Build Phase Result** (line 2926):
   ```
   return buildPhaseResult("impact_assessment", startTime, context, {
     credentials: [],
     assets: [],
     findings,
     evaluationIds: [],
     domain: "business"
   })
   ```

---

### Post-Phase Loop Completion (lines 773–850)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:773`

1. **Build unified attack graph** (lines 715–770):
   ```
   unifiedGraph = buildAttackGraph(chainId, phaseResults, context)
   ```
   - Constructs `AttackGraph { nodes: [...], edges: [...], criticalPath: [...] }`
   - Nodes: findings, credentials, assets, domains
   - Edges: lateral movement paths, privilege escalation chains

2. **Compute overall risk score** (lines 722–766):
   ```
   overallRiskScore = computeRiskScore(phaseResults)
   ```
   - Uses intelligent scoring v3.0: EPSS(45%) + CVSS(35%) + Agent(20%), KEV override at 85%

3. **Build reachability chain** (line 771):
   ```
   pivotResults: PivotResult[] = phaseResults
     .flatMap(pr => pr.findings.map(f => ({ 
       source: f.source, targetHost: ..., protocol: f.technique || ..., found: true
     })))
   reachabilityChain = buildReachabilityChain(chainId, entryHost, pivotResults)
   ```
   - **File**: `/Users/dre/prod/OdinForge-AI/server/services/reachability-chain.ts`
   - Returns: `{ deepestNode: { depth, host }, pivots: [...] }`

4. **Final Evidence Quality Gate** (line 777):
   ```
   allFindings: EvaluatedFinding[] = phaseResults.flatMap(pr =>
     pr.findings.map(f => ({ ...f, source: pr.phaseName }))
   )
   finalQualityVerdict = evidenceQualityGate.evaluateBatch(allFindings)
   ```
   - **File**: `/Users/dre/prod/OdinForge-AI/server/services/evidence-quality-gate.ts:80`
   - Returns: `BatchVerdict { passed: QualityVerdict[], failed: QualityVerdict[], summary: { proven, corroborated, inferred, unverifiable, total, passRate } }`

5. **Generate all Defender's Mirror rules** (line 780):
   ```
   allDetectionRules = defendersMirror.getRulesForEngagement(chainId)
   ```
   - Collects all detection rules generated during execution
   - Returns: `DetectionRuleSet[]`

6. **Finalize replay recording** (line 781):
   ```
   replayManifest = replayRecorder.finalize()
   ```
   - **File**: `/Users/dre/prod/OdinForge-AI/server/services/replay-recorder.ts`
   - Returns: `EngagementReplayManifest { events: [...], timeline: [...] }`

7. **Compute executive summary** (line 778):
   ```
   executiveSummary = computeExecutiveSummary({
     chainId, phaseResults, riskScore, ...
   })
   ```
   - Returns: narrative string of breach impact

---

### Storage Write #3: Complete Breach Chain (line 782)

```
await storage.updateBreachChain(chainId, {
  status: "completed",
  progress: 100,
  currentPhase: null,
  phaseResults,                           // ALL 6 BreachPhaseResult objects
  currentContext: context,                // Final merged context
  unifiedAttackGraph: unifiedGraph,       // AttackGraph
  overallRiskScore,                       // Number
  totalCredentialsHarvested: context.credentials.length,
  totalAssetsCompromised: context.compromisedAssets.length,
  domainsBreached: context.domainsCompromised,
  maxPrivilegeAchieved: context.currentPrivilegeLevel,
  executiveSummary,                       // String narrative
  completedAt: new Date(),
  durationMs: Date.now() - startTime,
  // GTM v1.0 feature data
  replayManifest: replayManifest,         // Serialized manifest
  reachabilityChain: reachabilityChain,   // Reachability graph
  evidenceQualitySummary: finalQualityVerdict.summary,  // Quality counts
  detectionRules: allDetectionRules,      // DetectionRuleSet[]
})
```

**File**: `/Users/dre/prod/OdinForge-AI/server/storage.ts:1935`
- Database operation: `UPDATE breachChains SET ... WHERE id = chainId`

8. **Broadcast final graph update** (line 805):
   ```
   wsService.sendBreachChainGraphUpdate(chainId, "completed", unifiedGraph, enabledPhases.length, enabledPhases.length)
   ```

9. **Broadcast completion progress** (line 809):
   ```
   broadcastBreachProgress(chainId, "completed", 100, "Breach chain complete — {proven} proven, {rules} detection rules generated")
   ```

10. **Record Prometheus metrics** (lines 813–827):
    - `recordEngagementComplete(durationMs)`
    - `recordDetectionRules(count)`
    - For each quality tier: `recordFindingQuality(quality)`
    - `pivotDepthMax.set(depth)`
    - `evidenceQualityRatio.set(provenCount / totalFindings)`

11. **Clean up module-level stores** (lines 821–822):
    - `phase1AEvidenceStore.delete(chainId)` — Free memory from Phase 1A raw evidence
    - `chainEmitterStore.delete(chainId)` — Free emitter instance

12. **Auto-generate Purple Team findings** (line 830):
    - `createPurpleTeamFindingsFromChain(chainId, organizationId, phaseResults)`
    - Creates internal attack simulation findings

13. **Auto-Remediation: Generate fix proposals** (line 835):
    - `generateFixProposalsForChain(chainId, finalQualityVerdict)`
    - **File**: `/Users/dre/prod/OdinForge-AI/server/services/remediation/pr-automation-service.ts`

14. **v3.0 Continuous Exposure: Append risk snapshot** (lines 840–850):
    - `appendRiskSnapshot(chainId, { score, nodeCount, criticalPathLength, completedAt })`
    - `initializeSla(chainId, overallRiskScore)`
    - Tracks risk over time for SLA management

**On Error** (lines 851–864):
- If any error occurs, call `storage.updateBreachChain(chainId, { status: "failed", currentContext: context, phaseResults })`
- Broadcast failure: `broadcastBreachProgress(chainId, "failed", 0, "Breach chain failed: {error}")`

---

## PATH 3: EVIDENCE CONSTRUCTION

Evidence is constructed **at the moment of finding creation**, not post-hoc. Each phase creates findings with `source` and `evidenceQuality` fields inline:

### HTTP Evidence Creation (Phase 1–2)
- **Location**: Per phase executor when creating findings
- **Example** (Phase 1A, line 1575):
  ```
  findings.push({
    id: fid,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    technique: finding.exploitChain,
    source: "active_exploit_engine",
    evidenceQuality: "proven",           // SET HERE
    statusCode: activeExploitResult.response.statusCode,  // Real HTTP evidence
    responseBody: activeExploitResult.response.body,      // Real HTTP response
  })
  ```

### RealFinding Factory (conditional)
- **File**: `/Users/dre/prod/OdinForge-AI/server/lib/real-finding.ts`
- **Factories**:
  - `RealFinding.fromHttpEvidence({ severity, title, description, technique, source, evidence: RealHttpEvidence[] })` (line 45)
    - Throws if `evidence.length === 0`
    - Sets `evidenceQuality: "proven"`
  - `RealFinding.fromRealExecution({ severity, title, description, technique, source, statusCode, responseBody })` (line 81)
    - Sets `evidenceQuality: (statusCode > 0 ? "proven" : "corroborated")`
  - `RealFinding.synthesis({ severity, title, description, technique })` (line 110)
    - Sets `evidenceQuality: "inferred"`, `source: "impact_synthesis"`
    - Title gets `[SYNTHESIS]` prefix

### Evidence Quality Gate (line 600 per phase, line 777 final)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/evidence-quality-gate.ts:80`

```
class EvidenceQualityGate {
  evaluate(finding: EvaluatedFinding): QualityVerdict {
    // 0. Pre-validation: warn on missing source field
    IF !finding.source {
      hasRealEvidence = hasRealHttpEvidence(finding) ||
                        hasRealProtocolAuthSuccess(finding) ||
                        isRealAttemptWithFailure(finding)
      IF !hasRealEvidence {
        LOG ERROR: "Finding has no source and no real evidence, classifying as UNVERIFIABLE"
        RETURN { quality: UNVERIFIABLE, passed: false, ... }
      }
    }

    // 1. Real HTTP evidence check: statusCode + responseBody
    IF finding.statusCode && finding.responseBody {
      RETURN { quality: PROVEN, passed: true, ... }
    }

    // 2. Real protocol auth evidence check: SMB, SSH, RDP, WinRM, LDAP success
    IF finding.evidenceType IN REAL_AUTH_EVIDENCE_TYPES {
      RETURN { quality: finding.success ? PROVEN : CORROBORATED, passed: true, ... }
    }

    // 3. Real attempt with failure: HTTP request made, explicit failure
    IF finding.success === false && finding.statusCode {
      RETURN { quality: CORROBORATED, passed: true, ... }
    }

    // 4. LLM inference only: no real evidence
    IF finding.source === "llm_inference" {
      RETURN { quality: INFERRED, passed: false, ... }
    }

    // Fallback: UNVERIFIABLE
    RETURN { quality: UNVERIFIABLE, passed: false, ... }
  }

  evaluateBatch(findings: EvaluatedFinding[]): BatchVerdict {
    passed: QualityVerdict[] = []
    failed: QualityVerdict[] = []
    
    FOR each finding {
      verdict = evaluate(finding)
      IF verdict.passed {
        passed.push(verdict)
      } ELSE {
        failed.push(verdict)
      }
    }

    RETURN {
      passed,
      failed,
      summary: {
        proven: passed.filter(v => v.quality === PROVEN).length,
        corroborated: passed.filter(v => v.quality === CORROBORATED).length,
        inferred: failed.filter(v => v.quality === INFERRED).length,
        unverifiable: failed.filter(v => v.quality === UNVERIFIABLE).length,
        total: findings.length,
        passRate: passed.length / findings.length
      }
    }
  }
}
```

### Report Integrity Filter

**File**: `/Users/dre/prod/OdinForge-AI/server/services/report-integrity-filter.ts`

```
class ReportIntegrityFilter {
  filter(findings: EvaluatedFinding[]): FilteredFindings {
    customerFindings: EvaluatedFinding[] = []
    internalFindings: EvaluatedFinding[] = []
    
    FOR each finding {
      IF finding.evidenceQuality === "proven" || finding.evidenceQuality === "corroborated" {
        customerFindings.push(finding)
      } ELSE {
        internalFindings.push(finding)  // INFERRED + UNVERIFIABLE suppressed from customer
      }
    }

    RETURN {
      customerFindings,
      internalFindings,
      audit: {
        totalInput: findings.length,
        customerOutput: customerFindings.length,
        suppressed: internalFindings.length,
        proven: findings.filter(f => f.evidenceQuality === "proven").length,
        corroborated: findings.filter(f => f.evidenceQuality === "corroborated").length,
        inferred: findings.filter(f => f.evidenceQuality === "inferred").length,
        unverifiable: findings.filter(f => f.evidenceQuality === "unverifiable").length,
      }
    }
  }
}
```

---

## PATH 4: ENGAGEMENT PACKAGE GENERATION

### Seal Route

**File**: `/Users/dre/prod/OdinForge-AI/server/routes.ts:8105`

**Handler**: `POST /api/breach-chains/:id/seal`

**Middleware Stack**:
- `apiRateLimiter`
- `uiAuthMiddleware` (verifies JWT, sets `req.uiUser`)
- `requirePermission("reports:generate")`

**Route Handler** (lines 8105–8144):

1. Fetch chain: `chain = await storage.getBreachChain(req.params.id)` (storage.ts:1916)
2. Validate not running: `IF chain.status === "running" RETURN 400`
3. Import seal functions:
   - `sealEngagementPackage` from `./services/engagement/engagement-package`
   - `deactivateKeysForEngagement` from `./services/engagement/engagement-api-keys`
   - `generateReengagementOffer` from `./services/engagement/reengagement-offer`
4. Seal package: `pkg = sealEngagementPackage(chain, sealedBy)` (line 8118)
5. Create seal event: `sealEvent = createSealEvent(pkg)` (line 8119)
6. Deactivate API keys: `deactivatedKeys = deactivateKeysForEngagement(chain.id, "sealed")` (line 8122)
7. Generate reengagement offer: `offer = generateReengagementOffer(chain, pkg)` (line 8125)
8. Return 200 JSON response with package, sealEvent, deactivatedKeys, reengagementOffer

### Seal Function

**File**: `/Users/dre/prod/OdinForge-AI/server/services/engagement/engagement-package.ts:201`

```
export function sealEngagementPackage(chain: BreachChain, sealedBy: string): EngagementPackage {
  packageId = "pkg-" + uuid.slice(0, 12)

  // 1. Generate CISO Report
  cisoReport = generateCISOReport(chain)  // File: ./ciso-report.ts
  // Returns: { riskGrade: A-F, narrative: string, businessImpact: string, ... }

  // 2. Generate Engineer Report
  engineerReport = generateEngineerReport(chain)  // File: ./engineer-report.ts
  // Returns: { chainTrace: [...], httpEvidence: [...], remediationDiffs: [...], ... }

  // 3. Build Evidence JSON
  evidenceJSON = buildEvidenceJSON(chain)  // Lines 115–159
  // Extract phase results → all findings
  phases = chain.phaseResults as BreachPhaseResult[] || []
  allFindings = phases.flatMap(p => p.findings.map(f => ({ ...f, _phase: p.phaseName })))
  
  // Evaluate through Evidence Quality Gate
  evaluated = allFindings.map(f => ({ ...f, id: f.id, severity: f.severity, ... }))
  filtered = reportIntegrityFilter.filter(evaluated)  // Filter out INFERRED/UNVERIFIABLE
  
  findings = filtered.customerFindings.map(f => ({
    id, phase, severity, title, description, source, evidenceQuality,
    technique, mitreId, statusCode, responseBodyPreview: body.slice(0, 500)
  }))
  
  RETURN {
    engagementId: chain.id,
    generatedAt: now,
    evidenceStandard: "ADR-001: Sealed EvidenceContract — PROVEN and CORROBORATED only",
    findings,
    auditSummary: {
      totalInput: filtered.audit.totalInput,
      customerOutput: filtered.audit.customerOutput,
      suppressed: filtered.audit.suppressed,
      proven, corroborated, inferred, unverifiable
    }
  }

  // 4. Build Defender's Mirror rules
  mirrorRules = buildDefendersMirror(chain)  // Lines 163–191
  // For each proven/corroborated finding → generate detection rule
  rules = []
  FOR each phase OF phases {
    FOR each finding OF phase.findings {
      IF finding.evidenceQuality NOT IN ["inferred", "unverifiable"] {
        evidence = { id, engagementId, phase, techniqueCategory, statusCode, success: true }
        ruleSet = defendersMirror.generateFromEvidence(evidence)
        rules.push(ruleSet)
      }
    }
  }
  RETURN rules

  // 5. Generate Breach Chain Replay HTML
  replayHTML = generateReplayHTML(chain)  // File: ./breach-chain-replay.ts
  // Returns: self-contained HTML visualization of breach chain

  // 6. Compute SHA-256 integrity hashes
  cisoReportHash = sha256(JSON.stringify(cisoReport))
  engineerReportHash = sha256(JSON.stringify(engineerReport))
  evidenceJSONHash = sha256(JSON.stringify(evidenceJSON))
  defendersMirrorHash = sha256(JSON.stringify(mirrorRules))
  replayHTMLHash = sha256(replayHTML)
  packageHash = sha256(
    cisoReportHash + engineerReportHash + evidenceJSONHash + 
    defendersMirrorHash + replayHTMLHash
  )

  config = chain.config as any
  phases = chain.phaseResults || []

  RETURN {
    packageId,
    engagementId: chain.id,
    organizationId: chain.organizationId,
    sealedAt: now,
    sealedBy,
    
    components: {
      cisoReport,
      engineerReport,
      evidenceJSON,
      defendersMirror: mirrorRules,
      breachChainReplayHTML: replayHTML
    },
    
    integrity: {
      cisoReportHash,
      engineerReportHash,
      evidenceJSONHash,
      defendersMirrorHash,
      replayHTMLHash,
      packageHash
    },
    
    metadata: {
      targetAssets: chain.assetIds,
      executionMode: config.executionMode,
      phasesExecuted: phases.filter(p => p.status === "completed").length,
      totalPhases: 6,
      riskGrade: ...,  // Computed from overallRiskScore
      overallRiskScore: chain.overallRiskScore,
      totalFindings: phases.flatMap(p => p.findings).length,
      customerFindings: filtered.audit.customerOutput,
      durationMs: chain.durationMs,
      reengagementEligible: ...,
      reengagementWindowDays: 90
    }
  }
}

function createSealEvent(pkg: EngagementPackage): SealEvent {
  RETURN {
    packageId: pkg.packageId,
    engagementId: pkg.engagementId,
    sealedAt: pkg.sealedAt,
    sealedBy: pkg.sealedBy,
    componentHashes: pkg.integrity
  }
}
```

### CISO Report Generator

**File**: `/Users/dre/prod/OdinForge-AI/server/services/engagement/ciso-report.ts`

```
export function generateCISOReport(chain: BreachChain): CISOReport {
  // Extract summary data from chain
  score = chain.overallRiskScore || 0
  riskGrade = scoreToGrade(score)  // A-F mapping
  
  // Build narrative from breach chain
  narrative = buildNarrative(chain)  // Plain-English story of breach progression
  
  // Extract business impact findings
  businessImpact = extractBusinessImpact(chain)  // Cost, regulatory, reputational
  
  // Compliance mappings
  complianceMappings = mapFindingsToFrameworks(chain)  // PCI-DSS, HIPAA, SOC2, etc.
  
  RETURN {
    riskGrade,
    narrative,
    businessImpact,
    complianceMappings,
    executiveSummary: chain.executiveSummary,
    recommendations: [...],
    generatedAt: now
  }
}
```

### Engineer Report Generator

**File**: `/Users/dre/prod/OdinForge-AI/server/services/engagement/engineer-report.ts`

```
export function generateEngineerReport(chain: BreachChain): EngineerReport {
  // 1. Chain trace: execution order of phases + findings per phase
  chainTrace = chain.phaseResults.map(pr => ({
    phase: pr.phaseName,
    status: pr.status,
    findings: pr.findings.map(f => ({
      id, severity, title, technique, evidenceQuality
    })),
    credentials: pr.outputContext.credentials.length,
    assets: pr.outputContext.compromisedAssets.length
  }))
  
  // 2. HTTP evidence: raw requests/responses for PROVEN findings
  httpEvidence = []
  FOR each phase OF chain.phaseResults {
    FOR each finding OF phase.findings {
      IF finding.evidenceQuality === "proven" && finding.statusCode {
        httpEvidence.push({
          findingId: finding.id,
          method: "POST",  // Inferred from payload
          url: finding.targetUrl || chain.assetIds[0],
          statusCode: finding.statusCode,
          responsePreview: finding.responseBody.slice(0, 1000),
          curlCommand: buildCurlCommand(finding)
        })
      }
    }
  }
  
  // 3. Remediation diffs: for each phase, show fixes
  remediationDiffs = []
  FOR each phase OF chain.phaseResults {
    FOR each finding OF phase.findings.filter(f => f.severity === "critical" || "high") {
      // Import remediation templates per technique
      templates = getRemediationTemplate(finding.technique)
      diff = {
        findingId: finding.id,
        affected: finding.title,
        before: templates.before,
        after: templates.after,
        effort: templates.effort  // estimated time to fix
      }
      remediationDiffs.push(diff)
    }
  }
  
  RETURN {
    chainTrace,
    httpEvidence,
    remediationDiffs,
    generatedAt: now
  }
}
```

### Breach Chain Replay Generator

**File**: `/Users/dre/prod/OdinForge-AI/server/services/engagement/breach-chain-replay.ts`

```
export function generateReplayHTML(chain: BreachChain): string {
  // Build self-contained HTML with embedded JSON manifest
  // Frontend renders interactive step-by-step visualization
  
  manifest = buildReplayManifest(chain)
  
  html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Breach Chain Replay — ${chain.name}</title>
      <style>...</style>
    </head>
    <body>
      <div id="app"></div>
      <script>
        const manifest = ${JSON.stringify(manifest)};
        // Initialize replay UI with manifest
      </script>
    </body>
    </html>
  `
  
  RETURN html
}

export function buildReplayManifest(chain: BreachChain): ReplayManifest {
  events = []
  timeline = []
  
  FOR each phase OF chain.phaseResults {
    FOR each finding OF phase.findings {
      events.push({
        id: finding.id,
        type: "finding_discovered",
        phase: phase.phaseName,
        timestamp: ...,
        finding: { severity, title, description, technique, evidenceQuality }
      })
    }
    
    FOR each cred OF phase.outputContext.credentials {
      events.push({
        id: cred.id,
        type: "credential_harvested",
        phase: phase.phaseName,
        timestamp: ...,
        credential: { type, username, accessLevel, source }
      })
    }
  }
  
  RETURN {
    engagementId: chain.id,
    generatedAt: now,
    events,
    timeline,
    totalDuration: chain.durationMs
  }
}
```

### Engagement API Keys (ADR-009)

**File**: `/Users/dre/prod/OdinForge-AI/server/services/engagement/engagement-api-keys.ts`

```
export function deactivateKeysForEngagement(engagementId: string, reason: string): number {
  // Mark all API keys created for this engagement as deactivated_on_seal
  // Cannot be used to access engagement data after seal
  
  keys = getKeysForEngagement(engagementId)  // Fetch from DB
  
  FOR each key OF keys {
    await storage.updateEngagementApiKey(key.id, {
      status: "deactivated",
      deactivatedAt: now,
      deactivationReason: reason
    })
  }
  
  RETURN keys.length
}
```

---

## PATH 5: REPORT RENDERING (LEGACY)

**Route Entry Point**

**File**: `/Users/dre/prod/OdinForge-AI/server/routes.ts:1795`

**Handler**: `POST /api/reports/generate`

**Middleware Stack**:
- `reportRateLimiter`
- `uiAuthMiddleware`
- `requirePermission("reports:generate")`

**Route Handler** (lines 1795–2191):

1. Extract request body: `type, format, from, to, framework, organizationId, evaluationId, breachChainId`
2. If `breachChainId` provided:
   - `chain = await storage.getBreachChain(breachChainId)`
   - Generate report from chain data (line 1800+)
3. Otherwise:
   - Fetch evaluations/results from DB
   - Build report from traditional evaluation data
4. Call `reportGenerator.generateReport()`:
   ```
   report = await reportGenerator.generateReport({
     type: "executive" | "technical" | "compliance",
     format: "json" | "pdf",
     findings: [...],
     chainData: chain,
     complianceFramework: framework
   })
   ```
   - **File**: `/Users/dre/prod/OdinForge-AI/server/services/report-generator.ts:70`
5. Store report in DB: `storage.createReport({ type, format, content, ... })`
6. Return 200 JSON or PDF blob

---

## PATH 6: WEBSOCKET / PROGRESS EVENTS

### Event Broadcasting

**Function**: `broadcastBreachProgress(chainId, phase, progress, message)`

**File**: `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts:3544`

```
function broadcastBreachProgress(
  chainId: string,
  phase: string,
  progress: number,
  message: string
): void {
  wsService.broadcastToChannel(`breach_chain:${chainId}`, {
    type: "breach_chain_progress",
    chainId,
    phase,
    progress,
    message,
    timestamp: new Date().toISOString(),
  })
}
```

**Called From**:
- Line 267: Initial start
- Line 534: Phase skipped
- Line 547: Phase starting
- Line 654: Phase complete
- Line 809: Breach chain complete
- Line 860: Breach chain failed
- Line 879: Breach chain aborted

### WebSocket Service

**File**: `/Users/dre/prod/OdinForge-AI/server/services/websocket.ts`

```
class WebSocketService {
  broadcastToChannel(channel: string, message: any): void {
    // Send message to all clients subscribed to this channel
    // Channel format: "breach_chain:{chainId}"
    // Message type: "breach_chain_progress"
  }
  
  sendBreachChainGraphUpdate(
    chainId: string,
    status: "running" | "completed" | "failed",
    graph: AttackGraph,
    completedPhases: number,
    totalPhases: number
  ): void {
    // Send unified attack graph update to all clients
  }
}
```

### Breach Event Emitter (GTM v1.0)

**File**: `/Users/dre/prod/OdinForge-AI/server/lib/breach-event-emitter.ts`

**Instance per engagement**: Created at line 453 of breach-orchestrator.ts

```
class BreachEventEmitter {
  nodeAdded(params: {
    kind: BreachNodeKind,
    phase: BreachPhaseId,
    phaseIndex: number,
    label: string,
    detail: string,
    severity: BreachNodeSeverity,
    technique?: string,
    evidenceRef?: string,
    curlCommand?: string,
    targetUrl?: string,
    statusCode?: number,
    responseSnippet?: string,
    timestamp: string
  }): string {
    // Fire "breach_node_added" event
    // Emit via wsService.broadcastToChannel(`breach_chain:${chainId}`, { type: "breach_node_added", ... })
    // Return nodeId
  }
  
  edgeAdded(
    fromNodeId: string,
    toNodeId: string,
    confirmed: boolean,
    label?: string
  ): void {
    // Fire "breach_edge_added" event
    // Shows connection between nodes (e.g., exploit → credential → lateral movement)
  }
  
  surfaceSignal(
    kind: SurfaceSignalKind,  // "stack" | "endpoint" | "cloud" | "secret" | "port" | "domain"
    label: string,
    detail: string
  ): void {
    // Fire "breach_surface_signal" event
    // Called during active exploit crawl to show discovered surface (line 1519–1527)
  }
  
  reasoning(
    phase: BreachPhaseId,
    agentId: string,
    decision: string,
    rationale: string,
    outcome: "confirmed" | "failed" | "pivoting" | "investigating",
    linkedNodeId?: string,
    techniqueTried?: string
  ): void {
    // Fire "breach_reasoning" event
    // Shows AI agent's decision-making process
  }
  
  phaseTransition(
    fromPhase: BreachPhaseId | null,
    toPhase: BreachPhaseId,
    phaseIndex: number,
    findingCount: number,
    credentialCount: number
  ): void {
    // Fire "breach_phase_transition" event
  }
}
```

### Frontend Subscription

The frontend subscribes to `breach_chain:{chainId}` and receives:
- `breach_chain_progress` events (phase progress)
- `breach_node_added` events (new finding, credential, asset)
- `breach_edge_added` events (exploitation path, lateral movement path)
- `breach_surface_signal` events (discovered endpoint, secret, etc.)
- `breach_reasoning` events (AI agent decision)
- `breach_phase_transition` events (phase completed)
- `breach_chain_graph_update` events (unified attack graph)

These events fire **in real-time** as the phase executors discover things, enabling a live reactive UI.

---

## PATH 7: AUTH MIDDLEWARE

### uiAuthMiddleware

**File**: `/Users/dre/prod/OdinForge-AI/server/services/ui-auth.ts:206`

**Execution for every authenticated route:**

```
function uiAuthMiddleware(
  req: UIAuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  // 1. Extract token from Authorization header
  authHeader = req.headers.authorization
  IF !authHeader || !authHeader.startsWith("Bearer ") {
    RES.status(401).json({ error: "Unauthorized" })
    RETURN
  }

  token = authHeader.slice(7)

  // 2. Verify access token asynchronously
  verifyUIAccessToken(token)  // Lines 114–138
    .then(async (payload) => {
      IF !payload {
        RES.status(401).json({ error: "Unauthorized", message: "Invalid or expired token" })
        RETURN
      }

      // 3. Attach decoded payload to request
      req.uiUser = {
        userId: payload.userId,
        tenantId: payload.tenantId,
        organizationId: payload.organizationId,
        email: payload.email,
        roleId: payload.roleId,
        tokenVersion: payload.tokenVersion
      }

      // 4. Set RLS (Row-Level Security) context
      await setTenantContext(payload.organizationId)

      // 5. Clear RLS context when response finishes
      res.on("finish", () => {
        clearTenantContext()  // Async cleanup
      })

      // 6. Update user's lastActivityAt in DB
      storage.updateUIUser(payload.userId, { lastActivityAt: new Date() })

      // 7. Call next middleware
      next()
    })
}
```

### verifyUIAccessToken

**File**: `/Users/dre/prod/OdinForge-AI/server/services/ui-auth.ts:114`

```
export async function verifyUIAccessToken(token: string): Promise<UIJWTPayload | null> {
  TRY {
    // 1. Verify JWT signature and expiration
    { payload } = await jwtVerify(token, UI_JWT_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE
    })

    uiPayload = payload as unknown as UIJWTPayload

    // 2. Check token type
    IF uiPayload.type !== "access" {
      RETURN null
    }

    // 3. Fetch user from DB
    user = await storage.getUIUser(uiPayload.userId)

    // 4. Verify token version matches (prevents use of revoked tokens)
    IF !user || user.tokenVersion !== uiPayload.tokenVersion {
      RETURN null
    }

    // 5. Check user status is active
    IF user.status !== "active" {
      RETURN null
    }

    RETURN uiPayload
  } CATCH {
    RETURN null
  }
}
```

### requirePermission

**File**: `/Users/dre/prod/OdinForge-AI/server/services/ui-auth.ts` (not shown in excerpt)

Returns middleware that:
1. Fetches user's role from DB using `req.uiUser?.roleId`
2. Retrieves role's permissions: `getPermissionsForDbRole(role)`
3. **File**: `/Users/dre/prod/OdinForge-AI/shared/schema.ts` (defines 67 permission strings and 8 roles)
4. Checks if permission exists in role
5. If not found, returns 403 Forbidden

---

## PATH 8: STORAGE WRITES — COMPLETE LIST

All `storage.updateBreachChain()` calls in execution order:

| Line | Timing | Data Written |
|------|--------|--------------|
| 250 | Validation fail | `status: "failed", completedAt` |
| 262 | Run start | `status: "running", startedAt` |
| 391 | Mesh fail | `status: failed, ...` |
| 413 | Mesh fail | `status: failed` |
| 502 | Timeout | `status: "failed", currentContext, phaseResults` |
| 529 | Gate skip | `phaseResults, currentContext` |
| 542 | Phase start | `currentPhase: phaseName, progress` |
| 691 | Phase paused | `status: "paused", phaseResults, currentContext` |
| 721 | User pause | `status: "paused"` |
| 782 | Completion | `status: "completed", progress: 100, currentPhase: null, phaseResults, currentContext, unifiedAttackGraph, overallRiskScore, totalCredentialsHarvested, totalAssetsCompromised, domainsBreached, maxPrivilegeAchieved, executiveSummary, completedAt, durationMs, replayManifest, reachabilityChain, evidenceQualitySummary, detectionRules` |
| 855 | Error | `status: "failed", currentContext, phaseResults` |
| 873 | Resume | `status: "running"` |
| 878 | Abort | `status: "aborted"` |

### Database Tables Written

1. **breachChains** (primary table)
   - Status, progress, phase data
   - Phase results with all findings
   - Attack graph, context
   - Timestamps
   - Metadata (risk score, credentials, assets)

2. **breachChainAlerts** (v3.0 Continuous Exposure)
   - Created by `appendRiskSnapshot()` / `initializeSla()`

3. **uiRefreshTokens**
   - Created when user logs in (auth route, not breach chain)
   - Updated/revoked on logout

4. **UIUser** (lastActivityAt)
   - Updated by `uiAuthMiddleware` after each authenticated request
   - Tracks user activity for session management

5. **Purple Team Findings** (Auto-generated)
   - Created by `createPurpleTeamFindingsFromChain()` at line 830
   - Internal findings for benchmarking against AI simulation

6. **Fix Proposals**
   - Created by `generateFixProposalsForChain()` at line 835
   - Remediation suggestions for each finding

---

## SUMMARY: COMPLETE CALL GRAPH

```
POST /api/breach-chains (routes.ts:7686)
├─ evaluationRateLimiter
├─ uiAuthMiddleware (ui-auth.ts:206)
│  ├─ verifyUIAccessToken (ui-auth.ts:114)
│  ├─ setTenantContext (RLS setup)
│  └─ storage.updateUIUser(lastActivityAt)
├─ requirePermission("evaluations:create")
├─ governanceEnforcement.canStartOperation()
├─ storage.createBreachChain() [DB WRITE #1]
└─ runBreachChain(chainId) [FIRE & FORGET]
   ├─ storage.getBreachChain()
   ├─ validateLiveTarget()
   ├─ storage.updateBreachChain(status: "running") [DB WRITE #2]
   ├─ broadcastBreachProgress(starting)
   ├─ createBreachEventEmitter(chainId)
   ├─ recordEngagementStart() [Prometheus]
   │
   └─ FOR EACH enabledPhase IN [phase1..phase6]:
      ├─ checkPhaseGate()
      ├─ storage.updateBreachChain(currentPhase, progress)
      ├─ replayRecorder.recordPhaseStart()
      ├─ getPhaseExecutor(phaseName)
      │
      ├─ executeApplicationCompromise() [PHASE 1, lines 1464–2042]
      │  ├─ resolveAssetUrl(assetId)
      │  ├─ runActiveExploitEngine(exploitTarget) [active-exploit-engine.ts]
      │  │  ├─ crawl endpoints
      │  │  ├─ execute payloads
      │  │  └─ validate findings
      │  ├─ phase1AEvidenceStore.set(chainId, validated)
      │  ├─ mapToBreachPhaseContext(activeExploitResult)
      │  ├─ Create findings, credentials, assets
      │  ├─ microOrchestrator.dispatch(agentSpecs) [MicroAgentOrchestrator]
      │  └─ buildPhaseResult(phase1, ...)
      │
      ├─ executeCredentialExtraction() [PHASE 2, lines 2046–2156]
      │  ├─ Filter phase 1 credentials
      │  ├─ phase1AEvidenceStore.get(chainId)
      │  ├─ Parse HTTP response bodies with CREDENTIAL_PATTERNS regex
      │  ├─ credentialStore.create()
      │  ├─ Create findings with evidenceQuality: "proven"
      │  ├─ phase1AEvidenceStore.delete(chainId)
      │  └─ buildPhaseResult(phase2, ...)
      │
      ├─ executeCloudIAMEscalation() [PHASE 3, lines 2162–2353]
      │  ├─ Filter cloud credentials
      │  ├─ awsPentestService.analyzeIAMPrivilegeEscalation()
      │  ├─ Create findings + escalated credentials
      │  └─ buildPhaseResult(phase3, ...)
      │
      ├─ executeContainerK8sBreakout() [PHASE 4, lines 2354–2713]
      │  ├─ Filter K8s credentials
      │  ├─ kubernetesPentestService.analyzeK8sPrivilegeEscalation()
      │  ├─ Create escape findings
      │  └─ buildPhaseResult(phase4, ...)
      │
      ├─ executeLateralMovement() [PHASE 5, lines 2714–2853]
      │  ├─ PivotQueue(credentials)
      │  ├─ LateralMovementSubAgent.execute() [per-node auth attempts]
      │  ├─ Create findings from pivot results
      │  └─ buildPhaseResult(phase5, ...)
      │
      ├─ executeImpactAssessment() [PHASE 6, lines 2859–2926]
      │  ├─ Aggregate breach impact
      │  ├─ Create SYNTHESIS findings (marked [SYNTHESIS], evidenceQuality: "inferred")
      │  └─ buildPhaseResult(phase6, ...)
      │
      ├─ mergeContexts(context, phaseResult.outputContext)
      ├─ getCredentialBus().publish(chainId, cred) [per new credential]
      ├─ replayRecorder.recordPhaseComplete()
      ├─ evidenceQualityGate.evaluateBatch(phaseFindings)
      │  ├─ Classify each finding: PROVEN | CORROBORATED | INFERRED | UNVERIFIABLE
      │  └─ Return BatchVerdict { passed, failed, summary }
      ├─ defendersMirror.generateFromEvidence() [per high-severity finding]
      ├─ breachEmitter.phaseTransition()
      ├─ recordPhaseMetric(phaseName, duration, status)
      ├─ broadcastBreachProgress(phase, progress, message)
      │
      └─ [END FOR]
   │
   ├─ buildAttackGraph(chainId, phaseResults, context) [Unified graph]
   ├─ computeRiskScore(phaseResults) [Intelligent v3.0 scoring]
   ├─ buildReachabilityChain(chainId, entryHost, pivots) [GTM v1.0]
   ├─ allFindings = flatten all findings from all phases
   ├─ evidenceQualityGate.evaluateBatch(allFindings) [FINAL quality check]
   ├─ defendersMirror.getRulesForEngagement(chainId)
   ├─ replayRecorder.finalize() [ReplayManifest]
   ├─ computeExecutiveSummary(chain, phaseResults, riskScore)
   ├─ storage.updateBreachChain(status: "completed", ...) [DB WRITE #3]
   │  └─ phaseResults, currentContext, unifiedAttackGraph, overallRiskScore,
   │     totalCredentialsHarvested, totalAssetsCompromised, domainsBreached,
   │     maxPrivilegeAchieved, executiveSummary, completedAt, durationMs,
   │     replayManifest, reachabilityChain, evidenceQualitySummary, detectionRules
   ├─ wsService.sendBreachChainGraphUpdate(chainId, "completed", graph, ...)
   ├─ broadcastBreachProgress(chainId, "completed", 100, ...)
   ├─ recordEngagementComplete(durationMs) [Prometheus]
   ├─ recordDetectionRules(count) [Prometheus]
   ├─ recordFindingQuality(quality) × summary.proven|corroborated|inferred|unverifiable [Prometheus]
   ├─ phase1AEvidenceStore.delete(chainId)
   ├─ chainEmitterStore.delete(chainId)
   ├─ createPurpleTeamFindingsFromChain() [background]
   ├─ generateFixProposalsForChain(chainId, qualityVerdict) [background]
   └─ appendRiskSnapshot(chainId, {...}) + initializeSla(chainId, score) [v3.0 Continuous Exposure]

POST /api/breach-chains/:id/seal (routes.ts:8105)
├─ apiRateLimiter
├─ uiAuthMiddleware
├─ requirePermission("reports:generate")
├─ storage.getBreachChain(chainId)
├─ sealEngagementPackage(chain, sealedBy) [engagement-package.ts:201]
│  ├─ generateCISOReport(chain) [ciso-report.ts]
│  ├─ generateEngineerReport(chain) [engineer-report.ts]
│  ├─ buildEvidenceJSON(chain)
│  │  ├─ flatten all findings from phaseResults
│  │  ├─ reportIntegrityFilter.filter(findings) [Suppress INFERRED+UNVERIFIABLE]
│  │  └─ Map to EvidenceJSONFinding[]
│  ├─ buildDefendersMirror(chain) [Generate detection rules per finding]
│  ├─ generateReplayHTML(chain) [breach-chain-replay.ts]
│  │  └─ buildReplayManifest(chain)
│  ├─ sha256(cisoReport, engineerReport, evidenceJSON, mirrorRules, replayHTML)
│  └─ RETURN EngagementPackage { packageId, components, integrity, metadata }
├─ createSealEvent(pkg)
├─ deactivateKeysForEngagement(chainId, "sealed")
├─ generateReengagementOffer(chain, pkg)
└─ RES.json({ package, sealEvent, deactivatedApiKeys, reengagementOffer })

GET /api/breach-chains/:id/package (routes.ts:8147)
├─ apiRateLimiter
├─ uiAuthMiddleware
├─ requirePermission("reports:export")
├─ storage.getBreachChain(chainId)
├─ sealEngagementPackage(chain, "readonly-generation")
└─ RES.json(pkg) [EngagementPackage]
```

---

## KEY INSIGHTS

1. **No database writes during phase execution** — Storage.updateBreachChain is called BETWEEN phases, not during. All phase data is constructed in memory, merged into context, then written as batch at the end.

2. **Evidence quality is determined at creation time**, not post-hoc. Each finding has `source` and `evidenceQuality` fields set when `findings.push()` is called by the phase executor.

3. **Report integrity filter runs TWICE**: once per-phase (line 600) and once final (line 777). This ensures INFERRED/UNVERIFIABLE findings are flagged early, and suppressed from customer reports.

4. **Engagement package sealing is read-only** — `sealEngagementPackage()` does not write to the database. It only reads `chain` and generates the 5 components in memory. The seal event is created but not persisted by this function.

5. **WebSocket events fire DURING phase execution**, not after. The `breachEmitter` and `broadcastBreachProgress()` calls enable real-time UI updates.

6. **Auth is enforced at every route** — `uiAuthMiddleware` decodes JWT, verifies token version against DB, sets RLS context, and updates `lastActivityAt`. RLS ensures multi-tenant isolation.

7. **Phase executors are pure functions** (except for DB reads) — they take chain + context, return BreachPhaseResult. Context is merged between phases via `mergeContexts()`, enabling credential carry-forward and asset accumulation.

8. **Cleanup is explicit** — `phase1AEvidenceStore.delete()` and `chainEmitterStore.delete()` free memory after use. No dangling references.

---

Absolute file paths for reference:
- `/Users/dre/prod/OdinForge-AI/server/routes.ts` — All route handlers
- `/Users/dre/prod/OdinForge-AI/server/services/breach-orchestrator.ts` — Orchestrator + all 6 phase executors
- `/Users/dre/prod/OdinForge-AI/server/storage.ts` — All DB operations
- `/Users/dre/prod/OdinForge-AI/server/services/ui-auth.ts` — Auth middleware
- `/Users/dre/prod/OdinForge-AI/server/services/evidence-quality-gate.ts` — Finding classification
- `/Users/dre/prod/OdinForge-AI/server/services/engagement/engagement-package.ts` — Package sealing
- `/Users/dre/prod/OdinForge-AI/server/lib/breach-event-emitter.ts` — Real-time events
- `/Users/dre/prod/OdinForge-AI/server/lib/real-finding.ts` — Finding factories (ADR-001)
