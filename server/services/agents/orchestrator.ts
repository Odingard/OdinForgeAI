import type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
  SafetyDecision,
  ExploitFindings,
  LateralFindings,
  BusinessLogicFindings,
  MultiVectorFindings,
  ImpactFindings,
  EnhancedBusinessLogicFindings,
  ConfidenceBreakdown,
  ExploitState,
} from "./types";
import type { AdversaryProfile, EvaluationPhaseProgress, DebateSummary } from "@shared/schema";
import { runDebateModule, filterVerifiedFindings, type DebateResult } from "./debate-module";
import { applyNoiseReduction, type NoiseReductionResult } from "./noise-reduction";
import { runExploitAgent } from "./exploit";
import { synthesizeResults } from "./synthesizer";
import { createFallbackGraph } from "./graph-synthesizer";
import { generateEvidenceFromAnalysis } from "./evidence-collector";
import { generateDeterministicScore } from "./scoring-engine";
import { parseCVSSVector } from "../cvss-parser";
import { getEPSSScores } from "../threat-intel/epss-client";
import { AevTelemetryRecorder } from "../aev-telemetry";
import { runWithHeartbeat, updateAgentHeartbeat } from "./heartbeat-tracker";
import { withCircuitBreaker } from "./circuit-breaker";
import { wsService } from "../websocket";
import { storage } from "../../storage";
import { createAuditLogger } from "../audit-logger";
import { gateReconSuccess, gateExploitConfirmed } from "./pipeline-gates";
import { validateExploitFindings, type PolicyGuardianContext } from "./policy-guardian";

// Pipeline-level timeout: 10 minutes max for entire orchestration
// (Claude models need 30-60s per LLM call × 4 tiers of agents + overhead)
const PIPELINE_TIMEOUT_MS = 600_000;

// Per-agent circuit breaker timeout: must exceed Claude's ~60s response time
const AGENT_CB_TIMEOUT_MS = 180_000; // 3min — exploit agent's 12-turn loop needs this

// Timeout for PolicyGuardian check loops
const GUARDIAN_LOOP_TIMEOUT_MS = 15_000;

// Empty findings constants for circuit breaker fallbacks
const EMPTY_EXPLOIT_FINDINGS: ExploitFindings = {
  exploitable: false,
  exploitChains: [],
  cveReferences: [],
  misconfigurations: [],
};

const EMPTY_LATERAL_FINDINGS: LateralFindings = {
  pivotPaths: [],
  privilegeEscalation: [],
  tokenReuse: [],
};

const EMPTY_BL_FINDINGS: BusinessLogicFindings = {
  workflowAbuse: [],
  stateManipulation: [],
  raceConditions: [],
  authorizationBypass: [],
  criticalFlows: [],
};

const EMPTY_MV_FINDINGS: MultiVectorFindings = {
  findings: [],
  cloudFindings: [],
  iamFindings: [],
  saasFindings: [],
  shadowAdminIndicators: [],
  chainedAttackPaths: [],
};

const EMPTY_IMPACT_FINDINGS: ImpactFindings = {
  dataExposure: { types: [], severity: "low", estimatedRecords: "0" },
  financialImpact: { estimate: "Unknown", factors: [] },
  complianceImpact: [],
  reputationalRisk: "low",
};

// Phase tracking helper — persists phase progress to DB
async function updatePhase(
  evaluationId: string,
  phases: EvaluationPhaseProgress[],
  phaseName: string,
  update: Partial<EvaluationPhaseProgress>
): Promise<void> {
  const idx = phases.findIndex(p => p.phase === phaseName);
  if (idx >= 0) Object.assign(phases[idx], update);
  try {
    await storage.updateEvaluationPhaseProgress(evaluationId, phases);
  } catch (err) {
    console.warn(`[Orchestrator] Failed to persist phase progress for ${phaseName}:`, err);
  }
}

function initPhases(): EvaluationPhaseProgress[] {
  return [
    { phase: "recon", status: "pending" },
    { phase: "exploit", status: "pending" },
    { phase: "business_logic", status: "pending" },
    { phase: "lateral", status: "pending" },
    { phase: "impact", status: "pending" },
    { phase: "synthesis", status: "pending" },
    { phase: "finalization", status: "pending" },
  ];
}

export interface OrchestratorOptions {
  adversaryProfile?: AdversaryProfile;
  organizationId?: string;
  executionMode?: "safe" | "simulation" | "live";
  /** Skip writing phase progress to DB (used when orchestrator is called multiple times, e.g. simulation rounds) */
  skipPhaseTracking?: boolean;
  /** Scheduled scan ID for drift tracking (set by scan scheduler) */
  scheduledScanId?: string;
  /** Live-mode enforcement directive injected into all AI agent prompts (breach chain use) */
  breachDirective?: string;
}

export async function runAgentOrchestrator(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  evaluationId: string,
  onProgress?: ProgressCallback,
  options?: OrchestratorOptions
): Promise<OrchestratorResult> {
  // Wrap entire pipeline in a master timeout
  return Promise.race([
    runPipeline(assetId, exposureType, priority, description, evaluationId, onProgress, options),
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Pipeline timeout: ${PIPELINE_TIMEOUT_MS / 60_000} minutes exceeded`)),
        PIPELINE_TIMEOUT_MS
      )
    ),
  ]);
}

async function runPipeline(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  evaluationId: string,
  onProgress?: ProgressCallback,
  options?: OrchestratorOptions
): Promise<OrchestratorResult> {
  const startTime = Date.now();
  const executionId = `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  const auditLogger = createAuditLogger({
    executionId,
    evaluationId,
    organizationId: options?.organizationId || "default",
  });

  await auditLogger.logAgentDecision(
    "Orchestrator",
    "START_EVALUATION",
    `Starting evaluation for ${exposureType} on asset ${assetId}`,
    { assetId, exposureType, priority, description, executionMode: options?.executionMode }
  );

  // Initialize phase tracking in DB (skip for simulation rounds to avoid cycling)
  const phases = initPhases();
  const trackPhases = !options?.skipPhaseTracking;
  const trackPhase = trackPhases
    ? (phase: string, update: Partial<EvaluationPhaseProgress>) => updatePhase(evaluationId, phases, phase, update)
    : async (_phase: string, _update: Partial<EvaluationPhaseProgress>) => {};
  await trackPhase("recon", { status: "pending" });

  // ──────────────────────────────────────────────────────────────
  // Tier 0: Policy Context (no LLM, ~1s)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Policy Engine", "policy", 1, "Loading Rules of Engagement...");

  let policyContext = "";
  // core-v2: getAgentPolicyContext (policy-context module) removed — skip policy loading
  console.log(`[Orchestrator] Policy context loading skipped (core-v2 strip-down)`);

  // ──────────────────────────────────────────────────────────────
  // Tier -1: Load ground-truth scan data (no LLM, DB queries only)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Data Loader", "ground_truth", 2, "Loading real scan data...");
  // core-v2: scan-data-loader module removed — ground truth loading skipped
  let realScanData: any | undefined;
  console.log(`[Orchestrator] Ground truth loading skipped (core-v2 strip-down)`);

  const context: AgentContext = {
    assetId,
    exposureType,
    priority,
    description,
    evaluationId,
    adversaryProfile: options?.adversaryProfile,
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    policyContext,
    realScanData,
  };

  const memory: AgentMemory = {
    context,
    safetyDecisions: [],
    groundTruth: realScanData,
    ...(options?.breachDirective ? { breachDirective: options.breachDirective } : {}),
  };

  const guardianContext = {
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    targetType: exposureType,
    assetId,
    evaluationId,
  };

  // ──────────────────────────────────────────────────────────────
  // Tier 0.5: Phase 1 Recon Engine (real scanning, no LLM, ~30s)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Recon Engine", "recon_engine", 3, "Running Phase 1 reconnaissance...");

  // core-v2: recon/index, recon/aev-mapper, and external-recon modules removed
  // Phase 1 recon engine is no longer available — exploit agent handles its own fingerprinting
  console.log(`[Orchestrator] Phase 1 recon skipped (core-v2 strip-down — recon modules removed)`);

  // ──────────────────────────────────────────────────────────────
  // Tier 1: Recon Agent (1 LLM call, max 30s)
  // ──────────────────────────────────────────────────────────────
  const reconStart = Date.now();
  await trackPhase("recon", { status: "running", startedAt: new Date().toISOString(), message: "Initializing reconnaissance..." });
  onProgress?.("Recon Agent", "recon", 5, "Initializing reconnaissance...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Initiating reconnaissance phase to discover attack surface and entry points");

  // core-v2: runReconAgent removed — use empty findings (exploit agent does its own fingerprinting)
  const reconResult = {
    success: true,
    findings: {
      attackSurface: [] as string[],
      entryPoints: [] as string[],
      apiEndpoints: [] as string[],
      authMechanisms: [] as string[],
      technologies: [] as string[],
      potentialVulnerabilities: [] as string[],
      resolvedIp: "",
      openPorts: [] as number[],
      bannerData: {} as Record<string, import("./types").BannerInfo>,
      httpFingerprint: { server: null, framework: null, cdn: null, waf: null },
      attackReadinessScore: 0,
      externalReconSource: "none" as const,
    },
    agentName: "Recon Agent",
    processingTime: 0,
  };
  memory.recon = reconResult.findings;

  const reconSummary = `Discovered ${reconResult.findings.attackSurface?.length || 0} attack surface elements`;
  await trackPhase("recon", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - reconStart, findingSummary: reconSummary,
  });
  wsService.sendSharedMemoryUpdate(evaluationId, "recon_agent", "ReconAgent", "recon", reconSummary);

  // ──────────────────────────────────────────────────────────────
  // Tier 1.25: Threat Intel Enrichment (non-fatal, <5s)
  // ──────────────────────────────────────────────────────────────
  try {
    const vulnImports = await storage.getVulnerabilityImportsByAssetId(assetId);
    const cveIds = vulnImports.map(v => v.cveId).filter((id): id is string => !!id);
    if (cveIds.length > 0) {
      const epssResults = await getEPSSScores(cveIds);
      const orgId = options?.organizationId || "default";
      const kevCves: string[] = [];
      for (const cveId of cveIds) {
        const indicator = await storage.getThreatIntelIndicatorByValue(cveId, orgId);
        if (indicator) kevCves.push(cveId);
      }
      const epssArray = Array.from(epssResults.entries());
      memory.threatIntel = {
        epssScores: epssArray.map(([cve, data]) => ({ cve, epss: data.epss, percentile: data.percentile })),
        kevCves,
      };
      if (kevCves.length > 0 || epssArray.length > 0) {
        console.log(`[Orchestrator] Threat intel: ${kevCves.length} KEV CVEs, ${epssArray.length} EPSS scores`);
      }
    }
  } catch (err) {
    console.warn("[Orchestrator] Threat intel enrichment failed (non-fatal):", err);
  }

  // ──────────────────────────────────────────────────────────────
  // Tier 1.5: Plan Agent (1 LLM call, max 15s)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Plan Agent", "plan", 22, "Building attack plan...");

  // core-v2: plan agent removed — exploit agent runs without pre-planned chains
  console.log(`[Orchestrator] Plan agent skipped (core-v2 strip-down)`);

  // ──────────────────────────────────────────────────────────────
  // Logic_Recon_Success Gate — stops pipeline if recon found nothing
  // ──────────────────────────────────────────────────────────────
  const reconGate = gateReconSuccess(memory.recon);
  console.log(`[Orchestrator] Logic_Recon_Success: ${reconGate.passed ? "PASS" : "FAIL"} — ${reconGate.reason}`);
  wsService.sendReasoningTrace(evaluationId, "pipeline_gate", "Logic_Recon_Success",
    `${reconGate.passed ? "PASS" : "FAIL"}: ${reconGate.reason}`, reconGate.metrics);

  // ──────────────────────────────────────────────────────────────
  // Tier 2: Parallel — Exploit + Business Logic + Multi-Vector
  // Thread A: EXPLOIT_AGENT, Thread B: BUSINESS_LOGIC_AGENT,
  // Thread C: MULTI_VECTOR_AGENT — all share read-only memory.recon
  // POLICY_GUARDIAN_EXPLOIT runs as post-validation on all results
  // ──────────────────────────────────────────────────────────────
  const tier2Start = Date.now();
  onProgress?.("Analysis Agents", "analysis", 25, "Running analysis agents in parallel...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Running exploit, business logic, and multi-vector analysis in parallel threads (Step 3)");

  // Freeze a read-only copy of recon for parallel threads
  const readOnlyRecon = Object.freeze({ ...memory.recon });

  // --- Thread A: Exploit Agent ---
  const threadAPromise = (async (): Promise<{ success: boolean; findings: ExploitFindings; agentName: string; processingTime: number }> => {
    await trackPhase("exploit", { status: "running", startedAt: new Date().toISOString(), message: "Analyzing exploit chains..." });
    // Build a read-only memory snapshot for this thread — threads never write to each other
    const threadMemory: AgentMemory = { ...memory, recon: readOnlyRecon as typeof memory.recon };
    try {
      return await withCircuitBreaker(
        "openai",
        () => runWithHeartbeat(evaluationId, "Exploit Agent",
          () => runExploitAgent(threadMemory, (stage: string, progress: number, message: string) => {
            updateAgentHeartbeat(evaluationId, "Exploit Agent", stage, progress, message);
            onProgress?.("Exploit Agent", stage, 25 + Math.floor(progress * 0.1), message);
          })
        ),
        () => ({ success: true, findings: EMPTY_EXPLOIT_FINDINGS, agentName: "Exploit Agent", processingTime: 0 }),
        AGENT_CB_TIMEOUT_MS
      );
    } catch {
      return { success: true, findings: EMPTY_EXPLOIT_FINDINGS, agentName: "Exploit Agent", processingTime: 0 };
    }
  })();

  // --- Thread B: Business Logic Agent ---
  const threadBPromise = (async (): Promise<{ success: boolean; findings: BusinessLogicFindings; agentName: string; processingTime: number }> => {
    await trackPhase("business_logic", { status: "running", startedAt: new Date().toISOString(), message: "Analyzing business logic..." });
    // core-v2: runBusinessLogicAgent removed — return empty findings
    return { success: true, findings: EMPTY_BL_FINDINGS, agentName: "Business Logic Agent", processingTime: 0 };
  })();

  // --- Thread C: Multi-Vector Agent ---
  const threadCPromise = (async (): Promise<{ success: boolean; findings: MultiVectorFindings; agentName: string; processingTime: number } | null> => {
    // core-v2: shouldRunMultiVectorAnalysis and runMultiVectorAnalysisAgent removed — always null
    return null;
  })();

  // Execute all three threads in parallel via Promise.all
  const [exploitResult, blResult, mvResult] = await Promise.all([
    threadAPromise,
    threadBPromise,
    threadCPromise,
  ]);

  const exploitSummary = `Identified ${exploitResult.findings.exploitChains?.length || 0} potential exploit chains`;
  await trackPhase("exploit", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - tier2Start, findingSummary: exploitSummary,
  });
  wsService.sendSharedMemoryUpdate(evaluationId, "exploit_agent", "ExploitAgent", "exploit", exploitSummary);

  const blSummary = `Found ${blResult.findings.workflowAbuse?.length || 0} workflow abuse patterns`;
  await trackPhase("business_logic", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - tier2Start, findingSummary: blSummary,
  });

  console.log(`[Orchestrator] Tier 2 (parallel threads) completed in ${Date.now() - tier2Start}ms`);

  // ──────────────────────────────────────────────────────────────
  // POLICY_GUARDIAN_EXPLOIT: Validate exploit findings (max 15s)
  // Guard runs BEFORE findings are written to memory
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Policy Guardian", "policy_check", 40, "Validating exploit chains against policies...");

  const policyGuardianCtx: PolicyGuardianContext = {
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    assetId,
    evaluationId,
  };

  const guardianResult = validateExploitFindings(exploitResult.findings, policyGuardianCtx);
  const guardedExploitFindings = guardianResult.findings;

  // Record safety decisions from policy guardian
  if (guardianResult.decisions.length > 0) {
    memory.safetyDecisions = [...(memory.safetyDecisions || []), ...guardianResult.decisions];
    console.log(`[Orchestrator] POLICY_GUARDIAN_EXPLOIT: ${guardianResult.allowedCount} allowed, ${guardianResult.modifiedCount} modified, ${guardianResult.blockedCount} blocked`);
    wsService.sendReasoningTrace(evaluationId, "policy_guardian", "PolicyGuardianExploit",
      `${guardianResult.allowedCount} allowed, ${guardianResult.modifiedCount} modified, ${guardianResult.blockedCount} blocked`);
  }

  // ──────────────────────────────────────────────────────────────
  // Debate Module: Adversarial validation of exploit findings
  // Uses Llama 3.3 70B via OpenRouter to challenge false positives
  // ──────────────────────────────────────────────────────────────
  let debateResult: DebateResult | undefined;
  let debatedExploitFindings = guardedExploitFindings;

  // Skip debate when confidence is extreme (clearly confirmed or clearly weak)
  const avgExploitConfidence = guardedExploitFindings.exploitChains.length > 0
    ? guardedExploitFindings.exploitChains.reduce((sum, c) => sum + (c.validationConfidence || 50), 0) / guardedExploitFindings.exploitChains.length
    : 0;
  const skipDebate = avgExploitConfidence > 90 || avgExploitConfidence < 20;

  if (guardedExploitFindings.exploitable && guardedExploitFindings.exploitChains.length > 0 && !skipDebate) {
    onProgress?.("Debate Module", "debate", 43, "Initiating adversarial validation...");
    wsService.sendReasoningTrace(evaluationId, "debate_module", "DebateModule",
      "CriticAgent (Llama 3.3 70B) challenging exploit findings for false positives");

    try {
      debateResult = await withCircuitBreaker(
        "openrouter",
        () => runDebateModule(
          memory,
          guardedExploitFindings,
          {},
          (stage: string, progress: number, message: string) => {
            onProgress?.("Debate Module", stage, 43 + Math.floor(progress * 0.05), message);
          }
        ),
        () => undefined as unknown as DebateResult,
        AGENT_CB_TIMEOUT_MS
      );

      if (debateResult) {
        debatedExploitFindings = filterVerifiedFindings(debateResult);
        const verified = debateResult.verifiedChains.filter(c => c.verificationStatus === "verified").length;
        const disputed = debateResult.verifiedChains.filter(c => c.verificationStatus === "disputed").length;
        const rejected = debateResult.verifiedChains.filter(c => c.verificationStatus === "rejected").length;

        console.log(`[Orchestrator] Debate complete: ${debateResult.finalVerdict} — ${verified} verified, ${disputed} disputed, ${rejected} rejected (confidence: ${debateResult.adjustedConfidence.toFixed(2)})`);

        wsService.sendReasoningTrace(evaluationId, "debate_module", "DebateModule",
          `Verdict: ${debateResult.finalVerdict} — ${verified} verified, ${disputed} disputed, ${rejected} rejected`,
          { confidence: debateResult.adjustedConfidence });
      } else {
        console.log("[Orchestrator] Debate module skipped (OpenRouter circuit breaker fallback)");
      }
    } catch (err) {
      console.warn("[Orchestrator] Debate module failed (non-fatal, proceeding without):", err);
    }
  } else if (skipDebate && guardedExploitFindings.exploitChains.length > 0) {
    console.log(`[Orchestrator] Debate skipped: avg confidence ${avgExploitConfidence.toFixed(0)}% (${avgExploitConfidence > 90 ? "clearly confirmed" : "clearly weak"})`);
  }

  // ──────────────────────────────────────────────────────────────
  // Noise Reduction: Swiss Cheese 4-layer filtering
  // ──────────────────────────────────────────────────────────────
  let noiseReductionResult: NoiseReductionResult | undefined;

  if (debatedExploitFindings.exploitChains.length > 0) {
    onProgress?.("Noise Reduction", "noise_filter", 47, "Applying Swiss Cheese noise filters...");

    noiseReductionResult = applyNoiseReduction(
      debatedExploitFindings,
      realScanData,
      { exposureType, priority, assetId, description, executionMode: options?.executionMode },
      memory.recon
    );

    debatedExploitFindings = {
      ...debatedExploitFindings,
      exploitChains: noiseReductionResult.filteredChains,
      exploitable: noiseReductionResult.filteredChains.length > 0 && debatedExploitFindings.exploitable,
    };

    const stats = noiseReductionResult.stats;
    if (stats.inputCount !== stats.finalCount) {
      console.log(`[Orchestrator] Noise reduction: ${stats.inputCount} → ${stats.finalCount} chains (removed ${stats.inputCount - stats.finalCount})`);
      wsService.sendReasoningTrace(evaluationId, "noise_reduction", "NoiseReduction",
        `Filtered ${stats.inputCount} → ${stats.finalCount} exploit chains: ${stats.removedChains.map(r => `${r.name} (${r.layer})`).join(", ") || "none removed"}`);
    }
  }

  memory.exploit = debatedExploitFindings;
  memory.businessLogic = blResult.findings;
  if (mvResult) memory.multiVector = (mvResult as { findings: MultiVectorFindings }).findings;

  // ──────────────────────────────────────────────────────────────
  // Logic_Exploit_Confirmed Gate — only proceed to Tier 3 if any
  // thread confirmed a real finding (EvidenceContract compliant)
  // ──────────────────────────────────────────────────────────────
  const exploitGate = gateExploitConfirmed(
    debatedExploitFindings,
    blResult.findings,
    mvResult ? (mvResult as { findings: MultiVectorFindings }).findings : undefined
  );
  console.log(`[Orchestrator] Logic_Exploit_Confirmed: ${exploitGate.passed ? "PASS" : "FAIL"} — ${exploitGate.reason}`);
  wsService.sendReasoningTrace(evaluationId, "pipeline_gate", "Logic_Exploit_Confirmed",
    `${exploitGate.passed ? "PASS" : "FAIL"}: ${exploitGate.reason}`, exploitGate.metrics);

  // ──────────────────────────────────────────────────────────────
  // Tier 3: Lateral → Impact → Enhanced BL
  // Only runs if Logic_Exploit_Confirmed gate passed
  // ──────────────────────────────────────────────────────────────
  const tier3Start = Date.now();
  onProgress?.("Analysis Agents", "analysis_tier3", 50, "Running lateral, impact, and enhanced analysis...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Running lateral movement, impact assessment, and enhanced analysis (rate limit aware)");

  // core-v2: shouldRunEnhancedEngine removed — always false
  const runEnhanced = false;

  // Skip lateral movement agent when exploit gate failed or no exploits found
  const skipLateral = !exploitGate.passed || !debatedExploitFindings.exploitable || debatedExploitFindings.exploitChains.length === 0;
  if (skipLateral) {
    console.log("[Orchestrator] Skipping lateral agent: Logic_Exploit_Confirmed gate did not pass");
  }

  // --- Lateral Agent ---
  // core-v2: runLateralAgent removed — return empty findings
  await trackPhase("lateral", { status: "running", startedAt: new Date().toISOString(), message: "Identifying lateral movement paths..." });
  const lateralResult = { success: true, findings: EMPTY_LATERAL_FINDINGS, agentName: "Lateral Movement Agent", processingTime: 0 };

  const lateralSummary = `Discovered ${lateralResult.findings.pivotPaths?.length || 0} lateral movement paths`;
  await trackPhase("lateral", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - tier3Start, findingSummary: lateralSummary,
  });
  wsService.sendSharedMemoryUpdate(evaluationId, "lateral_agent", "LateralAgent", "lateral", lateralSummary);

  // --- Impact Agent ---
  // core-v2: runImpactAgent removed — return empty findings
  await trackPhase("impact", { status: "running", startedAt: new Date().toISOString(), message: "Assessing business impact..." });
  const impactResult = { success: true, findings: EMPTY_IMPACT_FINDINGS, agentName: "Impact Agent", processingTime: 0 };

  const impactSummary = `Data exposure severity: ${impactResult.findings.dataExposure?.severity || "unknown"}`;
  await trackPhase("impact", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - tier3Start, findingSummary: impactSummary,
  });

  // --- Enhanced Business Logic Engine (optional) ---
  // core-v2: runEnhancedBusinessLogicEngine removed — always null
  let enhancedResult: { success: boolean; findings: EnhancedBusinessLogicFindings; agentName: string; processingTime: number } | null = null;

  console.log(`[Orchestrator] Tier 3 completed in ${Date.now() - tier3Start}ms`);

  // ──────────────────────────────────────────────────────────────
  // PolicyGuardian: Lateral movement validation (max 15s)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Policy Guardian", "policy_check", 70, "Validating lateral movements against policies...");

  const guardedLateralFindings = await withTimeout(
    runLateralGuardianCheckLoop(lateralResult.findings, guardianContext, evaluationId, memory, onProgress),
    GUARDIAN_LOOP_TIMEOUT_MS,
    lateralResult.findings
  );

  memory.lateral = guardedLateralFindings;
  memory.impact = impactResult.findings;
  if (enhancedResult) memory.enhancedBusinessLogic = (enhancedResult as { findings: EnhancedBusinessLogicFindings }).findings;

  // ──────────────────────────────────────────────────────────────
  // Tier 4: Synthesizer (1 LLM call)
  // ──────────────────────────────────────────────────────────────
  const synthesisStart = Date.now();
  await trackPhase("synthesis", { status: "running", startedAt: new Date().toISOString(), message: "Generating final report..." });
  onProgress?.("Synthesizer", "synthesis", 80, "Generating final report...");

  const result = await withCircuitBreaker(
    "openai",
    () => synthesizeResults(memory),
    () => ({
      exploitable: memory.exploit?.exploitable || false,
      confidence: 0.5,
      score: memory.exploit?.exploitable ? 60 : 20,
      attackPath: [],
      impact: "Analysis completed with fallback synthesis",
      recommendations: [],
    }),
    AGENT_CB_TIMEOUT_MS
  );

  await trackPhase("synthesis", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - synthesisStart,
    findingSummary: `Exploitable: ${result.exploitable}, Score: ${result.score}`,
  });

  // ──────────────────────────────────────────────────────────────
  // Tier 5: Structural/Rule-based (no LLM, ~100ms)
  // ──────────────────────────────────────────────────────────────
  const finalizationStart = Date.now();
  await trackPhase("finalization", { status: "running", startedAt: new Date().toISOString(), message: "Building attack graph and scoring..." });
  onProgress?.("Finalization", "finalization", 90, "Building attack graph and scoring...");

  const attackGraph = createFallbackGraph(memory);

  const exploitToolCallLog = memory.exploit?.toolCallLog;
  const evidenceArtifacts = generateEvidenceFromAnalysis(
    {
      evaluationId,
      assetId,
      exposureType,
      attackPath: result.attackPath,
      businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
      multiVectorFindings: memory.multiVector?.findings,
    },
    undefined,
    exploitToolCallLog
  );

  // core-v2: evidence-uploader module removed — skip upload
  // Evidence artifacts are still generated and returned in the result

  // Look up CVSS data, asset criticality, EPSS, and KEV for deterministic scoring
  let cvssData: ReturnType<typeof parseCVSSVector> | undefined;
  let assetCriticality: "critical" | "high" | "medium" | "low" | undefined;
  let epssScore: number | undefined;
  let epssPercentile: number | undefined;
  let isKevListed = false;
  let kevRansomwareUse = false;

  try {
    const discoveredAsset = await storage.getDiscoveredAssetByIdentifier(assetId);
    assetCriticality = (discoveredAsset?.criticality as typeof assetCriticality) ?? undefined;
    const vulnImports = await storage.getVulnerabilityImportsByAssetId(assetId);
    const parsedVectors = vulnImports
      .filter(v => v.cvssVector)
      .map(v => parseCVSSVector(v.cvssVector!))
      .filter((v): v is NonNullable<typeof v> => v !== null);
    // Use the highest-scored CVSS vector for primary scoring
    cvssData = parsedVectors.sort((a, b) => b.baseScore - a.baseScore)[0] ?? undefined;

    // EPSS enrichment: batch fetch exploitation probability for all CVEs
    const cveIds = vulnImports
      .map(v => v.cveId)
      .filter((id): id is string => !!id);
    if (cveIds.length > 0) {
      try {
        const epssResults = await getEPSSScores(cveIds);
        // Use highest EPSS score (most likely to be exploited)
        const epssArray = Array.from(epssResults.values());
        if (epssArray.length > 0) {
          const best = epssArray.reduce((a, b) => a.epss > b.epss ? a : b);
          epssScore = best.epss;
          epssPercentile = best.percentile;
        }
      } catch { /* EPSS non-fatal */ }

      // KEV enrichment: check if any CVE is on CISA KEV
      try {
        const orgId = options?.organizationId || "default";
        for (const cveId of cveIds) {
          const indicator = await storage.getThreatIntelIndicatorByValue(cveId, orgId);
          if (indicator) {
            isKevListed = true;
            if (indicator.knownRansomwareCampaignUse) kevRansomwareUse = true;
            break;
          }
        }
      } catch { /* KEV non-fatal */ }
    }
  } catch {
    // Non-fatal — scoring works without enrichment data
  }

  const intelligentScore = generateDeterministicScore({
    assetId,
    exposureType,
    priority,
    description,
    exploitable: result.exploitable,
    attackPath: result.attackPath,
    attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
    cvssData: cvssData ?? undefined,
    assetCriticality,
    epssScore,
    epssPercentile,
    isKevListed,
    kevRansomwareUse,
  });

  // core-v2: generateRemediationGuidance (remediation-engine) removed — skip
  onProgress?.("Remediation Engine", "remediation", 95, "Generating remediation guidance...");
  const remediationGuidance = undefined as any;

  const totalProcessingTime = Date.now() - startTime;

  // Persist safety decisions to database for audit trail
  if (memory.safetyDecisions && memory.safetyDecisions.length > 0) {
    try {
      await storage.createSafetyDecisionsBatch(
        memory.safetyDecisions.map((sd) => ({
          id: sd.id,
          evaluationId: sd.evaluationId,
          organizationId: sd.organizationId || "default",
          agentName: sd.agentName,
          originalAction: sd.originalAction,
          decision: sd.decision,
          modifiedAction: sd.modifiedAction,
          reasoning: sd.reasoning,
          policyReferences: sd.policyReferences || [],
          executionMode: sd.executionMode || "safe",
        }))
      );
      console.log(`[Orchestrator] Persisted ${memory.safetyDecisions.length} safety decisions to database`);
    } catch (error) {
      console.error("[Orchestrator] Failed to persist safety decisions:", error);
    }
  }

  await trackPhase("finalization", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - finalizationStart,
    findingSummary: `Score: ${intelligentScore?.riskRank?.overallScore ?? result.score}, ${result.recommendations?.length || 0} recommendations`,
  });

  // Record evaluation snapshot and compute drift (non-fatal)
  let evaluationDiff: import("@shared/schema").DriftResult | null = null;
  try {
    const { computeEvaluationDiff, recordEvaluationSnapshot } = await import("../evaluation-differ");
    const evaluation = await storage.getEvaluation(evaluationId);
    if (evaluation) {
      evaluationDiff = await computeEvaluationDiff({
        currentEvaluation: evaluation,
        currentResult: result as any,
        assetId,
      });
      await recordEvaluationSnapshot(evaluation, result as any, options?.scheduledScanId);
      if (evaluationDiff) {
        console.log(`[Orchestrator] Drift detected: ${evaluationDiff.riskTrend}, score change: ${evaluationDiff.changes.scoreChange}`);
      }
    }
  } catch (err) {
    console.warn("[Orchestrator] Evaluation diff/snapshot failed (non-fatal):", err);
  }

  onProgress?.("Complete", "complete", 100, "Analysis complete");
  console.log(`[Orchestrator] Pipeline completed in ${totalProcessingTime}ms`);

  return {
    ...result,
    attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
    workflowAnalysis: memory.enhancedBusinessLogic?.workflowAnalysis || undefined,
    evidenceArtifacts,
    intelligentScore,
    remediationGuidance,
    llmValidation: undefined,
    llmValidationVerdict: undefined,
    validationStats: undefined,
    debateSummary: debateResult ? {
      finalVerdict: debateResult.finalVerdict,
      consensusReached: debateResult.consensusReached,
      verifiedChains: debateResult.verifiedChains,
      adjustedConfidence: debateResult.adjustedConfidence,
      debateRounds: debateResult.debateRounds,
      criticModelUsed: debateResult.criticResult.modelUsed,
      criticReasoning: debateResult.criticResult.reasoning,
      processingTime: debateResult.processingTime,
    } as DebateSummary : undefined,
    confidenceBreakdown: buildConfidenceBreakdown(debateResult, realScanData),
    noiseReductionStats: noiseReductionResult?.stats,
    agentFindings: {
      recon: memory.recon!,
      exploit: memory.exploit!,
      lateral: memory.lateral!,
      businessLogic: memory.businessLogic!,
      enhancedBusinessLogic: memory.enhancedBusinessLogic,
      multiVector: memory.multiVector,
      impact: memory.impact!,
    },
    totalProcessingTime,
    safetyDecisions: memory.safetyDecisions,
  };
}

// ──────────────────────────────────────────────────────────────
// Helper: Timeout wrapper for sub-operations
// ──────────────────────────────────────────────────────────────
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Operation timeout: ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
  } catch {
    return fallback;
  }
}

// ──────────────────────────────────────────────────────────────
// PolicyGuardian: Exploit chain check loop
// core-v2: checkExploitChain (policy-guardian) removed — pass-through all chains
// ──────────────────────────────────────────────────────────────
async function runPolicyGuardianCheckLoop(
  exploitFindings: ExploitFindings,
  _agentName: string,
  _guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  _evaluationId: string,
  _memory: AgentMemory,
  _onProgress?: ProgressCallback
): Promise<ExploitFindings> {
  // core-v2: policy-guardian module removed — allow all chains through
  return exploitFindings;
}

// ──────────────────────────────────────────────────────────────
// PolicyGuardian: Lateral movement check loop
// ──────────────────────────────────────────────────────────────
// PolicyGuardian: Lateral movement check loop
// core-v2: checkLateralMovement (policy-guardian) removed — pass-through all paths
// ──────────────────────────────────────────────────────────────
async function runLateralGuardianCheckLoop(
  lateralFindings: LateralFindings,
  _guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  _evaluationId: string,
  _memory: AgentMemory,
  _onProgress?: ProgressCallback
): Promise<LateralFindings> {
  // core-v2: policy-guardian module removed — allow all lateral paths through
  return lateralFindings;
}

// ──────────────────────────────────────────────────────────────
// Confidence Breakdown Builder
// ──────────────────────────────────────────────────────────────
function buildConfidenceBreakdown(
  debateResult: DebateResult | undefined,
  realScanData: any | undefined
): ConfidenceBreakdown | undefined {
  if (!debateResult && !realScanData) return undefined;

  const exploitConfidence = debateResult?.adjustedConfidence ?? 0.5;

  // Ground truth confidence: how much real scan data backs the findings
  const groundTruthConfidence = realScanData?.dataAvailability.coverageScore ?? 0;

  // Weighted combination: 60% exploit validation, 40% ground truth backing
  const overallConfidence = exploitConfidence * 0.6 + groundTruthConfidence * 0.4;

  const verifiedFindings = debateResult?.verifiedChains.filter(c => c.verificationStatus === "verified").length ?? 0;
  const disputedFindings = debateResult?.verifiedChains.filter(c => c.verificationStatus === "disputed").length ?? 0;
  const rejectedFindings = debateResult?.verifiedChains.filter(c => c.verificationStatus === "rejected").length ?? 0;

  return {
    exploitConfidence,
    groundTruthConfidence,
    overallConfidence: Math.max(0, Math.min(1, overallConfidence)),
    verifiedFindings,
    disputedFindings,
    rejectedFindings,
  };
}

// ── Chain Continuation Loop ───────────────────────────────────────────────

const MAX_CHAIN_ITERATIONS = process.env.CHAIN_LOOP_MAX_ITERS
  ? parseInt(process.env.CHAIN_LOOP_MAX_ITERS, 10)
  : 3;

function createInitialExploitState(context: AgentContext): ExploitState {
  return {
    discoveredEndpoints: [],
    confirmedVulns: [],
    credentials: [],
    privilegeLevel: "none",
    capabilities: [],
    extractedArtifacts: [],
    constraints: {
      blockedEndpoints: [],
      maxRequests: 100,
      remainingBudget: MAX_CHAIN_ITERATIONS * 12, // turns per iteration × iterations
    },
    objectives: [
      { id: "confirm_vuln", description: "Confirm at least one exploitable vulnerability", achieved: false },
      { id: "chain_exploit", description: "Chain confirmed vulns for deeper access", achieved: false },
      { id: "demonstrate_impact", description: "Demonstrate business impact of exploitation", achieved: false },
    ],
    iteration: 0,
    lastUpdatedAt: new Date().toISOString(),
  };
}

function updateExploitState(state: ExploitState, findings: ExploitFindings): ExploitState {
  const updated = { ...state };

  // Merge confirmed vulns
  for (const chain of findings.exploitChains || []) {
    const alreadyKnown = updated.confirmedVulns.some(
      v => v.type === chain.technique && v.endpoint === (chain as any).endpoint
    );
    if (!alreadyKnown && chain.success_likelihood !== "low") {
      updated.confirmedVulns.push({
        type: chain.technique,
        endpoint: (chain as any).endpoint || "unknown",
        technique: chain.name,
        confidence: chain.success_likelihood === "high" ? 90 : 60,
      });
    }
  }

  // Merge discovered endpoints from tool call log
  for (const tc of findings.toolCallLog || []) {
    const args = tc.arguments as Record<string, unknown>;
    const url = String(args?.url || args?.target || "");
    if (url && !updated.discoveredEndpoints.includes(url)) {
      updated.discoveredEndpoints.push(url);
    }
  }

  // Update capabilities based on findings
  if (findings.exploitable) {
    if (!updated.capabilities.includes("vulnerability_confirmed")) {
      updated.capabilities.push("vulnerability_confirmed");
    }
    updated.objectives = updated.objectives.map(o =>
      o.id === "confirm_vuln" ? { ...o, achieved: true } : o
    );
  }

  if (updated.confirmedVulns.length >= 2) {
    if (!updated.capabilities.includes("multi_vuln")) {
      updated.capabilities.push("multi_vuln");
    }
    updated.objectives = updated.objectives.map(o =>
      o.id === "chain_exploit" ? { ...o, achieved: true } : o
    );
  }

  // Update privilege level based on exploit chain names
  const chainText = (findings.exploitChains || []).map(c => `${c.name} ${c.description}`).join(" ").toLowerCase();
  if (chainText.includes("admin") || chainText.includes("privilege") || chainText.includes("escalat")) {
    if (updated.privilegeLevel === "none" || updated.privilegeLevel === "user") {
      updated.privilegeLevel = "admin";
    }
  } else if (chainText.includes("rce") || chainText.includes("command injection") || chainText.includes("root")) {
    updated.privilegeLevel = "root";
  } else if (updated.privilegeLevel === "none" && findings.exploitable) {
    updated.privilegeLevel = "user";
  }

  updated.constraints.remainingBudget -= 12; // consumed one iteration's turn budget
  updated.iteration = state.iteration + 1;
  updated.lastUpdatedAt = new Date().toISOString();

  return updated;
}

function shouldContinueChain(state: ExploitState, prevFindingCount: number): boolean {
  // Stop if all objectives achieved
  if (state.objectives.every(o => o.achieved)) return false;
  // Stop if no new vulns found (no progress)
  if (state.confirmedVulns.length <= prevFindingCount) return false;
  // Stop if budget exhausted
  if (state.constraints.remainingBudget <= 0) return false;
  return true;
}

export interface ChainLoopResult {
  iterations: number;
  finalState: ExploitState;
  allFindings: ExploitFindings;
  totalProcessingTime: number;
}

/**
 * Multi-iteration exploit loop that carries persistent state across runs.
 * Each iteration runs a full exploit agent pass, merges findings into ExploitState,
 * and checks termination conditions before continuing.
 */
export async function runChainLoop(
  context: AgentContext,
  onProgress?: ProgressCallback,
): Promise<ChainLoopResult> {
  const startTime = Date.now();
  const state = createInitialExploitState(context);
  const allChains: ExploitFindings["exploitChains"] = [];
  const allCveRefs: string[] = [];
  const allMisconfigs: string[] = [];
  const allToolCallLog: NonNullable<ExploitFindings["toolCallLog"]> = [];

  const telemetry = new AevTelemetryRecorder({
    evaluationId: context.evaluationId,
    organizationId: context.organizationId || "unknown",
    runType: "exploit_agent",
    executionMode: context.executionMode || "simulation",
  });
  void telemetry.start();

  let iterations = 0;

  for (let i = 0; i < MAX_CHAIN_ITERATIONS; i++) {
    iterations = i + 1;
    const prevVulnCount = state.confirmedVulns.length;

    onProgress?.("Chain Loop", `iteration_${i}`, Math.floor((i / MAX_CHAIN_ITERATIONS) * 100),
      `Chain iteration ${i + 1}/${MAX_CHAIN_ITERATIONS} — ${state.confirmedVulns.length} vulns confirmed`);

    // Build memory with state context injected into description
    const stateContext = state.confirmedVulns.length > 0
      ? `\n\nPREVIOUS FINDINGS (carry forward — do NOT re-test):\n${state.confirmedVulns.map(v => `- ${v.technique} at ${v.endpoint} (confidence: ${v.confidence}%)`).join("\n")}\nPrivilege level: ${state.privilegeLevel}\nCapabilities: ${state.capabilities.join(", ") || "none"}\n\nFOCUS: Chain from confirmed vulns into deeper access. Try escalation, lateral movement, or data exfiltration.`
      : "";

    const memory: AgentMemory = {
      context: {
        ...context,
        description: (context.description || "") + stateContext,
      },
    };

    try {
      const result = await runExploitAgent(memory, (stage, progress, message) => {
        onProgress?.("Chain Loop", stage, Math.floor((i / MAX_CHAIN_ITERATIONS) * 100) + Math.floor(progress * (1 / MAX_CHAIN_ITERATIONS)), message);
      });

      if (result.success && result.findings) {
        const findings = result.findings;
        // Merge findings
        allChains.push(...(findings.exploitChains || []));
        allCveRefs.push(...(findings.cveReferences || []));
        allMisconfigs.push(...(findings.misconfigurations || []));
        if (findings.toolCallLog) allToolCallLog.push(...findings.toolCallLog);

        // Update state
        const newState = updateExploitState(state, findings);
        Object.assign(state, newState);

        if (!shouldContinueChain(state, prevVulnCount)) {
          break;
        }
      } else {
        // Agent failed — stop chain
        break;
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      void telemetry.recordFailure("orchestrator_timeout", "chain_loop", errMsg);
      break;
    }
  }

  const mergedFindings: ExploitFindings = {
    exploitable: allChains.length > 0,
    exploitChains: allChains,
    cveReferences: Array.from(new Set(allCveRefs)),
    misconfigurations: Array.from(new Set(allMisconfigs)),
    toolCallLog: allToolCallLog.length > 0 ? allToolCallLog : undefined,
  };

  void telemetry.finish({
    stopReason: state.objectives.every(o => o.achieved) ? "completed"
      : state.constraints.remainingBudget <= 0 ? "budget_exceeded"
      : "no_progress",
    exploitable: mergedFindings.exploitable,
    overallConfidence: state.confirmedVulns.reduce((max, v) => Math.max(max, v.confidence), 0),
    findingCount: allChains.length,
    totalTurns: iterations,
    totalToolCalls: allToolCallLog.length,
    exploitState: state as unknown as Record<string, unknown>,
  });

  return {
    iterations,
    finalState: state,
    allFindings: mergedFindings,
    totalProcessingTime: Date.now() - startTime,
  };
}
