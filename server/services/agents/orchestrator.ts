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
} from "./types";
import type { AdversaryProfile, EvaluationPhaseProgress, DebateSummary } from "@shared/schema";
import { runDebateModule, filterVerifiedFindings, type DebateResult } from "./debate-module";
import { applyNoiseReduction, type NoiseReductionResult } from "./noise-reduction";
import { runReconAgent } from "./recon";
import { runExploitAgent } from "./exploit";
import { runLateralAgent } from "./lateral";
import { runBusinessLogicAgent, runEnhancedBusinessLogicEngine, shouldRunEnhancedEngine } from "./business-logic";
import { runMultiVectorAnalysisAgent, shouldRunMultiVectorAnalysis } from "./multi-vector";
import { runImpactAgent } from "./impact";
import { synthesizeResults } from "./synthesizer";
import { createFallbackGraph } from "./graph-synthesizer";
import { generateEvidenceFromAnalysis } from "./evidence-collector";
import { generateFallbackScore } from "./scoring-engine";
import { generateRemediationGuidance } from "./remediation-engine";
import { runWithHeartbeat, updateAgentHeartbeat } from "./heartbeat-tracker";
import { withCircuitBreaker } from "./circuit-breaker";
import { getAgentPolicyContext } from "./policy-context";
import { checkExploitChain, checkLateralMovement } from "./policy-guardian";
import { wsService } from "../websocket";
import { storage } from "../../storage";
import { createAuditLogger } from "../audit-logger";

// Pipeline-level timeout: 3 minutes max for entire orchestration
const PIPELINE_TIMEOUT_MS = 180_000;

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
        () => reject(new Error("Pipeline timeout: 3 minutes exceeded")),
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
  try {
    policyContext = await getAgentPolicyContext(
      "penetration testing",
      `${exposureType} assessment on ${assetId}`,
      {
        organizationId: options?.organizationId,
        executionMode: options?.executionMode || "safe",
        targetType: exposureType,
      }
    );
    console.log(`[Orchestrator] Loaded policy context (${policyContext.length} chars)`);
  } catch (err) {
    console.warn("[Orchestrator] Failed to load policy context:", err);
  }

  // ──────────────────────────────────────────────────────────────
  // Tier -1: Load ground-truth scan data (no LLM, DB queries only)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Data Loader", "ground_truth", 2, "Loading real scan data...");
  let realScanData: import("./scan-data-loader").RealScanData | undefined;
  try {
    const { loadScanDataForAsset } = await import("./scan-data-loader");
    realScanData = await loadScanDataForAsset(assetId, options?.organizationId || "default", evaluationId);
    const avail = realScanData.dataAvailability;
    const sources = [avail.hasRecon && "recon", avail.hasNetwork && "network", avail.hasAuth && "auth", avail.hasCloud && "cloud", avail.hasExploitValidation && "exploit", avail.hasTelemetry && "telemetry"].filter(Boolean);
    console.log(`[Orchestrator] Ground truth loaded: ${sources.length}/6 sources (${sources.join(", ") || "none"}) — coverage ${(avail.coverageScore * 100).toFixed(0)}%`);
  } catch (err) {
    console.warn("[Orchestrator] Failed to load scan data (agents will proceed without ground truth):", err);
  }

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

  const memory: AgentMemory = { context, safetyDecisions: [], groundTruth: realScanData };

  const guardianContext = {
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    targetType: exposureType,
    assetId,
    evaluationId,
  };

  // ──────────────────────────────────────────────────────────────
  // Tier 1: Recon Agent (1 LLM call, max 30s)
  // ──────────────────────────────────────────────────────────────
  const reconStart = Date.now();
  await trackPhase("recon", { status: "running", startedAt: new Date().toISOString(), message: "Initializing reconnaissance..." });
  onProgress?.("Recon Agent", "recon", 5, "Initializing reconnaissance...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Initiating reconnaissance phase to discover attack surface and entry points");

  const reconResult = await withCircuitBreaker(
    "openai",
    () => runWithHeartbeat(evaluationId, "Recon Agent",
      () => runReconAgent(memory, (stage: string, progress: number, message: string) => {
        updateAgentHeartbeat(evaluationId, "Recon Agent", stage, progress, message);
        onProgress?.("Recon Agent", stage, Math.min(20, 5 + Math.floor(progress * 0.15)), message);
      })
    ),
    () => ({
      success: true,
      findings: { attackSurface: [], entryPoints: [], apiEndpoints: [], authMechanisms: [], technologies: [], potentialVulnerabilities: [] },
      agentName: "Recon Agent",
      processingTime: 0,
    }),
    30_000
  );
  memory.recon = reconResult.findings;

  const reconSummary = `Discovered ${reconResult.findings.attackSurface?.length || 0} attack surface elements`;
  await trackPhase("recon", {
    status: "completed", completedAt: new Date().toISOString(),
    duration: Date.now() - reconStart, findingSummary: reconSummary,
  });
  wsService.sendSharedMemoryUpdate(evaluationId, "recon_agent", "ReconAgent", "recon", reconSummary);

  // ──────────────────────────────────────────────────────────────
  // Tier 2: Parallel — Exploit + Business Logic + Multi-Vector (max 30s wall-clock)
  // ──────────────────────────────────────────────────────────────
  const tier2Start = Date.now();
  await trackPhase("exploit", { status: "running", startedAt: new Date().toISOString(), message: "Analyzing exploit chains..." });
  await trackPhase("business_logic", { status: "running", startedAt: new Date().toISOString(), message: "Analyzing business logic..." });
  onProgress?.("Analysis Agents", "analysis", 25, "Running parallel analysis...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Running exploit, business logic, and multi-vector analysis in parallel");

  const [exploitSettled, blSettled, mvSettled] = await Promise.allSettled([
    withCircuitBreaker(
      "openai",
      () => runWithHeartbeat(evaluationId, "Exploit Agent",
        () => runExploitAgent(memory, (stage: string, progress: number, message: string) => {
          updateAgentHeartbeat(evaluationId, "Exploit Agent", stage, progress, message);
          onProgress?.("Exploit Agent", stage, 25 + Math.floor(progress * 0.1), message);
        })
      ),
      () => ({ success: true, findings: EMPTY_EXPLOIT_FINDINGS, agentName: "Exploit Agent", processingTime: 0 }),
      120_000
    ),
    withCircuitBreaker(
      "openai",
      () => runWithHeartbeat(evaluationId, "Business Logic Agent",
        () => runBusinessLogicAgent(memory, (stage: string, progress: number, message: string) => {
          updateAgentHeartbeat(evaluationId, "Business Logic Agent", stage, progress, message);
          onProgress?.("Business Logic Agent", stage, 25 + Math.floor(progress * 0.1), message);
        })
      ),
      () => ({ success: true, findings: EMPTY_BL_FINDINGS, agentName: "Business Logic Agent", processingTime: 0 }),
      30_000
    ),
    shouldRunMultiVectorAnalysis(exposureType)
      ? withCircuitBreaker(
          "openai",
          () => runWithHeartbeat(evaluationId, "Multi-Vector Agent",
            () => runMultiVectorAnalysisAgent(memory, (stage: string, progress: number, message: string) => {
              updateAgentHeartbeat(evaluationId, "Multi-Vector Agent", stage, progress, message);
              onProgress?.("Multi-Vector Agent", stage, 25 + Math.floor(progress * 0.1), message);
            })
          ),
          () => ({ success: true, findings: EMPTY_MV_FINDINGS, agentName: "Multi-Vector Agent", processingTime: 0 }),
          30_000
        )
      : Promise.resolve(null),
  ]);

  // Extract Tier 2 results (use fallbacks for rejected promises)
  const exploitResult = exploitSettled.status === "fulfilled" && exploitSettled.value
    ? exploitSettled.value
    : { success: true, findings: EMPTY_EXPLOIT_FINDINGS, agentName: "Exploit Agent", processingTime: 0 };
  const blResult = blSettled.status === "fulfilled" && blSettled.value
    ? blSettled.value
    : { success: true, findings: EMPTY_BL_FINDINGS, agentName: "Business Logic Agent", processingTime: 0 };
  const mvResult = mvSettled.status === "fulfilled" && mvSettled.value
    ? mvSettled.value
    : null;

  const exploitSummary = `Identified ${exploitResult.findings.exploitChains?.length || 0} potential exploit chains`;
  const blSummary = `Found ${blResult.findings.workflowAbuse?.length || 0} workflow abuse patterns`;
  await trackPhase("exploit", {
    status: exploitSettled.status === "fulfilled" ? "completed" : "failed",
    completedAt: new Date().toISOString(), duration: Date.now() - tier2Start,
    findingSummary: exploitSummary,
    error: exploitSettled.status === "rejected" ? String((exploitSettled as PromiseRejectedResult).reason) : undefined,
  });
  await trackPhase("business_logic", {
    status: blSettled.status === "fulfilled" ? "completed" : "failed",
    completedAt: new Date().toISOString(), duration: Date.now() - tier2Start,
    findingSummary: blSummary,
    error: blSettled.status === "rejected" ? String((blSettled as PromiseRejectedResult).reason) : undefined,
  });

  wsService.sendSharedMemoryUpdate(evaluationId, "exploit_agent", "ExploitAgent", "exploit", exploitSummary);

  console.log(`[Orchestrator] Tier 2 completed in ${Date.now() - tier2Start}ms`);

  // ──────────────────────────────────────────────────────────────
  // PolicyGuardian: Exploit chain validation (max 15s)
  // ──────────────────────────────────────────────────────────────
  onProgress?.("Policy Guardian", "policy_check", 40, "Validating exploit chains against policies...");

  const guardedExploitFindings = await withTimeout(
    runPolicyGuardianCheckLoop(exploitResult.findings, "Exploit Agent", guardianContext, evaluationId, memory, onProgress),
    GUARDIAN_LOOP_TIMEOUT_MS,
    exploitResult.findings
  );

  // ──────────────────────────────────────────────────────────────
  // Debate Module: Adversarial validation of exploit findings
  // Uses Llama 3.3 70B via OpenRouter to challenge false positives
  // ──────────────────────────────────────────────────────────────
  let debateResult: DebateResult | undefined;
  let debatedExploitFindings = guardedExploitFindings;

  if (guardedExploitFindings.exploitable && guardedExploitFindings.exploitChains.length > 0) {
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
        30_000
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
  if (mvResult) memory.multiVector = mvResult.findings;

  // ──────────────────────────────────────────────────────────────
  // Tier 3: Parallel — Lateral + Impact + Enhanced BL (max 30s wall-clock)
  // ──────────────────────────────────────────────────────────────
  const tier3Start = Date.now();
  await trackPhase("lateral", { status: "running", startedAt: new Date().toISOString(), message: "Identifying lateral movement paths..." });
  await trackPhase("impact", { status: "running", startedAt: new Date().toISOString(), message: "Assessing business impact..." });
  onProgress?.("Analysis Agents", "analysis_tier3", 50, "Running lateral, impact, and enhanced analysis...");
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator",
    "Running lateral movement, impact assessment, and enhanced analysis in parallel");

  const runEnhanced = shouldRunEnhancedEngine(exposureType);

  const [lateralSettled, impactSettled, enhancedSettled] = await Promise.allSettled([
    withCircuitBreaker(
      "openai",
      () => runWithHeartbeat(evaluationId, "Lateral Movement Agent",
        () => runLateralAgent(memory, (stage: string, progress: number, message: string) => {
          updateAgentHeartbeat(evaluationId, "Lateral Movement Agent", stage, progress, message);
          onProgress?.("Lateral Movement Agent", stage, 50 + Math.floor(progress * 0.1), message);
        })
      ),
      () => ({ success: true, findings: EMPTY_LATERAL_FINDINGS, agentName: "Lateral Movement Agent", processingTime: 0 }),
      30_000
    ),
    withCircuitBreaker(
      "openai",
      () => runWithHeartbeat(evaluationId, "Impact Agent",
        () => runImpactAgent(memory, (stage: string, progress: number, message: string) => {
          updateAgentHeartbeat(evaluationId, "Impact Agent", stage, progress, message);
          onProgress?.("Impact Agent", stage, 50 + Math.floor(progress * 0.1), message);
        })
      ),
      () => ({ success: true, findings: EMPTY_IMPACT_FINDINGS, agentName: "Impact Agent", processingTime: 0 }),
      30_000
    ),
    runEnhanced
      ? withCircuitBreaker(
          "openai",
          () => runWithHeartbeat(evaluationId, "Business Logic Engine",
            () => runEnhancedBusinessLogicEngine(memory, (stage: string, progress: number, message: string) => {
              updateAgentHeartbeat(evaluationId, "Business Logic Engine", stage, progress, message);
              onProgress?.("Business Logic Engine", stage, 50 + Math.floor(progress * 0.1), message);
            })
          ),
          () => ({
            success: true,
            findings: {
              basicFindings: EMPTY_BL_FINDINGS,
              detailedFindings: [],
              workflowAnalysis: null,
              paymentFlowVulnerabilities: [],
              stateTransitionViolations: [],
              inferredWorkflows: [],
            } as EnhancedBusinessLogicFindings,
            agentName: "Business Logic Engine",
            processingTime: 0,
          }),
          30_000
        )
      : Promise.resolve(null),
  ]);

  // Extract Tier 3 results
  const lateralResult = lateralSettled.status === "fulfilled" && lateralSettled.value
    ? lateralSettled.value
    : { success: true, findings: EMPTY_LATERAL_FINDINGS, agentName: "Lateral Movement Agent", processingTime: 0 };
  const impactResult = impactSettled.status === "fulfilled" && impactSettled.value
    ? impactSettled.value
    : { success: true, findings: EMPTY_IMPACT_FINDINGS, agentName: "Impact Agent", processingTime: 0 };
  const enhancedResult = enhancedSettled.status === "fulfilled" && enhancedSettled.value
    ? enhancedSettled.value
    : null;

  const lateralSummary = `Discovered ${lateralResult.findings.pivotPaths?.length || 0} lateral movement paths`;
  const impactSummary = `Data exposure severity: ${impactResult.findings.dataExposure?.severity || "unknown"}`;
  await trackPhase("lateral", {
    status: lateralSettled.status === "fulfilled" ? "completed" : "failed",
    completedAt: new Date().toISOString(), duration: Date.now() - tier3Start,
    findingSummary: lateralSummary,
    error: lateralSettled.status === "rejected" ? String((lateralSettled as PromiseRejectedResult).reason) : undefined,
  });
  await trackPhase("impact", {
    status: impactSettled.status === "fulfilled" ? "completed" : "failed",
    completedAt: new Date().toISOString(), duration: Date.now() - tier3Start,
    findingSummary: impactSummary,
    error: impactSettled.status === "rejected" ? String((impactSettled as PromiseRejectedResult).reason) : undefined,
  });

  wsService.sendSharedMemoryUpdate(evaluationId, "lateral_agent", "LateralAgent", "lateral", lateralSummary);

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
  if (enhancedResult) memory.enhancedBusinessLogic = enhancedResult.findings;

  // ──────────────────────────────────────────────────────────────
  // Tier 4: Synthesizer (1 LLM call, max 30s)
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
    30_000
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

  const evidenceArtifacts = generateEvidenceFromAnalysis({
    evaluationId,
    assetId,
    exposureType,
    attackPath: result.attackPath,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
  });

  const intelligentScore = generateFallbackScore({
    assetId,
    exposureType,
    priority,
    description,
    exploitable: result.exploitable,
    attackPath: result.attackPath,
    attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
  });

  onProgress?.("Remediation Engine", "remediation", 95, "Generating remediation guidance...");
  const remediationGuidance = await generateRemediationGuidance({
    assetId,
    exposureType,
    priority,
    description,
    exploitable: result.exploitable,
    attackPath: result.attackPath,
    attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
    intelligentScore,
  }, evaluationId, (stage, progress, message) => {
    onProgress?.("Remediation Engine", stage, 95 + Math.floor(progress / 25), message);
  });

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
// ──────────────────────────────────────────────────────────────
async function runPolicyGuardianCheckLoop(
  exploitFindings: ExploitFindings,
  agentName: string,
  guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  evaluationId: string,
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<ExploitFindings> {
  if (!exploitFindings.exploitChains || exploitFindings.exploitChains.length === 0) {
    return exploitFindings;
  }

  const allowedChains: typeof exploitFindings.exploitChains = [];
  let blockedCount = 0;
  let modifiedCount = 0;

  for (let i = 0; i < exploitFindings.exploitChains.length; i++) {
    const chain = exploitFindings.exploitChains[i];

    onProgress?.(
      "Policy Guardian",
      "policy_check",
      40 + Math.floor((i / exploitFindings.exploitChains.length) * 5),
      `Checking exploit chain ${i + 1}/${exploitFindings.exploitChains.length}: ${chain.name}`
    );

    try {
      const checkResult = await checkExploitChain(chain, guardianContext);

      const policyNames = checkResult.relevantPolicies.map((p) =>
        p.metadata.filename || p.metadata.policyType || "policy"
      );

      wsService.sendReasoningTrace(
        evaluationId,
        "policy_guardian",
        "PolicyGuardian",
        `Evaluating "${chain.name}": ${checkResult.reasoning}`,
        {
          context: `Exploit chain: ${chain.technique || "unknown technique"}`,
          policiesChecked: policyNames.length > 0 ? policyNames : ["default-policy"],
          decision: checkResult.decision,
        }
      );

      const safetyDecision: SafetyDecision = {
        id: `sd-${Date.now()}-${i}`,
        evaluationId,
        agentName,
        originalAction: `${chain.name}: ${chain.description}`,
        decision: checkResult.decision,
        modifiedAction: checkResult.modifiedAction,
        reasoning: checkResult.reasoning,
        policyReferences: checkResult.relevantPolicies.map((p) =>
          `${p.metadata.filename || "policy"}: ${p.content.substring(0, 80)}...`
        ),
        timestamp: checkResult.timestamp,
      };

      memory.safetyDecisions?.push(safetyDecision);

      wsService.sendSafetyBlock(
        evaluationId,
        agentName,
        checkResult.decision,
        `${chain.name}: ${chain.description}`,
        checkResult.reasoning,
        checkResult.modifiedAction
      );

      switch (checkResult.decision) {
        case "ALLOW":
          allowedChains.push(chain);
          break;
        case "DENY":
          blockedCount++;
          console.log(`[Orchestrator] Blocked exploit chain: ${chain.name} - ${checkResult.reasoning}`);
          break;
        case "MODIFY":
          modifiedCount++;
          allowedChains.push({
            ...chain,
            name: `[MODIFIED] ${chain.name}`,
            description: checkResult.modifiedAction || chain.description,
          });
          console.log(`[Orchestrator] Modified exploit chain: ${chain.name}`);
          break;
      }
    } catch (error) {
      console.error(`[Orchestrator] Policy check failed for chain ${chain.name}:`, error);
      if (guardianContext.executionMode === "safe") {
        blockedCount++;
      } else {
        allowedChains.push(chain);
      }
    }
  }

  console.log(`[Orchestrator] Policy Guardian results: ${allowedChains.length} allowed, ${blockedCount} blocked, ${modifiedCount} modified`);

  return {
    ...exploitFindings,
    exploitChains: allowedChains,
    exploitable: allowedChains.length > 0 && exploitFindings.exploitable,
  };
}

// ──────────────────────────────────────────────────────────────
// PolicyGuardian: Lateral movement check loop
// ──────────────────────────────────────────────────────────────
async function runLateralGuardianCheckLoop(
  lateralFindings: LateralFindings,
  guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  evaluationId: string,
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<LateralFindings> {
  if (!lateralFindings.pivotPaths || lateralFindings.pivotPaths.length === 0) {
    return lateralFindings;
  }

  const allowedPaths: typeof lateralFindings.pivotPaths = [];
  let blockedCount = 0;

  for (let i = 0; i < lateralFindings.pivotPaths.length; i++) {
    const path = lateralFindings.pivotPaths[i];

    onProgress?.(
      "Policy Guardian",
      "policy_check",
      70 + Math.floor((i / lateralFindings.pivotPaths.length) * 3),
      `Checking lateral path ${i + 1}/${lateralFindings.pivotPaths.length}: ${path.from} → ${path.to}`
    );

    try {
      const checkResult = await checkLateralMovement(path, guardianContext);

      const policyNames = checkResult.relevantPolicies.map((p) =>
        p.metadata.filename || p.metadata.policyType || "policy"
      );

      wsService.sendReasoningTrace(
        evaluationId,
        "policy_guardian",
        "PolicyGuardian",
        `Evaluating lateral path "${path.from} → ${path.to}": ${checkResult.reasoning}`,
        {
          context: `Lateral movement via ${path.method}`,
          policiesChecked: policyNames.length > 0 ? policyNames : ["default-policy"],
          decision: checkResult.decision,
        }
      );

      const safetyDecision: SafetyDecision = {
        id: `sd-lat-${Date.now()}-${i}`,
        evaluationId,
        agentName: "Lateral Movement Agent",
        originalAction: `${path.from} → ${path.to}: ${path.method}`,
        decision: checkResult.decision,
        modifiedAction: checkResult.modifiedAction,
        reasoning: checkResult.reasoning,
        policyReferences: checkResult.relevantPolicies.map((p) =>
          `${p.metadata.filename || "policy"}: ${p.content.substring(0, 80)}...`
        ),
        timestamp: checkResult.timestamp,
      };

      memory.safetyDecisions?.push(safetyDecision);

      wsService.sendSafetyBlock(
        evaluationId,
        "Lateral Movement Agent",
        checkResult.decision,
        `${path.from} → ${path.to}: ${path.method}`,
        checkResult.reasoning,
        checkResult.modifiedAction
      );

      if (checkResult.decision === "ALLOW" || checkResult.decision === "MODIFY") {
        allowedPaths.push(path);
      } else {
        blockedCount++;
        console.log(`[Orchestrator] Blocked lateral path: ${path.from} → ${path.to}`);
      }
    } catch (error) {
      console.error(`[Orchestrator] Policy check failed for lateral path:`, error);
      if (guardianContext.executionMode === "safe") {
        blockedCount++;
      } else {
        allowedPaths.push(path);
      }
    }
  }

  console.log(`[Orchestrator] Lateral Guardian results: ${allowedPaths.length} allowed, ${blockedCount} blocked`);

  return {
    ...lateralFindings,
    pivotPaths: allowedPaths,
  };
}

// ──────────────────────────────────────────────────────────────
// Confidence Breakdown Builder
// ──────────────────────────────────────────────────────────────
function buildConfidenceBreakdown(
  debateResult: DebateResult | undefined,
  realScanData: import("./scan-data-loader").RealScanData | undefined
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
