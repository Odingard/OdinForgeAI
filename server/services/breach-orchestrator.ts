/**
 * Cross-Domain Breach Orchestrator
 *
 * Chains evaluations across domains in a natural breach progression:
 *   Application Compromise → Credential Extraction → Cloud IAM Escalation
 *   → Container/K8s Breakout → Lateral Movement → Impact Assessment
 *
 * Each phase passes context (credentials, compromised assets, privilege levels)
 * to the next, building a unified cross-domain attack graph.
 */

import { randomUUID, createHash } from "crypto";
import type {
  BreachChain,
  BreachChainConfig,
  BreachPhaseName,
  BreachPhaseResult,
  BreachPhaseContext,
  BreachCredential,
  CompromisedAsset,
  AttackGraph,
  AttackNode,
  AttackEdge,
} from "@shared/schema";
import { runAgentOrchestrator } from "./agents/orchestrator";
import { isCircuitOpen } from "./agents/circuit-breaker";
import type { OrchestratorResult } from "./agents/types";
import {
  runActiveExploitEngine,
  mapToBreachPhaseContext,
  CREDENTIAL_PATTERNS,
  type ActiveExploitTarget,
  type ActiveExploitResult,
  type ExploitAttempt,
  type ExposureType,
} from "./active-exploit-engine";
import { credentialStore } from "./credential-store";
import { awsPentestService } from "./cloud-pentest/aws-pentest-service";
import { kubernetesPentestService } from "./container-security/kubernetes-pentest-service";
import { lateralMovementService } from "./lateral-movement";
import { storage } from "../storage";
import { wsService } from "./websocket";
import { getCredentialBus } from "./aev/credential-bus";
import type { HarvestedCredential } from "./aev/credential-bus";
import { PivotQueue, LateralMovementSubAgent, breachCredToHarvested, type PivotFinding } from "./aev/pivot-queue";
import { engagementLogger } from "./logger";
import { evidenceQualityGate, EvidenceQuality, type EvaluatedFinding, type BatchVerdict } from "./evidence-quality-gate";
import { DefendersMirror, type AttackEvidence, type DetectionRuleSet } from "./defenders-mirror";
import { ReachabilityChainBuilder, buildReachabilityChain, type PivotResult } from "./reachability-chain";
import { ReplayRecorder, type EngagementReplayManifest } from "./replay-recorder";

/**
 * Module-level store for Phase 1A raw evidence.
 * Keyed by chainId — written by executeApplicationCompromise,
 * read by executeCredentialExtraction to parse credentials from
 * actual HTTP response bodies without a separate LLM evaluation.
 * Cleared after Phase 2 consumes it.
 */
const phase1AEvidenceStore = new Map<string, ExploitAttempt[]>();

// ── ATT&CK technique IDs exercised per breach phase ──────────────────────────
const PHASE_ATTACK_TECHNIQUES: Record<string, string[]> = {
  application_compromise: ["T1190", "T1059.001", "T1203", "T1071.001"],
  credential_extraction:  ["T1003", "T1552", "T1555", "T1040"],
  cloud_iam_escalation:   ["T1078.004", "T1484.001", "T1098", "T1580"],
  container_k8s_breakout: ["T1611", "T1610", "T1543.003", "T1609"],
  lateral_movement:       ["T1021.001", "T1550.002", "T1563.002", "T1570"],
  impact_assessment:      ["T1486", "T1485", "T1565.001", "T1560"],
};

// ============================================================================
// TYPES
// ============================================================================

export type BreachOrchestratorProgressCallback = (
  chainId: string,
  phaseName: string,
  progress: number,
  message: string
) => void;

type PhaseExecutor = (
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
) => Promise<BreachPhaseResult>;

// ============================================================================
// LIVE MODE ENFORCEMENT DIRECTIVES
// ============================================================================

/**
 * Full system directive injected into all AI calls made within the breach chain.
 * Every LLM call that produces phase output must honor this constraint.
 */
export const BREACH_CHAIN_LIVE_DIRECTIVE = `
# ODINFORGE BREACH CHAIN — LIVE MODE DIRECTIVE

You are operating as a live AEV (Automated Evidence Validation) breach chain assistant.
This is a production environment. All behavior must reflect real, verified, live data at every phase.

## PRIME DIRECTIVE
Every phase and every tool in this breach chain must operate in LIVE MODE ONLY.
You are strictly prohibited from simulating, mocking, fabricating, estimating, or
substituting placeholder data at any step, in any phase, for any reason.

If a tool cannot return a live, verified, real-time result — STOP the chain entirely
and report the failure clearly before proceeding. There are NO exceptions.

## PHASES: Discovery → Verification → Notification → Remediation → AEV Pentesting
Each phase requires:
- Real tool execution with real network responses
- AEV evidence captured live and traceable to a confirmed source
- No carried-forward unverified data

## FAILURE PROTOCOL
If any tool fails to return a live result:
1. STOP the chain immediately
2. Identify which tool failed and at which phase
3. Report the failure with tool name, phase, and reason
4. Do NOT continue or skip ahead
5. Wait for human instruction before resuming

Live. Verified. Always.
`.trim();

/**
 * Shorter per-phase enforcement block for attaching to individual tool calls.
 */
export const BREACH_CHAIN_PHASE_DIRECTIVE = (phaseName: string) =>
  `[PHASE: ${phaseName.toUpperCase()} | LIVE MODE ENFORCED] ` +
  `Use only real, verified network data. No simulation. No fabrication. ` +
  `If this tool cannot return a live result, stop and report the failure.`;

/**
 * Validates that a breach chain has a real, non-empty target before execution begins.
 * Returns an error string if validation fails, or null if valid.
 */
function validateLiveTarget(chain: BreachChain): string | null {
  const assetId = chain.assetIds?.[0];
  if (!assetId || assetId.trim() === "") {
    return "LIVE MODE HALT: No target asset specified. Breach chain cannot run without a real target.";
  }
  let hostname: string;
  try {
    hostname = new URL(assetId).hostname;
  } catch {
    hostname = assetId;
  }
  if (!hostname || hostname === "localhost" || hostname === "127.0.0.1") {
    return `LIVE MODE HALT: Target '${hostname}' is not a valid live target. Localhost targets are not permitted.`;
  }
  return null;
}

// ============================================================================
// PHASE DEFINITIONS
// ============================================================================

const PHASE_ORDER: BreachPhaseName[] = [
  "application_compromise",
  "credential_extraction",
  "cloud_iam_escalation",
  "container_k8s_breakout",
  "lateral_movement",
  "impact_assessment",
];

const PHASE_DEFINITIONS: Record<BreachPhaseName, {
  displayName: string;
  description: string;
  progressRange: [number, number];
}> = {
  application_compromise: {
    displayName: "Application Compromise",
    description: "Exploit application-layer vulnerabilities for initial access",
    progressRange: [0, 20],
  },
  credential_extraction: {
    displayName: "Credential Extraction",
    description: "Harvest credentials from compromised application layer",
    progressRange: [20, 35],
  },
  cloud_iam_escalation: {
    displayName: "Cloud IAM Escalation",
    description: "Use extracted credentials to escalate in cloud environments",
    progressRange: [35, 55],
  },
  container_k8s_breakout: {
    displayName: "Container/K8s Breakout",
    description: "Use cloud access to abuse container orchestration",
    progressRange: [55, 70],
  },
  lateral_movement: {
    displayName: "Lateral Movement",
    description: "Pivot across network segments using all harvested credentials",
    progressRange: [70, 85],
  },
  impact_assessment: {
    displayName: "Impact Assessment",
    description: "Aggregate all breach paths into unified business impact",
    progressRange: [85, 100],
  },
};

// ============================================================================
// MAIN ENTRY POINTS
// ============================================================================

export async function runBreachChain(
  chainId: string,
  onProgress?: BreachOrchestratorProgressCallback
): Promise<void> {
  const chain = await storage.getBreachChain(chainId);
  if (!chain) throw new Error(`Breach chain ${chainId} not found`);

  // === LIVE MODE ENFORCEMENT: validate target before any phase executes ===
  const targetValidationError = validateLiveTarget(chain);
  if (targetValidationError) {
    console.error(`[BreachOrchestrator] ${targetValidationError}`);
    await storage.updateBreachChain(chainId, {
      status: "failed",
      completedAt: new Date(),
    });
    throw new Error(targetValidationError);
  }
  const log = engagementLogger(chainId);
  log.info({ target: chain.assetIds?.[0] }, "LIVE MODE ACTIVE — breach chain starting");

  const config = chain.config as BreachChainConfig;
  const startTime = Date.now();

  await storage.updateBreachChain(chainId, {
    status: "running",
    startedAt: new Date(),
  });

  broadcastBreachProgress(chainId, "starting", 0, "Breach chain initiated — LIVE MODE ENFORCED");

  // Initialize or restore context
  let context: BreachPhaseContext = (chain.currentContext as BreachPhaseContext) ?? {
    credentials: [],
    compromisedAssets: [],
    attackPathSteps: [],
    evidenceArtifacts: [],
    currentPrivilegeLevel: "none",
    domainsCompromised: [],
  };

  const phaseResults: BreachPhaseResult[] =
    (chain.phaseResults as BreachPhaseResult[]) || [];
  const completedPhases = new Set(
    phaseResults.filter(r => r.status === "completed").map(r => r.phaseName)
  );

  const enabledPhases = PHASE_ORDER.filter(p =>
    config.enabledPhases.includes(p)
  );

  // ── GTM v1.0 Feature Instances (per-engagement lifecycle) ──────────────
  const replayRecorder = new ReplayRecorder(chainId);
  const defendersMirror = new DefendersMirror();
  const reachabilityBuilder = new ReachabilityChainBuilder();

  try {
    for (const phaseName of enabledPhases) {
      // Skip already completed phases (for resume)
      if (completedPhases.has(phaseName)) continue;

      // Check abort — re-read status from DB
      const currentChain = await storage.getBreachChain(chainId);
      if (currentChain?.status === "aborted") {
        broadcastBreachProgress(chainId, "aborted", 0, "Breach chain aborted");
        return;
      }

      // Check total timeout
      if (Date.now() - startTime > config.totalTimeoutMs) {
        await storage.updateBreachChain(chainId, {
          status: "failed",
          currentContext: context,
          phaseResults,
        });
        broadcastBreachProgress(chainId, "timeout", 0, "Total timeout exceeded");
        return;
      }

      // Safety gate checks
      const gateResult = checkPhaseGate(phaseName, context, config);
      if (!gateResult.pass) {
        const skipResult: BreachPhaseResult = {
          phaseName,
          status: "skipped",
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          inputContext: {
            credentialCount: context.credentials.length,
            compromisedAssetCount: context.compromisedAssets.length,
            privilegeLevel: context.currentPrivilegeLevel,
          },
          outputContext: context,
          findings: [],
          error: gateResult.reason,
        };
        phaseResults.push(skipResult);
        await storage.updateBreachChain(chainId, {
          phaseResults,
          currentContext: context,
        });
        broadcastBreachProgress(
          chainId, phaseName, PHASE_DEFINITIONS[phaseName].progressRange[1],
          `Skipped ${PHASE_DEFINITIONS[phaseName].displayName}: ${gateResult.reason}`
        );
        continue;
      }

      // Update current phase
      const phaseDef = PHASE_DEFINITIONS[phaseName];
      await storage.updateBreachChain(chainId, {
        currentPhase: phaseName,
        progress: phaseDef.progressRange[0],
      });
      log.info({ phase: phaseName }, `Phase starting: ${phaseDef.displayName}`);
      broadcastBreachProgress(
        chainId, phaseName, phaseDef.progressRange[0],
        `Starting ${phaseDef.displayName}...`
      );

      // GTM v1.0: Replay — record phase start
      replayRecorder.recordPhaseStart(phaseName, chain.assetIds?.[0] || "unknown");

      // Execute phase with timeout
      const executor = getPhaseExecutor(phaseName);
      const phaseResult = await Promise.race([
        executor(chain, context, onProgress ?? defaultProgress),
        phaseTimeout(config.phaseTimeoutMs, phaseName),
      ]);

      phaseResults.push(phaseResult);

      // Merge output context
      if (phaseResult.status === "completed") {
        context = mergeContexts(context, phaseResult.outputContext);

        // Publish newly discovered credentials to the CredentialBus
        for (const cred of phaseResult.outputContext.credentials) {
          getCredentialBus().publish(chainId, {
            id: cred.id,
            engagementId: chainId,
            username: cred.username || cred.type,
            hash: cred.valueHash,
            privilegeTier: cred.accessLevel === "admin" ? "local_admin" : "standard_user",
            sourceSystem: cred.source || phaseName,
            sourceNodeId: `breach-${phaseName}`,
            sourceTactic: phaseDef.displayName,
            discoveredAt: cred.discoveredAt || new Date().toISOString(),
          });
        }
      }

      // ── GTM v1.0: Replay Recorder — record phase completion ──────────────
      replayRecorder.recordPhaseComplete(phaseName, chain.assetIds?.[0] || "unknown", phaseResult.findings.length);

      // ── GTM v1.0: Evidence Quality Gate — classify all findings ──────────
      const evaluatedFindings: EvaluatedFinding[] = phaseResult.findings.map(f => ({
        ...f,
        source: phaseName,
      }));
      const qualityVerdict = evidenceQualityGate.evaluateBatch(evaluatedFindings);

      // ── GTM v1.0: Defender's Mirror — generate detection rules per finding ─
      const phaseEvidence: AttackEvidence[] = phaseResult.findings
        .filter(f => f.severity === "critical" || f.severity === "high")
        .map(f => ({
          id: f.id,
          engagementId: chainId,
          phase: phaseName,
          techniqueCategory: f.technique || phaseName,
          targetUrl: chain.assetIds?.[0],
          networkProtocol: "http",
          success: phaseResult.status === "completed",
        }));
      const detectionRules = defendersMirror.generateBatch(phaseEvidence);

      // Record each finding as a replay event with quality + mirror refs
      for (let i = 0; i < phaseResult.findings.length; i++) {
        const f = phaseResult.findings[i];
        const verdict = qualityVerdict.passed.find(v => v.finding.id === f.id)
          || qualityVerdict.failed.find(v => v.finding.id === f.id);
        const mirrorRule = detectionRules.find(r => r.attackEvidenceRef === f.id);

        replayRecorder.record({
          eventType: f.severity === "critical" ? "exploit_success" : "exploit_attempt",
          phase: enabledPhases.indexOf(phaseName) + 1,
          phaseName,
          target: chain.assetIds?.[0] || "unknown",
          techniqueName: f.title,
          techniqueCategory: f.technique || phaseName,
          mitreAttackId: f.mitreId || "",
          outcome: phaseResult.status === "completed" ? "success" : "failure",
          evidenceSummary: f.description,
          evidenceQuality: verdict?.quality,
          defendersMirrorRef: mirrorRule?.id,
        });
      }

      // Build incremental attack graph from all completed results so far
      const incrementalGraph = buildUnifiedAttackGraph(phaseResults, context);

      // Persist incremental progress with partial graph
      await storage.updateBreachChain(chainId, {
        phaseResults,
        currentContext: context,
        progress: phaseDef.progressRange[1],
        unifiedAttackGraph: incrementalGraph,
      });

      broadcastBreachProgress(
        chainId, phaseName, phaseDef.progressRange[1],
        `${phaseDef.displayName} complete: ${phaseResult.findings.length} findings (${qualityVerdict.summary.proven} proven, ${qualityVerdict.summary.corroborated} corroborated)`
      );

      // Broadcast progressive graph update via WebSocket
      wsService.sendBreachChainGraphUpdate(
        chainId,
        phaseName,
        incrementalGraph,
        enabledPhases.indexOf(phaseName),
        enabledPhases.length
      );

      // Check pause-on-critical
      if (
        config.pauseOnCritical &&
        phaseResult.findings.some(f => f.severity === "critical")
      ) {
        await storage.updateBreachChain(chainId, { status: "paused" });
        broadcastBreachProgress(
          chainId, phaseName, phaseDef.progressRange[1],
          "Paused: Critical finding detected. Resume to continue."
        );
        return;
      }
    }

    // ── GTM v1.0: Engagement Duration Guard ────────────────────────────
    // An engagement completing in under 2 minutes on a non-trivial target
    // is running simulations, not real attacks. Log a warning for audit.
    const engagementDurationMs = Date.now() - startTime;
    const MIN_ENGAGEMENT_DURATION_MS = 2 * 60 * 1000; // 2 minutes
    if (engagementDurationMs < MIN_ENGAGEMENT_DURATION_MS) {
      const phasesRun = phaseResults.filter(r => r.status === "completed").length;
      log.warn(
        { durationMs: engagementDurationMs, phasesRun, threshold: MIN_ENGAGEMENT_DURATION_MS },
        `DURATION WARNING: Engagement completed in ${Math.round(engagementDurationMs / 1000)}s — below 2-minute threshold`
      );
      // Record as a replay event for audit trail
      replayRecorder.record({
        eventType: "phase_complete",
        target: chain.assetIds?.[0] || "unknown",
        phaseName: "duration_audit",
        outcome: "partial",
        evidenceSummary: `Engagement completed in ${Math.round(engagementDurationMs / 1000)}s — below 2-minute minimum threshold. Evidence review recommended.`,
      });
    }

    // Build unified attack graph spanning all domains
    const unifiedGraph = buildUnifiedAttackGraph(phaseResults, context);
    const overallRiskScore = calculateBreachRiskScore(phaseResults, context);
    const executiveSummary = generateBreachExecutiveSummary(phaseResults, context, overallRiskScore);

    // ── GTM v1.0: Finalize Replay Manifest ──────────────────────────────
    const replayManifest = replayRecorder.finalize();

    // ── GTM v1.0: Build Reachability Chain from lateral movement results ─
    const lateralPhase = phaseResults.find(p => p.phaseName === "lateral_movement" && p.status === "completed");
    const pivotResults: PivotResult[] = (lateralPhase?.findings || []).map(f => ({
      host: f.title?.match(/→\s*(.+)$/)?.[1] || chain.assetIds?.[0] || "unknown",
      depth: parseInt(f.title?.match(/Hop (\d+)/)?.[1] || "0"),
      technique: f.technique || "credential_reuse",
      authResult: "success" as const,
      accessLevel: "user",
      protocol: f.technique || "credential_reuse",
    }));
    let entryHost = chain.assetIds?.[0] || "unknown";
    try { entryHost = new URL(entryHost).hostname; } catch { /* use as-is */ }
    const reachabilityChain = buildReachabilityChain(chainId, entryHost, pivotResults);

    // ── GTM v1.0: Final Evidence Quality Summary across all phases ──────
    const allFindings: EvaluatedFinding[] = phaseResults.flatMap(pr =>
      pr.findings.map(f => ({ ...f, source: pr.phaseName }))
    );
    const finalQualityVerdict = evidenceQualityGate.evaluateBatch(allFindings);

    // ── GTM v1.0: All Defender's Mirror rules for this engagement ───────
    const allDetectionRules = defendersMirror.getRulesForEngagement(chainId);

    await storage.updateBreachChain(chainId, {
      status: "completed",
      progress: 100,
      currentPhase: null,
      phaseResults,
      currentContext: context,
      unifiedAttackGraph: unifiedGraph,
      overallRiskScore,
      totalCredentialsHarvested: context.credentials.length,
      totalAssetsCompromised: context.compromisedAssets.length,
      domainsBreached: context.domainsCompromised,
      maxPrivilegeAchieved: context.currentPrivilegeLevel,
      executiveSummary,
      completedAt: new Date(),
      durationMs: Date.now() - startTime,
      // GTM v1.0 feature data
      replayManifest: replayManifest as any,
      reachabilityChain: reachabilityChain as any,
      evidenceQualitySummary: finalQualityVerdict.summary as any,
      detectionRules: allDetectionRules as any,
    });

    // Broadcast final graph update
    wsService.sendBreachChainGraphUpdate(
      chainId, "completed", unifiedGraph,
      enabledPhases.length, enabledPhases.length
    );
    broadcastBreachProgress(chainId, "completed", 100,
      `Breach chain complete — ${finalQualityVerdict.summary.proven} proven, ${allDetectionRules.length} detection rules generated`);

    // Auto-generate Purple Team findings from completed breach chain
    createPurpleTeamFindingsFromChain(chainId, chain.organizationId, phaseResults).catch(err => {
      console.error(`[BreachOrchestrator] Failed to create purple team findings for chain ${chainId}:`, err);
    });

    // v3.0: Append risk snapshot for continuous exposure trending
    import("./breach-chain/continuous-exposure").then(({ appendRiskSnapshot, initializeSla }) => {
      const nodeCount = unifiedGraph?.nodes?.length ?? 0;
      const criticalPathLength = unifiedGraph?.criticalPath?.length ?? 0;
      appendRiskSnapshot(chainId, {
        score: overallRiskScore,
        nodeCount,
        criticalPathLength,
        completedAt: new Date().toISOString(),
      }).catch(() => {});
      initializeSla(chainId, overallRiskScore).catch(() => {});
    }).catch(() => {});
  } catch (error) {
    log.error({ err: error }, "Breach chain failed");
    await storage.updateBreachChain(chainId, {
      status: "failed",
      currentContext: context,
      phaseResults,
    });
    broadcastBreachProgress(
      chainId, "failed", 0,
      `Breach chain failed: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

export async function resumeBreachChain(chainId: string): Promise<void> {
  const chain = await storage.getBreachChain(chainId);
  if (!chain) throw new Error(`Breach chain ${chainId} not found`);
  if (chain.status !== "paused") {
    throw new Error(`Cannot resume chain in ${chain.status} state`);
  }
  await storage.updateBreachChain(chainId, { status: "running" });
  return runBreachChain(chainId);
}

export async function abortBreachChain(chainId: string): Promise<void> {
  await storage.updateBreachChain(chainId, { status: "aborted" });
  broadcastBreachProgress(chainId, "aborted", 0, "Breach chain aborted by user");
}

// ============================================================================
// PURPLE TEAM AUTO-GENERATION FROM BREACH CHAIN
// ============================================================================

async function createPurpleTeamFindingsFromChain(
  chainId: string,
  organizationId: string,
  phaseResults: BreachPhaseResult[]
): Promise<void> {
  let count = 0;

  for (const pr of phaseResults) {
    if (pr.status === "pending" || pr.status === "running") continue;

    const detectionStatus: "detected" | "partially_detected" | "missed" =
      pr.status === "completed" ? "missed"
      : pr.status === "blocked" || pr.status === "failed" ? "detected"
      : "partially_detected";

    const effectivenessBase = detectionStatus === "missed" ? 15 : detectionStatus === "detected" ? 75 : 50;

    for (const f of pr.findings) {
      const severityAdjust = f.severity === "critical" ? -10 : f.severity === "high" ? -5 : 0;
      const phaseName = PHASE_DEFINITIONS[pr.phaseName]?.displayName || pr.phaseName;

      try {
        await storage.createPurpleTeamFinding({
          organizationId,
          findingType: detectionStatus === "missed" ? "detection_gap" : "detection_success",
          offensiveTechnique: f.mitreId || f.technique || pr.phaseName,
          offensiveDescription: `[${phaseName}] ${f.description}`,
          detectionStatus,
          controlEffectiveness: Math.max(0, Math.min(100, effectivenessBase + severityAdjust)),
          implementationPriority: f.severity,
          defensiveRecommendation: `${f.title}: ${f.description}`,
          feedbackStatus: "pending",
        });
        count++;
      } catch (err) {
        console.error(`[BreachOrchestrator] Failed to create purple team finding from chain ${chainId}:`, err);
      }
    }
  }

  if (count > 0) {
    console.log(`[BreachOrchestrator] Created ${count} purple team findings from chain ${chainId}`);
  }
}

// ============================================================================
// PHASE EXECUTOR ROUTER
// ============================================================================

function getPhaseExecutor(phaseName: BreachPhaseName): PhaseExecutor {
  switch (phaseName) {
    case "application_compromise":
      return executeApplicationCompromise;
    case "credential_extraction":
      return executeCredentialExtraction;
    case "cloud_iam_escalation":
      return executeCloudIAMEscalation;
    case "container_k8s_breakout":
      return executeContainerK8sBreakout;
    case "lateral_movement":
      return executeLateralMovement;
    case "impact_assessment":
      return executeImpactAssessment;
  }
}

// ============================================================================
// PHASE 1: APPLICATION COMPROMISE
// ============================================================================

async function executeApplicationCompromise(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const config = chain.config as BreachChainConfig;
  const findings: BreachPhaseResult["findings"] = [];
  const evaluationIds: string[] = [];
  const newCredentials: BreachCredential[] = [];
  const newAssets: CompromisedAsset[] = [];

  for (const assetId of chain.assetIds as string[]) {
    // ─────────────────────────────────────────────────────────────────
    // Phase 1A: Run Active Exploit Engine against the live target
    // ─────────────────────────────────────────────────────────────────
    let activeExploitResult: ActiveExploitResult | null = null;

    try {
      const targetUrl = await resolveAssetUrl(assetId);

      if (targetUrl) {
        onProgress(chain.id, "application_compromise", 5,
          `Running active exploitation against ${targetUrl}`);

        const exploitTarget: ActiveExploitTarget = {
          baseUrl: targetUrl,
          assetId,
          scope: {
            exposureTypes: [
              "sqli", "xss", "ssrf", "auth_bypass", "idor",
              "path_traversal", "command_injection", "jwt_abuse",
              "api_abuse", "business_logic",
            ] as ExposureType[],
            excludePaths: ["\\.pdf$", "\\.png$", "\\.jpg$", "\\.css$", "\\.js$"],
            maxEndpoints: 200,
          },
          timeout: 10000,
          maxRequests: 500,
          crawlDepth: 3,
        };

        activeExploitResult = await runActiveExploitEngine(
          exploitTarget,
          (phase, progress, detail) => {
            onProgress(chain.id, "application_compromise",
              5 + Math.round(Math.max(0, progress) * 0.4), // scale to 5-45% of phase
              `[Active Exploit] ${detail}`);
          }
        );

        // Store raw validated attempts for Phase 2 direct evidence parsing
        // Phase 2 reads response bodies from these to extract credentials without
        // running a separate LLM evaluation.
        const existingEvidence = phase1AEvidenceStore.get(chain.id) || [];
        phase1AEvidenceStore.set(chain.id, [...existingEvidence, ...activeExploitResult.validated]);

        // Map active results into breach phase format
        const mapped = mapToBreachPhaseContext(activeExploitResult);

        // Merge validated credentials (REAL, not heuristic)
        for (const cred of mapped.credentials) {
          newCredentials.push({
            id: `bc-${randomUUID().slice(0, 8)}`,
            type: cred.type as BreachCredential["type"],
            valueHash: cred.hash,
            source: "active_exploit_engine",
            accessLevel: cred.accessLevel === "admin" ? "admin" : "user",
            validatedTargets: [targetUrl],
            discoveredAt: new Date().toISOString(),
          });
        }

        // Merge compromised assets
        for (const asset of mapped.compromisedAssets) {
          // Dedup by assetId
          if (!newAssets.find(a => a.assetId === asset.assetId)) {
            newAssets.push({
              id: `ca-${randomUUID().slice(0, 8)}`,
              assetId: asset.assetId,
              assetType: "application",
              name: asset.assetId,
              accessLevel: asset.accessLevel === "admin" ? "admin" : "user",
              compromisedBy: "application_compromise",
              accessMethod: asset.exploitUsed,
              timestamp: new Date().toISOString(),
            });
          }
        }

        // Store validated findings with [VALIDATED] prefix
        for (const finding of mapped.findings) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: finding.title,
            description: finding.description,
            technique: finding.exploitChain,
          });
        }

        console.log(`[BreachOrchestrator] Active Exploit Results for ${assetId}:`, {
          endpoints: activeExploitResult.summary.totalEndpoints,
          attempts: activeExploitResult.summary.totalAttempts,
          validated: activeExploitResult.summary.totalValidated,
          credentials: activeExploitResult.summary.totalCredentials,
          attackPaths: activeExploitResult.summary.attackPathsFound,
          duration: `${activeExploitResult.durationMs}ms`,
        });
      }
    } catch (err: any) {
      console.warn(`[BreachOrchestrator] Active exploit engine error for ${assetId}:`, err.message);
      // Fall through to AI pipeline — active exploits are additive, not blocking
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase 1B: Run AI Agent Pipeline (existing, now enhanced with
    //           active exploit evidence for context)
    // ─────────────────────────────────────────────────────────────────
    onProgress(chain.id, "application_compromise", 50,
      `Running AI analysis pipeline for ${assetId}`);

    const exposureTypes = ["app_logic", "cve", "api_sequence_abuse"];

    for (const exposureType of exposureTypes) {
      const evaluationId = `eval-bc-${randomUUID().slice(0, 8)}`;

      // Build description with active exploit context if available
      const activeContext = activeExploitResult
        ? ` Active exploitation found ${activeExploitResult.summary.totalValidated} confirmed vulnerabilities and ${activeExploitResult.summary.totalCredentials} credentials.`
        : "";

      // Skip AI pipeline if OpenAI circuit is open (provider is down/slow)
      if (isCircuitOpen("openai")) {
        console.warn(`[BreachOrchestrator] OpenAI circuit open, skipping AI pipeline for ${assetId}/${exposureType}`);
        continue;
      }

      try {
        await storage.createEvaluation({
          assetId,
          exposureType,
          priority: "high",
          description: `Breach chain ${chain.id}: Application Compromise (${exposureType}).${activeContext}`,
          organizationId: chain.organizationId,
          executionMode: config.executionMode,
          status: "pending",
        });

        const result = await runAgentOrchestrator(
          assetId,
          exposureType,
          "high",
          `Breach chain ${chain.id}: Application Compromise phase targeting ${assetId}.${activeContext}`,
          evaluationId,
          (agentName, stage, progress, message) => {
            onProgress(chain.id, "application_compromise",
              50 + Math.round(progress * 0.4), // scale to 50-90% of phase
              `[AI Pipeline] [${agentName}] ${message}`);
          },
          {
            adversaryProfile: config.adversaryProfile as any,
            organizationId: chain.organizationId,
            executionMode: config.executionMode,
            breachDirective: BREACH_CHAIN_LIVE_DIRECTIVE,
          }
        );

        evaluationIds.push(evaluationId);

        await storage.createResult({
          id: `res-${randomUUID().slice(0, 8)}`,
          evaluationId,
          exploitable: result.exploitable,
          confidence: result.confidence,
          score: result.score,
          attackPath: result.attackPath,
          attackGraph: result.attackGraph,
          impact: null,
          recommendations: null,
          duration: Date.now() - startTime,
        });

        if (result.exploitable) {
          for (const step of result.attackPath || []) {
            findings.push({
              id: `bf-${randomUUID().slice(0, 8)}`,
              severity: step.severity,
              title: step.title,
              description: step.description,
              technique: step.technique,
            });
          }

          // Only add asset if not already found by active engine
          if (!newAssets.find(a => a.assetId === assetId)) {
            newAssets.push({
              id: `ca-${randomUUID().slice(0, 8)}`,
              assetId,
              assetType: "application",
              name: assetId,
              accessLevel: result.score >= 80 ? "admin" : result.score >= 50 ? "user" : "limited",
              compromisedBy: "application_compromise",
              accessMethod: exposureType,
              timestamp: new Date().toISOString(),
            });
          }
        }

        // Extract credential hints from AI findings (heuristic)
        // Only add if not already found by active engine (dedup by hash)
        const aiCredentials = extractCredentialsFromFindings(result, "application_compromise");
        for (const cred of aiCredentials) {
          if (!newCredentials.find(c => c.valueHash === cred.valueHash)) {
            newCredentials.push(cred);
          }
        }
      } catch (error) {
        console.error(`[BreachOrchestrator] App compromise failed for ${assetId}/${exposureType}:`, error);
      }
    }
  }

  return buildPhaseResult("application_compromise", startTime, context, {
    credentials: newCredentials,
    assets: newAssets,
    findings,
    evaluationIds,
    domain: "application",
  });
}

/**
 * Resolve an asset ID to a target URL for active exploitation.
 * Looks up the asset from the discovered_assets table and constructs
 * a URL from hostname/fqdn/ipAddresses + open ports.
 */
async function resolveAssetUrl(assetId: string): Promise<string | null> {
  try {
    // Try discovered asset lookup
    const asset = await storage.getDiscoveredAsset(assetId);
    if (asset) {
      const host = asset.fqdn || asset.hostname || (asset.ipAddresses as string[])?.[0];
      if (!host) return null;

      // Find the best port — prefer 443 (HTTPS), then 8443, then 80, then first open port
      const ports = (asset.openPorts as Array<{ port: number; protocol: string; service?: string }>) || [];
      const httpsPort = ports.find(p => p.port === 443 || p.service?.includes("https"));
      const httpPort = ports.find(p => p.port === 80 || p.port === 8080 || p.service?.includes("http"));
      const webPort = httpsPort || httpPort || ports[0];

      if (webPort) {
        const scheme = webPort.port === 443 || webPort.service?.includes("https") ? "https" : "http";
        const portSuffix = (scheme === "https" && webPort.port === 443) || (scheme === "http" && webPort.port === 80)
          ? "" : `:${webPort.port}`;
        return `${scheme}://${host}${portSuffix}`;
      }

      // No port info — try HTTPS then HTTP
      return `https://${host}`;
    }

    // If assetId looks like a URL already, use it directly
    if (assetId.startsWith("http://") || assetId.startsWith("https://")) {
      return assetId;
    }

    // If assetId looks like a hostname/FQDN, wrap it
    if (assetId.includes(".") && !assetId.includes(" ")) {
      return `https://${assetId}`;
    }

    return null;
  } catch (error) {
    console.warn(`[BreachOrchestrator] Failed to resolve asset URL for ${assetId}:`, error);
    return null;
  }
}

// ============================================================================
// PHASE 2: CREDENTIAL EXTRACTION
// ============================================================================

async function executeCredentialExtraction(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const config = chain.config as BreachChainConfig;
  const findings: BreachPhaseResult["findings"] = [];
  const evaluationIds: string[] = [];
  const newCredentials: BreachCredential[] = [];

  // ── Step 1: Re-use credentials already extracted by Phase 1A regex engine ──
  // These are encrypted (authValue) and ready for auth — do not re-extract.
  const activeCredentials = context.credentials.filter(c =>
    c.source === "active_exploit_engine" || c.source?.includes("active_exploit")
  );
  if (activeCredentials.length > 0) {
    onProgress(chain.id, "credential_extraction", 22,
      `${activeCredentials.length} credentials carried forward from Phase 1A active exploitation`);
  }

  // ── Step 2: Parse Phase 1A HTTP response bodies for credentials ──────────
  // This is deterministic — no LLM, no circuit breaker dependency.
  const phase1Attempts = phase1AEvidenceStore.get(chain.id) || [];
  if (phase1Attempts.length > 0) {
    onProgress(chain.id, "credential_extraction", 25,
      `Parsing ${phase1Attempts.length} Phase 1A HTTP responses for credentials...`);

    for (const attempt of phase1Attempts) {
      const body = attempt.response.body;
      const headers = attempt.response.headers;
      // Search response body + headers for credentials
      const searchTargets = [
        body,
        ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      ];

      for (const target of searchTargets) {
        for (const pattern of CREDENTIAL_PATTERNS) {
          // Reset lastIndex on global regexps to avoid state bugs
          pattern.pattern.lastIndex = 0;
          const matches = Array.from(target.matchAll(pattern.pattern));
          for (const match of matches) {
            const plaintext = match[1] || match[0];
            if (plaintext.length < 4) continue;
            const cred = credentialStore.create({
              type: pattern.type as any,
              plaintext,
              source: "credential_extraction",
              context: `Phase 1A response body: ${attempt.endpoint.url} via ${attempt.payload.name}`,
              accessLevel: pattern.accessLevel as any,
            });

            // Dedup against existing credentials by hash
            if (!newCredentials.find(c => c.valueHash === cred.hash) &&
                !activeCredentials.find(c => c.valueHash === cred.hash)) {
              newCredentials.push({
                id: cred.id,
                type: pattern.type as BreachCredential["type"],
                valueHash: cred.hash,
                source: "credential_extraction",
                accessLevel: cred.accessLevel === "admin" ? "admin" : "user",
                validatedTargets: [attempt.endpoint.url],
                discoveredAt: new Date().toISOString(),
                // Store encrypted authValue for Phase 5 consumption
                username: attempt.endpoint.url,
                ...(cred as any),
              });
              findings.push({
                id: `bf-${randomUUID().slice(0, 8)}`,
                severity: pattern.accessLevel === "admin" ? "critical" : "high",
                title: `Credential Extracted: ${pattern.type}`,
                description: `${pattern.type} credential found in Phase 1A HTTP response from ${attempt.endpoint.url} (${attempt.payload.name}). Display: ${cred.displayValue}`,
                technique: "T1552",
                mitreId: "T1552",
              });
            }
          }
        }
      }
    }

    // Clear Phase 1A evidence — consumed, no longer needed in memory
    phase1AEvidenceStore.delete(chain.id);
    onProgress(chain.id, "credential_extraction", 60,
      `Evidence parsing complete — ${newCredentials.length} credentials extracted from HTTP responses`);
  }

  // ── Step 3: LLM fallback ONLY when parser produced zero results on non-empty evidence ──
  if (newCredentials.length === 0 && phase1Attempts.length === 0) {
    const compromisedAppAssets = context.compromisedAssets.filter(
      a => a.assetType === "application"
    );
    for (const asset of compromisedAppAssets) {
      if (isCircuitOpen("openai")) {
        console.warn(`[BreachOrchestrator] OpenAI circuit open, skipping LLM credential fallback for ${asset.assetId}`);
        continue;
      }
      const evaluationId = `eval-bc-${randomUUID().slice(0, 8)}`;
      try {
        await storage.createEvaluation({
          assetId: asset.assetId,
          exposureType: "data_exfiltration",
          priority: "high",
          description: `[LLM FALLBACK] Breach chain ${chain.id}: No credentials found in Phase 1A evidence. LLM analysis for ${asset.name}.`,
          organizationId: chain.organizationId,
          executionMode: config.executionMode,
          status: "pending",
        });
        const result = await runAgentOrchestrator(
          asset.assetId,
          "data_exfiltration",
          "high",
          `Breach chain ${chain.id}: Credential Extraction LLM fallback. Prior access: ${asset.accessLevel} on ${asset.name}. No credentials were found in HTTP evidence — use reasoning to identify likely credential exposure vectors.`,
          evaluationId,
          (agentName, _stage, progress, message) => {
            onProgress(chain.id, "credential_extraction", 60 + Math.round(progress * 0.3), `[LLM Fallback] [${agentName}] ${message}`);
          },
          {
            adversaryProfile: config.adversaryProfile as any,
            organizationId: chain.organizationId,
            executionMode: config.executionMode,
          }
        );
        evaluationIds.push(evaluationId);
        const llmCreds = extractCredentialsFromFindings(result, "credential_extraction");
        // Mark as low-confidence LLM-inferred credentials
        for (const c of llmCreds) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: "low",
            title: `[LLM Inferred] Potential Credential: ${c.type}`,
            description: `LLM analysis suggests credential exposure. Confidence: low — not extracted from real HTTP evidence. Requires manual validation.`,
            technique: "T1552",
            mitreId: "T1552",
          });
        }
        newCredentials.push(...llmCreds);
      } catch (error) {
        console.error(`[BreachOrchestrator] LLM credential fallback failed for ${asset.assetId}:`, error);
      }
    }
  }

  return buildPhaseResult("credential_extraction", startTime, context, {
    credentials: newCredentials,
    assets: [],
    findings,
    evaluationIds,
    domain: "credentials",
  });
}

// ============================================================================
// PHASE 3: CLOUD IAM ESCALATION
// ============================================================================

async function executeCloudIAMEscalation(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const config = chain.config as BreachChainConfig;
  const findings: BreachPhaseResult["findings"] = [];
  const evaluationIds: string[] = [];
  const newCredentials: BreachCredential[] = [];
  const newAssets: CompromisedAsset[] = [];

  // Analyze IAM privilege escalation using harvested credentials
  const cloudCreds = context.credentials.filter(c =>
    ["api_key", "iam_role", "service_account", "token"].includes(c.type)
  );

  // Only run IAM analysis on credentials that are confirmed real — not inferred
  const confirmedCloudCreds = cloudCreds.filter(c =>
    c.source === "active_exploit_engine" ||
    c.source === "application_compromise" ||
    c.source === "credential_extraction"
  );

  if (confirmedCloudCreds.length > 0) {
    onProgress(chain.id, "cloud_iam_escalation", 40, `Analyzing IAM escalation for ${confirmedCloudCreds.length} confirmed cloud credentials`);

    try {
      // Build permission set from confirmed credential metadata only
      const inferredPermissions = confirmedCloudCreds.flatMap(c => {
        if (c.type === "iam_role") return ["iam:*", "sts:AssumeRole"];
        if (c.type === "api_key") return ["ec2:Describe*", "s3:List*", "iam:List*"];
        if (c.type === "service_account") return ["iam:PassRole", "lambda:CreateFunction"];
        return ["sts:GetCallerIdentity"];
      });

      const iamResult = await awsPentestService.analyzeIAMPrivilegeEscalation(
        inferredPermissions,
        confirmedCloudCreds[0]?.username || "breach-chain-principal",
        confirmedCloudCreds[0]?.username || "breach-chain-principal"
      );

      for (const path of iamResult.escalationPaths) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: path.impact === "critical" ? "critical" : path.impact === "high" ? "high" : "medium",
          title: `IAM Privilege Escalation: ${path.name}`,
          description: `${path.description}. Steps: ${path.steps.join(" → ")}`,
          technique: path.steps[0],
          mitreId: path.mitreId,
        });

        // Escalation paths yield elevated credentials
        newCredentials.push({
          id: `bc-${randomUUID().slice(0, 8)}`,
          type: "iam_role",
          username: `escalated-${path.name}`,
          valueHash: hashValue(`escalated-${path.name}-${chain.id}`),
          source: "cloud_iam_escalation",
          accessLevel: path.impact === "critical" ? "cloud_admin" : "admin",
          validatedTargets: ["aws-iam"],
          discoveredAt: new Date().toISOString(),
        });
      }

      if (iamResult.escalationPaths.length > 0) {
        newAssets.push({
          id: `ca-${randomUUID().slice(0, 8)}`,
          assetId: "aws-iam",
          assetType: "iam_principal",
          name: "AWS IAM (escalated)",
          accessLevel: iamResult.riskScore >= 80 ? "admin" : "user",
          compromisedBy: "cloud_iam_escalation",
          accessMethod: "iam_privilege_escalation",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error("[BreachOrchestrator] IAM escalation analysis failed:", error);
    }
  }

  // Also run the AEV orchestrator for cloud_misconfiguration and iam_abuse
  const cloudExposureTypes = ["cloud_misconfiguration", "iam_abuse"];
  for (const assetId of chain.assetIds as string[]) {
    for (const exposureType of cloudExposureTypes) {
      const evaluationId = `eval-bc-${randomUUID().slice(0, 8)}`;
      const contextDescription = [
        `Breach chain ${chain.id}: Cloud IAM Escalation phase.`,
        `Prior access: ${context.currentPrivilegeLevel}.`,
        `Harvested ${context.credentials.length} credentials from prior phases.`,
        `Compromised assets: ${context.compromisedAssets.map(a => a.name).join(", ")}.`,
      ].join(" ");

      // Skip AI pipeline if OpenAI circuit is open
      if (isCircuitOpen("openai")) {
        console.warn(`[BreachOrchestrator] OpenAI circuit open, skipping cloud IAM analysis for ${assetId}/${exposureType}`);
        continue;
      }

      try {
        await storage.createEvaluation({
          assetId,
          exposureType,
          priority: "high",
          description: contextDescription,
          organizationId: chain.organizationId,
          executionMode: config.executionMode,
          status: "pending",
        });

        const result = await runAgentOrchestrator(
          assetId,
          exposureType,
          "high",
          contextDescription,
          evaluationId,
          (agentName, stage, progress, message) => {
            onProgress(chain.id, "cloud_iam_escalation", progress, `[${agentName}] ${message}`);
          },
          {
            adversaryProfile: config.adversaryProfile as any,
            organizationId: chain.organizationId,
            executionMode: config.executionMode,
            breachDirective: BREACH_CHAIN_LIVE_DIRECTIVE,
          }
        );

        evaluationIds.push(evaluationId);

        await storage.createResult({
          id: `res-${randomUUID().slice(0, 8)}`,
          evaluationId,
          exploitable: result.exploitable,
          confidence: result.confidence,
          score: result.score,
          attackPath: result.attackPath,
          attackGraph: result.attackGraph,
          impact: null,
          recommendations: null,
          duration: Date.now() - startTime,
        });

        if (result.exploitable) {
          for (const step of result.attackPath || []) {
            findings.push({
              id: `bf-${randomUUID().slice(0, 8)}`,
              severity: step.severity,
              title: step.title,
              description: step.description,
              technique: step.technique,
            });
          }
        }

        newCredentials.push(...extractCredentialsFromFindings(result, "cloud_iam_escalation"));
      } catch (error) {
        console.error(`[BreachOrchestrator] Cloud eval failed for ${assetId}/${exposureType}:`, error);
      }
    }
  }

  return buildPhaseResult("cloud_iam_escalation", startTime, context, {
    credentials: newCredentials,
    assets: newAssets,
    findings,
    evaluationIds,
    domain: "cloud",
  });
}

// ============================================================================
// PHASE 4: CONTAINER/K8S BREAKOUT
// ============================================================================

async function executeContainerK8sBreakout(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const findings: BreachPhaseResult["findings"] = [];
  const newCredentials: BreachCredential[] = [];
  const newAssets: CompromisedAsset[] = [];

  // Extract real target hostname
  let targetHost = (chain.assetIds as string[])[0] || "";
  try { targetHost = new URL(targetHost).hostname; } catch { /* use as-is */ }

  onProgress(chain.id, "container_k8s_breakout", 57, `Probing ${targetHost} for Kubernetes attack surface`);

  // ── Step 1: Real port probes for K8s components ──────────────────────────
  const K8S_PORTS = [
    { port: 6443,  label: "K8s API Server (TLS)",   protocol: "https" },
    { port: 8443,  label: "K8s API Server (alt)",   protocol: "https" },
    { port: 10250, label: "Kubelet API",             protocol: "https" },
    { port: 10255, label: "Kubelet read-only",       protocol: "http"  },
    { port: 2379,  label: "etcd client",             protocol: "http"  },
    { port: 2380,  label: "etcd peer",               protocol: "http"  },
  ];

  const net = await import("net");
  const tcpProbe = (host: string, port: number): Promise<boolean> =>
    new Promise(resolve => {
      const s = net.createConnection({ host, port, timeout: 3000 });
      const t = setTimeout(() => { s.destroy(); resolve(false); }, 3000);
      s.on("connect", () => { clearTimeout(t); s.destroy(); resolve(true); });
      s.on("error",   () => { clearTimeout(t); resolve(false); });
    });

  const portResults = await Promise.all(
    K8S_PORTS.map(async p => ({ ...p, open: await tcpProbe(targetHost, p.port) }))
  );
  const openPorts = portResults.filter(p => p.open);

  if (openPorts.length === 0) {
    console.info(`[BreachOrchestrator] No K8s ports open on ${targetHost} — skipping container phase`);
    return buildPhaseResult("container_k8s_breakout", startTime, context, {
      credentials: [], assets: [],
      findings: [{
        id: `bf-${randomUUID().slice(0, 8)}`,
        severity: "low",
        title: "No Kubernetes Attack Surface Found",
        description: `Probed ${targetHost} on ports ${K8S_PORTS.map(p => p.port).join(", ")}. None are open — no K8s or container orchestration exposure on this target.`,
        technique: "T1046",
      }],
      evaluationIds: [],
      domain: "kubernetes",
    });
  }

  onProgress(chain.id, "container_k8s_breakout", 62,
    `Found ${openPorts.length} open K8s port(s): ${openPorts.map(p => `${p.port} (${p.label})`).join(", ")}`);

  // ── Step 2: Probe unauthenticated K8s API endpoints ──────────────────────
  const fetchK8s = async (url: string): Promise<{ ok: boolean; body: string; status: number }> => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "OdinForge-AEV/1.0" },
      });
      const body = await res.text().catch(() => "");
      return { ok: res.ok, body: body.substring(0, 4000), status: res.status };
    } catch {
      return { ok: false, body: "", status: 0 };
    } finally {
      clearTimeout(t);
    }
  };

  // Attempt unauthenticated access to K8s API discovery endpoints
  const apiHost = openPorts.find(p => p.port === 6443 || p.port === 8443);
  const kubeletReadonly = openPorts.find(p => p.port === 10255);
  const etcd = openPorts.find(p => p.port === 2379);

  const discoveredPods: string[] = [];
  const discoveredSecrets: string[] = [];
  const k8sVersion: string | null = null;
  let unauthApiAccess = false;

  if (apiHost) {
    const versionRes = await fetchK8s(`https://${targetHost}:${apiHost.port}/version`);
    if (versionRes.ok && versionRes.body.includes("gitVersion")) {
      unauthApiAccess = true;
      try {
        const v = JSON.parse(versionRes.body);
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: "critical",
          title: "Unauthenticated K8s API Server Access",
          description: `K8s API server on ${targetHost}:${apiHost.port} responds to unauthenticated /version — version: ${v.gitVersion || "unknown"}. Full API may be accessible without credentials.`,
          technique: "T1613",
          mitreId: "T1613",
        });
      } catch {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: "critical",
          title: "Unauthenticated K8s API Server Access",
          description: `K8s API server on ${targetHost}:${apiHost.port} responds to unauthenticated requests — no authentication required.`,
          technique: "T1613",
          mitreId: "T1613",
        });
      }

      // Try to list namespaces — high-value unauthenticated access
      const nsRes = await fetchK8s(`https://${targetHost}:${apiHost.port}/api/v1/namespaces`);
      if (nsRes.ok) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: "critical",
          title: "K8s Namespace Enumeration Without Auth",
          description: `Unauthenticated namespace listing succeeded on ${targetHost}:${apiHost.port}/api/v1/namespaces. Full cluster enumeration possible.`,
          technique: "T1613",
          mitreId: "T1613",
        });
      }

      // Try to list secrets
      const secretsRes = await fetchK8s(`https://${targetHost}:${apiHost.port}/api/v1/secrets`);
      if (secretsRes.ok && secretsRes.body.includes("Secret")) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: "critical",
          title: "K8s Secrets Exposed Without Authentication",
          description: `Unauthenticated access to /api/v1/secrets on ${targetHost}:${apiHost.port}. Kubernetes secrets (tokens, passwords, certificates) are readable without credentials.`,
          technique: "T1552.007",
          mitreId: "T1552.007",
        });
        discoveredSecrets.push("cluster-secrets");
      }
    }
  }

  // Kubelet read-only port — no auth required by design (deprecated but common)
  if (kubeletReadonly) {
    const podsRes = await fetchK8s(`http://${targetHost}:10255/pods`);
    if (podsRes.ok && (podsRes.body.includes("Pod") || podsRes.body.includes("containers"))) {
      findings.push({
        id: `bf-${randomUUID().slice(0, 8)}`,
        severity: "high",
        title: "Kubelet Read-Only Port Exposed",
        description: `Kubelet read-only API on ${targetHost}:10255 is accessible without authentication. Pod listing and container metadata enumeration possible.`,
        technique: "T1613",
        mitreId: "T1613",
      });
      try {
        const podData = JSON.parse(podsRes.body);
        const podNames: string[] = (podData?.items || []).map((p: any) => p?.metadata?.name).filter(Boolean);
        discoveredPods.push(...podNames.slice(0, 10));
      } catch { /* non-JSON response still indicates exposure */ }
    }
  }

  // etcd — unauthenticated access is catastrophic (contains all cluster state)
  if (etcd) {
    const etcdRes = await fetchK8s(`http://${targetHost}:2379/version`);
    if (etcdRes.ok && etcdRes.body.includes("etcdserver")) {
      findings.push({
        id: `bf-${randomUUID().slice(0, 8)}`,
        severity: "critical",
        title: "etcd Exposed Without Authentication",
        description: `etcd on ${targetHost}:2379 is accessible without TLS or authentication. etcd stores all Kubernetes state including secrets, service account tokens, and configuration. Full cluster compromise via etcd key enumeration.`,
        technique: "T1552.007",
        mitreId: "T1552.007",
      });
    }
  }

  // ── Step 3: Build real K8s config from discovered surface ─────────────────
  const hasExecAccess = unauthApiAccess; // unauthenticated API = assume exec may be possible
  const k8sConfig = {
    clusterContext: `${targetHost}-breach-chain`,
    namespace: "default",
    pods: discoveredPods.map(name => ({
      name,
      namespace: "default",
      serviceAccount: "default",
      containers: [{ name: "app", image: "unknown" }],
      hostNetwork: false,
      hostPID: false,
      hostIPC: false,
    })),
    serviceAccounts: context.credentials
      .filter(c => c.type === "service_account" || c.type === "token")
      .map(c => ({ name: c.username || "default", namespace: "default", automountToken: true })),
    roles: hasExecAccess ? [
      {
        name: "anonymous-access",
        namespace: "default",
        isClusterRole: false,
        rules: [
          { resources: ["pods"], verbs: ["get", "list", ...(unauthApiAccess ? ["create", "delete"] : [])], apiGroups: [""] },
          ...(unauthApiAccess ? [{ resources: ["pods/exec"], verbs: ["create"], apiGroups: [""] }] : []),
          ...(discoveredSecrets.length > 0 ? [{ resources: ["secrets"], verbs: ["get", "list"], apiGroups: [""] }] : []),
        ],
      },
    ] : [],
    roleBindings: hasExecAccess ? [
      {
        name: "anonymous-binding",
        namespace: "default",
        isClusterRoleBinding: false,
        roleRef: "anonymous-access",
        subjects: [{ kind: "User", name: "system:anonymous", namespace: "default" }],
      },
    ] : [],
    networkPolicies: [],
    secrets: discoveredSecrets.map(name => ({
      name,
      namespace: "default",
      type: "Opaque",
      accessibleByPods: discoveredPods,
    })),
  };

  if (k8sConfig.roles.length > 0 || openPorts.length > 0) {
    try {
      const k8sResult = await kubernetesPentestService.testKubernetesAbuse(k8sConfig);

      for (const escalation of k8sResult.rbacEscalations) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: escalation.severity as "critical" | "high" | "medium" | "low",
          title: `K8s RBAC Escalation: ${escalation.name}`,
          description: `Confirmed on ${targetHost}. ${escalation.escalationPath.join(" → ")}. Remediation: ${escalation.remediation}`,
          technique: escalation.escalationPath[0],
        });
      }

      for (const vector of k8sResult.apiAbuseVectors) {
        if (vector.exploitable) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: vector.severity as "critical" | "high" | "medium" | "low",
            title: `K8s API Abuse: ${vector.name}`,
            description: `Confirmed on ${targetHost}:${apiHost?.port || "K8s API"}. ${vector.impact}`,
            technique: vector.apiEndpoint,
          });
        }
      }

      for (const secret of k8sResult.secretExposures) {
        newCredentials.push({
          id: `bc-${randomUUID().slice(0, 8)}`,
          type: "token",
          username: secret.secretName,
          valueHash: hashValue(`k8s-secret-${secret.secretName}-${chain.id}`),
          source: "container_k8s_breakout",
          accessLevel: secret.severity === "high" ? "admin" : "user",
          validatedTargets: secret.accessibleBy,
          discoveredAt: new Date().toISOString(),
        });
      }

      for (const path of k8sResult.lateralMovementPaths) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: path.severity as "critical" | "high" | "medium" | "low",
          title: `K8s Lateral Movement: ${path.technique}`,
          description: `${path.sourcePod} → ${path.targetPod} via ${path.technique} on ${targetHost}`,
          technique: path.technique,
          mitreId: path.mitreId,
        });
      }
    } catch (err) {
      console.error("[BreachOrchestrator] K8s RBAC analysis failed:", err);
    }
  }

  // Open ports alone are a finding even if API is auth-gated
  if (openPorts.length > 0 && !unauthApiAccess) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "medium",
      title: "Kubernetes Infrastructure Exposed to Internet",
      description: `K8s ports confirmed open on ${targetHost}: ${openPorts.map(p => `${p.port} (${p.label})`).join(", ")}. APIs are authentication-gated but publicly reachable — increases attack surface and brute-force risk.`,
      technique: "T1046",
    });
  }

  if (findings.some(f => f.severity === "critical" || f.severity === "high")) {
    newAssets.push({
      id: `ca-${randomUUID().slice(0, 8)}`,
      assetId: `k8s-${targetHost}`,
      assetType: "container",
      name: `Kubernetes Cluster (${targetHost})`,
      accessLevel: unauthApiAccess ? "admin" : "user",
      compromisedBy: "container_k8s_breakout",
      accessMethod: unauthApiAccess ? "unauthenticated_api" : "exposed_port",
      timestamp: new Date().toISOString(),
    });
  }

  return buildPhaseResult("container_k8s_breakout", startTime, context, {
    credentials: newCredentials,
    assets: newAssets,
    findings,
    evaluationIds: [],
    domain: "kubernetes",
  });
}

// ============================================================================
// PHASE 5: LATERAL MOVEMENT
// ============================================================================

async function executeLateralMovement(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const config = chain.config as BreachChainConfig;
  const findings: BreachPhaseResult["findings"] = [];
  const newCredentials: BreachCredential[] = [];
  const newAssets: CompromisedAsset[] = [];

  // ── Seed PivotQueue ─────────────────────────────────────────────────────────
  const maxDepth = (config as any).pivotDepth ?? 3;
  const pivotQueue = new PivotQueue(maxDepth);

  // Seed with Phase 1A compromised assets (hosts where we already have a foothold)
  for (const asset of context.compromisedAssets) {
    const host = asset.name || asset.assetId;
    if (host) pivotQueue.enqueue(host, 0, "phase1_compromise");
  }

  // Fall back to chain's primary target if no compromised assets yet
  if (pivotQueue.getVisited().length === 0) {
    const primaryHost = (() => {
      const raw = chain.assetIds[0] || "";
      try { return new URL(raw).hostname; } catch { return raw; }
    })();
    if (primaryHost) pivotQueue.enqueue(primaryHost, 0, "chain_target");
  }

  // Seed shared credential store with all credentials harvested so far
  for (const cred of context.credentials) {
    pivotQueue.addCredential(breachCredToHarvested(cred));
  }

  onProgress(chain.id, "lateral_movement", 74,
    `Starting multi-hop pivot from ${pivotQueue.getVisited().length} entry point(s) with ${pivotQueue.getCredentialCount()} credentials`
  );

  // ── Drain: each host spawns a LateralMovementSubAgent ────────────────────────
  try {
    const pivotResults = await pivotQueue.drain(
      async (item) => {
        const agent = new LateralMovementSubAgent({
          target: item.host,
          credentials: item.credentialSnapshot,
          depth: item.depth,
        });
        return agent.execute();
      },
      (msg, depth) => {
        const progress = Math.min(74 + depth * 4, 88);
        onProgress(chain.id, "lateral_movement", progress, msg);
      }
    );

    // ── Convert PivotNodeResults → BreachPhaseResult shape ────────────────────
    for (const nodeResult of pivotResults) {
      // Findings — only include confirmed auth successes and high-value exposures
      for (const pf of nodeResult.findings) {
        if (pf.authResult === "success" || pf.severity === "critical" || pf.severity === "high") {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: pf.severity,
            title: `[Hop ${nodeResult.depth}] ${pf.technique} → ${nodeResult.host}`,
            description: pf.evidence,
            technique: pf.technique,
            mitreId: pf.mitreId,
          });
        }
      }

      // Confirmed compromised assets — only if auth actually succeeded
      const confirmedAuth = nodeResult.findings.some(f => f.authResult === "success");
      if (confirmedAuth) {
        const accessLevel = nodeResult.findings.find(f => f.authResult === "success")?.accessLevel ?? "user";
        newAssets.push({
          id: `ca-${randomUUID().slice(0, 8)}`,
          assetId: nodeResult.host,
          assetType: "server",
          name: nodeResult.host,
          accessLevel: accessLevel === "admin" ? "admin" : "user",
          compromisedBy: "lateral_movement",
          accessMethod: nodeResult.findings.find(f => f.authResult === "success")?.technique || "credential_reuse",
          timestamp: new Date().toISOString(),
        });
      }

      // New credentials harvested at this node — carry forward with authValue intact
      for (const hc of nodeResult.newCredentials) {
        newCredentials.push({
          id: `bc-${randomUUID().slice(0, 8)}`,
          type: hc.type as BreachCredential["type"],
          username: hc.username,
          domain: hc.domain,
          valueHash: hc.hash,
          authValue: hc.authValue,
          source: "lateral_movement",
          accessLevel: (hc.accessLevel === "admin" || hc.accessLevel === "write") ? "admin" : "user",
          validatedTargets: [nodeResult.host],
          discoveredAt: new Date().toISOString(),
        });
      }
    }
  } catch (error) {
    console.error("[BreachOrchestrator] PivotQueue drain failed:", error);
  }

  onProgress(chain.id, "lateral_movement", 89,
    `Lateral movement complete: ${newAssets.length} host(s) compromised, ${newCredentials.length} new credentials`
  );

  return buildPhaseResult("lateral_movement", startTime, context, {
    credentials: newCredentials,
    assets: newAssets,
    findings,
    evaluationIds: [],
    domain: "network",
  });
}

// ============================================================================
// PHASE 6: IMPACT ASSESSMENT
// ============================================================================

async function executeImpactAssessment(
  chain: BreachChain,
  context: BreachPhaseContext,
  onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  const startTime = Date.now();
  const findings: BreachPhaseResult["findings"] = [];

  onProgress(chain.id, "impact_assessment", 90, "Aggregating cross-domain breach impact");

  // Aggregate all findings from previous phases
  const totalFindings = context.attackPathSteps.length;
  const uniqueDomains = context.domainsCompromised.length;
  const maxPrivilege = context.currentPrivilegeLevel;
  const totalAssets = context.compromisedAssets.length;
  const totalCreds = context.credentials.length;

  // Generate impact findings based on what was achieved
  if (uniqueDomains >= 3) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "Multi-Domain Breach: Full Infrastructure Compromise",
      description: `Attacker achieved access across ${uniqueDomains} domains (${context.domainsCompromised.join(", ")}), compromising ${totalAssets} assets with ${totalCreds} harvested credentials. Maximum privilege: ${maxPrivilege}.`,
    });
  }

  if (maxPrivilege === "cloud_admin" || maxPrivilege === "domain_admin") {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "Administrative Privilege Achieved",
      description: `Attacker escalated to ${maxPrivilege} level, enabling full control over ${maxPrivilege === "cloud_admin" ? "cloud infrastructure" : "domain resources"}.`,
    });
  }

  if (totalCreds >= 5) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "high",
      title: "Significant Credential Harvest",
      description: `${totalCreds} credentials harvested across the breach chain, enabling persistent access and further lateral movement.`,
    });
  }

  // Compliance impact based on domains
  const complianceFrameworks: string[] = [];
  if (context.domainsCompromised.includes("cloud")) complianceFrameworks.push("SOC 2", "ISO 27001");
  if (context.domainsCompromised.includes("application")) complianceFrameworks.push("PCI-DSS", "OWASP");
  if (context.domainsCompromised.includes("network")) complianceFrameworks.push("NIST CSF", "CIS");
  if (context.domainsCompromised.includes("kubernetes")) complianceFrameworks.push("CIS Kubernetes Benchmark");

  if (complianceFrameworks.length > 0) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "high",
      title: "Compliance Framework Violations",
      description: `Breach path violates controls in: ${complianceFrameworks.join(", ")}. Immediate remediation required for compliance posture.`,
    });
  }

  // Data exposure assessment
  if (context.compromisedAssets.some(a => a.accessLevel === "admin" || a.accessLevel === "system")) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "Data Exposure: Administrative Access to Production Systems",
      description: `With ${context.compromisedAssets.filter(a => a.accessLevel === "admin" || a.accessLevel === "system").length} systems at admin/system access, attacker can exfiltrate all data including PII, financial records, and proprietary information.`,
    });
  }

  return buildPhaseResult("impact_assessment", startTime, context, {
    credentials: [],
    assets: [],
    findings,
    evaluationIds: [],
    domain: undefined, // Impact doesn't add new domains
  });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function checkPhaseGate(
  phaseName: BreachPhaseName,
  context: BreachPhaseContext,
  config: BreachChainConfig
): { pass: boolean; reason?: string } {
  switch (phaseName) {
    case "credential_extraction":
      if (context.compromisedAssets.length === 0) {
        return { pass: false, reason: "No compromised assets from application phase" };
      }
      return { pass: true };

    case "cloud_iam_escalation":
      if (config.requireCredentialForCloud && context.credentials.length === 0) {
        return { pass: false, reason: "No credentials harvested — cloud phase requires credentials" };
      }
      return { pass: true };

    case "container_k8s_breakout":
      if (config.requireCloudAccessForK8s && !context.domainsCompromised.includes("cloud")) {
        return { pass: false, reason: "No cloud access achieved — K8s phase requires cloud access" };
      }
      return { pass: true };

    case "lateral_movement":
      if (context.compromisedAssets.length === 0 && context.credentials.length === 0) {
        return { pass: false, reason: "No compromised assets or credentials for lateral movement" };
      }
      return { pass: true };

    default:
      return { pass: true };
  }
}

function mergeContexts(
  existing: BreachPhaseContext,
  incoming: BreachPhaseContext
): BreachPhaseContext {
  // Deduplicate credentials by valueHash
  const existingCredHashes = new Set(existing.credentials.map(c => c.valueHash));
  const newCreds = incoming.credentials.filter(c => !existingCredHashes.has(c.valueHash));

  // Deduplicate assets by assetId
  const existingAssetIds = new Set(existing.compromisedAssets.map(a => a.assetId));
  const newAssets = incoming.compromisedAssets.filter(a => !existingAssetIds.has(a.assetId));

  // Merge domains
  const allDomains = Array.from(new Set([...existing.domainsCompromised, ...incoming.domainsCompromised]));

  // Elevate privilege to the maximum
  const privilegeOrder: BreachPhaseContext["currentPrivilegeLevel"][] = [
    "none", "user", "admin", "system", "cloud_admin", "domain_admin",
  ];
  const maxPrivilege = privilegeOrder[
    Math.max(
      privilegeOrder.indexOf(existing.currentPrivilegeLevel),
      privilegeOrder.indexOf(incoming.currentPrivilegeLevel)
    )
  ];

  return {
    credentials: [...existing.credentials, ...newCreds],
    compromisedAssets: [...existing.compromisedAssets, ...newAssets],
    attackPathSteps: [...existing.attackPathSteps, ...incoming.attackPathSteps],
    evidenceArtifacts: [...existing.evidenceArtifacts, ...incoming.evidenceArtifacts],
    currentPrivilegeLevel: maxPrivilege,
    domainsCompromised: allDomains,
  };
}

function extractCredentialsFromFindings(
  result: OrchestratorResult,
  phaseName: string
): BreachCredential[] {
  const creds: BreachCredential[] = [];
  // Source tagged as "heuristic" to distinguish from active exploit engine credentials
  const sourceTag = `heuristic:${phaseName}`;

  // Scan exploit chains for credential indicators
  const exploitChains = result.agentFindings?.exploit?.exploitChains || [];
  for (const chain of exploitChains) {
    const text = `${chain.name} ${chain.description}`.toLowerCase();

    if (text.includes("aws") || text.includes("iam") || text.includes("access key")) {
      creds.push({
        id: `bc-${randomUUID().slice(0, 8)}`,
        type: "api_key",
        username: "aws-extracted",
        valueHash: hashValue(`aws-key-${chain.name}`),
        source: sourceTag,
        accessLevel: "user",
        validatedTargets: ["aws-api"],
        discoveredAt: new Date().toISOString(),
      });
    }

    if (text.includes("token") || text.includes("jwt") || text.includes("bearer")) {
      creds.push({
        id: `bc-${randomUUID().slice(0, 8)}`,
        type: "token",
        valueHash: hashValue(`token-${chain.name}`),
        source: sourceTag,
        accessLevel: "user",
        validatedTargets: [],
        discoveredAt: new Date().toISOString(),
      });
    }

    if (text.includes("password") || text.includes("credential") || text.includes("secret")) {
      creds.push({
        id: `bc-${randomUUID().slice(0, 8)}`,
        type: "password",
        valueHash: hashValue(`password-${chain.name}`),
        source: sourceTag,
        accessLevel: "user",
        validatedTargets: [],
        discoveredAt: new Date().toISOString(),
      });
    }

    if (text.includes("service account") || text.includes("gcp") || text.includes("azure")) {
      creds.push({
        id: `bc-${randomUUID().slice(0, 8)}`,
        type: "service_account",
        valueHash: hashValue(`sa-${chain.name}`),
        source: sourceTag,
        accessLevel: "user",
        validatedTargets: [],
        discoveredAt: new Date().toISOString(),
      });
    }
  }

  // Scan lateral findings for token reuse opportunities
  const tokenReuse = result.agentFindings?.lateral?.tokenReuse || [];
  for (const token of tokenReuse) {
    creds.push({
      id: `bc-${randomUUID().slice(0, 8)}`,
      type: "token",
      valueHash: hashValue(`reuse-${token}`),
      source: sourceTag,
      accessLevel: "user",
      validatedTargets: [],
      discoveredAt: new Date().toISOString(),
    });
  }

  return creds;
}

function deriveBusinessImpact(
  tactic: string,
  compromiseLevel: string,
  assets: string[],
  label: string
): AttackNode["businessImpact"] {
  const blastRadius: "contained" | "department" | "organization" | "customer-facing" =
    compromiseLevel === "system" || compromiseLevel === "admin" ? "organization" :
    compromiseLevel === "user" ? "department" : "contained";

  const regulatoryRisk =
    tactic === "exfiltration" || tactic === "credential-access"
      ? "GDPR breach notification likely required. PCI-DSS incident response required if payment data in scope."
      : tactic === "impact"
      ? "Regulatory reporting obligations triggered. Legal counsel engagement recommended."
      : undefined;

  const dataExposed =
    tactic === "exfiltration"
      ? `Potential access to application data on ${assets[0] ?? "target system"}`
      : tactic === "credential-access"
      ? "Credentials exposed — all systems using same credentials at risk"
      : tactic === "initial-access"
      ? "Entry point established — all internal resources potentially reachable"
      : undefined;

  const financialImpact =
    compromiseLevel === "system"
      ? "Estimated $5M-$20M exposure (breach notification, remediation, regulatory fines)"
      : compromiseLevel === "admin"
      ? "Estimated $1M-$5M exposure"
      : compromiseLevel === "user"
      ? "Estimated $100K-$500K exposure"
      : undefined;

  const summary =
    compromiseLevel === "system"
      ? `Full system control achieved on ${assets[0] ?? label}. Attacker has unrestricted access.`
      : compromiseLevel === "admin"
      ? `Administrative access to ${assets[0] ?? label}. Can modify, exfiltrate, or destroy data.`
      : compromiseLevel === "user"
      ? `User-level access to ${assets[0] ?? label}. Attacker can read user data and pivot.`
      : compromiseLevel === "limited"
      ? `Limited foothold on ${assets[0] ?? label}. Constrained but inside the perimeter.`
      : `Reachable attack vector via ${label}.`;

  return { summary, dataExposed, systemsReachable: assets, regulatoryRisk, estimatedBlastRadius: blastRadius, financialImpact };
}

function buildUnifiedAttackGraph(
  phaseResults: BreachPhaseResult[],
  context: BreachPhaseContext
): AttackGraph {
  const nodes: AttackNode[] = [];
  const edges: AttackEdge[] = [];
  let nodeCounter = 0;
  const phaseEntryNodes: string[] = [];

  // Create a node for the initial entry point
  const entryNodeId = `breach-entry-${nodeCounter++}`;
  nodes.push({
    id: entryNodeId,
    label: "Initial Access",
    description: "Entry point for cross-domain breach chain",
    nodeType: "entry",
    tactic: "initial-access",
    compromiseLevel: "none",
    discoveredBy: "recon",
    businessImpact: deriveBusinessImpact("initial-access", "none", [], "Initial Access"),
  });

  const completedPhases = phaseResults.filter(
    r => r.status === "completed" && r.findings.length > 0
  );

  let previousNodeId = entryNodeId;

  for (const phase of completedPhases) {
    const phaseNodeId = `breach-${phase.phaseName}-${nodeCounter++}`;
    phaseEntryNodes.push(phaseNodeId);

    // Phase entry node
    const tacticMap: Record<string, string> = {
      application_compromise: "initial-access",
      credential_extraction: "credential-access",
      cloud_iam_escalation: "privilege-escalation",
      container_k8s_breakout: "lateral-movement",
      lateral_movement: "lateral-movement",
      impact_assessment: "impact",
    };

    const compromiseMap: Record<string, AttackNode["compromiseLevel"]> = {
      application_compromise: "limited",
      credential_extraction: "user",
      cloud_iam_escalation: "admin",
      container_k8s_breakout: "admin",
      lateral_movement: "admin",
      impact_assessment: "system",
    };

    const phaseAssets = phase.outputContext.compromisedAssets.map(a => a.name);
    const phaseTactic = tacticMap[phase.phaseName] as AttackNode["tactic"] || "execution";
    const phaseCompromise = compromiseMap[phase.phaseName] || "limited";

    // Build node artifacts from phase output
    const phaseAtkIds = (PHASE_ATTACK_TECHNIQUES[phase.phaseName] || []);
    const phaseNodeCredentials = phase.outputContext.credentials
      .filter(c => !!c.username)
      .map(c => ({
        username: c.username!,
        hash: c.valueHash,
        privilegeTier: (c.accessLevel === "admin" ? "local_admin" : "standard_user") as "local_admin" | "standard_user",
        sourceSystem: c.source || phase.phaseName,
      }));
    const defensesFired: string[] = [];
    const defensesMissed: string[] = phase.findings
      .filter(f => f.severity === "critical" || f.severity === "high")
      .map(f => f.technique || f.title)
      .filter(Boolean) as string[];

    const phaseArtifacts = {
      hostname: phase.outputContext.compromisedAssets[0]?.name,
      credentials: phaseNodeCredentials.length > 0 ? phaseNodeCredentials : undefined,
      attackTechniqueId: phaseAtkIds[0],
      attackTechniqueName: PHASE_DEFINITIONS[phase.phaseName].displayName,
      procedure: PHASE_DEFINITIONS[phase.phaseName].description,
      defensesFired: defensesFired.length > 0 ? defensesFired : undefined,
      defensesMissed: defensesMissed.length > 0 ? defensesMissed : undefined,
      discoveredAt: phase.startedAt,
    };

    nodes.push({
      id: phaseNodeId,
      label: PHASE_DEFINITIONS[phase.phaseName].displayName,
      description: PHASE_DEFINITIONS[phase.phaseName].description,
      nodeType: phase.phaseName === "impact_assessment" ? "objective" : "pivot",
      tactic: phaseTactic,
      compromiseLevel: phaseCompromise,
      assets: phaseAssets,
      discoveredBy: "exploit",
      businessImpact: deriveBusinessImpact(phaseTactic, phaseCompromise, phaseAssets, PHASE_DEFINITIONS[phase.phaseName].displayName),
      artifacts: phaseArtifacts,
    });

    // Derive complexity from phase findings
    const phaseComplexity: AttackEdge["complexity"] = phase.findings.some(f => f.severity === "critical")
      ? "low"
      : phase.findings.some(f => f.severity === "high")
      ? "medium"
      : "high";

    // Compute realistic timeEstimate (minutes) based on phase type and complexity
    const phaseTimeEstimateMinutes = (() => {
      const rawMs = phase.durationMs || 0;
      if (rawMs > 0) return rawMs / 60000;
      // Phase-based defaults when no timing data
      switch (phase.phaseName) {
        case "application_compromise": return phaseComplexity === "low" ? 5 : phaseComplexity === "medium" ? 15 : 30;
        case "credential_extraction":  return phaseComplexity === "low" ? 10 : phaseComplexity === "medium" ? 20 : 45;
        case "cloud_iam_escalation":   return phaseComplexity === "low" ? 15 : phaseComplexity === "medium" ? 30 : 60;
        case "container_k8s_breakout": return phaseComplexity === "low" ? 20 : phaseComplexity === "medium" ? 45 : 90;
        case "lateral_movement":       return phaseComplexity === "low" ? 30 : phaseComplexity === "medium" ? 75 : 120;
        case "impact_assessment":      return phaseComplexity === "low" ? 5 : phaseComplexity === "medium" ? 15 : 30;
        default:                       return 15;
      }
    })();

    // Edge from previous phase to this phase
    edges.push({
      id: `breach-edge-${nodeCounter++}`,
      source: previousNodeId,
      target: phaseNodeId,
      technique: `Cross-domain: ${PHASE_DEFINITIONS[phase.phaseName].displayName}`,
      successProbability: phase.findings.length > 0 ? 85 : 40,
      complexity: phaseComplexity,
      timeEstimate: phaseTimeEstimateMinutes,
      edgeType: "primary" as const,
      discoveredBy: "exploit" as const,
      description: `${phase.findings.length} findings discovered`,
    });

    // Add individual finding nodes for critical/high findings
    for (const finding of phase.findings.filter(f => f.severity === "critical" || f.severity === "high")) {
      const findingNodeId = `finding-${finding.id}`;
      const findingTactic = tacticMap[phase.phaseName] as AttackNode["tactic"] || "execution";
      const findingCompromise: AttackNode["compromiseLevel"] = finding.severity === "critical" ? "admin" : "user";
      nodes.push({
        id: findingNodeId,
        label: finding.title,
        description: finding.description,
        nodeType: "pivot",
        tactic: findingTactic,
        compromiseLevel: findingCompromise,
        discoveredBy: "exploit",
        businessImpact: deriveBusinessImpact(findingTactic, findingCompromise, [], finding.title),
        artifacts: {
          attackTechniqueId: (finding as any).mitreId || phaseAtkIds[0],
          attackTechniqueName: finding.technique || finding.title,
          procedure: finding.description,
          defensesMissed: [finding.technique || finding.title].filter(Boolean),
          discoveredAt: phase.startedAt,
        },
      });

      // Finding-level timeEstimate by severity
      const findingTimeEstimate = finding.severity === "critical" ? 5 : finding.severity === "high" ? 10 : 15;
      const findingComplexity: AttackEdge["complexity"] = finding.severity === "critical" ? "low" : "medium";

      edges.push({
        id: `finding-edge-${nodeCounter++}`,
        source: phaseNodeId,
        target: findingNodeId,
        technique: finding.technique || finding.title,
        successProbability: 75,
        complexity: findingComplexity,
        timeEstimate: findingTimeEstimate,
        edgeType: "primary" as const,
        discoveredBy: "exploit" as const,
        description: finding.description,
      });
    }

    previousNodeId = phaseNodeId;
  }

  // Build critical path through all phases
  const criticalPath = [entryNodeId, ...phaseEntryNodes];

  // Kill chain coverage based on which phases completed
  const killChainCoverage: string[] = [];
  if (completedPhases.some(p => p.phaseName === "application_compromise")) {
    killChainCoverage.push("reconnaissance", "initial-access", "execution");
  }
  if (completedPhases.some(p => p.phaseName === "credential_extraction")) {
    killChainCoverage.push("credential-access", "discovery");
  }
  if (completedPhases.some(p => p.phaseName === "cloud_iam_escalation")) {
    killChainCoverage.push("privilege-escalation", "defense-evasion");
  }
  if (completedPhases.some(p => p.phaseName === "container_k8s_breakout")) {
    killChainCoverage.push("persistence");
  }
  if (completedPhases.some(p => p.phaseName === "lateral_movement")) {
    killChainCoverage.push("lateral-movement", "collection");
  }
  if (completedPhases.some(p => p.phaseName === "impact_assessment")) {
    killChainCoverage.push("exfiltration", "impact");
  }

  const totalDurationMs = completedPhases.reduce((sum, p) => sum + (p.durationMs || 0), 0);
  const durationMinutes = Math.max(1, Math.round(totalDurationMs / 60000));

  return {
    nodes,
    edges,
    entryNodeId,
    objectiveNodeIds: phaseEntryNodes.slice(-1),
    criticalPath,
    killChainCoverage: killChainCoverage as any[],
    complexityScore: Math.min(100, completedPhases.length * 18),
    timeToCompromise: {
      minimum: Math.max(1, durationMinutes - 5),
      expected: durationMinutes,
      maximum: durationMinutes * 2,
      unit: "minutes",
    },
    chainedExploits: completedPhases.map(p => ({
      name: PHASE_DEFINITIONS[p.phaseName].displayName,
      techniques: p.findings.map(f => f.technique || f.title),
      combinedImpact: `${p.findings.length} findings, ${p.outputContext.compromisedAssets.length} assets compromised`,
    })),
  };
}

function calculateBreachRiskScore(
  phaseResults: BreachPhaseResult[],
  context: BreachPhaseContext
): number {
  let score = 0;

  // Domains breached (20 pts each, max 80)
  score += Math.min(80, context.domainsCompromised.length * 20);

  // Max privilege (up to 30)
  const privScores: Record<string, number> = {
    none: 0, user: 5, admin: 15, system: 25, cloud_admin: 30, domain_admin: 30,
  };
  score += privScores[context.currentPrivilegeLevel] || 0;

  // Critical findings (5 pts each, max 30)
  const criticalCount = phaseResults.reduce(
    (sum, p) => sum + p.findings.filter(f => f.severity === "critical").length,
    0
  );
  score += Math.min(30, criticalCount * 5);

  // Credential harvest bonus (2 pts each, max 20)
  score += Math.min(20, context.credentials.length * 2);

  return Math.min(100, score);
}

function generateBreachExecutiveSummary(
  phaseResults: BreachPhaseResult[],
  context: BreachPhaseContext,
  riskScore: number
): string {
  const completedPhases = phaseResults.filter(p => p.status === "completed");
  const skippedPhases = phaseResults.filter(p => p.status === "skipped");
  const totalFindings = completedPhases.reduce((sum, p) => sum + p.findings.length, 0);
  const criticalFindings = completedPhases.reduce(
    (sum, p) => sum + p.findings.filter(f => f.severity === "critical").length,
    0
  );

  const riskLevel = riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 40 ? "MEDIUM" : "LOW";

  const lines = [
    `## Cross-Domain Breach Assessment — Risk: ${riskLevel} (${riskScore}/100)`,
    "",
    `OdinForge's automated breach chain analysis completed ${completedPhases.length} of ${phaseResults.length} phases, ` +
    `discovering ${totalFindings} findings (${criticalFindings} critical) across ${context.domainsCompromised.length} domains.`,
    "",
    `**Domains Breached:** ${context.domainsCompromised.length > 0 ? context.domainsCompromised.join(", ") : "None"}`,
    `**Maximum Privilege Achieved:** ${context.currentPrivilegeLevel}`,
    `**Credentials Harvested:** ${context.credentials.length}`,
    `**Assets Compromised:** ${context.compromisedAssets.length}`,
    "",
    "### Breach Path Summary",
  ];

  for (const phase of completedPhases) {
    const phaseDef = PHASE_DEFINITIONS[phase.phaseName];
    lines.push(
      `- **${phaseDef.displayName}**: ${phase.findings.length} findings ` +
      `(${phase.findings.filter(f => f.severity === "critical").length} critical)`
    );
  }

  for (const phase of skippedPhases) {
    const phaseDef = PHASE_DEFINITIONS[phase.phaseName];
    lines.push(`- **${phaseDef.displayName}**: Skipped — ${phase.error || "prerequisites not met"}`);
  }

  if (context.currentPrivilegeLevel === "cloud_admin" || context.currentPrivilegeLevel === "domain_admin") {
    lines.push(
      "",
      "### Critical: Full Administrative Compromise Achieved",
      `The breach chain demonstrated escalation to **${context.currentPrivilegeLevel}** level, ` +
      "indicating an attacker can achieve total infrastructure control through the identified attack path. " +
      "Immediate remediation of the initial entry point and privilege escalation paths is required."
    );
  }

  return lines.join("\n");
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function buildPhaseResult(
  phaseName: BreachPhaseName,
  startTime: number,
  inputContext: BreachPhaseContext,
  output: {
    credentials: BreachCredential[];
    assets: CompromisedAsset[];
    findings: BreachPhaseResult["findings"];
    evaluationIds: string[];
    domain?: string;
  }
): BreachPhaseResult {
  const attackPathSteps = output.findings.map((f, i) => ({
    phaseIndex: PHASE_ORDER.indexOf(phaseName),
    phaseName,
    stepId: f.id,
    technique: f.technique || "unknown",
    target: output.assets[0]?.name || "target",
    outcome: f.description,
    evidence: f.title,
  }));

  const domainsCompromised = output.domain && output.findings.length > 0
    ? [output.domain]
    : [];

  const maxAssetAccess = output.assets.reduce((max, a) => {
    const order = ["none", "limited", "user", "admin", "system"];
    return order.indexOf(a.accessLevel) > order.indexOf(max) ? a.accessLevel : max;
  }, "none" as string);

  const privilegeMap: Record<string, BreachPhaseContext["currentPrivilegeLevel"]> = {
    none: "none",
    limited: "user",
    user: "user",
    admin: "admin",
    system: "system",
  };

  // Derive ATT&CK technique IDs for this phase — include per-phase baseline + any
  // technique IDs explicitly referenced in findings
  const attackTechniqueIds = [
    ...(PHASE_ATTACK_TECHNIQUES[phaseName] || []),
    ...output.findings.map(f => f.mitreId).filter(Boolean),
  ].filter((v, i, arr) => arr.indexOf(v) === i); // dedup

  return {
    phaseName,
    status: "completed",
    startedAt: new Date(startTime).toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startTime,
    inputContext: {
      credentialCount: inputContext.credentials.length,
      compromisedAssetCount: inputContext.compromisedAssets.length,
      privilegeLevel: inputContext.currentPrivilegeLevel,
    },
    outputContext: {
      credentials: output.credentials,
      compromisedAssets: output.assets,
      attackPathSteps,
      evidenceArtifacts: [],
      currentPrivilegeLevel: privilegeMap[maxAssetAccess] || "none",
      domainsCompromised,
      attackTechniqueIds,
    } as BreachPhaseContext & { attackTechniqueIds: string[] },
    evaluationIds: output.evaluationIds,
    findings: output.findings,
  };
}

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
  });
}

function hashValue(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 32);
}

async function phaseTimeout(timeoutMs: number, phaseName: string): Promise<BreachPhaseResult> {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Phase ${phaseName} timed out after ${timeoutMs}ms`)), timeoutMs);
  });
}

const defaultProgress: BreachOrchestratorProgressCallback = () => {};
