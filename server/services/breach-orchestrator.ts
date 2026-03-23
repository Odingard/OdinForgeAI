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
// core-v2: Phases 3-5 services removed — executors return "disabled" stubs
import { storage } from "../storage";
import { wsService } from "./websocket";
import { getCredentialBus } from "./aev/credential-bus";
import type { HarvestedCredential } from "./aev/credential-bus";
import { destroyAllRateLimiters } from "./agent-rate-limiter";
import { engagementLogger } from "./logger";
import { evidenceQualityGate, EvidenceQuality, type EvaluatedFinding, type BatchVerdict } from "./evidence-quality-gate";
import type { AgentEvent } from "./aev/agent-event-bus";

/**
 * Runtime check — separated into a function so esbuild cannot
 * evaluate it at build time and tree-shake the mesh code path.
 */
function isAgentMeshEnabled(): boolean {
  return String(process.env.AGENT_MESH).toLowerCase() === "true";
}
import { DefendersMirror, type AttackEvidence, type DetectionRuleSet } from "./defenders-mirror";
import { ReachabilityChainBuilder, buildReachabilityChain, type PivotResult } from "./reachability-chain";
import { ReplayRecorder, type EngagementReplayManifest } from "./replay-recorder";
import { createBreachEventEmitter, emitCognitiveEvent, type BreachEventEmitter } from "../lib/breach-event-emitter";
import { formatError } from "../lib/exploit-diagnostics";
import { getPortfolioOrchestrator } from "./aev/portfolio-orchestrator";
import {
  recordEngagementStart,
  recordEngagementComplete,
  recordPhaseComplete as recordPhaseMetric,
  recordCredentialHarvested,
  recordFindingQuality,
  recordDetectionRules,
  pivotDepthMax,
  evidenceQualityRatio,
} from "./metrics";

/**
 * Module-level store for Phase 1A raw evidence.
 * Keyed by chainId — written by executeApplicationCompromise,
 * read by executeCredentialExtraction to parse credentials from
 * actual HTTP response bodies without a separate LLM evaluation.
 * Cleared after Phase 2 consumes it.
 */
const phase1AEvidenceStore = new Map<string, ExploitAttempt[]>();

// Module-level emitter store — keyed by chainId, same pattern as phase1AEvidenceStore.
// Phase executors (standalone functions) read from here rather than receiving
// breachEmitter as a parameter (which would require changing the PhaseExecutor type).
const chainEmitterStore = new Map<string, BreachEventEmitter>();

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

  // Phase 13: Register run with portfolio orchestrator
  const portfolio = getPortfolioOrchestrator();
  portfolio.registerRun(chainId, chainId, chain.assetIds?.[0] || "unknown");
  portfolio.updateRunState(chainId, "discovering");

  // ── AGENT_MESH: Event-driven 4-agent mesh replaces sequential pipeline ────
  if (isAgentMeshEnabled()) {
    log.info("AGENT_MESH enabled — delegating to AgentMeshOrchestrator");
    broadcastBreachProgress(chainId, "starting", 5, "Agent Mesh active — 4-agent event-driven pipeline");

    const targetUrl = Array.isArray(chain.assetIds) ? chain.assetIds[0] : "";
    // core-v2: AgentMeshOrchestrator removed — this code path is only reached if AGENT_MESH=true
    const AgentMeshOrchestratorStub = class { constructor(_opts: any) {} getBus() { return { subscribe: (..._a: any[]) => {} }; } async run(): Promise<any> { return { status: "completed", eventLog: [], durationMs: 0, findingCount: 0, totalEvents: 0 }; } };
    const mesh = new AgentMeshOrchestratorStub({
      chainId,
      engagementId: chainId,
      targetUrl,
      timeout: config.totalTimeoutMs ?? 120_000,
    });

    // ── Live Event Bridge: stream mesh events to WebSocket in real-time ────
    const liveEventThrottle = new Map<string, number>(); // eventKind → lastSentMs
    const LIVE_THROTTLE_MS = 500;
    const bus = mesh.getBus();
    bus.subscribe("*", (event: any) => {
      const kindMap: Record<string, string> = {
        "target.discovered": "scanning",
        "surface.expanded": "scanning",
        "endpoint.viable": "scanning",
        "scan.finished": "scanning",
        "vuln.confirmed": "exploit_attempt",
        "breach.confirmed": "vuln_confirmed",
        "credential.extracted": "credential_extracted",
        "credential.found": "credential_extracted",
        "exploit.finished": "exploit_attempt",
        "pivot.available": "scanning",
        "chain.complete": "vuln_confirmed",
      };
      const eventKind = kindMap[event.type] || "scanning";
      const now = Date.now();
      const lastSent = liveEventThrottle.get(eventKind) || 0;
      if (now - lastSent < LIVE_THROTTLE_MS) return;
      liveEventThrottle.set(eventKind, now);

      const payload = event.payload as Record<string, unknown> | undefined;
      const target = (event.evidence?.[0] as { targetUrl?: string } | undefined)?.targetUrl
        ?? (payload?.endpoint as string | undefined)
        ?? (payload?.source as string | undefined)
        ?? targetUrl;
      const detail = (payload?.description as string | undefined)
        ?? (payload?.vulnClass as string | undefined)
        ?? event.type.replace(/\./g, " ");

      wsService.broadcastToChannel(`breach_chain:${chainId}`, {
        type: "breach_chain_live_event",
        chainId,
        eventKind,
        target: typeof target === "string" ? target.slice(0, 120) : "",
        detail: typeof detail === "string" ? detail.slice(0, 200) : "",
        phase: String((payload?.phase as number | undefined) ?? 1),
        timestamp: event.timestamp,
      } as any);
    });

    try {
      const result = await mesh.run();

      // Convert mesh event log into phaseResults + attack graph for UI compatibility
      const meshPhaseResults = buildMeshPhaseResults(result);
      const meshGraph = buildMeshAttackGraph(result);
      const meshRiskScore = meshPhaseResults.reduce((max, pr) => {
        const phaseMax = pr.findings.reduce((m, f) =>
          Math.max(m, f.severity === "critical" ? 95 : f.severity === "high" ? 80 : f.severity === "medium" ? 60 : 40), 0);
        return Math.max(max, phaseMax);
      }, 0);

      // ── Credential Web: publish extracted credentials to CredentialBus ──────
      const credEvents = result.eventLog.filter((e: any) => e.type === "credential.extracted");
      if (credEvents.length > 0) {
        const credBus = getCredentialBus();
        for (const ce of credEvents) {
          const p = ce.payload as { source?: string; phase?: number };
          const ev = ce.evidence?.[0];
          credBus.publish(chainId, {
            id: `cred-${ce.id}`,
            engagementId: chainId,
            username: p.source ?? "unknown",
            privilegeTier: "service_account",
            sourceSystem: ev?.targetUrl ?? p.source ?? "unknown",
            sourceNodeId: ce.id,
            sourceTactic: "credential-access",
            discoveredAt: ce.timestamp,
          });
        }
        log.info({ count: credEvents.length }, "Published credentials to CredentialBus");
      }

      // ── Defense Gaps: generate Defender's Mirror detection rules ─────────────
      const meshDefendersMirror = new DefendersMirror();
      const PHASE_TECHNIQUE_MAP: Record<number, string> = {
        1: "auth_bypass", 2: "credential_reuse", 3: "iam_abuse",
        4: "k8s_api_abuse", 5: "ssh_pivot", 6: "data_exfiltration",
      };
      const allMeshEvents = result.eventLog.filter(
        (e: any) => e.type === "vuln.confirmed" || e.type === "breach.confirmed" || e.type === "credential.extracted"
      );
      const meshAttackEvidence: AttackEvidence[] = allMeshEvents.map((e: any) => {
        const p = e.payload as { phase?: number; vulnClass?: string; endpoint?: string; source?: string; description?: string };
        const ev = e.evidence?.[0];
        const phase = p.phase ?? 1;
        return {
          id: e.id,
          engagementId: chainId,
          phase: phase === 1 ? "application_compromise"
            : phase === 2 ? "credential_extraction"
            : phase === 3 ? "cloud_iam_escalation"
            : phase === 4 ? "container_k8s_breakout"
            : phase === 5 ? "lateral_movement"
            : "impact_assessment",
          techniqueCategory: p.vulnClass ?? PHASE_TECHNIQUE_MAP[phase] ?? "auth_bypass",
          targetUrl: ev?.targetUrl ?? p.endpoint ?? p.source,
          statusCode: ev?.statusCode,
          networkProtocol: "http",
          success: true,
        };
      });
      const meshDetectionRules = meshDefendersMirror.generateBatch(meshAttackEvidence);
      log.info({ ruleCount: meshDetectionRules.length }, "Generated Defender's Mirror rules for mesh chain");

      await storage.updateBreachChain(chainId, {
        status: result.status === "completed" ? "completed" : "failed",
        progress: result.status === "completed" ? 100 : 0,
        currentPhase: null,
        completedAt: new Date(),
        durationMs: result.durationMs,
        phaseResults: meshPhaseResults,
        unifiedAttackGraph: meshGraph as any,
        overallRiskScore: meshRiskScore,
        totalCredentialsHarvested: credEvents.length,
        detectionRules: meshDetectionRules as any,
        executiveSummary: `Agent Mesh ${result.status}: ${result.totalEvents} events, ${result.findingCount} findings in ${Math.round(result.durationMs / 1000)}s`,
      });

      broadcastBreachProgress(
        chainId,
        result.status === "completed" ? "completed" : "failed",
        result.status === "completed" ? 100 : 0,
        `Agent Mesh ${result.status} — ${result.findingCount} findings, ${result.totalEvents} events in ${Math.round(result.durationMs / 1000)}s`,
      );
    } catch (error) {
      log.error({ err: error }, "Agent Mesh failed");
      await storage.updateBreachChain(chainId, {
        status: "failed",
        completedAt: new Date(),
      });
      broadcastBreachProgress(
        chainId, "failed", 0,
        `Agent Mesh failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
    return;
  }

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

  // ── Live graph event emitter — one instance per engagement ───────────
  // Passed through to each phase executor so granular events (node added,
  // edge added, reasoning, surface signal) fire at the moment of confirmation.
  const breachEmitter = createBreachEventEmitter(chainId);
  // Register in module-level store so standalone phase executor functions
  // can access it without changing the PhaseExecutor type signature.
  chainEmitterStore.set(chainId, breachEmitter);

  // Emit the engagement-start spine nodes for all 6 phases up front
  // so the frontend can render the skeleton immediately.
  const PHASE_IDS = [
    "application_compromise", "credential_extraction", "cloud_iam_escalation",
    "container_k8s_breakout", "lateral_movement", "impact_assessment",
  ] as const;
  const spineNodeIds: Record<string, string> = {};
  PHASE_IDS.forEach((phaseId, idx) => {
    const nodeId = breachEmitter.nodeAdded({
      kind: "phase_spine",
      phase: phaseId,
      phaseIndex: idx,
      label: PHASE_DEFINITIONS[phaseId]?.displayName ?? phaseId,
      detail: `Phase ${idx + 1} — awaiting execution`,
      severity: "info",
    });
    spineNodeIds[phaseId] = nodeId;
    // Wire spine edges so the chain is visually connected from the start
    if (idx > 0) {
      breachEmitter.edgeAdded(
        spineNodeIds[PHASE_IDS[idx - 1]],
        nodeId,
        false, // not yet confirmed — will flip to true on phase completion
      );
    }
  });

  // ── GTM v1.0: Prometheus metrics — engagement start ──────────────────
  recordEngagementStart();

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

      // Phase 13: Update portfolio lifecycle state per phase
      const phaseToLifecycle: Record<string, string> = {
        application_compromise: 'exploiting',
        credential_extraction: 'validating',
        cloud_iam_escalation: 'replaying',
        container_k8s_breakout: 'replaying',
        lateral_movement: 'replaying',
        impact_assessment: 'summarizing',
      };
      portfolio.updateRunState(chainId, (phaseToLifecycle[phaseName] || 'exploiting') as any);

      // Execute phase with timeout
      const executor = getPhaseExecutor(phaseName);
      const phaseResult = await Promise.race([
        executor(chain, context, onProgress ?? defaultProgress),
        phaseTimeout(config.phaseTimeoutMs, phaseName),
      ]);

      phaseResults.push(phaseResult);
      log.info({ phase: phaseName, status: phaseResult.status, findings: phaseResult.findings?.length ?? 0 }, `Phase executor returned`);

      // ── 0-findings diagnostic ─────────────────────────────────────────
      // If a phase completed with zero findings, emit a structured diagnostic
      // explaining what happened so operators and customers see WHY, not just silence.
      if (phaseResult.findings.length === 0) {
        type ZeroFindingsCategory =
          | "phase_error"
          | "phase_skipped"
          | "waf_blocking"
          | "crawl_failure"
          | "no_vulnerable_endpoints"
          | "all_payloads_failed"
          | "target_unreachable"
          | "timeout";

        let diagnosticCategory: ZeroFindingsCategory;
        let reason: string;

        if (phaseResult.error) {
          const errLower = (phaseResult.error || "").toLowerCase();
          if (errLower.includes("timeout") || errLower.includes("timed out")) {
            diagnosticCategory = "timeout";
            reason = `Phase timed out: ${phaseResult.error}`;
          } else if (errLower.includes("enotfound") || errLower.includes("econnrefused") || errLower.includes("unreachable")) {
            diagnosticCategory = "target_unreachable";
            reason = `Target unreachable: ${phaseResult.error}. Verify the target URL is accessible and DNS resolves correctly.`;
          } else if (errLower.includes("403") || errLower.includes("waf") || errLower.includes("blocked") || errLower.includes("rate limit")) {
            diagnosticCategory = "waf_blocking";
            reason = `WAF or rate limiting detected: ${phaseResult.error}. The target may be blocking automated testing.`;
          } else {
            diagnosticCategory = "phase_error";
            reason = `Phase error: ${phaseResult.error}`;
          }
        } else if (phaseResult.status === "skipped") {
          diagnosticCategory = "phase_skipped";
          reason = `Phase skipped: ${phaseResult.error || "prerequisite not met (e.g., no credentials from prior phase)"}`;
        } else {
          // Phase completed normally but found nothing
          const subAgentCount = phaseResult.subAgentRuns?.length ?? 0;
          if (subAgentCount === 0) {
            diagnosticCategory = "crawl_failure";
            reason = `Phase completed but no sub-agents ran. The crawl may have discovered 0 endpoints — ` +
              `check [AEE:precheck] and [AEE:crawl] logs. Possible causes: target returned no HTML content, ` +
              `robots.txt blocked crawling, or the target redirected to an external domain.`;
          } else {
            diagnosticCategory = "no_vulnerable_endpoints";
            reason = `Phase completed ${subAgentCount} sub-agent run(s) but no exploitable findings were validated. ` +
              `The target's endpoints were tested but none matched known vulnerability patterns above the confidence threshold (>= 0.6). ` +
              `This may indicate the target is well-hardened, or WAF silently filtering payloads without explicit 403 responses.`;
          }
        }

        emitCognitiveEvent({
          type: "intelligence.strategy",
          chainId,
          summary: `Phase ${phaseName}: 0 findings [${diagnosticCategory}]`,
          detail: reason,
          timestamp: new Date().toISOString(),
        });
        log.warn({ phase: phaseName, diagnosticCategory }, `0-findings diagnostic: ${reason}`);

        // Attach diagnostic to phase result for UI and PDF consumption
        (phaseResult as any).zeroFindingsDiagnostic = {
          category: diagnosticCategory,
          reason,
          subAgentRuns: phaseResult.subAgentRuns?.length ?? 0,
        };
      }

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

      // ── GTM v1.0: Prometheus metrics — per-phase ──────────────────────────
      const phaseElapsed = Date.now() - startTime; // approximate phase duration
      recordPhaseMetric(phaseName, phaseElapsed, phaseResult.status === "completed");
      if (phaseResult.outputContext?.credentials?.length) {
        recordCredentialHarvested(phaseResult.outputContext.credentials.length);
      }

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

      // ── Live graph — emit phase transition ───────────────────────────
      const phaseIdx = enabledPhases.indexOf(phaseName);
      const prevPhase = phaseIdx > 0 ? (enabledPhases[phaseIdx - 1] as import("../lib/breach-event-emitter").BreachPhaseId) : null;
      breachEmitter.phaseTransition(
        prevPhase,
        phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
        phaseIdx,
        phaseResult.findings.length,
        phaseResult.outputContext?.credentials?.length ?? 0,
        `${PHASE_DEFINITIONS[phaseName]?.displayName} complete — ${qualityVerdict.summary.proven} proven, ${qualityVerdict.summary.corroborated} corroborated`,
      );

      // ── Live graph — emit node + edge per confirmed finding ──────────
      const spineNodeId = spineNodeIds[phaseName];
      let findingSide = 0; // alternates left/right so nodes fan out

      // Record each finding as a replay event with quality + mirror refs
      for (let i = 0; i < phaseResult.findings.length; i++) {
        const f = phaseResult.findings[i];
        const verdict = qualityVerdict.passed.find(v => v.finding.id === f.id)
          || qualityVerdict.failed.find(v => v.finding.id === f.id);
        const mirrorRule = detectionRules.find(r => r.attackEvidenceRef === f.id);

        // Only emit nodes for PROVEN or CORROBORATED findings — respect EvidenceContract
        const isReal = verdict?.quality === EvidenceQuality.PROVEN || verdict?.quality === EvidenceQuality.CORROBORATED;
        if (isReal && spineNodeId) {
          const findingNodeId = breachEmitter.nodeAdded({
            kind: "finding",
            phase: phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
            phaseIndex: phaseIdx,
            label: f.title?.split(" ")[0] ?? "Finding",
            detail: f.description ?? f.title,
            severity: (f.severity ?? "medium") as import("../lib/breach-event-emitter").BreachNodeSeverity,
            technique: f.mitreId,
          });
          breachEmitter.edgeAdded(spineNodeId, findingNodeId, true, f.technique ?? phaseName);
          findingSide++;
        }

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

      // ── Live graph — emit credential nodes ───────────────────────────
      for (const cred of phaseResult.outputContext?.credentials ?? []) {
        const credNodeId = breachEmitter.nodeAdded({
          kind: "credential",
          phase: phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
          phaseIndex: phaseIdx,
          label: cred.type ?? "Credential",
          detail: `${cred.type} extracted — access level: ${cred.accessLevel}`,
          severity: cred.accessLevel === "admin" ? "critical" : "high",
        });
        if (spineNodeId) {
          breachEmitter.edgeAdded(spineNodeId, credNodeId, true, "extracted");
        }
      }

      // Build incremental attack graph from all completed results so far
      const incrementalGraph = buildUnifiedAttackGraph(phaseResults, context);

      // Persist incremental progress with partial graph
      try {
        log.info({ phase: phaseName, phaseResultsCount: phaseResults.length, graphNodes: incrementalGraph?.nodes?.length ?? 0 }, `Persisting phase results to DB`);
        await storage.updateBreachChain(chainId, {
          phaseResults,
          currentContext: context,
          progress: phaseDef.progressRange[1],
          unifiedAttackGraph: incrementalGraph,
        });
        log.info({ phase: phaseName }, `Phase results persisted successfully`);
      } catch (dbErr) {
        log.error({ err: dbErr, phase: phaseName }, `FAILED to persist phase results to DB`);
      }

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

    // Phase 13: Update portfolio with final stats
    const portfolioFindingsCount = phaseResults.reduce((s: number, pr: any) => s + (pr.findings?.length || 0), 0);
    portfolio.updateRunStats(chainId, {
      findingsCount: portfolioFindingsCount,
      pathsCount: (unifiedGraph as any)?.nodes?.length || 0,
      replaySuccesses: 0, // TODO: pipe from pivot results when available
      primaryPath: executiveSummary?.slice(0, 80) || null,
      highestTrustZone: 'authenticated', // from surface model when wired
      highestSensitivity: portfolioFindingsCount > 0 ? 'config' : 'generic',
      primaryPathConfidence: portfolioFindingsCount >= 5 ? 'strong' : portfolioFindingsCount > 0 ? 'moderate' : 'low',
      primaryPathScore: overallRiskScore || 0,
    });
    portfolio.updateRunState(chainId, "completed");

    // ── GTM v1.0: Prometheus metrics — engagement complete ──────────────
    recordEngagementComplete(Date.now() - startTime);
    recordDetectionRules(allDetectionRules.length);
    // Record quality distribution
    for (const quality of ["proven", "corroborated", "inferred", "unverifiable"] as const) {
      const count = finalQualityVerdict.summary[quality] || 0;
      for (let i = 0; i < count; i++) recordFindingQuality(quality);
    }
    // Clean up module-level stores for this chain
    phase1AEvidenceStore.delete(chainId);
    chainEmitterStore.delete(chainId);
    // Set gauge metrics
    const maxDepth = reachabilityChain?.deepestNode?.depth ?? 0;
    pivotDepthMax.set(maxDepth);
    const totalFindings = allFindings.length || 1;
    evidenceQualityRatio.set(finalQualityVerdict.summary.proven / totalFindings);

    // Auto-generate Purple Team findings from completed breach chain
    createPurpleTeamFindingsFromChain(chainId, chain.organizationId, phaseResults).catch(err => {
      console.error(`[BreachOrchestrator] Failed to create purple team findings for chain ${chainId}:`, err);
    });

    // Auto-Remediation Loop: Generate fix proposals for PROVEN/CORROBORATED findings
    generateFixProposalsForChain(chainId, finalQualityVerdict).catch(err => {
      console.error(`[BreachOrchestrator] Fix proposal generation failed for chain ${chainId}:`, err);
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
    portfolio.updateRunState(chainId, "failed");
    // Decrement active engagement gauge on failure
    recordEngagementComplete(Date.now() - startTime);
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
// AGENT MESH → BREACH CHAIN DATA CONVERSION
// ============================================================================

function buildMeshPhaseResults(result: any): BreachPhaseResult[] {
  const phases: BreachPhaseResult[] = [];
  const eventLog = result.eventLog;
  const startTime = eventLog[0]?.timestamp ?? new Date().toISOString();

  // Extract findings from vuln.confirmed and breach.confirmed events
  const vulnEvents = eventLog.filter((e: any) => e.type === "vuln.confirmed");
  const breachEvents = eventLog.filter((e: any) => e.type === "breach.confirmed");
  const credEvents = eventLog.filter((e: any) => e.type === "credential.extracted");

  const emptyContext: BreachPhaseContext = {
    credentials: [],
    compromisedAssets: [],
    attackPathSteps: [],
    evidenceArtifacts: [],
    currentPrivilegeLevel: "none",
    domainsCompromised: [],
  };

  // Phase 1: Application Compromise — from vuln.confirmed events
  if (vulnEvents.length > 0) {
    phases.push({
      phaseName: "application_compromise",
      status: "completed",
      startedAt: startTime,
      completedAt: eventLog.find((e: any) => e.type === "scan.finished")?.timestamp ?? startTime,
      durationMs: result.durationMs,
      inputContext: { credentialCount: 0, compromisedAssetCount: 0, privilegeLevel: "none" },
      outputContext: emptyContext,
      findings: vulnEvents.map((e: any) => {
        const p = e.payload as { vulnClass?: string; endpoint?: string; severity?: string; technique?: string; findingId?: string };
        const ev = e.evidence?.[0];
        return {
          id: p.findingId ?? e.id,
          severity: (p.severity as "critical" | "high" | "medium" | "low") ?? "high",
          title: `[VALIDATED] ${p.vulnClass ?? "Unknown"} — ${p.endpoint ?? ""}`,
          description: p.technique ?? `${p.vulnClass} confirmed at ${p.endpoint}`,
          technique: p.technique,
          source: "active_exploit_engine" as const,
          evidenceQuality: "proven" as const,
          statusCode: ev?.statusCode,
          responseBody: ev?.rawResponseBody?.slice(0, 500),
        };
      }),
    });
  }

  // Phase 2: Credential Extraction — from credential.extracted events
  if (credEvents.length > 0) {
    phases.push({
      phaseName: "credential_extraction",
      status: "completed",
      startedAt: credEvents[0].timestamp,
      completedAt: credEvents[credEvents.length - 1].timestamp,
      inputContext: { credentialCount: 0, compromisedAssetCount: vulnEvents.length, privilegeLevel: "user" },
      outputContext: emptyContext,
      findings: credEvents.map((e: any) => {
        const p = e.payload as { source?: string; phase?: number };
        return {
          id: e.id,
          severity: "critical" as const,
          title: `Credential extracted from ${p.source ?? "unknown"}`,
          description: `Live credential harvested during breach chain phase ${p.phase ?? 2}`,
          source: "credential_extraction" as const,
          evidenceQuality: "proven" as const,
        };
      }),
    });
  }

  // Phase 3+: Breach phases — from breach.confirmed events (phases 3-6)
  for (const be of breachEvents) {
    const p = be.payload as { phase?: number; description?: string };
    if (p.phase && p.phase > 1) {
      const phaseName = p.phase === 3 ? "cloud_iam_escalation"
        : p.phase === 4 ? "container_k8s_breakout"
        : p.phase === 5 ? "lateral_movement"
        : "impact_assessment";
      const ev = be.evidence?.[0];
      phases.push({
        phaseName: phaseName as BreachPhaseName,
        status: "completed",
        startedAt: be.timestamp,
        completedAt: be.timestamp,
        inputContext: { credentialCount: credEvents.length, compromisedAssetCount: vulnEvents.length, privilegeLevel: "user" },
        outputContext: emptyContext,
        findings: [{
          id: be.id,
          severity: "high" as const,
          title: `[VALIDATED] ${p.description ?? phaseName}`,
          description: p.description ?? `Breach phase ${p.phase} confirmed`,
          source: phaseName === "cloud_iam_escalation" ? "cloud_iam_escalation" as const
            : phaseName === "container_k8s_breakout" ? "k8s_breakout" as const
            : phaseName === "impact_assessment" ? "impact_synthesis" as const
            : "lateral_movement" as const,
          evidenceQuality: "proven" as const,
          statusCode: ev?.statusCode,
          responseBody: ev?.rawResponseBody?.slice(0, 500),
        }],
      });
    }
  }

  return phases;
}

function buildMeshAttackGraph(result: any): Record<string, unknown> {
  const nodes: Record<string, unknown>[] = [];
  const edges: Record<string, unknown>[] = [];
  const criticalPath: string[] = [];
  let nodeIdx = 0;

  // Helper: extract short hostname from URL for readable labels
  function shortHost(url?: string): string {
    if (!url) return "target";
    try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return url.slice(0, 30); }
  }

  // ── Phase definition for spine nodes ──────────────────────────────────────
  interface PhaseGroup {
    spineId: string;
    label: string;
    tactic: string;
    nodeType: string;
    compromiseLevel: string;
    blastRadius: string;
    attackTechniqueId: string;
    findingNodes: Record<string, unknown>[];
  }

  const PHASE_CONFIG: Record<number, Omit<PhaseGroup, "spineId" | "findingNodes">> = {
    1: { label: "Application Compromise", tactic: "initial-access", nodeType: "pivot", compromiseLevel: "admin", blastRadius: "contained", attackTechniqueId: "T1190" },
    2: { label: "Credential Extraction", tactic: "credential-access", nodeType: "pivot", compromiseLevel: "admin", blastRadius: "department", attackTechniqueId: "T1078" },
    3: { label: "Cloud IAM Escalation", tactic: "privilege-escalation", nodeType: "pivot", compromiseLevel: "system", blastRadius: "organization", attackTechniqueId: "T1078.004" },
    4: { label: "Container Breakout", tactic: "defense-evasion", nodeType: "pivot", compromiseLevel: "system", blastRadius: "organization", attackTechniqueId: "T1613" },
    5: { label: "Lateral Movement", tactic: "lateral-movement", nodeType: "objective", compromiseLevel: "system", blastRadius: "organization", attackTechniqueId: "T1021" },
    6: { label: "Impact Assessment", tactic: "impact", nodeType: "objective", compromiseLevel: "system", blastRadius: "organization", attackTechniqueId: "T1048" },
  };

  // ── Group events by phase ─────────────────────────────────────────────────
  const phaseGroups = new Map<number, { events: AgentEvent[] }>();

  for (const e of result.eventLog) {
    if (e.type === "vuln.confirmed") {
      if (!phaseGroups.has(1)) phaseGroups.set(1, { events: [] });
      phaseGroups.get(1)!.events.push(e);
    }
    if (e.type === "credential.extracted") {
      const p = e.payload as { phase?: number };
      const phase = p.phase ?? 2;
      if (!phaseGroups.has(phase)) phaseGroups.set(phase, { events: [] });
      phaseGroups.get(phase)!.events.push(e);
    }
    if (e.type === "breach.confirmed") {
      const p = e.payload as { phase?: number };
      const phase = p.phase ?? 1;
      if (!phaseGroups.has(phase)) phaseGroups.set(phase, { events: [] });
      phaseGroups.get(phase)!.events.push(e);
    }
  }

  // ── Detect subdomain branching ───────────────────────────────────────────
  // Extract hostname from each event's evidence or payload
  function eventHost(e: AgentEvent): string {
    const ev = e.evidence?.[0] as { targetUrl?: string } | undefined;
    const p = e.payload as { endpoint?: string; source?: string; vulnClass?: string };
    return shortHost(ev?.targetUrl ?? p.endpoint ?? p.source);
  }

  const allHosts = new Set<string>();
  for (const [, group] of Array.from(phaseGroups.entries())) {
    for (const e of group.events) allHosts.add(eventHost(e));
  }
  allHosts.delete("target"); // remove generic fallback

  const isBranchMode = allHosts.size >= 2;
  const MAX_BRANCHES = 8;

  // If branching: group hosts by finding count, collapse smallest into "Other"
  let branchHosts: string[] = [];
  let collapsedHosts: string[] = [];
  if (isBranchMode) {
    const hostCounts = new Map<string, number>();
    for (const [, group] of Array.from(phaseGroups.entries())) {
      for (const e of group.events) {
        const h = eventHost(e);
        hostCounts.set(h, (hostCounts.get(h) || 0) + 1);
      }
    }
    const sorted = Array.from(hostCounts.entries()).sort((a, b) => b[1] - a[1]);
    branchHosts = sorted.slice(0, MAX_BRANCHES).map(([h]) => h);
    collapsedHosts = sorted.slice(MAX_BRANCHES).map(([h]) => h);
  }

  // ── Entry node ────────────────────────────────────────────────────────────
  const entryId = `mesh-entry-${nodeIdx++}`;
  nodes.push({
    id: entryId,
    label: "Reconnaissance",
    description: `Target surface mapped — ${allHosts.size || 1} subdomain${allHosts.size !== 1 ? "s" : ""}`,
    nodeType: "entry",
    tactic: "reconnaissance",
    compromiseLevel: "none",
    discoveredBy: "recon",
    businessImpact: { summary: "Entry point — target surface mapped", estimatedBlastRadius: "contained" },
  });
  criticalPath.push(entryId);

  // ── Helpers for building satellite nodes from an event ────────────────────
  function makeSatelliteNode(e: AgentEvent, phase: number, config: typeof PHASE_CONFIG[1]) {
    const satId = `mesh-finding-${nodeIdx++}`;
    let satLabel: string;
    let satDesc: string;
    let satArtifacts: Record<string, unknown> = {};

    if (e.type === "vuln.confirmed") {
      const p = e.payload as { vulnClass?: string; endpoint?: string; technique?: string };
      satLabel = `${p.vulnClass ?? "vuln"} · ${shortHost(p.endpoint)}`;
      satDesc = p.technique ?? `${p.vulnClass} at ${shortHost(p.endpoint)}`;
      satArtifacts = { procedure: p.technique, discoveredAt: e.timestamp, attackTechniqueId: "T1190", attackTechniqueName: satLabel, hostname: eventHost(e) };
    } else if (e.type === "credential.extracted") {
      const p = e.payload as { source?: string };
      const ev = e.evidence?.[0] as { targetUrl?: string } | undefined;
      satLabel = `Credential · ${shortHost(ev?.targetUrl ?? p.source)}`;
      satDesc = `Credential from ${shortHost(ev?.targetUrl ?? p.source)}`;
      satArtifacts = {
        procedure: satDesc, discoveredAt: e.timestamp, attackTechniqueId: "T1078", attackTechniqueName: "Valid Accounts",
        credentials: [{ username: shortHost(p.source), privilegeTier: "service_account", sourceSystem: ev?.targetUrl ?? p.source ?? "unknown" }],
        hostname: eventHost(e),
      };
    } else {
      const p = e.payload as { description?: string; phase?: number };
      const desc = p.description ?? `Phase ${p.phase} breach`;
      satLabel = desc.length > 40 ? desc.slice(0, 38) + "…" : desc;
      satDesc = desc;
      satArtifacts = { procedure: desc, discoveredAt: e.timestamp, attackTechniqueId: config.attackTechniqueId, attackTechniqueName: satLabel, hostname: eventHost(e) };
    }

    return {
      node: {
        id: satId,
        label: satLabel,
        description: satDesc,
        nodeType: phase >= 5 ? "objective" : "pivot",
        tactic: config.tactic,
        compromiseLevel: config.compromiseLevel,
        discoveredBy: "exploit",
        artifacts: satArtifacts,
        businessImpact: { summary: satDesc, estimatedBlastRadius: config.blastRadius },
      },
      id: satId,
    };
  }

  const alternativePaths: string[][] = [];
  const sortedPhases = Array.from(phaseGroups.keys()).sort((a, b) => a - b);

  if (!isBranchMode) {
    // ── Single-spine mode (original) ──────────────────────────────────────
    let prevSpineId = entryId;

    for (const phase of sortedPhases) {
      const config = PHASE_CONFIG[phase];
      if (!config) continue;
      const group = phaseGroups.get(phase)!;

      const spineId = `mesh-phase-${phase}-${nodeIdx++}`;
      const findingCount = group.events.length;

      nodes.push({
        id: spineId,
        label: config.label,
        description: `${findingCount} finding${findingCount !== 1 ? "s" : ""} confirmed`,
        nodeType: config.nodeType,
        tactic: config.tactic,
        compromiseLevel: config.compromiseLevel,
        discoveredBy: "exploit",
        artifacts: {
          procedure: config.label,
          discoveredAt: group.events[0]?.timestamp,
          attackTechniqueId: config.attackTechniqueId,
          attackTechniqueName: config.label,
        },
        businessImpact: {
          summary: `${config.label}: ${findingCount} confirmed`,
          estimatedBlastRadius: config.blastRadius,
        },
      });
      criticalPath.push(spineId);

      edges.push({
        id: `mesh-edge-${nodeIdx++}`,
        source: prevSpineId,
        target: spineId,
        technique: config.label,
        edgeType: "primary",
        successProbability: 85,
      });
      prevSpineId = spineId;

      for (const e of group.events) {
        const { node: satNode, id: satId } = makeSatelliteNode(e, phase, config);
        nodes.push(satNode);
        edges.push({
          id: `mesh-edge-${nodeIdx++}`,
          source: spineId,
          target: satId,
          technique: satNode.label,
          edgeType: "secondary",
          successProbability: 90,
        });
      }
    }
  } else {
    // ── Branch mode: fan-out per subdomain ─────────────────────────────────
    // Entry → branch nodes (one per subdomain) → phase nodes along each branch → converge

    // Group events by host → phase
    const hostPhaseEvents = new Map<string, Map<number, AgentEvent[]>>();
    for (const [phase, group] of Array.from(phaseGroups.entries())) {
      for (const e of group.events) {
        let h = eventHost(e);
        // Collapse small branches into "Other"
        if (collapsedHosts.includes(h)) h = `Other (${collapsedHosts.length} subdomains)`;
        if (!hostPhaseEvents.has(h)) hostPhaseEvents.set(h, new Map());
        const hm = hostPhaseEvents.get(h)!;
        if (!hm.has(phase)) hm.set(phase, []);
        hm.get(phase)!.push(e);
      }
    }

    // Sort branches: most findings first (that becomes the criticalPath primary branch)
    const branchList = Array.from(hostPhaseEvents.entries()).map(([host, phases]) => {
      let totalFindings = 0;
      for (const [, events] of Array.from(phases.entries())) totalFindings += events.length;
      return { host, phases, totalFindings };
    }).sort((a, b) => b.totalFindings - a.totalFindings);

    // Convergence node at the end
    const convergeId = `mesh-converge-${nodeIdx++}`;
    const impactConfig = PHASE_CONFIG[6] || PHASE_CONFIG[5];

    // Build each branch
    branchList.forEach((branch, branchIdx) => {
      const isPrimary = branchIdx === 0;
      const branchPath: string[] = [];

      // Branch root node (subdomain entry)
      const branchRootId = `mesh-branch-${branchIdx}-${nodeIdx++}`;
      nodes.push({
        id: branchRootId,
        label: branch.host,
        description: `${branch.totalFindings} finding${branch.totalFindings !== 1 ? "s" : ""} on ${branch.host}`,
        nodeType: "pivot",
        tactic: "initial-access",
        compromiseLevel: "limited",
        discoveredBy: "recon",
        artifacts: { hostname: branch.host, procedure: `Branch: ${branch.host}`, discoveredAt: new Date().toISOString() },
        businessImpact: { summary: `Subdomain: ${branch.host}`, estimatedBlastRadius: "contained" },
        branchId: branchIdx,
      });
      branchPath.push(branchRootId);

      // Edge from entry to branch root
      edges.push({
        id: `mesh-edge-${nodeIdx++}`,
        source: entryId,
        target: branchRootId,
        technique: branch.host,
        edgeType: isPrimary ? "primary" : "alternative",
        successProbability: 80,
      });

      if (isPrimary) criticalPath.push(branchRootId);

      // Phase nodes along this branch
      const branchSortedPhases = Array.from(branch.phases.keys()).sort((a, b) => a - b);
      let prevId = branchRootId;

      for (const phase of branchSortedPhases) {
        const config = PHASE_CONFIG[phase];
        if (!config) continue;
        const events = branch.phases.get(phase)!;

        const phaseNodeId = `mesh-branch-${branchIdx}-phase-${phase}-${nodeIdx++}`;
        nodes.push({
          id: phaseNodeId,
          label: `${config.label}`,
          description: `${events.length} on ${branch.host}`,
          nodeType: config.nodeType,
          tactic: config.tactic,
          compromiseLevel: config.compromiseLevel,
          discoveredBy: "exploit",
          artifacts: {
            hostname: branch.host,
            procedure: config.label,
            discoveredAt: events[0]?.timestamp,
            attackTechniqueId: config.attackTechniqueId,
            attackTechniqueName: config.label,
          },
          businessImpact: {
            summary: `${config.label} on ${branch.host}: ${events.length}`,
            estimatedBlastRadius: config.blastRadius,
          },
          branchId: branchIdx,
        });
        branchPath.push(phaseNodeId);

        edges.push({
          id: `mesh-edge-${nodeIdx++}`,
          source: prevId,
          target: phaseNodeId,
          technique: config.label,
          edgeType: isPrimary ? "primary" : "alternative",
          successProbability: 85,
        });
        prevId = phaseNodeId;

        if (isPrimary) criticalPath.push(phaseNodeId);

        // Satellite findings for this branch+phase
        for (const e of events) {
          const { node: satNode, id: satId } = makeSatelliteNode(e, phase, config);
          (satNode as any).branchId = branchIdx;
          nodes.push(satNode);
          edges.push({
            id: `mesh-edge-${nodeIdx++}`,
            source: phaseNodeId,
            target: satId,
            technique: satNode.label,
            edgeType: "secondary",
            successProbability: 90,
          });
        }
      }

      // Edge from branch's last phase to convergence
      edges.push({
        id: `mesh-edge-${nodeIdx++}`,
        source: prevId,
        target: convergeId,
        technique: "Converge",
        edgeType: isPrimary ? "primary" : "alternative",
        successProbability: 75,
      });

      if (!isPrimary) alternativePaths.push(branchPath);
    });

    // Convergence node
    const totalFindings = branchList.reduce((sum, b) => sum + b.totalFindings, 0);
    nodes.push({
      id: convergeId,
      label: "Impact Assessment",
      description: `${totalFindings} total findings across ${branchList.length} subdomains`,
      nodeType: "objective",
      tactic: "impact",
      compromiseLevel: "system",
      discoveredBy: "exploit",
      artifacts: { procedure: "Convergence — all branches", discoveredAt: new Date().toISOString() },
      businessImpact: {
        summary: `Full breach path: ${totalFindings} findings, ${branchList.length} subdomains`,
        estimatedBlastRadius: "organization",
      },
    });
    criticalPath.push(convergeId);
  }

  // ── Kill chain coverage ─────────────────────────────────────────────────
  const coveredTactics = new Set<string>();
  for (const node of nodes) {
    const tactic = (node as any).tactic;
    if (tactic) coveredTactics.add(tactic);
  }
  const killChainCoverage: string[] = [];
  if (coveredTactics.has("initial-access") || coveredTactics.has("reconnaissance")) killChainCoverage.push("reconnaissance", "initial-access", "execution");
  if (coveredTactics.has("credential-access")) killChainCoverage.push("credential-access", "discovery");
  if (coveredTactics.has("privilege-escalation")) killChainCoverage.push("privilege-escalation", "defense-evasion");
  if (coveredTactics.has("defense-evasion") && !killChainCoverage.includes("defense-evasion")) killChainCoverage.push("persistence");
  if (coveredTactics.has("lateral-movement")) killChainCoverage.push("lateral-movement", "collection");
  if (coveredTactics.has("impact")) killChainCoverage.push("exfiltration", "impact");

  // ── Time to compromise estimate ─────────────────────────────────────────
  const durationMs = result.durationMs || 30000;
  const estimatedMinutes = Math.max(5, Math.round(durationMs / 60000 * 3));

  return {
    nodes,
    edges,
    criticalPath,
    alternativePaths,
    entryNodeId: entryId,
    objectiveNodeIds: criticalPath.slice(-1),
    killChainCoverage,
    complexityScore: Math.min(100, sortedPhases.length * 18),
    timeToCompromise: {
      minimum: Math.max(5, Math.round(estimatedMinutes * 0.6)),
      expected: estimatedMinutes,
      maximum: Math.round(estimatedMinutes * 2),
      unit: "minutes" as const,
    },
  };
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
  const subAgentRuns: NonNullable<BreachPhaseResult["subAgentRuns"]> = [];

  let microDispatchSummaryOuter: BreachPhaseResult["agentDispatchSummary"] | undefined;

  for (const assetId of chain.assetIds as string[]) {
    // ─────────────────────────────────────────────────────────────────
    // Phase 1A: Run Active Exploit Engine against the live target
    // ─────────────────────────────────────────────────────────────────
    let activeExploitResult: ActiveExploitResult | null = null;
    let targetUrl: string | null = null;
    let exploitTarget: ActiveExploitTarget | null = null;

    try {
      targetUrl = await resolveAssetUrl(assetId);

      if (targetUrl) {
        onProgress(chain.id, "application_compromise", 5,
          `Running active exploitation against ${targetUrl}`);

        exploitTarget = {
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
              5 + Math.round(Math.max(0, progress) * 0.4),
              `[Active Exploit] ${detail}`);
          },
          // Surface signal callback — fires into live graph as crawl discovers things
          (kind, label, detail) => {
            const emitter = chainEmitterStore.get(chain.id);
            if (emitter) {
              emitter.surfaceSignal(
                kind as import("../lib/breach-event-emitter").SurfaceSignalKind,
                label,
                detail,
              );
            }
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
        // Also emit reasoning event per confirmed exploit so the live feed shows the AI's decision
        const phase1Emitter = chainEmitterStore.get(chain.id);
        for (const finding of mapped.findings) {
          const fid = `bf-${randomUUID().slice(0, 8)}`;
          findings.push({
            id: fid,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: finding.title,
            description: finding.description,
            technique: finding.exploitChain,
            source: "active_exploit_engine",
            evidenceQuality: "proven",
            // ADR-001: Propagate HTTP evidence fields from AEE for EvidenceContract
            statusCode: (finding as any).statusCode ?? undefined,
            responseBody: (finding as any).responseBody ?? undefined,
            ...((finding as any).curlCommand ? { curlCommand: (finding as any).curlCommand } : {}),
            ...((finding as any).confidence != null ? { confidence: (finding as any).confidence } : {}),
            ...((finding as any).matchedPatterns ? { matchedPatterns: (finding as any).matchedPatterns } : {}),
          });
          // Emit AI reasoning event: what the exploit agent confirmed and why it matters
          if (phase1Emitter) {
            phase1Emitter.reasoning(
              "application_compromise",
              "exploit-agent-p1a",
              `Confirmed: ${finding.title}`,
              finding.description,
              "confirmed",
              { techniqueTried: finding.exploitChain },
            );
          }
        }

        console.log(`[BreachOrchestrator] Active Exploit Results for ${assetId}:`, {
          endpoints: activeExploitResult.summary.totalEndpoints,
          attempts: activeExploitResult.summary.totalAttempts,
          validated: activeExploitResult.summary.totalValidated,
          credentials: activeExploitResult.summary.totalCredentials,
          attackPaths: activeExploitResult.summary.attackPathsFound,
          duration: `${activeExploitResult.durationMs}ms`,
        });
        subAgentRuns.push({
          name: `Active Exploit Engine (${assetId})`,
          status: "completed",
          findingsCount: mapped.findings.length,
          durationMs: activeExploitResult.durationMs,
        });
      }
    } catch (err: any) {
      console.error(`[BreachOrchestrator] Active exploit engine FAILED for ${assetId}:`, err.message);
      subAgentRuns.push({ name: `Active Exploit Engine (${assetId})`, status: "failed", error: err.message });

      emitCognitiveEvent({
        type: "exploration.failed",
        chainId: chain.id,
        target: assetId,
        summary: `Exploit engine failed for ${assetId}`,
        detail: formatError(err),
        timestamp: new Date().toISOString(),
      });
      // Fall through to AI pipeline — active exploits are additive, not blocking
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase 1B-micro: Parallel Specialized Agent Dispatch
    // Fan out micro-agents per (endpoint × vulnClass) for parallel
    // deterministic payload execution. Per LLM Boundary Amendment:
    // firePayloadBatch() is zero-LLM, findings require real evidence.
    // ─────────────────────────────────────────────────────────────────
    const MAX_CONCURRENT_MICRO_AGENTS = 50;
    let microAgentFindings = 0;
    let microDispatchSummary: BreachPhaseResult["agentDispatchSummary"] | undefined; // scoped inside loop

    if (activeExploitResult && exploitTarget && targetUrl && activeExploitResult.crawl.endpoints.length > 0) {
      try {
        onProgress(chain.id, "application_compromise", 45,
          `Dispatching parallel micro-agents across ${activeExploitResult.crawl.endpoints.length} endpoints`);

        // core-v2: MicroAgentOrchestrator removed — skip micro-agent dispatch
        const agentSpecs: any[] = [];

        if (agentSpecs.length > 0) {
          const merged = { findings: [] as any[], credentials: [] as any[], agentDispatchSummary: { totalAgents: 0, completedWithFindings: 0, completedWithoutFindings: 0, totalFindings: 0, discardedFindings: 0, executionTimeMs: 0 } };
          microAgentFindings = merged.findings.length;

          for (const f of merged.findings) {
            findings.push({
              id: f.id,
              severity: f.severity,
              title: f.title,
              description: f.description,
              technique: f.technique,
              mitreId: f.mitreId,
              source: "active_exploit_engine",
              evidenceQuality: f.statusCode && f.statusCode > 0 ? "proven" : "corroborated",
              statusCode: f.statusCode,
              responseBody: f.responseBody,
            });
          }

          for (const cred of merged.credentials) {
            const hash = createHash("sha256").update(cred.value).digest("hex");
            if (!newCredentials.find(c => c.valueHash === hash)) {
              const credType = (["password", "hash", "token", "key", "api_key"].includes(cred.type)
                ? cred.type : "token") as BreachCredential["type"];
              newCredentials.push({
                id: `cred-${randomUUID().slice(0, 8)}`,
                type: credType,
                valueHash: hash,
                authValue: cred.value,
                source: "micro_agent_dispatch",
                accessLevel: "none",
                validatedTargets: [],
                discoveredAt: new Date().toISOString(),
              });
            }
          }

          subAgentRuns.push({
            name: `Parallel MicroAgents (${agentSpecs.length} agents)`,
            status: "completed",
            findingsCount: merged.findings.length,
            durationMs: merged.agentDispatchSummary.executionTimeMs,
          });

          microDispatchSummary = {
            totalAgents: merged.agentDispatchSummary.totalAgents,
            tier1Completed: merged.agentDispatchSummary.completedWithFindings + merged.agentDispatchSummary.completedWithoutFindings,
            tier2Completed: 0,
            totalFindings: merged.agentDispatchSummary.totalFindings,
            falsePositivesFiltered: merged.agentDispatchSummary.discardedFindings,
            executionTimeMs: merged.agentDispatchSummary.executionTimeMs,
          };
          microDispatchSummaryOuter = microDispatchSummary;

          console.info(
            `[BreachOrchestrator] MicroAgent dispatch complete: ` +
            `${agentSpecs.length} agents, ${merged.findings.length} findings, ` +
            `${merged.agentDispatchSummary.discardedFindings} discarded (no evidence)`
          );
        }
      } catch (err: any) {
        console.warn(`[BreachOrchestrator] MicroAgent dispatch error:`, err.message);
        subAgentRuns.push({
          name: `Parallel MicroAgents`,
          status: "failed",
          error: err.message,
        });
      } finally {
        // Clean up rate limiters to prevent timer leaks
        destroyAllRateLimiters();
      }
    }

    // ─────────────────────────────────────────────────────────────────
    // Phase 1B: Run AI Agent Pipeline (fallback if micro-agents
    //           produced zero findings, or additive for app_logic/cve/api_sequence)
    // ─────────────────────────────────────────────────────────────────
    // Skip AI pipeline if micro-agents already found substantial results
    const skipAIPipeline = microAgentFindings >= 3;

    if (skipAIPipeline) {
      onProgress(chain.id, "application_compromise", 80,
        `[AI Pipeline] Skipped — ${microAgentFindings} findings from parallel agents`);
      subAgentRuns.push({
        name: "AI Pipeline (skipped — sufficient micro-agent findings)",
        status: "skipped",
      });
    } else {
      onProgress(chain.id, "application_compromise", 78,
        `Running AI analysis pipeline for ${assetId}`);
    }

    const exposureTypes = ["app_logic", "cve", "api_sequence_abuse"];

    for (const exposureType of exposureTypes) {
      if (skipAIPipeline) break;
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
          confidence: toInt100(result.confidence),
          score: toInt100(result.score),
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
              source: "active_exploit_engine",
              evidenceQuality: "corroborated",
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
        subAgentRuns.push({
          name: `AI Pipeline: ${exposureType} (${assetId})`,
          status: "completed",
          findingsCount: result.attackPath?.length || 0,
        });
      } catch (error: any) {
        console.error(`[BreachOrchestrator] App compromise failed for ${assetId}/${exposureType}:`, error);
        subAgentRuns.push({ name: `AI Pipeline: ${exposureType} (${assetId})`, status: "failed", error: error?.message });
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Phase 1C: Subdomain Agent Dispatch
  // Enumerate alive subdomains from the recon that ran inside Phase 1B's
  // orchestrator, then dispatch the active exploit engine against each one.
  // This ensures we attack the full discovered surface, not just chain.assetIds.
  // ─────────────────────────────────────────────────────────────────
  try {
    const MAX_SUBDOMAIN_AGENTS = 5; // cap concurrency — don't flood the target
    const primaryHosts = (chain.assetIds as string[]).map(id => {
      try { return new URL(id).hostname; } catch { return id; }
    });

    // core-v2: analyzeSubdomains (recon module) removed — skip subdomain enumeration
    const subdomainResults: PromiseSettledResult<{ subdomains: { isAlive: boolean; subdomain: string }[] }>[] = [];

    const aliveSubdomainUrls: string[] = [];
    for (const result of subdomainResults) {
      if (result.status === "fulfilled" && result.value?.subdomains) {
        for (const sub of result.value.subdomains) {
          if (sub.isAlive && sub.subdomain) {
            // Skip exact matches to primary hosts (already processed above)
            if (!primaryHosts.some(h => sub.subdomain === h)) {
              aliveSubdomainUrls.push(`https://${sub.subdomain}`);
            }
          }
        }
      }
    }

    if (aliveSubdomainUrls.length > 0) {
      onProgress(chain.id, "application_compromise", 92,
        `Dispatching subdomain agents against ${aliveSubdomainUrls.length} live subdomains (capped at ${MAX_SUBDOMAIN_AGENTS})`);

      const targetsToScan = aliveSubdomainUrls.slice(0, MAX_SUBDOMAIN_AGENTS);

      const subdomainAgentResults = await Promise.allSettled(
        targetsToScan.map(async (subUrl) => {
          const exploitTarget: ActiveExploitTarget = {
            baseUrl: subUrl,
            assetId: subUrl,
            scope: {
              exposureTypes: ["sqli", "xss", "ssrf", "auth_bypass", "idor", "command_injection"] as ExposureType[],
              excludePaths: ["\\.pdf$", "\\.png$", "\\.jpg$", "\\.css$", "\\.js$"],
              maxEndpoints: 50,  // tighter cap per subdomain
            },
            timeout: 8000,
            maxRequests: 100,
            crawlDepth: 2,
          };

          const result = await runActiveExploitEngine(exploitTarget, () => {});
          return { subUrl, result };
        })
      );

      for (const settled of subdomainAgentResults) {
        if (settled.status === "rejected") {
          subAgentRuns.push({ name: `Subdomain Agent (error)`, status: "failed", error: String(settled.reason) });
          continue;
        }
        const { subUrl, result } = settled.value;

        // Store subdomain evidence in phase1A store so Phase 2 can parse it
        if (result.validated.length > 0) {
          const existing = phase1AEvidenceStore.get(chain.id) || [];
          phase1AEvidenceStore.set(chain.id, [...existing, ...result.validated]);
        }

        const mapped = mapToBreachPhaseContext(result);
        for (const cred of mapped.credentials) {
          newCredentials.push({
            id: `bc-${randomUUID().slice(0, 8)}`,
            type: cred.type as BreachCredential["type"],
            valueHash: cred.hash,
            source: "active_exploit_engine",
            accessLevel: cred.accessLevel === "admin" ? "admin" : "user",
            validatedTargets: [subUrl],
            discoveredAt: new Date().toISOString(),
          });
        }
        for (const finding of mapped.findings) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: `[Subdomain: ${new URL(subUrl).hostname}] ${finding.title}`,
            description: finding.description,
            technique: finding.exploitChain,
            source: "active_exploit_engine",
            evidenceQuality: "proven",
            // ADR-001: Propagate HTTP evidence fields from AEE for EvidenceContract
            statusCode: (finding as any).statusCode ?? undefined,
            responseBody: (finding as any).responseBody ?? undefined,
            ...((finding as any).curlCommand ? { curlCommand: (finding as any).curlCommand } : {}),
            ...((finding as any).confidence != null ? { confidence: (finding as any).confidence } : {}),
            ...((finding as any).matchedPatterns ? { matchedPatterns: (finding as any).matchedPatterns } : {}),
          });
        }
        subAgentRuns.push({
          name: `Subdomain Agent (${new URL(subUrl).hostname})`,
          status: "completed",
          findingsCount: mapped.findings.length,
          durationMs: result.durationMs,
        });
      }

      onProgress(chain.id, "application_compromise", 98,
        `Subdomain sweep complete: ${subAgentRuns.filter(r => r.status === "completed" && r.name.startsWith("Subdomain")).length}/${targetsToScan.length} agents finished`);
    }
  } catch (subdomainErr: any) {
    console.warn("[BreachOrchestrator] Subdomain agent dispatch failed (non-fatal):", subdomainErr?.message);
    subAgentRuns.push({ name: "Subdomain Agent Dispatcher", status: "failed", error: subdomainErr?.message });
  }

  return buildPhaseResult("application_compromise", startTime, context, {
    credentials: newCredentials,
    assets: newAssets,
    findings,
    evaluationIds,
    domain: "application",
    subAgentRuns,
    agentDispatchSummary: microDispatchSummaryOuter,
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
                source: "credential_extraction",
                evidenceQuality: "proven",
                statusCode: attempt.response.statusCode,
                responseBody: attempt.response.body?.slice(0, 2000),
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

  // ADR-001/ADR-002: LLM credential fallback REMOVED.
  // If deterministic regex extraction found zero credentials, we return null.
  // LLM cannot generate credential data — only real HTTP evidence can.
  if (newCredentials.length === 0 && phase1Attempts.length === 0) {
    console.info(
      `[BreachOrchestrator] Phase 2: Zero credentials extracted from HTTP evidence. ` +
      `No LLM fallback — ADR-001 prohibits synthetic credential generation. ` +
      `Chain will continue with zero credentials; downstream phases gate on this.`
    );
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
  _onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  // core-v2: Phase disabled — cloud pentest services removed.
  // Returns skipped result with explicit reason.
  const startTime = Date.now();
  console.info(`[BreachOrchestrator] Phase cloud_iam_escalation disabled in core-v2 build`);
  const result = buildPhaseResult("cloud_iam_escalation", startTime, context, {
    credentials: [],
    assets: [],
    findings: [],
    evaluationIds: [],
    domain: "cloud",
  });
  (result as any).zeroFindingsDiagnostic = {
    category: "phase_skipped",
    reason: "Phase disabled in current build. Cloud IAM escalation requires cloud infrastructure services not yet implemented. No testing was attempted — this does not indicate the target is secure against cloud-based attacks.",
    subAgentRuns: 0,
  };
  return result;
}

// ============================================================================
// PHASE 4: CONTAINER/K8S BREAKOUT
// ============================================================================

async function executeContainerK8sBreakout(
  chain: BreachChain,
  context: BreachPhaseContext,
  _onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  // core-v2: Phase disabled — container security services removed.
  const startTime = Date.now();
  console.info(`[BreachOrchestrator] Phase container_k8s_breakout disabled in core-v2 build`);
  const result = buildPhaseResult("container_k8s_breakout", startTime, context, {
    credentials: [],
    assets: [],
    findings: [],
    evaluationIds: [],
    domain: "kubernetes",
  });
  (result as any).zeroFindingsDiagnostic = {
    category: "phase_skipped",
    reason: "Phase disabled in current build. Container and Kubernetes breakout testing requires container security services not yet implemented. No testing was attempted.",
    subAgentRuns: 0,
  };
  return result;
}

// ============================================================================
// PHASE 5: LATERAL MOVEMENT
// ============================================================================

async function executeLateralMovement(
  chain: BreachChain,
  context: BreachPhaseContext,
  _onProgress: BreachOrchestratorProgressCallback
): Promise<BreachPhaseResult> {
  // core-v2: Phase disabled — lateral movement services removed.
  const startTime = Date.now();
  console.info(`[BreachOrchestrator] Phase lateral_movement disabled in core-v2 build`);
  const result = buildPhaseResult("lateral_movement", startTime, context, {
    credentials: [],
    assets: [],
    findings: [],
    evaluationIds: [],
    domain: "network",
  });
  (result as any).zeroFindingsDiagnostic = {
    category: "phase_skipped",
    reason: "Phase disabled in current build. Lateral movement testing requires network pivoting services not yet implemented. No cross-system testing was attempted.",
    subAgentRuns: 0,
  };
  return result;
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

  // LLM Boundary: Impact findings are SYNTHESIS of earlier proven findings.
  // They aggregate real evidence from prior phases but do not themselves have
  // direct HTTP evidence. Mark all as "[SYNTHESIS]" and evidenceQuality: "inferred"
  // so the Evidence Quality Gate classifies them correctly and report-generator
  // suppresses them from customer-facing output. They appear only in internal views.
  if (uniqueDomains >= 3) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "[SYNTHESIS] Multi-Domain Breach: Full Infrastructure Compromise",
      description: `Attacker achieved access across ${uniqueDomains} domains (${context.domainsCompromised.join(", ")}), compromising ${totalAssets} assets with ${totalCreds} harvested credentials. Maximum privilege: ${maxPrivilege}.`,
      source: "impact_synthesis",
      evidenceQuality: "inferred",
    } as any);
  }

  if (maxPrivilege === "cloud_admin" || maxPrivilege === "domain_admin") {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "[SYNTHESIS] Administrative Privilege Achieved",
      description: `Attacker escalated to ${maxPrivilege} level, enabling full control over ${maxPrivilege === "cloud_admin" ? "cloud infrastructure" : "domain resources"}.`,
      source: "impact_synthesis",
      evidenceQuality: "inferred",
    } as any);
  }

  if (totalCreds >= 5) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "high",
      title: "[SYNTHESIS] Significant Credential Harvest",
      description: `${totalCreds} credentials harvested across the breach chain, enabling persistent access and further lateral movement.`,
      source: "impact_synthesis",
      evidenceQuality: "inferred",
    } as any);
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
      title: "[SYNTHESIS] Compliance Framework Violations",
      description: `Breach path violates controls in: ${complianceFrameworks.join(", ")}. Immediate remediation required for compliance posture.`,
      source: "impact_synthesis",
      evidenceQuality: "inferred",
    } as any);
  }

  // Data exposure assessment
  if (context.compromisedAssets.some(a => a.accessLevel === "admin" || a.accessLevel === "system")) {
    findings.push({
      id: `bf-${randomUUID().slice(0, 8)}`,
      severity: "critical",
      title: "[SYNTHESIS] Data Exposure: Administrative Access to Production Systems",
      description: `With ${context.compromisedAssets.filter(a => a.accessLevel === "admin" || a.accessLevel === "system").length} systems at admin/system access, attacker can exfiltrate all data including PII, financial records, and proprietary information.`,
      source: "impact_synthesis",
      evidenceQuality: "inferred",
    } as any);
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
  // Accumulate realistic phase estimates (not wall-clock execution time) for timeToCompromise
  let totalRealisticMinutes = 0;

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
    const phaseArtifacts = {
      hostname: phase.outputContext.compromisedAssets[0]?.name,
      credentials: phaseNodeCredentials.length > 0 ? phaseNodeCredentials : undefined,
      attackTechniqueId: phaseAtkIds[0],
      attackTechniqueName: PHASE_DEFINITIONS[phase.phaseName].displayName,
      procedure: PHASE_DEFINITIONS[phase.phaseName].description,
      // defensesFired / defensesMissed populated from real Defender's Mirror
      // rules via the defense-gaps endpoint — never hardcoded
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

    // Compute realistic timeEstimate (minutes) based on phase type and complexity.
    // NOTE: always use phase-specific realistic estimates — never raw execution wall-clock.
    // Real-world attack phases take orders of magnitude longer than automated execution.
    const phaseTimeEstimateMinutes = (() => {
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

    // Accumulate realistic total for timeToCompromise — this is the key variable
    totalRealisticMinutes += phaseTimeEstimateMinutes;

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

  // Use accumulated realistic phase estimates (not wall-clock) for timeToCompromise.
  // totalRealisticMinutes reflects what a real attacker would need for each phase
  // based on complexity — not how fast our engine ran it.
  const estimatedMinutes = Math.max(15, Math.round(totalRealisticMinutes));

  return {
    nodes,
    edges,
    entryNodeId,
    objectiveNodeIds: phaseEntryNodes.slice(-1),
    criticalPath,
    killChainCoverage: killChainCoverage as any[],
    complexityScore: Math.min(100, completedPhases.length * 18),
    timeToCompromise: {
      minimum: Math.max(15, Math.round(estimatedMinutes * 0.6)),
      expected: estimatedMinutes,
      maximum: Math.round(estimatedMinutes * 2.5),
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
    subAgentRuns?: BreachPhaseResult["subAgentRuns"];
    agentDispatchSummary?: BreachPhaseResult["agentDispatchSummary"];
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
    subAgentRuns: output.subAgentRuns,
    agentDispatchSummary: output.agentDispatchSummary,
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

/** Normalize confidence/score to integer 0-100 (agent may return 0-1 floats) */
function toInt100(val: number): number {
  if (val > 0 && val <= 1) return Math.round(val * 100);
  return Math.round(val);
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

// ============================================================================
// AUTO-REMEDIATION: Background fix proposal generation
// ============================================================================

async function generateFixProposalsForChain(
  chainId: string,
  qualityVerdict: { summary: { proven: number; corroborated: number }; passed: any[] },
): Promise<void> {

  const eligibleFindings = qualityVerdict.passed || [];
  if (eligibleFindings.length === 0) {
    console.info(`[FixGen] No PROVEN/CORROBORATED findings for chain ${chainId} — skipping fix generation`);
    return;
  }

  // Only generate for critical/high severity, cap at 20
  const highPriority = eligibleFindings.filter((f: any) =>
    f.finding?.severity === "critical" || f.finding?.severity === "high"
  ).slice(0, 20);

  let generated = 0;
  for (const verdict of highPriority) {
    const finding = verdict.finding || verdict;
    try {
      const quality = verdict.quality === "proven" ? "proven" : "corroborated";
      // core-v2: generateFixProposal (fix-proposal-generator) removed — generate minimal stub
      const proposal = {
        id: `fix-${chainId}-${generated}`,
        chainId,
        findingId: finding.id || `f-${generated}`,
        severity: finding.severity || "high",
        title: `Fix: ${finding.title || "Unknown Finding"}`,
        description: finding.description || "",
        status: "pending" as const,
        createdAt: new Date().toISOString(),
      };

      await storage.storeFixProposal(chainId, proposal);
      generated++;
    } catch (err) {
      console.warn(`[FixGen] Skipped finding:`, err);
    }
  }

  if (generated > 0) {
    console.info(`[FixGen] Generated ${generated} fix proposals for chain ${chainId}`);
  }
}
