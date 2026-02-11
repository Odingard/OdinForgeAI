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
  type ActiveExploitTarget,
  type ActiveExploitResult,
  type ExposureType,
} from "./active-exploit-engine";
import { awsPentestService } from "./cloud-pentest/aws-pentest-service";
import { kubernetesPentestService } from "./container-security/kubernetes-pentest-service";
import { lateralMovementService } from "./lateral-movement";
import { storage } from "../storage";
import { wsService } from "./websocket";

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

  const config = chain.config as BreachChainConfig;
  const startTime = Date.now();

  await storage.updateBreachChain(chainId, {
    status: "running",
    startedAt: new Date(),
  });

  broadcastBreachProgress(chainId, "starting", 0, "Breach chain initiated");

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
      broadcastBreachProgress(
        chainId, phaseName, phaseDef.progressRange[0],
        `Starting ${phaseDef.displayName}...`
      );

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
      }

      // Persist incremental progress
      await storage.updateBreachChain(chainId, {
        phaseResults,
        currentContext: context,
        progress: phaseDef.progressRange[1],
      });

      broadcastBreachProgress(
        chainId, phaseName, phaseDef.progressRange[1],
        `${phaseDef.displayName} complete: ${phaseResult.findings.length} findings`
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

    // Build unified attack graph spanning all domains
    const unifiedGraph = buildUnifiedAttackGraph(phaseResults, context);
    const overallRiskScore = calculateBreachRiskScore(phaseResults, context);
    const executiveSummary = generateBreachExecutiveSummary(phaseResults, context, overallRiskScore);

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
    });

    broadcastBreachProgress(chainId, "completed", 100, "Breach chain complete");

    // Auto-generate Purple Team findings from completed breach chain
    createPurpleTeamFindingsFromChain(chainId, chain.organizationId, phaseResults).catch(err => {
      console.error(`[BreachOrchestrator] Failed to create purple team findings for chain ${chainId}:`, err);
    });
  } catch (error) {
    console.error(`[BreachOrchestrator] Chain ${chainId} failed:`, error);
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

  // Check if active exploitation already provided real credentials
  const activeCredentials = context.credentials.filter(c =>
    c.source === "active_exploit_engine" || c.source?.includes("active_exploit")
  );

  if (activeCredentials.length > 0) {
    onProgress(chain.id, "credential_extraction", 25,
      `${activeCredentials.length} credentials already extracted via active exploitation`);
  }

  // For each compromised app, run data_exfiltration to find credentials
  const compromisedAppAssets = context.compromisedAssets.filter(
    a => a.assetType === "application"
  );

  for (const asset of compromisedAppAssets) {
    const evaluationId = `eval-bc-${randomUUID().slice(0, 8)}`;
    const contextDescription = [
      `Breach chain ${chain.id}: Credential Extraction phase.`,
      `Prior access: ${asset.accessLevel} on ${asset.name} via ${asset.accessMethod}.`,
      `Known credentials: ${context.credentials.length}.`,
      `Goal: Extract tokens, API keys, service account credentials, database credentials.`,
      `Search environment variables, config files, database tables with credential columns.`,
    ].join(" ");

    // Skip AI pipeline if OpenAI circuit is open
    if (isCircuitOpen("openai")) {
      console.warn(`[BreachOrchestrator] OpenAI circuit open, skipping credential extraction for ${asset.assetId}`);
      continue;
    }

    try {
      await storage.createEvaluation({
        assetId: asset.assetId,
        exposureType: "data_exfiltration",
        priority: "high",
        description: contextDescription,
        organizationId: chain.organizationId,
        executionMode: config.executionMode,
        status: "pending",
      });

      const result = await runAgentOrchestrator(
        asset.assetId,
        "data_exfiltration",
        "high",
        contextDescription,
        evaluationId,
        (agentName, stage, progress, message) => {
          onProgress(chain.id, "credential_extraction", progress, `[${agentName}] ${message}`);
        },
        {
          adversaryProfile: config.adversaryProfile as any,
          organizationId: chain.organizationId,
          executionMode: config.executionMode,
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

      newCredentials.push(...extractCredentialsFromFindings(result, "credential_extraction"));
    } catch (error) {
      console.error(`[BreachOrchestrator] Credential extraction failed for ${asset.assetId}:`, error);
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

  if (cloudCreds.length > 0) {
    onProgress(chain.id, "cloud_iam_escalation", 40, `Analyzing IAM escalation for ${cloudCreds.length} credentials`);

    try {
      // Derive permissions from credential types for IAM analysis
      const inferredPermissions = cloudCreds.flatMap(c => {
        if (c.type === "iam_role") return ["iam:*", "sts:AssumeRole"];
        if (c.type === "api_key") return ["ec2:Describe*", "s3:List*", "iam:List*"];
        if (c.type === "service_account") return ["iam:PassRole", "lambda:CreateFunction"];
        return ["sts:GetCallerIdentity"];
      });

      const iamResult = await awsPentestService.analyzeIAMPrivilegeEscalation(
        inferredPermissions,
        cloudCreds[0]?.username || "breach-chain-principal",
        cloudCreds[0]?.username || "breach-chain-principal"
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

  onProgress(chain.id, "container_k8s_breakout", 60, "Analyzing Kubernetes RBAC for escalation paths");

  try {
    // Build a K8s config from context — use compromised cloud credentials
    // to simulate what access the attacker would have
    const k8sConfig = {
      clusterContext: "breach-chain-analysis",
      namespace: "default",
      pods: [] as any[],
      serviceAccounts: context.credentials
        .filter(c => c.type === "service_account" || c.type === "token")
        .map(c => ({
          name: c.username || "default",
          namespace: "default",
          automountToken: true,
        })),
      roles: [
        // Simulate common roles an attacker might encounter after cloud escalation
        {
          name: "developer-role",
          namespace: "default",
          isClusterRole: false,
          rules: [
            { resources: ["pods"], verbs: ["get", "list", "create", "delete"], apiGroups: [""] },
            { resources: ["pods/exec"], verbs: ["create"], apiGroups: [""] },
            { resources: ["secrets"], verbs: ["get", "list"], apiGroups: [""] },
            { resources: ["configmaps"], verbs: ["get", "list"], apiGroups: [""] },
          ],
        },
      ],
      roleBindings: [
        {
          name: "developer-binding",
          namespace: "default",
          isClusterRoleBinding: false,
          roleRef: "developer-role",
          subjects: [{ kind: "ServiceAccount", name: "default", namespace: "default" }],
        },
      ],
      networkPolicies: [],
      secrets: [
        {
          name: "db-credentials",
          namespace: "default",
          type: "Opaque",
          accessibleByPods: ["app-pod", "worker-pod"],
        },
      ],
    };

    const k8sResult = await kubernetesPentestService.testKubernetesAbuse(k8sConfig);

    // Process RBAC escalation findings
    for (const escalation of k8sResult.rbacEscalations) {
      findings.push({
        id: `bf-${randomUUID().slice(0, 8)}`,
        severity: escalation.severity as "critical" | "high" | "medium" | "low",
        title: `K8s RBAC Escalation: ${escalation.name}`,
        description: `${escalation.escalationPath.join(" → ")}. Remediation: ${escalation.remediation}`,
        technique: escalation.escalationPath[0],
      });
    }

    // Process API abuse vectors
    for (const vector of k8sResult.apiAbuseVectors) {
      if (vector.exploitable) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: vector.severity as "critical" | "high" | "medium" | "low",
          title: `K8s API Abuse: ${vector.name}`,
          description: `${vector.impact}. Exploitability: ${vector.exploitability}`,
          technique: vector.apiEndpoint,
        });
      }
    }

    // Secret exposures yield new credentials
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

    // K8s lateral movement paths
    for (const path of k8sResult.lateralMovementPaths) {
      findings.push({
        id: `bf-${randomUUID().slice(0, 8)}`,
        severity: path.severity as "critical" | "high" | "medium" | "low",
        title: `K8s Lateral: ${path.technique}`,
        description: `${path.sourcePod} → ${path.targetPod} via ${path.technique}`,
        technique: path.technique,
        mitreId: path.mitreId,
      });
    }

    if (findings.length > 0) {
      newAssets.push({
        id: `ca-${randomUUID().slice(0, 8)}`,
        assetId: "k8s-cluster",
        assetType: "container",
        name: "Kubernetes Cluster",
        accessLevel: k8sResult.rbacEscalations.length > 0 ? "admin" : "user",
        compromisedBy: "container_k8s_breakout",
        accessMethod: "rbac_escalation",
        timestamp: new Date().toISOString(),
      });
    }
  } catch (error) {
    console.error("[BreachOrchestrator] K8s breakout analysis failed:", error);
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

  // Test credential reuse for each harvested credential
  const passwordCreds = context.credentials.filter(c =>
    ["password", "hash", "ticket"].includes(c.type)
  );

  for (const cred of passwordCreds) {
    onProgress(
      chain.id, "lateral_movement", 75,
      `Testing credential reuse for ${cred.username || "unknown"}`
    );

    try {
      const reuseResult = await lateralMovementService.testCredentialReuse({
        credentialType: cred.type,
        username: cred.username || "unknown",
        domain: cred.domain,
        credentialValue: cred.valueHash, // Will be tested in simulated mode
        targetHosts: cred.validatedTargets.length > 0
          ? cred.validatedTargets
          : ["10.0.0.1", "10.0.0.2", "10.0.0.5"], // Default internal targets
        techniques: ["credential_reuse", "pass_the_hash", "ssh_pivot"],
      });

      for (const finding of reuseResult.findings) {
        if (finding.success) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: `Lateral Movement: ${finding.technique} to ${finding.targetHost}`,
            description: `${finding.sourceHost} → ${finding.targetHost} via ${finding.technique}. Access: ${finding.accessLevel}`,
            technique: finding.technique,
            mitreId: finding.mitreAttackId || undefined,
          });

          newAssets.push({
            id: `ca-${randomUUID().slice(0, 8)}`,
            assetId: finding.targetHost,
            assetType: "server",
            name: finding.targetHost,
            accessLevel: finding.accessLevel === "admin" ? "admin" : "user",
            compromisedBy: "lateral_movement",
            accessMethod: finding.technique,
            timestamp: new Date().toISOString(),
          });
        }
      }
    } catch (error) {
      console.error(`[BreachOrchestrator] Credential reuse test failed for ${cred.username}:`, error);
    }
  }

  // Discover pivot points from the first compromised asset
  const entryPoint = context.compromisedAssets[0];
  if (entryPoint) {
    onProgress(chain.id, "lateral_movement", 80, "Discovering pivot points");

    try {
      const pivotResult = await lateralMovementService.discoverPivotPoints({
        startingHost: entryPoint.name,
        scanDepth: 3,
        techniques: ["ssh_pivot", "rdp_pivot", "smb_relay", "credential_reuse"],
      });

      for (const pivot of pivotResult.pivotPoints) {
        findings.push({
          id: `bf-${randomUUID().slice(0, 8)}`,
          severity: pivot.pivotScore && pivot.pivotScore >= 70 ? "high" : "medium",
          title: `Pivot Point: ${pivot.hostname}`,
          description: `Strategic value: ${pivot.strategicValue}. Reachable from: ${(pivot.reachableFrom as string[] || []).join(", ")}`,
          technique: pivot.accessMethod || "network_pivot",
        });

        newAssets.push({
          id: `ca-${randomUUID().slice(0, 8)}`,
          assetId: pivot.hostname,
          assetType: "server",
          name: pivot.hostname,
          accessLevel: pivot.accessLevel === "admin" ? "admin" : "user",
          compromisedBy: "lateral_movement",
          accessMethod: pivot.accessMethod || "pivot",
          timestamp: new Date().toISOString(),
        });
      }

      // Newly discovered credentials from pivot point harvesting
      for (const discoveredCred of pivotResult.credentialsDiscovered) {
        newCredentials.push({
          id: `bc-${randomUUID().slice(0, 8)}`,
          type: discoveredCred.credentialType as BreachCredential["type"],
          username: discoveredCred.username || undefined,
          domain: discoveredCred.domain || undefined,
          valueHash: discoveredCred.credentialHash || hashValue(`lateral-${randomUUID()}`),
          source: "lateral_movement",
          accessLevel: discoveredCred.privilegeLevel === "admin" ? "admin" : "user",
          validatedTargets: (discoveredCred.validatedOn as string[]) || [],
          discoveredAt: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error("[BreachOrchestrator] Pivot point discovery failed:", error);
    }
  }

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

    nodes.push({
      id: phaseNodeId,
      label: PHASE_DEFINITIONS[phase.phaseName].displayName,
      description: PHASE_DEFINITIONS[phase.phaseName].description,
      nodeType: phase.phaseName === "impact_assessment" ? "objective" : "pivot",
      tactic: tacticMap[phase.phaseName] as any || "execution",
      compromiseLevel: compromiseMap[phase.phaseName] || "limited",
      assets: phase.outputContext.compromisedAssets.map(a => a.name),
      discoveredBy: "exploit",
    });

    // Edge from previous phase to this phase
    edges.push({
      id: `breach-edge-${nodeCounter++}`,
      source: previousNodeId,
      target: phaseNodeId,
      technique: `Cross-domain: ${PHASE_DEFINITIONS[phase.phaseName].displayName}`,
      successProbability: phase.findings.length > 0 ? 85 : 40,
      complexity: phase.findings.some(f => f.severity === "critical") ? "low" as const : "medium" as const,
      timeEstimate: (phase.durationMs || 60000) / 60000,
      edgeType: "primary" as const,
      discoveredBy: "exploit" as const,
      description: `${phase.findings.length} findings discovered`,
    });

    // Add individual finding nodes for critical/high findings
    for (const finding of phase.findings.filter(f => f.severity === "critical" || f.severity === "high")) {
      const findingNodeId = `finding-${finding.id}`;
      nodes.push({
        id: findingNodeId,
        label: finding.title,
        description: finding.description,
        nodeType: "pivot",
        tactic: tacticMap[phase.phaseName] as any || "execution",
        compromiseLevel: finding.severity === "critical" ? "admin" : "user",
        discoveredBy: "exploit",
      });

      edges.push({
        id: `finding-edge-${nodeCounter++}`,
        source: phaseNodeId,
        target: findingNodeId,
        technique: finding.technique || finding.title,
        successProbability: 75,
        complexity: "medium" as const,
        timeEstimate: 5,
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
    },
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
