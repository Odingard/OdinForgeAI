// ═══════════════════════════════════════════════════════════════════════════════
//  Recon Scan Handler
//
//  Full Phase 1 pipeline: infrastructure recon → endpoint discovery →
//  deep checks → finding extraction → agent verification → AEV mapping.
//  Streams progress via WebSocket, stores results into AEV evaluation.
// ═══════════════════════════════════════════════════════════════════════════════

import { Job } from "bullmq";
import { randomUUID } from "crypto";
import { storage } from "../../../storage";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  analyzeDns, analyzeSubdomains, analyzePorts, analyzeSslTls,
  analyzeHeaders, analyzeTech, analyzeWaf, analyzeApiEndpoints,
  checkEndpoint,
} from "../../recon/index";
import type { FullReconResult } from "../../recon/index";
import type { SubdomainEnumResult, PortScanResult } from "../../recon/types";
import { AgentOrchestrator } from "../../recon/agents/orchestrator";
import { extractAllFindings } from "../../recon/agents/finding-router";
import {
  mapReconToAttackGraph,
  mapAgentEvidenceToArtifacts,
  mapReconToAgentMemory,
  buildIncrementalGraph,
} from "../../recon/aev-mapper";
import type { ReconScanJobData, JobResult, JobProgress } from "../job-types";
import type { AttackGraph } from "@shared/schema";

// ─── WebSocket Progress ─────────────────────────────────────────────────────

function emitScanProgress(
  tenantId: string,
  organizationId: string,
  scanId: string,
  evaluationId: string | undefined,
  event: {
    phase: string;
    progress: number;
    message: string;
    graph?: AttackGraph;
    findingsCount?: number;
    verifiedCount?: number;
    exploitableCount?: number;
  },
): void {
  console.log(`[ReconScan] ${scanId}: ${event.phase} (${event.progress}%) — ${event.message}`);

  try {
    const { broadcastToChannel } = require("../../ws-bridge");
    const channel = `recon_scan:${tenantId}:${organizationId}:${scanId}`;

    broadcastToChannel(channel, {
      type: "recon_scan_progress",
      scanId,
      evaluationId,
      ...event,
    });

    // Also emit standard aev_progress if linked to an evaluation
    if (evaluationId) {
      const evalChannel = `evaluation:${tenantId}:${organizationId}:${evaluationId}`;
      broadcastToChannel(evalChannel, {
        type: "aev_progress",
        evaluationId,
        agent: "Recon Engine",
        stage: event.phase,
        progress: event.progress,
        message: event.message,
      });
    }

    // Stream the graph update for live visualization
    if (event.graph && event.graph.nodes.length > 0) {
      broadcastToChannel(channel, {
        type: "breach_chain_graph_update",
        chainId: scanId,
        phase: event.phase,
        graph: event.graph,
        phaseIndex: event.progress,
        totalPhases: 100,
      });
    }
  } catch {
    // ws-bridge may not be available in all contexts
  }
}

// ─── Handler ────────────────────────────────────────────────────────────────

export async function handleReconScanJob(
  job: Job<ReconScanJobData>,
): Promise<JobResult> {
  const startTime = Date.now();
  const { scanId, evaluationId, target, options, tenantId, organizationId } = job.data;

  console.log(`[ReconScan] Starting full recon pipeline for: ${target}`);

  // Governance check
  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "recon_scan",
    target,
  );

  if (!governanceCheck.canStart) {
    console.log(`[ReconScan] Blocked by governance: ${governanceCheck.reason}`);
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "error",
      progress: 0,
      message: `Blocked: ${governanceCheck.reason}`,
    });
    return { success: false, error: governanceCheck.reason };
  }

  await governanceEnforcement.logOperationStarted(organizationId, "recon_scan", target);

  // Update evaluation status if linked
  if (evaluationId) {
    try {
      await storage.updateEvaluationStatus(evaluationId, "in_progress");
    } catch { /* evaluation may not exist yet */ }
  }

  const {
    skipSubdomains = false,
    skipPorts = false,
    endpointCheckConcurrency = 5,
    maxEndpointsToCheck = 50,
    agentConcurrency = 3,
    agentMaxFindings = 200,
    priorityFilter,
  } = options ?? {};

  let currentGraph: AttackGraph | null = null;

  try {
    // ── Phase 1: Infrastructure Recon (parallel) ────────────────────────
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "infrastructure",
      progress: 5,
      message: "Running DNS, ports, SSL, headers, tech, WAF scans...",
    });

    const host = target.replace(/^https?:\/\//, "").split("/")[0];

    // Detect protocol
    const protocol = await detectProtocol(host);
    const baseUrl = `${protocol}://${host}`;

    const [dns, subdomains, ports, ssl, headers, tech, waf] = await Promise.all([
      analyzeDns(host),
      skipSubdomains
        ? Promise.resolve({ domain: host, subdomains: [], totalFound: 0, aliveCount: 0 } as SubdomainEnumResult)
        : analyzeSubdomains(host),
      skipPorts
        ? Promise.resolve({ host, openPorts: [], filteredPorts: [], scanDuration: 0 } as PortScanResult)
        : analyzePorts(host),
      analyzeSslTls(host),
      analyzeHeaders(baseUrl),
      analyzeTech(baseUrl),
      analyzeWaf(baseUrl),
    ]);

    console.log(`[ReconScan] Phase 1 done: ${subdomains.totalFound} subdomains, ${ports.openPorts.length} open ports`);

    await job.updateProgress?.({ percent: 25, stage: "infrastructure", message: "Infrastructure scan complete" } as JobProgress);

    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "infrastructure",
      progress: 25,
      message: `Found ${ports.openPorts.length} open ports, ${subdomains.aliveCount} live subdomains`,
    });

    // ── Phase 2: API Endpoint Discovery ─────────────────────────────────
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "endpoint_discovery",
      progress: 30,
      message: "Discovering API endpoints...",
    });

    const apiDiscovery = await analyzeApiEndpoints(baseUrl, { methods: true });

    console.log(`[ReconScan] Phase 2 done: ${apiDiscovery.totalDiscovered} endpoints`);

    await job.updateProgress?.({ percent: 40, stage: "endpoint_discovery", message: `${apiDiscovery.totalDiscovered} endpoints found` } as JobProgress);

    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "endpoint_discovery",
      progress: 40,
      message: `Discovered ${apiDiscovery.totalDiscovered} endpoints`,
    });

    // ── Phase 3: Endpoint Deep-Check (batched) ─────────────────────────
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "endpoint_analysis",
      progress: 42,
      message: "Running deep endpoint checks...",
    });

    const endpointsToCheck = apiDiscovery.endpoints.slice(0, maxEndpointsToCheck);
    const endpointChecks: Awaited<ReturnType<typeof checkEndpoint>>[] = [];

    for (let i = 0; i < endpointsToCheck.length; i += endpointCheckConcurrency) {
      const batch = endpointsToCheck.slice(i, i + endpointCheckConcurrency);
      const batchResults = await Promise.all(
        batch.map(ep => checkEndpoint(ep.url, ep.method)),
      );
      endpointChecks.push(...batchResults);

      const pct = 42 + Math.round((i / endpointsToCheck.length) * 15);
      emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
        phase: "endpoint_analysis",
        progress: pct,
        message: `Checked ${endpointChecks.length}/${endpointsToCheck.length} endpoints`,
      });
    }

    console.log(`[ReconScan] Phase 3 done: ${endpointChecks.length} endpoints checked`);

    // Assemble the FullReconResult
    const reconResult: FullReconResult = {
      target: { host },
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      dns, subdomains, ports, ssl, headers, tech, waf,
      apiDiscovery,
      endpointChecks,
      summary: buildSummary(endpointChecks, ssl, headers),
    };

    // ── Phase 4: Finding Extraction ─────────────────────────────────────
    const findings = extractAllFindings(reconResult);
    console.log(`[ReconScan] Phase 4: Extracted ${findings.length} findings`);

    // Build initial graph from raw findings (before agent verification)
    currentGraph = buildIncrementalGraph(null, findings, []);

    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "finding_extraction",
      progress: 60,
      message: `Extracted ${findings.length} findings`,
      graph: currentGraph,
      findingsCount: findings.length,
    });

    await job.updateProgress?.({ percent: 60, stage: "finding_extraction", message: `${findings.length} findings extracted` } as JobProgress);

    // ── Phase 5: Agent Verification (batched) ───────────────────────────
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "agent_verification",
      progress: 62,
      message: "Dispatching verification agents...",
      graph: currentGraph,
      findingsCount: findings.length,
    });

    const orchestrator = new AgentOrchestrator();

    // Bridge agent events to WebSocket
    orchestrator.onEvent((event) => {
      if (event.type === "task:complete") {
        const result = event.data?.result;
        emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
          phase: "agent_verification",
          progress: 65,
          message: `${event.agentName}: ${result?.verified ? "verified" : "checked"} ${result?.exploitable ? "(exploitable)" : ""}`,
          graph: currentGraph ?? undefined,
        });
      }
    });

    const agentReport = await orchestrator.runFromRecon(reconResult, {
      concurrency: agentConcurrency,
      maxFindings: agentMaxFindings,
      priorityFilter,
    });

    console.log(`[ReconScan] Phase 5 done: ${agentReport.summary.verified} verified, ${agentReport.summary.exploitable} exploitable`);

    await job.updateProgress?.({ percent: 90, stage: "agent_verification", message: `${agentReport.summary.exploitable} exploitable findings` } as JobProgress);

    // ── Phase 6: AEV Mapping + Storage ──────────────────────────────────
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "aev_mapping",
      progress: 92,
      message: "Building attack graph and scoring...",
    });

    const attackGraph = mapReconToAttackGraph(reconResult, agentReport);
    const evidenceArtifacts = mapAgentEvidenceToArtifacts(agentReport.tasks);
    const reconFindings = mapReconToAgentMemory(reconResult);

    // Store result if linked to an evaluation
    if (evaluationId) {
      try {
        await storage.createResult({
          id: `res-${randomUUID().slice(0, 8)}`,
          evaluationId,
          exploitable: agentReport.summary.exploitable > 0,
          confidence: Math.round(
            (agentReport.summary.verified / Math.max(1, agentReport.totalFindings)) * 100,
          ),
          score: Math.min(100, agentReport.summary.criticalFindings * 25 + agentReport.summary.highFindings * 15),
          attackPath: attackGraph.criticalPath.map((nodeId, i) => ({
            id: i + 1,
            title: nodeId,
            description: `Attack path step ${i + 1}: ${nodeId}`,
            severity: "high" as const,
            technique: "recon-verified",
            discoveredBy: "recon" as const,
          })),
          attackGraph,
          evidenceArtifacts,
          impact: `${agentReport.summary.criticalFindings} critical, ${agentReport.summary.highFindings} high findings verified by recon agents`,
          recommendations: agentReport.topExploitable.slice(0, 10).map((e, i) => ({
            id: `rec-${i}`,
            priority: (e.severity === "critical" ? "critical" : e.severity === "high" ? "high" : "medium") as "critical" | "high" | "medium" | "low",
            title: `Remediate ${e.finding} on ${e.target}`,
            description: `${e.agent} confirmed this finding${e.cwe ? ` (${e.cwe})` : ""}${e.cvss ? ` with CVSS ${e.cvss}` : ""}`,
            type: "remediation" as const,
          })),
          duration: Date.now() - startTime,
        });

        await storage.updateEvaluationStatus(evaluationId, "completed");
      } catch (err) {
        console.error(`[ReconScan] Failed to store results:`, err);
      }
    }

    // Final progress with complete graph
    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "complete",
      progress: 100,
      message: `Scan complete: ${agentReport.summary.exploitable} exploitable, ${attackGraph.nodes.length} attack graph nodes`,
      graph: attackGraph,
      findingsCount: findings.length,
      verifiedCount: agentReport.summary.verified,
      exploitableCount: agentReport.summary.exploitable,
    });

    await job.updateProgress?.({ percent: 100, stage: "complete", message: "Recon scan complete" } as JobProgress);

    console.log(`[ReconScan] Pipeline complete for ${target} in ${((Date.now() - startTime) / 1000).toFixed(1)}s`);

    return {
      success: true,
      data: {
        scanId,
        evaluationId,
        target,
        findings: findings.length,
        verified: agentReport.summary.verified,
        exploitable: agentReport.summary.exploitable,
        criticalFindings: agentReport.summary.criticalFindings,
        highFindings: agentReport.summary.highFindings,
        attackGraphNodes: attackGraph.nodes.length,
        attackGraphEdges: attackGraph.edges.length,
        evidenceCount: evidenceArtifacts.length,
      },
      duration: Date.now() - startTime,
      metrics: {
        findings: findings.length,
        verified: agentReport.summary.verified,
        exploitable: agentReport.summary.exploitable,
        openPorts: ports.openPorts.length,
        endpoints: apiDiscovery.totalDiscovered,
      },
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`[ReconScan] Pipeline failed for ${target}:`, errorMessage);

    if (evaluationId) {
      try { await storage.updateEvaluationStatus(evaluationId, "failed"); } catch {}
    }

    emitScanProgress(tenantId, organizationId, scanId, evaluationId, {
      phase: "error",
      progress: 0,
      message: `Scan failed: ${errorMessage}`,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function detectProtocol(host: string): Promise<"https" | "http"> {
  const https = await import("https");
  const http = await import("http");

  return new Promise((resolve) => {
    const req = https.get(`https://${host}`, { timeout: 5000, rejectUnauthorized: false }, (res) => {
      res.resume();
      res.on("end", () => resolve("https"));
    });
    req.on("error", () => {
      const httpReq = http.get(`http://${host}`, { timeout: 5000 }, (res) => {
        res.resume();
        res.on("end", () => resolve("http"));
      });
      httpReq.on("error", () => resolve("http"));
      httpReq.on("timeout", () => { httpReq.destroy(); resolve("http"); });
    });
    req.on("timeout", () => { req.destroy(); resolve("http"); });
  });
}

function buildSummary(
  endpointChecks: Awaited<ReturnType<typeof checkEndpoint>>[],
  ssl: { issues: { severity: string }[] },
  headers: { issues: { status: string; severity: string }[] },
) {
  let totalIssues = 0, criticalIssues = 0, highIssues = 0, mediumIssues = 0, lowIssues = 0;
  const topIssues: { endpoint: string; title: string; severity: string }[] = [];

  for (const check of endpointChecks) {
    const allIssues = [...check.cors.issues, ...check.auth.issues, ...check.linting.issues, ...check.staleness.issues];
    totalIssues += allIssues.length;
    for (const issue of allIssues) {
      if (issue.severity === "critical") criticalIssues++;
      else if (issue.severity === "high") highIssues++;
      else if (issue.severity === "medium") mediumIssues++;
      else if (issue.severity === "low") lowIssues++;
      if (issue.severity === "critical" || issue.severity === "high") {
        topIssues.push({ endpoint: check.endpoint, title: issue.title, severity: issue.severity });
      }
    }
  }

  totalIssues += ssl.issues.length + headers.issues.filter(i => i.status !== "present").length;
  for (const issue of ssl.issues) {
    if (issue.severity === "critical") criticalIssues++;
    else if (issue.severity === "high") highIssues++;
    else if (issue.severity === "medium") mediumIssues++;
    else if (issue.severity === "low") lowIssues++;
  }

  return {
    totalEndpoints: endpointChecks.length,
    totalIssues,
    criticalIssues,
    highIssues,
    mediumIssues,
    lowIssues,
    topIssues: topIssues.slice(0, 20),
  };
}
