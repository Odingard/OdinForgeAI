// =============================================================================
// Task 06 — Endpoint Agent Orchestrator
// server/services/endpoint/endpointAgentOrchestrator.ts
//
// Entry point for endpoint scans. Provides:
//   - Agent factory (returns correct agent for OS)
//   - BullMQ job handler (integrates with OdinForge job queue)
//   - HTTP reporter (agent sends results to OdinForge API)
//   - CLI runner (for running agent directly on endpoint)
//
// Deployment modes:
//   A) OdinForge-managed: OdinForge SSH's into endpoint, runs agent via npx/node
//   B) Self-hosted agent: Agent installed on endpoint, calls back to OdinForge
//   C) Ephemeral: Agent runs in CI/CD and posts results
// =============================================================================

import { EndpointAgent, type EndpointScanResult, type OS } from "./EndpointAgent";
import { LinuxAgent }   from "./LinuxAgent";
import { MacOsAgent }   from "./MacOsAgent";
import { WindowsAgent } from "./WindowsAgent";
import { EntityGraphWriter } from "../entityGraph/entityGraphWriter";
import { db } from "../../db";

// —— Agent factory ————————————————————————————————————————————————
export function createEndpointAgent(os: OS): EndpointAgent {
  switch (os) {
    case "linux":   return new LinuxAgent();
    case "macos":   return new MacOsAgent();
    case "windows": return new WindowsAgent();
    default:
      throw new Error(`Unknown OS: ${os}. Supported: linux, macos, windows`);
  }
}

export function detectCurrentOS(): OS {
  const platform = process.platform;
  if (platform === "linux")  return "linux";
  if (platform === "darwin") return "macos";
  if (platform === "win32")  return "windows";
  throw new Error(`Unsupported platform: ${platform}`);
}

// —— BullMQ job handler ———————————————————————————————————————————

export interface EndpointScanJobData {
  organizationId: string;
  evaluationId:   string;
  os:             OS;
  hostname?:      string;   // For labeling in entity graph
}

export async function handleEndpointScanJob(job: {
  data: EndpointScanJobData;
  updateProgress: (p: number) => Promise<void>;
  log: (msg: string) => void;
}): Promise<EndpointScanResult> {
  const { organizationId, evaluationId, os } = job.data;

  job.log(`Starting ${os} endpoint scan for eval ${evaluationId}`);
  await job.updateProgress(5);

  const agent = createEndpointAgent(os);
  await job.updateProgress(10);

  let result: EndpointScanResult;
  try {
    result = await agent.run();
    await job.updateProgress(85);
  } catch (err: unknown) {
    job.log(`Endpoint scan failed: ${(err as Error).message}`);
    throw err;
  }

  // Write findings to entity graph
  const entityWriter = new EntityGraphWriter(db, organizationId);
  for (const finding of result.findings) {
    try {
      await entityWriter.writeFinding({
        organizationId,
        evaluationId,
        source:        `endpoint:${os}:${result.hostname}`,
        checkId:       finding.checkId,
        title:         finding.title,
        description:   finding.description,
        severity:      finding.severity,
        cvssScore:     finding.cvssScore ?? 5.0,
        isKev:         finding.isKev ?? false,
        resource:      finding.resource,
        resourceType:  finding.resourceType,
        evidence:      finding.evidence,
        remediation: {
          title:  finding.remediationTitle,
          steps:  finding.remediationSteps,
          effort: finding.remediationEffort,
        },
        mitreAttackIds: finding.mitreAttackIds ?? [],
      });
    } catch (err) {
      job.log(`Failed to write finding ${finding.checkId}: ${(err as Error).message}`);
    }
  }

  job.log(
    `Endpoint scan complete — os=${os} host=${result.hostname} ` +
    `findings=${result.findings.length} errors=${result.errors.length} ` +
    `checksRun=${result.checksRun}`
  );

  await job.updateProgress(100);
  return result;
}

// —— HTTP reporter (for standalone agent mode) ————————————————————
// Used when the agent runs directly on an endpoint and calls back to OdinForge.

export async function runAndReport(opts: {
  odinforgeUrl:   string;   // e.g. https://app.odinforge.com
  agentToken:     string;   // Pre-issued token for this endpoint
  organizationId: string;
  evaluationId:   string;
}): Promise<void> {
  const os    = detectCurrentOS();
  const agent = createEndpointAgent(os);

  console.log(`[endpoint-agent] Starting ${os} scan...`);
  const result = await agent.run();

  console.log(`[endpoint-agent] Scan complete — ${result.findings.length} findings`);
  console.log(`[endpoint-agent] Reporting to OdinForge...`);

  const reportUrl = `${opts.odinforgeUrl}/api/endpoint-results`;
  const response  = await fetch(reportUrl, {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${opts.agentToken}`,
    },
    body: JSON.stringify({
      organizationId: opts.organizationId,
      evaluationId:   opts.evaluationId,
      result,
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to report results: ${response.status} ${text}`);
  }

  console.log("[endpoint-agent] Results reported successfully");
}

// —— Endpoint results receiver (server-side) ——————————————————————
// POST /api/endpoint-results — receives results from standalone agents.

export interface EndpointResultPayload {
  organizationId: string;
  evaluationId:   string;
  result:         EndpointScanResult;
}

export async function processEndpointResults(
  payload:      EndpointResultPayload,
  entityWriter: EntityGraphWriter
): Promise<void> {
  const { organizationId, evaluationId, result } = payload;

  for (const finding of result.findings) {
    await entityWriter.writeFinding({
      organizationId,
      evaluationId,
      source:        `endpoint:${result.os}:${result.hostname}`,
      checkId:       finding.checkId,
      title:         finding.title,
      description:   finding.description,
      severity:      finding.severity,
      cvssScore:     finding.cvssScore ?? 5.0,
      isKev:         finding.isKev ?? false,
      resource:      finding.resource,
      resourceType:  finding.resourceType,
      evidence:      finding.evidence,
      remediation: {
        title:  finding.remediationTitle,
        steps:  finding.remediationSteps,
        effort: finding.remediationEffort,
      },
      mitreAttackIds: finding.mitreAttackIds ?? [],
    });
  }

  console.log(
    `[endpoint-results] Processed ${result.findings.length} findings ` +
    `from ${result.os}:${result.hostname} for eval ${evaluationId}`
  );
}

// —— CLI entry point ——————————————————————————————————————————————
// Used for: node dist/endpointAgent.js
// Deploy this as a standalone script on endpoints.
// ESM-compatible check: use import.meta.url
const isMainModule = typeof import.meta !== "undefined" &&
  import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
  const {
    ODINFORGE_URL,
    AGENT_TOKEN,
    ORGANIZATION_ID,
    EVALUATION_ID,
  } = process.env;

  if (!ODINFORGE_URL || !AGENT_TOKEN || !ORGANIZATION_ID || !EVALUATION_ID) {
    console.error("Missing required environment variables: ODINFORGE_URL, AGENT_TOKEN, ORGANIZATION_ID, EVALUATION_ID");
    process.exit(1);
  }

  runAndReport({
    odinforgeUrl:   ODINFORGE_URL,
    agentToken:     AGENT_TOKEN,
    organizationId: ORGANIZATION_ID,
    evaluationId:   EVALUATION_ID,
  }).catch(err => {
    console.error("[endpoint-agent] Fatal error:", err);
    process.exit(1);
  });
}
