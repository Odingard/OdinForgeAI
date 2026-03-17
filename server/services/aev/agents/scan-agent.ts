/**
 * OdinForge AEV — ScanAgent
 *
 * Subscribes to target.discovered. On receipt, spins up
 * MicroAgentOrchestrator for that target (up to 300 concurrent agents).
 *
 * LLM: validateAttempts() only — reads real response bodies, classifies vuln type.
 * LLM NEVER generates a finding. Evidence required before any publication.
 *
 * Publishes:
 *   vuln.confirmed   — with sealed EvidenceContract (bus rejects if missing)
 *   endpoint.viable  — auth surface confirmed
 */

import type { AgentEvent, AgentEventBus } from "../agent-event-bus";
import type { RealHttpEvidence } from "../../../lib/real-evidence";
import { makeRealHttpEvidence } from "../../../lib/real-evidence";
import {
  runActiveExploitEngine,
  type ExposureType,
  type ExploitAttempt,
} from "../../active-exploit-engine";
import { MicroAgentOrchestrator } from "../micro-agent-orchestrator";

interface DiscoveredTarget {
  url: string;
  openPorts: Array<{ port: number; protocol: string; process?: string }>;
  techStack: string[];
  ipAddress: string;
}

interface CredentialSignal {
  keyName: string;
  source: string;
  privilegeLevel: "admin" | "service" | "standard" | "unknown";
}

export class ScanAgent {
  constructor(
    private bus: AgentEventBus,
    private chainId: string,
  ) {
    bus.subscribe("target.discovered", this.onTargetDiscovered.bind(this));
    bus.subscribe("credential.found", this.onCredentialFound.bind(this));
    bus.subscribe("credential.extracted", this.onCredentialFound.bind(this));
  }

  private async onTargetDiscovered(event: AgentEvent): Promise<void> {
    if (event.chainId !== this.chainId) return;

    const target = event.payload as DiscoveredTarget;
    console.info(`[ScanAgent] Target received: ${target.url} — starting MicroAgentOrchestrator`);

    try {
      await this.runMicroAgentOrchestrator(target, null);
    } catch (err) {
      console.error(`[ScanAgent] Scan failed for ${target.url}:`, err);
    }

    // Signal scan completion so TCG can track when all scans are done
    this.bus.publish({
      type: "scan.finished",
      publishedBy: "scan",
      chainId: this.chainId,
      payload: { target: target.url },
      evidence: null,
    });
  }

  private async onCredentialFound(event: AgentEvent): Promise<void> {
    if (event.chainId !== this.chainId) return;
    const cred = event.payload as CredentialSignal;
    console.info(
      `[ScanAgent] New credential signal '${cred.keyName}' — re-queuing auth endpoints`,
    );
    await this.requeueWithCredential(cred);
  }

  private async runMicroAgentOrchestrator(
    target: DiscoveredTarget,
    credential: CredentialSignal | null,
  ): Promise<void> {
    const results = await this.callMicroAgentOrchestrator(target, credential);

    const withFindings = results.filter((r) => r.finding !== null);
    const withEvidence = withFindings.filter((r) => r.evidence && r.evidence.length > 0);
    console.info(
      `[ScanAgent] ${target.url} — ${results.length} results, ` +
        `${withFindings.length} with findings, ${withEvidence.length} with evidence`,
    );

    for (const result of results) {
      if (!result.finding || !result.evidence || result.evidence.length === 0) {
        continue;
      }

      this.bus.publish({
        type: "vuln.confirmed",
        publishedBy: "scan",
        chainId: this.chainId,
        payload: {
          vulnClass: result.spec.vulnClass,
          endpoint: result.spec.endpoint.url,
          severity: result.finding.severity,
          technique: result.finding.technique,
          findingId: result.finding.id,
        },
        evidence: result.evidence,
      });
    }
  }

  private async requeueWithCredential(credential: CredentialSignal): Promise<void> {
    // Wire to: re-trigger authenticated scan on known viable endpoints
    console.info(`[ScanAgent] TODO: re-queue endpoints with credential from ${credential.source}`);
  }

  // ─── Wire stub — replace throw with MicroAgentOrchestrator.dispatch() ───

  private async callMicroAgentOrchestrator(
    target: DiscoveredTarget,
    credential: CredentialSignal | null,
  ): Promise<
    Array<{
      finding: { id: string; severity: string; technique: string } | null;
      evidence: RealHttpEvidence[];
      spec: { vulnClass: string; endpoint: { url: string } };
    }>
  > {
    // Step 1: Crawl + active exploit to discover endpoints AND validated findings
    const scope: ExposureType[] = ["sqli", "xss", "ssrf", "command_injection", "path_traversal", "auth_bypass", "idor", "jwt_abuse", "api_abuse"];
    const activeResult = await runActiveExploitEngine({
      baseUrl: target.url,
      assetId: target.url,
      scope: { exposureTypes: scope, maxEndpoints: 200 },
      timeout: 10_000,
      maxRequests: 100,
      crawlDepth: 3,
    });

    // Collect results from the active exploit engine's own validated findings
    const engineFindings = (activeResult.validated || [])
      .filter((a: ExploitAttempt) => a.validated && a.confidence >= 0.6)
      .map((a: ExploitAttempt) => {
        const ev = makeRealHttpEvidence({
          requestPayload: a.request.body || `${a.request.method} ${a.request.url}`,
          targetUrl: a.request.url,
          method: a.request.method as "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
          statusCode: a.response.statusCode,
          rawResponseBody: a.response.body.slice(0, 4096),
          durationMs: a.durationMs,
        });
        return {
          finding: {
            id: `aev-${a.payload.name.replace(/\s+/g, "-").toLowerCase()}-${Date.now()}`,
            severity: a.payload.severity,
            technique: `${a.payload.name} → ${a.evidence.description}`,
          },
          evidence: [ev],
          spec: {
            vulnClass: a.payload.type || a.payload.mitreTactic,
            endpoint: { url: a.request.url },
          },
        };
      });

    if (engineFindings.length > 0) {
      console.info(
        `[ScanAgent] Active exploit engine found ${engineFindings.length} validated vulns for ${target.url}`,
      );
    }

    if (!activeResult.crawl?.endpoints || activeResult.crawl.endpoints.length === 0) {
      console.info(`[ScanAgent] No endpoints discovered for ${target.url}`);
      return engineFindings;
    }

    // Step 2: Build micro-agent specs and dispatch for deeper scanning
    const microOrch = new MicroAgentOrchestrator({ maxConcurrent: 50 });
    const specs = microOrch.buildAgentSpecs(
      activeResult.crawl.endpoints,
      scope,
      this.chainId,
      target.url,
    );

    if (specs.length === 0) {
      console.info(`[ScanAgent] No applicable micro-agent specs for ${target.url}`);
      return engineFindings;
    }

    console.info(`[ScanAgent] Dispatching ${specs.length} micro-agents for ${target.url}`);
    const results = await microOrch.dispatch(specs);

    // Map MicroAgentResult[] to the shape this method returns
    const microFindings = results.map((r) => ({
      finding: r.finding
        ? { id: r.finding.id, severity: r.finding.severity, technique: r.finding.technique }
        : null,
      evidence: r.evidence,
      spec: { vulnClass: r.spec.vulnClass as string, endpoint: { url: r.spec.endpoint.url } },
    }));

    return [...engineFindings, ...microFindings];
  }
}
