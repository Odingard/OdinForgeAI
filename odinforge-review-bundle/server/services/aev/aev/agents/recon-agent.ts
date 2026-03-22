/**
 * OdinForge AEV — ReconAgent
 *
 * Runs from chain start with no dependencies.
 * LLM: ZERO calls. Pure discovery — real HTTP probing,
 * Go agent telemetry, and DNS enumeration only.
 *
 * Publishes:
 *   target.discovered   — new exploitable target found
 *   surface.expanded    — new subdomain/attack surface (triggers dynamic TCG spawning)
 *   credential.found    — secret extracted from config file (key name only, no value)
 */

import type { AgentEventBus } from "../agent-event-bus";
import type { TCGNode } from "../task-coordination-graph";
import { analyzeSubdomains } from "../../recon/subdomain-enum";
import { analyzePorts } from "../../recon/port-scan";
import { analyzeTech } from "../../recon/tech-detection";
import { extractSecretsFromUrl } from "../../recon/secret-extractor";
import { RuntimeContextBroker } from "../runtime-context-broker";

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

export class ReconAgent {
  constructor(
    private bus: AgentEventBus,
    private chainId: string,
    private targetUrl: string,
  ) {}

  async runSubdomainDiscovery(node: TCGNode): Promise<void> {
    console.info(`[ReconAgent] Starting subdomain discovery for ${this.targetUrl}`);

    try {
      const subdomains = await this.discoverSubdomains(this.targetUrl);

      for (const subdomain of subdomains) {
        this.bus.publish({
          type: "target.discovered",
          publishedBy: "recon",
          chainId: this.chainId,
          payload: {
            url: subdomain.url,
            openPorts: subdomain.openPorts,
            techStack: subdomain.techStack,
            ipAddress: subdomain.ipAddress,
          } as DiscoveredTarget,
          evidence: null,
        });

        if (subdomain.url !== this.targetUrl) {
          this.bus.publish({
            type: "surface.expanded",
            publishedBy: "recon",
            chainId: this.chainId,
            payload: { newTarget: subdomain.url, discoveredVia: "subdomain_enum" },
            evidence: null,
          });
        }
      }
    } catch (err) {
      console.error("[ReconAgent] Subdomain discovery failed:", err);
    }
  }

  async runSecretExtraction(node: TCGNode): Promise<void> {
    console.info(`[ReconAgent] Running secret extraction via Go agent telemetry`);

    try {
      const configSignals = await this.getGoAgentConfigSignals(this.targetUrl);

      for (const signal of configSignals) {
        this.bus.publish({
          type: "credential.found",
          publishedBy: "recon",
          chainId: this.chainId,
          payload: {
            keyName: signal.keyName,
            source: signal.filePath,
            privilegeLevel: signal.privilegeLevel,
          } as CredentialSignal,
          evidence: null,
        });
      }
    } catch (err) {
      console.error("[ReconAgent] Secret extraction failed:", err);
    }
  }

  // ─── Wire stubs — replace throw with existing pipeline calls ────────────

  private async discoverSubdomains(targetUrl: string): Promise<DiscoveredTarget[]> {
    let hostname: string;
    try {
      hostname = new URL(targetUrl).hostname;
    } catch {
      hostname = targetUrl;
    }

    const results: DiscoveredTarget[] = [];

    // Subdomain enumeration
    const subResult = await analyzeSubdomains(hostname, {
      usePassive: true,
      useBruteForce: false, // fast mode for mesh — brute force runs in sequential pipeline
      usePermutation: false,
    });

    const aliveSubdomains = subResult.subdomains.filter((s) => s.isAlive);

    for (const sub of aliveSubdomains) {
      // Port scan each alive subdomain
      let openPorts: DiscoveredTarget["openPorts"] = [];
      try {
        const portResult = await analyzePorts(sub.subdomain, { timeout: 2000 });
        openPorts = portResult.openPorts.map((p) => ({
          port: p.port,
          protocol: p.service || "tcp",
          process: p.banner ?? undefined,
        }));
      } catch {
        // Port scan failure is non-fatal
      }

      // Tech detection
      let techStack: string[] = [];
      try {
        const techResult = await analyzeTech(`https://${sub.subdomain}`);
        techStack = techResult.technologies?.map((t: { name: string }) => t.name) ?? [];
      } catch {
        // Tech detection failure is non-fatal
      }

      results.push({
        url: `https://${sub.subdomain}`,
        openPorts,
        techStack,
        ipAddress: sub.ip || "",
      });
    }

    // Always include the primary target
    if (!results.some((r) => r.url === targetUrl)) {
      results.unshift({
        url: targetUrl,
        openPorts: [],
        techStack: [],
        ipAddress: "",
      });
    }

    return results;
  }

  private async getGoAgentConfigSignals(
    targetUrl: string,
  ): Promise<
    Array<{
      keyName: string;
      filePath: string;
      privilegeLevel: CredentialSignal["privilegeLevel"];
    }>
  > {
    const signals: Array<{
      keyName: string;
      filePath: string;
      privilegeLevel: CredentialSignal["privilegeLevel"];
    }> = [];

    // Try RuntimeContextBroker for Go agent telemetry
    try {
      let hostname: string;
      try {
        hostname = new URL(targetUrl).hostname;
      } catch {
        hostname = targetUrl;
      }
      const broker = new RuntimeContextBroker();
      const ctx = await broker.getContextForAsset(hostname);
      if (ctx) {
        for (const signal of ctx.signals) {
          if (signal.type === "cloud_credential_file" || signal.type === "env_file") {
            signals.push({
              keyName: signal.description,
              filePath: signal.type,
              privilegeLevel: signal.severity === "critical" ? "admin" : "service",
            });
          }
        }
      }
    } catch {
      // No Go agent available — fall through to secret extraction
    }

    // Also run web-based secret extraction
    try {
      const secrets = await extractSecretsFromUrl(targetUrl);
      for (const secret of secrets) {
        signals.push({
          keyName: secret.type,
          filePath: secret.source,
          privilegeLevel: secret.type.includes("admin") ? "admin" : "unknown",
        });
      }
    } catch {
      // Secret extraction failure is non-fatal
    }

    return signals;
  }
}
