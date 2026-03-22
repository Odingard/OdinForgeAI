/**
 * Runtime Context Broker — Capability 2
 *
 * Pulls Go agent telemetry (ports, services, config files) from storage
 * and formats it as structured prompt blocks for LLM phases.
 *
 * LLM Boundary: This module is ZERO-LLM. All signal derivation is deterministic.
 * The formatted output is consumed by LLM prompts in Phase 3 (Cloud IAM) and Phase 5 (Lateral Movement).
 */

import { storage } from "../../storage";
import type { AgentTelemetry, EndpointAgent } from "@shared/schema";

// ── Types ──────────────────────────────────────────────────────────────

export interface RuntimeSignal {
  type:
    | "database_service"
    | "web_server"
    | "container_runtime"
    | "kubernetes"
    | "message_queue"
    | "cache_service"
    | "ssh_service"
    | "monitoring"
    | "env_file"
    | "cloud_credential_file"
    | "security_finding";
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
}

export interface HostRuntimeContext {
  assetId: string;
  agentId: string;
  hostname: string;
  primaryIp: string | null;
  platform: string | null;
  containerRuntime: string | null;
  openPorts: Array<{ port: number; protocol: string; service?: string }>;
  runningServices: Array<{ name: string; version?: string; port?: number }>;
  signals: RuntimeSignal[];
  collectedAt: string | null;
}

// ── Well-known port/service → signal mappings (deterministic) ──────────

const DB_PORTS = new Set([3306, 5432, 1433, 27017, 6379, 9042, 5984, 26257]);
const DB_SERVICES = new Set([
  "mysql", "postgres", "postgresql", "mssql", "mongodb", "redis",
  "cassandra", "couchdb", "cockroachdb", "mariadb",
]);

const WEB_PORTS = new Set([80, 443, 8080, 8443, 3000, 5000, 8000, 9000]);
const K8S_SERVICES = new Set([
  "kubelet", "kube-proxy", "kube-apiserver", "kube-scheduler",
  "kube-controller-manager", "etcd",
]);

const MQ_SERVICES = new Set(["rabbitmq", "kafka", "nats", "mosquitto", "activemq"]);
const CACHE_SERVICES = new Set(["redis", "memcached", "hazelcast"]);
const CONTAINER_SERVICES = new Set(["docker", "dockerd", "containerd", "podman", "cri-o"]);
const MONITORING_SERVICES = new Set(["prometheus", "grafana", "telegraf", "datadog-agent", "node_exporter"]);

// ── RuntimeContextBroker ───────────────────────────────────────────────

export class RuntimeContextBroker {
  /**
   * Fetch runtime context for a given asset.
   * Returns null if no agent is associated or no telemetry exists.
   */
  async getContextForAsset(assetId: string): Promise<HostRuntimeContext | null> {
    const agent = await storage.getAgentByAssetId(assetId);
    if (!agent) return null;

    const telemetry = await storage.getLatestAgentTelemetry(agent.id);
    if (!telemetry) return null;

    return this.buildContext(assetId, agent, telemetry);
  }

  /**
   * Fetch runtime contexts for multiple assets in parallel.
   */
  async getContextsForAssets(assetIds: string[]): Promise<Map<string, HostRuntimeContext>> {
    const results = new Map<string, HostRuntimeContext>();
    const promises = assetIds.map(async (id) => {
      const ctx = await this.getContextForAsset(id);
      if (ctx) results.set(id, ctx);
    });
    await Promise.all(promises);
    return results;
  }

  /**
   * Derive deterministic signals from telemetry data. ZERO LLM.
   */
  deriveSignals(telemetry: AgentTelemetry): RuntimeSignal[] {
    const signals: RuntimeSignal[] = [];

    // Port-based signals
    if (telemetry.openPorts) {
      for (const port of telemetry.openPorts) {
        if (DB_PORTS.has(port.port)) {
          signals.push({
            type: "database_service",
            severity: "high",
            description: `Database port ${port.port} (${port.service || "unknown"}) is open — potential data exfiltration target`,
          });
        }
        if (port.port === 22) {
          signals.push({
            type: "ssh_service",
            severity: "medium",
            description: `SSH (port 22) is exposed — lateral movement vector`,
          });
        }
        if (WEB_PORTS.has(port.port)) {
          signals.push({
            type: "web_server",
            severity: "info",
            description: `Web server on port ${port.port} (${port.service || "http"})`,
          });
        }
      }
    }

    // Service-based signals
    if (telemetry.services) {
      for (const svc of telemetry.services) {
        const name = svc.name.toLowerCase();
        if (DB_SERVICES.has(name)) {
          signals.push({
            type: "database_service",
            severity: "high",
            description: `${svc.name}${svc.version ? ` v${svc.version}` : ""} running — data store target`,
          });
        }
        if (K8S_SERVICES.has(name)) {
          signals.push({
            type: "kubernetes",
            severity: "critical",
            description: `Kubernetes component: ${svc.name} — cluster-level access possible`,
          });
        }
        if (MQ_SERVICES.has(name)) {
          signals.push({
            type: "message_queue",
            severity: "medium",
            description: `Message queue: ${svc.name} — potential credential/data interception`,
          });
        }
        if (CACHE_SERVICES.has(name) && !DB_SERVICES.has(name)) {
          signals.push({
            type: "cache_service",
            severity: "medium",
            description: `Cache service: ${svc.name} — often stores session data`,
          });
        }
        if (CONTAINER_SERVICES.has(name)) {
          signals.push({
            type: "container_runtime",
            severity: "high",
            description: `Container runtime: ${svc.name} — container escape / privilege escalation vector`,
          });
        }
        if (MONITORING_SERVICES.has(name)) {
          signals.push({
            type: "monitoring",
            severity: "info",
            description: `Monitoring: ${svc.name} — may expose metrics endpoints`,
          });
        }
      }
    }

    // Security findings from agent
    if (telemetry.securityFindings) {
      for (const finding of telemetry.securityFindings) {
        signals.push({
          type: "security_finding",
          severity: (finding.severity as RuntimeSignal["severity"]) || "medium",
          description: `[Agent Finding] ${finding.title}: ${finding.description}`,
        });
      }
    }

    // Config data signals (populated by Go config_files.go collector)
    if (telemetry.configData) {
      const cfg = telemetry.configData;
      if (cfg.envFiles && Array.isArray(cfg.envFiles)) {
        for (const envFile of cfg.envFiles) {
          signals.push({
            type: "env_file",
            severity: "high",
            description: `Environment file detected: ${envFile.path} — keys: ${(envFile.keys || []).join(", ")}`,
          });
        }
      }
      if (cfg.cloudCredentialFiles && Array.isArray(cfg.cloudCredentialFiles)) {
        for (const credFile of cfg.cloudCredentialFiles) {
          signals.push({
            type: "cloud_credential_file",
            severity: "critical",
            description: `Cloud credential file: ${credFile.path} — type: ${credFile.type || "unknown"}`,
          });
        }
      }
    }

    return signals;
  }

  /**
   * Format runtime context as a structured text block for LLM prompts.
   * Includes the boundary instruction that constrains reasoning.
   */
  formatForPrompt(ctx: HostRuntimeContext): string {
    const lines: string[] = [
      "=== HOST RUNTIME CONTEXT (from deployed agent) ===",
      `Host: ${ctx.hostname} (${ctx.primaryIp || "unknown IP"})`,
      `Platform: ${ctx.platform || "unknown"}`,
      `Agent ID: ${ctx.agentId}`,
      `Data collected: ${ctx.collectedAt || "unknown"}`,
    ];

    if (ctx.containerRuntime) {
      lines.push(`Container runtime: ${ctx.containerRuntime}`);
    }

    if (ctx.openPorts.length > 0) {
      lines.push("", "Open Ports:");
      for (const p of ctx.openPorts) {
        lines.push(`  - ${p.port}/${p.protocol}${p.service ? ` (${p.service})` : ""}`);
      }
    }

    if (ctx.runningServices.length > 0) {
      lines.push("", "Running Services:");
      for (const s of ctx.runningServices) {
        lines.push(`  - ${s.name}${s.version ? ` v${s.version}` : ""}${s.port ? ` :${s.port}` : ""}`);
      }
    }

    if (ctx.signals.length > 0) {
      lines.push("", "Derived Signals:");
      for (const sig of ctx.signals) {
        lines.push(`  [${sig.severity.toUpperCase()}] ${sig.type}: ${sig.description}`);
      }
    }

    lines.push(
      "",
      "IMPORTANT: Reason ONLY from the data above. Do not extrapolate or assume services/ports that are not listed.",
      "=== END HOST RUNTIME CONTEXT ==="
    );

    return lines.join("\n");
  }

  // ── Private helpers ─────────────────────────────────────────────────

  private buildContext(
    assetId: string,
    agent: EndpointAgent,
    telemetry: AgentTelemetry,
  ): HostRuntimeContext {
    const signals = this.deriveSignals(telemetry);

    // Detect container runtime from services
    let containerRuntime: string | null = null;
    if (telemetry.services) {
      for (const svc of telemetry.services) {
        if (CONTAINER_SERVICES.has(svc.name.toLowerCase())) {
          containerRuntime = svc.name;
          break;
        }
      }
    }

    // Primary IP from agent record
    const primaryIp = agent.ipAddresses && agent.ipAddresses.length > 0
      ? agent.ipAddresses[0]
      : null;

    return {
      assetId,
      agentId: agent.id,
      hostname: agent.hostname || telemetry.systemInfo?.hostname || "unknown",
      primaryIp,
      platform: agent.platform || telemetry.systemInfo?.platform || null,
      containerRuntime,
      openPorts: (telemetry.openPorts || []).map((p) => ({
        port: p.port,
        protocol: p.protocol,
        service: p.service,
      })),
      runningServices: (telemetry.services || []).map((s) => ({
        name: s.name,
        version: s.version,
        port: s.port,
      })),
      signals,
      collectedAt: telemetry.collectedAt
        ? new Date(telemetry.collectedAt).toISOString()
        : null,
    };
  }
}
