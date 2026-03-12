import { describe, it, expect } from "vitest";
import { RuntimeContextBroker, RuntimeSignal } from "./runtime-context-broker";
import type { AgentTelemetry } from "@shared/schema";

function makeTelemetry(overrides: Partial<AgentTelemetry> = {}): AgentTelemetry {
  return {
    id: "tel-001",
    agentId: "agent-001",
    organizationId: "default",
    systemInfo: {
      hostname: "web-prod-01",
      platform: "linux",
      platformVersion: "Ubuntu 22.04",
      kernel: "5.15.0",
      architecture: "x86_64",
      uptime: 86400,
      bootTime: "2026-03-01T00:00:00Z",
    },
    resourceMetrics: null,
    services: null,
    openPorts: null,
    networkConnections: null,
    installedSoftware: null,
    configData: null,
    securityFindings: null,
    rawData: null,
    collectedAt: new Date("2026-03-12T10:00:00Z"),
    receivedAt: new Date("2026-03-12T10:00:05Z"),
    ...overrides,
  } as AgentTelemetry;
}

describe("RuntimeContextBroker", () => {
  const broker = new RuntimeContextBroker();

  describe("deriveSignals", () => {
    it("detects database ports", () => {
      const telemetry = makeTelemetry({
        openPorts: [
          { port: 5432, protocol: "tcp", service: "postgresql", state: "LISTEN", localAddress: "0.0.0.0" },
          { port: 3306, protocol: "tcp", service: "mysql", state: "LISTEN", localAddress: "0.0.0.0" },
        ],
      });
      const signals = broker.deriveSignals(telemetry);
      const dbSignals = signals.filter((s) => s.type === "database_service");
      expect(dbSignals.length).toBe(2);
      expect(dbSignals[0].severity).toBe("high");
      expect(dbSignals[0].description).toContain("5432");
    });

    it("detects SSH service", () => {
      const telemetry = makeTelemetry({
        openPorts: [
          { port: 22, protocol: "tcp", service: "ssh", state: "LISTEN", localAddress: "0.0.0.0" },
        ],
      });
      const signals = broker.deriveSignals(telemetry);
      const sshSignals = signals.filter((s) => s.type === "ssh_service");
      expect(sshSignals.length).toBe(1);
      expect(sshSignals[0].description).toContain("lateral movement");
    });

    it("detects Kubernetes components as critical", () => {
      const telemetry = makeTelemetry({
        services: [
          { name: "kubelet", status: "running", port: 10250 },
          { name: "kube-apiserver", status: "running", port: 6443 },
        ],
      });
      const signals = broker.deriveSignals(telemetry);
      const k8sSignals = signals.filter((s) => s.type === "kubernetes");
      expect(k8sSignals.length).toBe(2);
      expect(k8sSignals[0].severity).toBe("critical");
    });

    it("detects container runtime", () => {
      const telemetry = makeTelemetry({
        services: [
          { name: "dockerd", status: "running" },
        ],
      });
      const signals = broker.deriveSignals(telemetry);
      const containerSignals = signals.filter((s) => s.type === "container_runtime");
      expect(containerSignals.length).toBe(1);
      expect(containerSignals[0].severity).toBe("high");
    });

    it("includes agent security findings as signals", () => {
      const telemetry = makeTelemetry({
        securityFindings: [
          {
            type: "outdated_software",
            severity: "high",
            title: "OpenSSL outdated",
            description: "OpenSSL 1.0.2 is end-of-life",
            affectedComponent: "openssl",
          },
        ],
      });
      const signals = broker.deriveSignals(telemetry);
      const findingSignals = signals.filter((s) => s.type === "security_finding");
      expect(findingSignals.length).toBe(1);
      expect(findingSignals[0].description).toContain("OpenSSL outdated");
    });

    it("detects env file config data", () => {
      const telemetry = makeTelemetry({
        configData: {
          envFiles: [
            { path: "/app/.env", keys: ["DATABASE_URL", "API_KEY", "SECRET_KEY"] },
          ],
        },
      });
      const signals = broker.deriveSignals(telemetry);
      const envSignals = signals.filter((s) => s.type === "env_file");
      expect(envSignals.length).toBe(1);
      expect(envSignals[0].severity).toBe("high");
      expect(envSignals[0].description).toContain("DATABASE_URL");
    });

    it("detects cloud credential files", () => {
      const telemetry = makeTelemetry({
        configData: {
          cloudCredentialFiles: [
            { path: "/root/.aws/credentials", type: "aws" },
          ],
        },
      });
      const signals = broker.deriveSignals(telemetry);
      const credSignals = signals.filter((s) => s.type === "cloud_credential_file");
      expect(credSignals.length).toBe(1);
      expect(credSignals[0].severity).toBe("critical");
    });

    it("returns empty signals for empty telemetry", () => {
      const telemetry = makeTelemetry();
      const signals = broker.deriveSignals(telemetry);
      expect(signals).toEqual([]);
    });
  });

  describe("formatForPrompt", () => {
    it("produces structured text with boundary instruction", () => {
      const ctx = {
        assetId: "asset-001",
        agentId: "agent-001",
        hostname: "web-prod-01",
        primaryIp: "10.0.1.5",
        platform: "linux",
        containerRuntime: "docker",
        openPorts: [{ port: 5432, protocol: "tcp", service: "postgresql" }],
        runningServices: [{ name: "nginx", version: "1.24", port: 80 }],
        signals: [
          { type: "database_service" as const, severity: "high" as const, description: "DB port 5432 open" },
        ],
        collectedAt: "2026-03-12T10:00:00Z",
      };

      const prompt = broker.formatForPrompt(ctx);

      expect(prompt).toContain("=== HOST RUNTIME CONTEXT");
      expect(prompt).toContain("web-prod-01");
      expect(prompt).toContain("10.0.1.5");
      expect(prompt).toContain("docker");
      expect(prompt).toContain("5432/tcp (postgresql)");
      expect(prompt).toContain("nginx v1.24 :80");
      expect(prompt).toContain("[HIGH] database_service");
      expect(prompt).toContain("Reason ONLY from the data above");
      expect(prompt).toContain("=== END HOST RUNTIME CONTEXT ===");
    });
  });
});
