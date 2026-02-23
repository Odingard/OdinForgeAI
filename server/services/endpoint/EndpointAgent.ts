// =============================================================================
// Task 06 — Endpoint Agent Base
// server/services/endpoint/EndpointAgent.ts
//
// Abstract base for Linux, macOS, and Windows endpoint agents.
// Agents collect findings via local command execution and report back
// to OdinForge over HTTPS.
//
// Each check runs in isolation — one check failure never aborts the scan.
// Results are normalized into the same CloudFinding schema as cloud scans,
// so the entity graph and intelligence engine handle them uniformly.
// =============================================================================

import { exec as execCallback }  from "child_process";
import { promisify }             from "util";
import type { CloudFinding, CloudSeverity } from "../cloud/base/CloudScanner";

export const exec = promisify(execCallback);

export type OS = "linux" | "macos" | "windows";

// —— Endpoint finding = Cloud finding (reuse schema for entity graph compat) ——
export type EndpointFinding = CloudFinding;

export interface EndpointScanResult {
  hostname:     string;
  os:           OS;
  agentVersion: string;
  startedAt:    Date;
  finishedAt:   Date;
  findings:     EndpointFinding[];
  errors:       Array<{ checkId: string; message: string }>;
  checksRun:    number;
}

// —— Command execution result ————————————————————————————————————
export interface ExecResult {
  stdout: string;
  stderr: string;
  code:   number;
}

// —— Abstract base ———————————————————————————————————————————————
export abstract class EndpointAgent {
  protected readonly os:           OS;
  protected readonly agentVersion: string = "1.0.0";
  protected readonly findings:     EndpointFinding[] = [];
  protected readonly errors:       Array<{ checkId: string; message: string }> = [];
  private checksRun = 0;

  constructor(os: OS) {
    this.os = os;
  }

  // —— Public API ————————————————————————————————————————————
  async run(): Promise<EndpointScanResult> {
    const startedAt = new Date();
    const hostname  = await this.getHostname();

    this.log(`Starting ${this.os} endpoint scan on ${hostname}`);

    await this.runChecks();

    const finishedAt = new Date();
    this.log(`Scan complete — ${this.findings.length} findings, ${this.errors.length} errors`);

    return {
      hostname,
      os:           this.os,
      agentVersion: this.agentVersion,
      startedAt,
      finishedAt,
      findings:     this.findings,
      errors:       this.errors,
      checksRun:    this.checksRun,
    };
  }

  // —— Abstract — each OS implements this ————————————————————
  protected abstract runChecks(): Promise<void>;

  // —— Check isolation wrapper ———————————————————————————————
  protected async runCheck<T>(
    checkId:   string,
    checkFn:   () => Promise<T>,
    onResult:  (result: T) => void | Promise<void>
  ): Promise<void> {
    this.checksRun++;
    try {
      const result = await checkFn();
      await onResult(result);
    } catch (err: unknown) {
      const e = err as Error;
      this.errors.push({ checkId, message: e.message });
      this.log(`Check ${checkId} failed: ${e.message}`, "warn");
    }
  }

  // —— Command execution helpers —————————————————————————————
  protected async runCommand(
    command:   string,
    opts?:     { timeout?: number; allowFailure?: boolean }
  ): Promise<ExecResult> {
    const timeout = opts?.timeout ?? 15_000;
    try {
      const { stdout, stderr } = await exec(command, { timeout });
      return { stdout: stdout.trim(), stderr: stderr.trim(), code: 0 };
    } catch (err: unknown) {
      const e = err as Error & { code?: number; stdout?: string; stderr?: string };
      if (opts?.allowFailure) {
        return {
          stdout: e.stdout?.trim() ?? "",
          stderr: e.stderr?.trim() ?? "",
          code:   typeof e.code === "number" ? e.code : 1,
        };
      }
      throw err;
    }
  }

  // Parse key=value output into a map
  protected parseKeyValue(output: string, delimiter = "="): Map<string, string> {
    const map = new Map<string, string>();
    for (const line of output.split("\n")) {
      const idx = line.indexOf(delimiter);
      if (idx < 0) continue;
      const key = line.slice(0, idx).trim();
      const val = line.slice(idx + 1).trim();
      if (key) map.set(key, val);
    }
    return map;
  }

  protected addFinding(finding: EndpointFinding): void {
    this.findings.push(finding);
  }

  protected log(message: string, level: "info" | "warn" | "error" = "info"): void {
    const prefix = `[endpoint:${this.os}]`;
    if (level === "error") console.error(prefix, message);
    else if (level === "warn") console.warn(prefix, message);
    else console.log(prefix, message);
  }

  private async getHostname(): Promise<string> {
    try {
      const { stdout } = await this.runCommand(
        this.os === "windows" ? "hostname" : "hostname -f",
        { allowFailure: true }
      );
      return stdout || "unknown";
    } catch {
      return "unknown";
    }
  }

  protected severityFromBoolean(critical: boolean, high: boolean): CloudSeverity {
    if (critical) return "critical";
    if (high)     return "high";
    return "medium";
  }
}
