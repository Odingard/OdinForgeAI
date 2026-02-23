// =============================================================================
// Task 06 — Cloud Scanner Base
// server/services/cloud/base/CloudScanner.ts
//
// Abstract base class for all cloud provider scanners.
// Enforces a consistent interface, provides:
//   - Credential pre-validation (fail fast before spending API quota)
//   - Retry with exponential backoff + jitter for rate limits
//   - Finding normalization into OdinForge's scoring schema
//   - Entity graph writer integration (Task 01)
//   - Structured logging with provider/scan context
// =============================================================================

import { EntityGraphWriter } from "../../entityGraph/entityGraphWriter";

// —— Finding schema ——————————————————————————————————————————————
// Normalized output from every cloud check — maps to entity_graph.findings

export type CloudSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface CloudFinding {
  // Identity
  checkId:        string;   // e.g. "aws-iam-root-no-mfa"
  title:          string;
  description:    string;

  // Severity
  severity:       CloudSeverity;
  cvssScore?:     number;   // 0–10
  isKev?:         boolean;

  // Evidence
  resource:       string;   // ARN, resource ID, or human-readable name
  resourceType:   string;   // "iam_user" | "s3_bucket" | "security_group" etc.
  region?:        string;
  evidence:       Record<string, unknown>;   // Raw API response snippet

  // Remediation
  remediationTitle:   string;
  remediationSteps:   string[];
  remediationEffort:  "low" | "medium" | "high";   // hours / days / weeks
  references?:        string[];

  // MITRE
  mitreAttackIds?:    string[];   // e.g. ["T1078", "T1530"]
}

export interface CloudScanResult {
  provider:   string;
  accountId:  string;
  region?:    string;
  startedAt:  Date;
  finishedAt: Date;
  findings:   CloudFinding[];
  errors:     CloudScanError[];
  checksRun:  number;
}

export interface CloudScanError {
  checkId:  string;
  message:  string;
  code?:    string;
}

// —— Credentials schema ——————————————————————————————————————————
export interface AwsCredentials {
  accessKeyId:     string;
  secretAccessKey: string;
  sessionToken?:   string;
  region:          string;
  accountId?:      string;
}

export interface AzureCredentials {
  tenantId:       string;
  clientId:       string;
  clientSecret:   string;
  subscriptionId: string;
}

export interface GcpCredentials {
  projectId:          string;
  serviceAccountJson: string;   // Full JSON key file content
}

export interface K8sCredentials {
  kubeconfig:   string;   // Full kubeconfig YAML content
  context?:     string;   // Specific context to use
  namespace?:   string;   // Limit scope to namespace
}

export type CloudCredentials =
  | ({ provider: "aws" }     & AwsCredentials)
  | ({ provider: "azure" }   & AzureCredentials)
  | ({ provider: "gcp" }     & GcpCredentials)
  | ({ provider: "k8s" }     & K8sCredentials);

// —— Abstract base ———————————————————————————————————————————————
export abstract class CloudScanner {
  protected readonly provider:        string;
  protected readonly organizationId:  string;
  protected readonly evaluationId:    string;
  protected readonly entityWriter:    EntityGraphWriter;
  protected readonly findings:        CloudFinding[] = [];
  protected readonly errors:          CloudScanError[] = [];
  private checksRun = 0;

  constructor(opts: {
    provider:       string;
    organizationId: string;
    evaluationId:   string;
    entityWriter:   EntityGraphWriter;
  }) {
    this.provider       = opts.provider;
    this.organizationId = opts.organizationId;
    this.evaluationId   = opts.evaluationId;
    this.entityWriter   = opts.entityWriter;
  }

  // —— Public API ————————————————————————————————————————————
  async run(credentials: CloudCredentials): Promise<CloudScanResult> {
    const startedAt = new Date();
    this.log("Starting scan");

    // 1. Validate credentials before spending API calls
    await this.validateCredentials(credentials);
    this.log("Credentials validated");

    // 2. Run all checks
    await this.runChecks(credentials);

    const finishedAt = new Date();
    this.log(`Scan complete — ${this.findings.length} findings, ${this.errors.length} errors`);

    // 3. Write findings to entity graph
    for (const finding of this.findings) {
      await this.writeFindingToEntityGraph(finding);
    }

    return {
      provider:   this.provider,
      accountId:  this.extractAccountId(credentials),
      startedAt,
      finishedAt,
      findings:   this.findings,
      errors:     this.errors,
      checksRun:  this.checksRun,
    };
  }

  // —— Abstract methods — implemented by each provider ———————————
  protected abstract validateCredentials(credentials: CloudCredentials): Promise<void>;
  protected abstract runChecks(credentials: CloudCredentials): Promise<void>;
  protected abstract extractAccountId(credentials: CloudCredentials): string;

  // —— Check runner helpers (call from runChecks) —————————————————

  // Run a single check with error isolation — one check failure doesn't abort the scan
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
      const error = err as Error & { code?: string };
      // Don't fail the scan for permission errors — log and continue
      const isPermission = error.code?.includes("AccessDenied") ||
                           error.code?.includes("Unauthorized") ||
                           error.message?.includes("403") ||
                           error.message?.includes("permission");

      this.errors.push({
        checkId,
        message: isPermission
          ? `Insufficient permissions for check ${checkId}: ${error.message}`
          : error.message,
        code: error.code,
      });
      this.log(`Check ${checkId} error (${error.code ?? "unknown"}): ${error.message}`, "warn");
    }
  }

  // Add a finding from a check
  protected addFinding(finding: CloudFinding): void {
    this.findings.push(finding);
  }

  // —— Retry with exponential backoff + jitter ————————————————————
  protected async withRetry<T>(
    fn:      () => Promise<T>,
    opts?:   { maxRetries?: number; baseDelayMs?: number; label?: string }
  ): Promise<T> {
    const maxRetries  = opts?.maxRetries  ?? 3;
    const baseDelay   = opts?.baseDelayMs ?? 500;
    const label       = opts?.label       ?? "operation";

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (err: unknown) {
        const error = err as Error & { code?: string; statusCode?: number };

        const isRateLimit = error.code === "ThrottlingException" ||
                            error.code === "RequestLimitExceeded" ||
                            error.code === "TooManyRequests" ||
                            error.statusCode === 429 ||
                            error.message?.toLowerCase().includes("rate limit");

        const isRetryable = isRateLimit ||
                            error.code === "ServiceUnavailable" ||
                            error.statusCode === 503 ||
                            error.statusCode === 500;

        if (!isRetryable || attempt === maxRetries) throw err;

        const delay = baseDelay * Math.pow(2, attempt) + Math.random() * 200;
        this.log(`${label} throttled, retry ${attempt + 1}/${maxRetries} in ${Math.round(delay)}ms`, "warn");
        await this.sleep(delay);
      }
    }
    throw new Error("Unreachable");
  }

  // —— Entity graph writer ————————————————————————————————————————
  private async writeFindingToEntityGraph(finding: CloudFinding): Promise<void> {
    try {
      await this.entityWriter.writeFinding({
        organizationId: this.organizationId,
        evaluationId:   this.evaluationId,
        source:         `cloud:${this.provider}`,
        checkId:        finding.checkId,
        title:          finding.title,
        description:    finding.description,
        severity:       finding.severity,
        cvssScore:      finding.cvssScore ?? this.severityToScore(finding.severity),
        isKev:          finding.isKev ?? false,
        resource:       finding.resource,
        resourceType:   finding.resourceType,
        evidence:       finding.evidence,
        remediation: {
          title:   finding.remediationTitle,
          steps:   finding.remediationSteps,
          effort:  finding.remediationEffort,
        },
        mitreAttackIds: finding.mitreAttackIds ?? [],
      });
    } catch (err) {
      // Don't let entity graph failures abort scan result delivery
      this.log(`Failed to write finding ${finding.checkId} to entity graph: ${(err as Error).message}`, "warn");
    }
  }

  // —— Utilities ——————————————————————————————————————————————
  protected log(message: string, level: "info" | "warn" | "error" = "info"): void {
    const prefix = `[cloud:${this.provider}:${this.evaluationId.slice(0, 8)}]`;
    if (level === "error") console.error(prefix, message);
    else if (level === "warn") console.warn(prefix, message);
    else console.log(prefix, message);
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private severityToScore(severity: CloudSeverity): number {
    return { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0, info: 1.0 }[severity];
  }
}
