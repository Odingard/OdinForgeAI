/**
 * Horizontal Privilege Escalation Module
 *
 * Tests whether authenticated sessions can access other users' resources
 * (IDOR-based horizontal escalation). Detects broken object-level
 * authorization by swapping user-specific identifiers across sessions.
 */

import http from "http";
import https from "https";
import { createHash } from "crypto";
import { URL } from "url";

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface ProofArtifact {
  type: "request" | "response" | "comparison";
  data: string;
  capturedAt: string;
}

export interface HorizontalFinding {
  endpoint: string;
  method: string;
  paramName: string;
  originalValue: string;
  swappedValue: string;
  accessGranted: boolean;
  responseMatch: "identical" | "similar" | "different_user_data" | "denied";
  confidence: number;
  evidence: string;
}

export interface HorizontalPrivescResult {
  vulnerable: boolean;
  findings: HorizontalFinding[];
  endpointsTested: number;
  crossAccessCount: number;
  proof: ProofArtifact[];
}

export interface TestEndpoint {
  url: string;
  method: string;
  idParams?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface SessionAuth {
  cookie?: string;
  token?: string;
}

interface HttpResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const NUMERIC_ID_PATTERN = /\b\d{1,12}\b/;

const ID_FIELD_PATTERNS = [
  "id",
  "userId",
  "user_id",
  "accountId",
  "account_id",
  "profileId",
  "profile_id",
  "customerId",
  "customer_id",
  "memberId",
  "member_id",
  "uuid",
  "uid",
  "ownerId",
  "owner_id",
  "tenantId",
  "tenant_id",
  "orgId",
  "org_id",
];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export class HorizontalPrivescModule {
  private baseUrl: string;
  private timeout: number;
  private maxEndpoints: number;

  constructor(
    baseUrl: string,
    options?: { timeout?: number; maxEndpoints?: number }
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeout = options?.timeout ?? 10_000;
    this.maxEndpoints = options?.maxEndpoints ?? 50;
  }

  // -----------------------------------------------------------------------
  // Public methods
  // -----------------------------------------------------------------------

  /**
   * Test with two authenticated sessions. Uses session A to discover
   * user-specific IDs, then attempts to access session B's resources
   * through session A's credentials.
   */
  async testWithTwoSessions(
    sessionA: SessionAuth,
    sessionB: SessionAuth,
    endpoints: TestEndpoint[]
  ): Promise<HorizontalPrivescResult> {
    const findings: HorizontalFinding[] = [];
    const proof: ProofArtifact[] = [];
    let tested = 0;

    const limited = endpoints.slice(0, this.maxEndpoints);

    for (const ep of limited) {
      tested++;
      try {
        // Fetch with session A to get baseline
        const responseA = await this.request(ep.url, ep.method, sessionA);
        if (responseA.statusCode === 401 || responseA.statusCode === 403) continue;

        // Fetch same endpoint with session B to discover B's IDs
        const responseB = await this.request(ep.url, ep.method, sessionB);
        if (responseB.statusCode === 401 || responseB.statusCode === 403) continue;

        const idsA = this.extractUserIds(responseA.body);
        const idsB = this.extractUserIds(responseB.body);

        // For each ID that differs between A and B, try to access B's data via A's session
        for (const [field, valueB] of Array.from(idsB.entries())) {
          const valueA = idsA.get(field);
          if (!valueA || valueA === valueB) continue;

          const swappedUrl = this.substituteId(ep.url, field, valueA, valueB);
          const swappedResponse = await this.request(swappedUrl, ep.method, sessionA);

          const match = this.classifyResponse(swappedResponse, responseB);
          const accessGranted = match === "identical" || match === "different_user_data";

          const confidence = this.calculateConfidence(match, swappedResponse.statusCode);

          proof.push({
            type: "request",
            data: `${ep.method} ${swappedUrl} [session=A, target_id=${field}:${valueB}]`,
            capturedAt: new Date().toISOString(),
          });
          proof.push({
            type: "response",
            data: `HTTP ${swappedResponse.statusCode} (${swappedResponse.body.length} bytes)`,
            capturedAt: new Date().toISOString(),
          });

          findings.push({
            endpoint: ep.url,
            method: ep.method,
            paramName: field,
            originalValue: valueA,
            swappedValue: valueB,
            accessGranted,
            responseMatch: match,
            confidence,
            evidence: accessGranted
              ? `Session A accessed user B data via ${field}=${valueB} — ${match}`
              : `Access denied or data mismatch for ${field}=${valueB}`,
          });
        }
      } catch {
        // Network errors — skip endpoint
      }
    }

    const crossAccessCount = findings.filter((f) => f.accessGranted).length;

    return {
      vulnerable: crossAccessCount > 0,
      findings,
      endpointsTested: tested,
      crossAccessCount,
      proof,
    };
  }

  /**
   * Test by manipulating ID parameters in URLs/params with a single session.
   * Increments/decrements numeric IDs or swaps known test IDs to detect IDOR.
   */
  async testWithIdSwap(
    session: SessionAuth,
    endpoints: TestEndpoint[]
  ): Promise<HorizontalPrivescResult> {
    const findings: HorizontalFinding[] = [];
    const proof: ProofArtifact[] = [];
    let tested = 0;

    const limited = endpoints.slice(0, this.maxEndpoints);

    for (const ep of limited) {
      tested++;
      try {
        // Baseline request
        const baseline = await this.request(ep.url, ep.method, session);
        if (baseline.statusCode === 401 || baseline.statusCode === 403) continue;

        // Determine ID parameters to swap
        const idParams: Array<{ name: string; value: string }> = [];

        if (ep.idParams) {
          for (const [name, value] of Object.entries(ep.idParams)) {
            idParams.push({ name, value });
          }
        } else {
          // Auto-discover IDs from URL path segments
          const urlObj = new URL(ep.url);
          const segments = urlObj.pathname.split("/").filter(Boolean);
          for (let i = 0; i < segments.length; i++) {
            const seg = segments[i];
            if (NUMERIC_ID_PATTERN.test(seg) && seg.length <= 12) {
              const prevSegment = i > 0 ? segments[i - 1] : "id";
              idParams.push({ name: prevSegment, value: seg });
            } else if (UUID_PATTERN.test(seg)) {
              const prevSegment = i > 0 ? segments[i - 1] : "uuid";
              idParams.push({ name: prevSegment, value: seg });
            }
          }

          // Also extract from response body
          const bodyIds = this.extractUserIds(baseline.body);
          for (const [name, value] of Array.from(bodyIds.entries())) {
            if (!idParams.some((p) => p.value === value)) {
              idParams.push({ name, value });
            }
          }
        }

        for (const param of idParams) {
          const swappedValues = this.generateSwappedValues(param.value);

          for (const swapped of swappedValues) {
            const swappedUrl = this.substituteId(ep.url, param.name, param.value, swapped);
            const swappedResponse = await this.request(swappedUrl, ep.method, session);

            const match = this.compareResponses(baseline.body, swappedResponse.body);
            const accessGranted =
              (swappedResponse.statusCode >= 200 && swappedResponse.statusCode < 300) &&
              (match === "different_user_data" || match === "identical");

            const confidence = this.calculateConfidence(
              match === "identical" ? "similar" : match,
              swappedResponse.statusCode
            );

            proof.push({
              type: "comparison",
              data: JSON.stringify({
                original: param.value,
                swapped,
                baselineStatus: baseline.statusCode,
                swappedStatus: swappedResponse.statusCode,
                match,
              }),
              capturedAt: new Date().toISOString(),
            });

            findings.push({
              endpoint: ep.url,
              method: ep.method,
              paramName: param.name,
              originalValue: param.value,
              swappedValue: swapped,
              accessGranted,
              responseMatch: match,
              confidence,
              evidence: accessGranted
                ? `Swapping ${param.name} from ${param.value} to ${swapped} returned different user data`
                : `Swapping ${param.name} from ${param.value} to ${swapped}: ${match}`,
            });
          }
        }
      } catch {
        // Network errors — skip endpoint
      }
    }

    const crossAccessCount = findings.filter((f) => f.accessGranted).length;

    return {
      vulnerable: crossAccessCount > 0,
      findings,
      endpointsTested: tested,
      crossAccessCount,
      proof,
    };
  }

  /**
   * Discover ID-like parameters from an endpoint's response.
   */
  async discoverIdParameters(
    session: SessionAuth,
    endpoint: string
  ): Promise<string[]> {
    try {
      const response = await this.request(endpoint, "GET", session);
      if (response.statusCode === 401 || response.statusCode === 403) return [];

      const discovered = new Set<string>();

      // Check response body for ID fields
      const bodyIds = this.extractUserIds(response.body);
      for (const name of Array.from(bodyIds.keys())) {
        discovered.add(name);
      }

      // Check URL path segments for numeric/UUID patterns
      const urlObj = new URL(endpoint);
      const segments = urlObj.pathname.split("/").filter(Boolean);
      for (let i = 0; i < segments.length; i++) {
        const seg = segments[i];
        if (NUMERIC_ID_PATTERN.test(seg) && seg.length <= 12) {
          const label = i > 0 ? segments[i - 1] : `path_segment_${i}`;
          discovered.add(label);
        } else if (UUID_PATTERN.test(seg)) {
          const label = i > 0 ? segments[i - 1] : `path_uuid_${i}`;
          discovered.add(label);
        }
      }

      // Check query parameters
      for (const [key] of Array.from(urlObj.searchParams.entries())) {
        const lower = key.toLowerCase();
        if (ID_FIELD_PATTERNS.some((p) => lower === p.toLowerCase())) {
          discovered.add(key);
        }
      }

      return Array.from(discovered);
    } catch {
      return [];
    }
  }

  // -----------------------------------------------------------------------
  // Private methods
  // -----------------------------------------------------------------------

  /**
   * Extract user-specific ID fields from a JSON response body.
   */
  private extractUserIds(body: string): Map<string, string> {
    const ids = new Map<string, string>();

    try {
      const parsed = JSON.parse(body);
      this.walkObject(parsed, "", ids);
    } catch {
      // Not JSON — try regex extraction
      for (const field of ID_FIELD_PATTERNS) {
        const pattern = new RegExp(`"${field}"\\s*:\\s*"?([^",}\\s]+)"?`, "gi");
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(body)) !== null) {
          ids.set(field, match[1]);
        }
      }
    }

    return ids;
  }

  private walkObject(
    obj: any,
    prefix: string,
    ids: Map<string, string>
  ): void {
    if (obj === null || obj === undefined) return;

    if (Array.isArray(obj)) {
      // Only inspect the first element to avoid explosion
      if (obj.length > 0) {
        this.walkObject(obj[0], prefix, ids);
      }
      return;
    }

    if (typeof obj !== "object") return;

    for (const key of Object.keys(obj)) {
      const value = obj[key];
      const fullKey = prefix ? `${prefix}.${key}` : key;
      const lower = key.toLowerCase();

      if (typeof value === "string" || typeof value === "number") {
        const strVal = String(value);
        const isIdField = ID_FIELD_PATTERNS.some(
          (p) => lower === p.toLowerCase()
        );
        const looksLikeId =
          lower.endsWith("id") ||
          lower.endsWith("_id") ||
          lower === "uuid" ||
          lower === "uid";

        if (isIdField || looksLikeId) {
          ids.set(key, strVal);
        } else if (UUID_PATTERN.test(strVal)) {
          ids.set(key, strVal);
        }
      } else if (typeof value === "object") {
        this.walkObject(value, fullKey, ids);
      }
    }
  }

  /**
   * Compare two response bodies to determine IDOR outcome.
   */
  private compareResponses(
    responseA: string,
    responseB: string
  ): "identical" | "similar" | "different_user_data" | "denied" {
    // Exact match
    if (responseA === responseB) return "identical";

    // Try JSON structural comparison
    try {
      const objA = JSON.parse(responseA);
      const objB = JSON.parse(responseB);

      const keysA = this.flattenKeys(objA);
      const keysB = this.flattenKeys(objB);

      // Same structure?
      const sameStructure =
        keysA.length === keysB.length &&
        keysA.every((k, i) => k === keysB[i]);

      if (sameStructure) {
        // Same structure, check if values differ
        const valuesA = this.flattenValues(objA);
        const valuesB = this.flattenValues(objB);

        let diffCount = 0;
        for (let i = 0; i < valuesA.length; i++) {
          if (valuesA[i] !== valuesB[i]) diffCount++;
        }

        if (diffCount === 0) return "similar";

        // Many differing values with same structure → different user data (IDOR)
        const diffRatio = diffCount / Math.max(valuesA.length, 1);
        if (diffRatio > 0.1) return "different_user_data";

        return "similar";
      }

      // Different structure but both valid JSON — likely different endpoint behavior
      return "similar";
    } catch {
      // Non-JSON: compare lengths as rough heuristic
      const lenRatio =
        Math.min(responseA.length, responseB.length) /
        Math.max(responseA.length, responseB.length, 1);

      if (lenRatio > 0.9 && responseA !== responseB) return "different_user_data";
      if (lenRatio > 0.5) return "similar";
      return "denied";
    }
  }

  /**
   * Classify a swapped response against a known target response.
   */
  private classifyResponse(
    swapped: HttpResponse,
    target: HttpResponse
  ): "identical" | "similar" | "different_user_data" | "denied" {
    if (swapped.statusCode === 401 || swapped.statusCode === 403 || swapped.statusCode === 404) {
      return "denied";
    }

    return this.compareResponses(swapped.body, target.body);
  }

  /**
   * Generate alternative ID values to test for IDOR.
   */
  private generateSwappedValues(original: string): string[] {
    const swapped: string[] = [];

    // Numeric IDs: increment and decrement
    if (/^\d+$/.test(original)) {
      const num = parseInt(original, 10);
      if (num > 1) swapped.push(String(num - 1));
      swapped.push(String(num + 1));
      if (num > 100) swapped.push(String(num - 100));
      swapped.push(String(num + 100));
      // Common test user IDs
      if (num !== 1) swapped.push("1");
      if (num !== 2) swapped.push("2");
    }

    // UUID: flip last hex digit
    if (UUID_PATTERN.test(original)) {
      const lastChar = original.charAt(original.length - 1);
      const flipped = lastChar === "0" ? "1" : "0";
      swapped.push(original.slice(0, -1) + flipped);
    }

    // If nothing matched, try simple alternatives
    if (swapped.length === 0) {
      swapped.push("1");
      swapped.push("admin");
    }

    return swapped;
  }

  /**
   * Replace an ID value in a URL (path segments, query params).
   */
  private substituteId(
    url: string,
    _paramName: string,
    oldValue: string,
    newValue: string
  ): string {
    // Direct string replacement in URL — covers path and query params
    return url.replace(oldValue, newValue);
  }

  private calculateConfidence(
    match: "identical" | "similar" | "different_user_data" | "denied",
    statusCode: number
  ): number {
    if (match === "denied") return 0.1;
    if (match === "similar") return 0.3;
    if (match === "identical" && statusCode >= 200 && statusCode < 300) return 0.6;
    if (match === "different_user_data") return 0.95;
    return 0.2;
  }

  // -----------------------------------------------------------------------
  // JSON helpers
  // -----------------------------------------------------------------------

  private flattenKeys(obj: any, prefix: string = ""): string[] {
    const keys: string[] = [];
    if (obj === null || obj === undefined || typeof obj !== "object") return keys;

    if (Array.isArray(obj)) {
      keys.push(`${prefix}[]`);
      if (obj.length > 0) {
        keys.push(...this.flattenKeys(obj[0], `${prefix}[]`));
      }
      return keys;
    }

    for (const key of Object.keys(obj).sort()) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      keys.push(fullKey);
      if (typeof obj[key] === "object" && obj[key] !== null) {
        keys.push(...this.flattenKeys(obj[key], fullKey));
      }
    }
    return keys;
  }

  private flattenValues(obj: any): string[] {
    const values: string[] = [];
    if (obj === null || obj === undefined) return values;

    if (Array.isArray(obj)) {
      if (obj.length > 0) values.push(...this.flattenValues(obj[0]));
      return values;
    }

    if (typeof obj !== "object") {
      values.push(String(obj));
      return values;
    }

    for (const key of Object.keys(obj).sort()) {
      values.push(...this.flattenValues(obj[key]));
    }
    return values;
  }

  // -----------------------------------------------------------------------
  // HTTP client (native http/https)
  // -----------------------------------------------------------------------

  private request(
    url: string,
    method: string,
    session: SessionAuth
  ): Promise<HttpResponse> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const isHttps = parsed.protocol === "https:";
      const transport = isHttps ? https : http;

      const headers: Record<string, string> = {
        Accept: "application/json",
        "User-Agent": "OdinForge-AEV/1.0",
      };

      if (session.token) {
        headers["Authorization"] = `Bearer ${session.token}`;
      }
      if (session.cookie) {
        headers["Cookie"] = session.cookie;
      }

      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (isHttps ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method: method.toUpperCase(),
          headers,
          timeout: this.timeout,
          rejectUnauthorized: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            resolve({
              statusCode: res.statusCode || 0,
              body: Buffer.concat(chunks).toString("utf-8"),
              headers: res.headers as Record<string, string | string[] | undefined>,
            });
          });
        }
      );

      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Request timed out"));
      });

      req.end();
    });
  }
}
