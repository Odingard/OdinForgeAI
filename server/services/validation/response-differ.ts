import { ValidatingHttpClient, type ValidatingResponse } from "./validating-http-client";
import { buildPayloadRequest, type PayloadExecutionContext } from "./payloads/payload-types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AnomalyType =
  | "reflection"
  | "error_based"
  | "time_based"
  | "structural"
  | "blind"
  | "none";

/** Fingerprint of an HTTP response captured as a baseline or injected probe. */
export interface ResponseFingerprint {
  statusCode: number;
  bodyLength: number;
  responseTimeMs: number;
  contentType: string;
  headers: Record<string, string>;
  /** Sorted JSON keys (for JSON bodies) or sorted HTML tag sequence (for HTML). */
  structureHash: string;
  body: string;
}

/** Structural diff between a baseline and an injected-payload response. */
export interface ResponseDiff {
  statusCodeChanged: boolean;
  bodyLengthDelta: number;
  bodyLengthDeltaPercent: number;
  timingDelta: number;
  structureChanged: boolean;
  headersDiff: string[];
  newContentPatterns: string[];
  anomalyScore: number;
  anomalyReasons: string[];
}

export interface AnomalyClassification {
  isAnomaly: boolean;
  confidence: number;
  type: AnomalyType;
}

export interface DiffResult {
  baseline: ResponseFingerprint;
  injected: ResponseFingerprint;
  diff: ResponseDiff;
  classification: AnomalyClassification;
}

// ---------------------------------------------------------------------------
// Error-pattern regexes
// ---------------------------------------------------------------------------

const SQL_ERROR_PATTERNS: RegExp[] = [
  /SQL syntax/i,
  /mysql_/i,
  /pg_query/i,
  /ORA-\d+/,
  /ODBC/i,
  /sqlite3/i,
  /Microsoft SQL/i,
];

const TEMPLATE_ERROR_PATTERNS: RegExp[] = [
  /TemplateSyntaxError/,
  /UndefinedError/,
  /Twig_Error/,
  /SyntaxError.*template/i,
];

const PATH_ERROR_PATTERNS: RegExp[] = [
  /No such file/i,
  /Permission denied/i,
  /root:x:/,
  /\[boot loader\]/i,
];

const COMMAND_OUTPUT_PATTERNS: RegExp[] = [
  /uid=\d+/,
  /Linux.*GNU/,
  /Windows.*NT/,
  /total \d+/,
];

const STACK_TRACE_PATTERNS: RegExp[] = [
  /at .*\.js:\d+/,
  /Traceback/,
  /Exception in thread/,
  /panic:/,
];

const ALL_ERROR_PATTERNS: { label: string; patterns: RegExp[] }[] = [
  { label: "SQL error", patterns: SQL_ERROR_PATTERNS },
  { label: "Template error", patterns: TEMPLATE_ERROR_PATTERNS },
  { label: "Path disclosure", patterns: PATH_ERROR_PATTERNS },
  { label: "Command output", patterns: COMMAND_OUTPUT_PATTERNS },
  { label: "Stack trace", patterns: STACK_TRACE_PATTERNS },
];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const client = new ValidatingHttpClient({ timeout: 15_000 });

/** Extract a structure fingerprint from a response body. */
function computeStructureHash(body: string, contentType: string): string {
  if (contentType.includes("json")) {
    try {
      const parsed = JSON.parse(body);
      return extractJsonKeys(parsed).sort().join(",");
    } catch {
      return "";
    }
  }
  // For HTML / other text, extract tag sequence
  const tagMatches = body.match(/<\/?[a-zA-Z][a-zA-Z0-9]*[^>]*>/g);
  if (tagMatches) {
    const tags = tagMatches.map((t) => {
      const m = t.match(/^<\/?([a-zA-Z][a-zA-Z0-9]*)/);
      return m ? m[1].toLowerCase() : "";
    });
    return tags.filter(Boolean).join(",");
  }
  return "";
}

/** Recursively extract all key paths from a JSON value. */
function extractJsonKeys(obj: unknown, prefix = ""): string[] {
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return prefix ? [prefix] : [];
  }
  if (Array.isArray(obj)) {
    if (obj.length === 0) return prefix ? [`${prefix}[]`] : [];
    // Sample first element only to keep fingerprint stable
    return extractJsonKeys(obj[0], `${prefix}[]`);
  }
  const keys: string[] = [];
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    keys.push(...extractJsonKeys((obj as Record<string, unknown>)[key], path));
  }
  return keys;
}

/** Build a fingerprint from a ValidatingResponse. */
function toFingerprint(resp: ValidatingResponse): ResponseFingerprint {
  const contentType = resp.headers["content-type"] || "";
  return {
    statusCode: resp.statusCode,
    bodyLength: resp.body.length,
    responseTimeMs: resp.timing.durationMs,
    contentType,
    headers: { ...resp.headers },
    structureHash: computeStructureHash(resp.body, contentType),
    body: resp.body,
  };
}

/** Detect error patterns present in `injected` but absent from `baseline`. */
function detectNewPatterns(baselineBody: string, injectedBody: string): string[] {
  const found: string[] = [];
  for (const group of ALL_ERROR_PATTERNS) {
    for (const re of group.patterns) {
      if (re.test(injectedBody) && !re.test(baselineBody)) {
        found.push(group.label);
        break; // one match per group is sufficient
      }
    }
  }
  return found;
}

/** Compute header-level differences. */
function diffHeaders(
  baseline: Record<string, string>,
  injected: Record<string, string>
): string[] {
  const diffs: string[] = [];
  const allKeys = new Set([...Object.keys(baseline), ...Object.keys(injected)]);
  Array.from(allKeys).forEach((key) => {
    const bVal = baseline[key];
    const iVal = injected[key];
    if (bVal === undefined) {
      diffs.push(`+${key}: ${iVal}`);
    } else if (iVal === undefined) {
      diffs.push(`-${key}: ${bVal}`);
    } else if (bVal !== iVal) {
      diffs.push(`~${key}: ${bVal} -> ${iVal}`);
    }
  });
  return diffs;
}

// ---------------------------------------------------------------------------
// Core public API
// ---------------------------------------------------------------------------

/**
 * Send a clean (no-payload) request and capture a response fingerprint.
 *
 * @param url    Target URL
 * @param method HTTP method
 * @param params Optional request parameters (headers, body)
 * @returns A `ResponseFingerprint` representing the baseline behaviour
 */
export async function captureBaseline(
  url: string,
  method: string,
  params?: { headers?: Record<string, string>; body?: string }
): Promise<ResponseFingerprint> {
  const { response } = await client.request({
    method,
    url,
    headers: params?.headers,
    body: params?.body,
    followRedirects: false,
  });
  return toFingerprint(response);
}

/**
 * Structurally compare a baseline fingerprint against an injected response.
 *
 * Produces an `anomalyScore` (0-100) with human-readable `anomalyReasons`.
 */
export function diffResponse(
  baseline: ResponseFingerprint,
  injected: ResponseFingerprint
): ResponseDiff {
  let anomalyScore = 0;
  const anomalyReasons: string[] = [];

  // --- Status code ---
  const statusCodeChanged = baseline.statusCode !== injected.statusCode;
  if (statusCodeChanged) {
    const isServerError =
      baseline.statusCode >= 200 &&
      baseline.statusCode < 300 &&
      injected.statusCode >= 500;
    const isRedirectOrForbidden =
      baseline.statusCode >= 200 &&
      baseline.statusCode < 300 &&
      (injected.statusCode === 302 ||
        injected.statusCode === 301 ||
        injected.statusCode === 403);

    if (isServerError) {
      anomalyScore += 40;
      anomalyReasons.push(
        `Status code changed from ${baseline.statusCode} to ${injected.statusCode} (server error)`
      );
    } else if (isRedirectOrForbidden) {
      anomalyScore += 20;
      anomalyReasons.push(
        `Status code changed from ${baseline.statusCode} to ${injected.statusCode} (redirect/forbidden)`
      );
    } else {
      anomalyScore += 15;
      anomalyReasons.push(
        `Status code changed from ${baseline.statusCode} to ${injected.statusCode}`
      );
    }
  }

  // --- Body length delta ---
  const bodyLengthDelta = injected.bodyLength - baseline.bodyLength;
  const bodyLengthDeltaPercent =
    baseline.bodyLength > 0
      ? Math.abs(bodyLengthDelta) / baseline.bodyLength
      : injected.bodyLength > 0
        ? 1
        : 0;
  if (bodyLengthDeltaPercent > 0.3) {
    anomalyScore += 25;
    anomalyReasons.push(
      `Body length changed by ${(bodyLengthDeltaPercent * 100).toFixed(1)}% (${bodyLengthDelta > 0 ? "+" : ""}${bodyLengthDelta} bytes)`
    );
  }

  // --- Timing delta ---
  const timingDelta = injected.responseTimeMs - baseline.responseTimeMs;
  if (timingDelta > 3000) {
    anomalyScore += 35;
    anomalyReasons.push(
      `Response time increased by ${timingDelta}ms (potential time-based blind injection)`
    );
  } else if (timingDelta > 1000) {
    anomalyScore += 15;
    anomalyReasons.push(`Response time increased by ${timingDelta}ms`);
  }

  // --- New error patterns ---
  const newContentPatterns = detectNewPatterns(baseline.body, injected.body);
  if (newContentPatterns.length > 0) {
    anomalyScore += 30;
    anomalyReasons.push(
      `New error patterns detected: ${newContentPatterns.join(", ")}`
    );
  }

  // --- Structural change ---
  const structureChanged =
    baseline.structureHash !== "" &&
    injected.structureHash !== "" &&
    baseline.structureHash !== injected.structureHash;
  if (structureChanged) {
    anomalyScore += 20;
    anomalyReasons.push("Response structure changed (JSON keys or HTML tag sequence differ)");
  }

  // --- Header differences ---
  const headersDiff = diffHeaders(baseline.headers, injected.headers);
  const hasNewErrorHeaders = headersDiff.some(
    (h) =>
      h.startsWith("+") &&
      (/x-error/i.test(h) || /x-debug/i.test(h) || /x-powered-by/i.test(h))
  );
  if (hasNewErrorHeaders) {
    anomalyScore += 10;
    anomalyReasons.push("New error-related headers appeared in response");
  }

  // Cap at 100
  anomalyScore = Math.min(anomalyScore, 100);

  return {
    statusCodeChanged,
    bodyLengthDelta,
    bodyLengthDeltaPercent,
    timingDelta,
    structureChanged,
    headersDiff,
    newContentPatterns,
    anomalyScore,
    anomalyReasons,
  };
}

/**
 * Classify a response diff into an anomaly type with a confidence score.
 *
 * @returns `isAnomaly` is true when `anomalyScore >= 25`.
 */
export function classifyAnomaly(diff: ResponseDiff): AnomalyClassification {
  if (diff.anomalyScore < 25) {
    return { isAnomaly: false, confidence: 0, type: "none" };
  }

  // Determine primary anomaly type based on which signals fired
  let type: AnomalyType = "blind";

  if (diff.newContentPatterns.length > 0) {
    // Error messages surfaced — likely error-based injection
    type = "error_based";
  } else if (diff.timingDelta > 3000) {
    type = "time_based";
  } else if (diff.structureChanged) {
    type = "structural";
  } else if (diff.statusCodeChanged && diff.bodyLengthDeltaPercent > 0.3) {
    type = "reflection";
  } else if (diff.timingDelta > 1000) {
    type = "time_based";
  }

  // Confidence scales with anomaly score — cap at 95
  const confidence = Math.min(Math.round(diff.anomalyScore * 0.95), 95);

  return { isAnomaly: true, confidence, type };
}

/**
 * Convenience function: capture a baseline, fire a payload, and return the
 * full diff result including classification.
 *
 * Uses `buildPayloadRequest` to construct the injected request so that
 * payload placement is consistent with the rest of the validation engine.
 *
 * @param url            Target URL
 * @param method         HTTP method
 * @param params         Optional headers / body for the clean request
 * @param payloadValue   The payload string to inject
 * @param paramName      Target parameter name
 * @param paramLocation  Where to inject (url_param, body_param, header, cookie, path)
 */
export async function captureAndDiff(
  url: string,
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  params: { headers?: Record<string, string>; body?: string } | undefined,
  payloadValue: string,
  paramName: string,
  paramLocation: "url_param" | "body_param" | "header" | "cookie" | "path"
): Promise<DiffResult> {
  // 1. Capture baseline (clean request)
  const baseline = await captureBaseline(url, method, params);

  // 2. Build injected request via shared PreparedRequest logic
  const ctx: PayloadExecutionContext = {
    targetUrl: url,
    parameterName: paramName,
    parameterLocation: paramLocation,
    httpMethod: method,
    headers: params?.headers,
  };
  const prepared = buildPayloadRequest(ctx, payloadValue);

  // 3. Fire injected request
  const { response: injectedResp } = await client.request({
    method,
    url: prepared.url,
    headers: { ...params?.headers, ...prepared.headers },
    body: prepared.body,
    followRedirects: false,
  });
  const injected = toFingerprint(injectedResp);

  // 4. Diff and classify
  const diff = diffResponse(baseline, injected);
  const classification = classifyAnomaly(diff);

  return { baseline, injected, diff, classification };
}
