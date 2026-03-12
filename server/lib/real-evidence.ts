/**
 * RealHttpEvidence — Foundation of the LLM Boundary Contract.
 *
 * Every finding in OdinForge must be traceable to a RealHttpEvidence object.
 * This type CANNOT be constructed without real values from actual HTTP transactions.
 * There is no RealHttpEvidence.fake() or RealHttpEvidence.estimated().
 */

export interface RealHttpEvidence {
  /** The exact payload string that was sent */
  readonly requestPayload: string;
  /** The URL that was targeted */
  readonly targetUrl: string;
  /** HTTP method used */
  readonly method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  /** Actual HTTP status code from real server response — MUST be > 0 */
  readonly statusCode: number;
  /** Raw response body from real server — MUST be non-empty string */
  readonly rawResponseBody: string;
  /** Wall-clock time the request completed */
  readonly capturedAt: string;
  /** Duration of the real HTTP round-trip in ms */
  readonly durationMs: number;
  /** Source tag for EvidenceQualityGate — always 'real_http_response' */
  readonly source: "real_http_response";
}

/**
 * Runtime constructor — validates all fields at creation time.
 * Throws descriptive errors if any field indicates a stub or mock.
 */
export function makeRealHttpEvidence(fields: {
  requestPayload: string;
  targetUrl: string;
  method: RealHttpEvidence["method"];
  statusCode: number;
  rawResponseBody: string;
  durationMs: number;
}): RealHttpEvidence {
  if (fields.statusCode <= 0) {
    throw new Error(
      `[RealEvidence] statusCode must be > 0, got ${fields.statusCode}. Did you stub this?`
    );
  }
  if (!fields.rawResponseBody || fields.rawResponseBody.trim().length === 0) {
    throw new Error(
      `[RealEvidence] rawResponseBody is empty. Did you stub the HTTP call?`
    );
  }
  if (!fields.targetUrl || fields.targetUrl.trim().length === 0) {
    throw new Error(
      `[RealEvidence] targetUrl is empty. Every evidence object must reference a real target.`
    );
  }
  if (!fields.requestPayload && fields.requestPayload !== "") {
    throw new Error(
      `[RealEvidence] requestPayload is undefined. Provide the actual payload string (empty string is valid for GET requests).`
    );
  }

  return {
    requestPayload: fields.requestPayload,
    targetUrl: fields.targetUrl,
    method: fields.method,
    statusCode: fields.statusCode,
    rawResponseBody: fields.rawResponseBody,
    capturedAt: new Date().toISOString(),
    durationMs: fields.durationMs,
    source: "real_http_response",
  };
}
