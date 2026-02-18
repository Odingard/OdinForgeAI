export type PayloadCategory = 
  | "sqli"
  | "xss"
  | "command_injection"
  | "path_traversal"
  | "ssrf"
  | "auth_bypass"
  | "header_injection"
  | "template_injection";

export type PayloadRiskLevel = "safe" | "low" | "medium" | "high";

export type PayloadTechnique =
  | "error_based"
  | "time_based"
  | "boolean_based"
  | "union_based"
  | "stacked_queries"
  | "reflected"
  | "stored"
  | "dom_based"
  | "blind"
  | "out_of_band";

export interface Payload {
  id: string;
  category: PayloadCategory;
  technique: PayloadTechnique;
  riskLevel: PayloadRiskLevel;
  value: string;
  description: string;
  expectedBehavior: string;
  successIndicators: string[];
  failureIndicators: string[];
  applicableContexts: ("url_param" | "body_param" | "header" | "cookie" | "path")[];
  encoding?: "none" | "url" | "base64" | "html" | "unicode";
  dbTypes?: ("mysql" | "postgresql" | "mssql" | "oracle" | "sqlite")[];
}

export interface PayloadSet {
  category: PayloadCategory;
  name: string;
  description: string;
  payloads: Payload[];
}

export interface PayloadExecutionContext {
  targetUrl: string;
  parameterName: string;
  parameterLocation: "url_param" | "body_param" | "header" | "cookie" | "path";
  originalValue?: string;
  httpMethod: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Record<string, string>;
  timeout?: number;
}

export interface PayloadResult {
  payloadId: string;
  payload: string;
  success: boolean;
  confidence: number;
  responseCode: number;
  responseTime: number;
  matchedIndicators: string[];
  evidence: string;
  verdict: "confirmed" | "likely" | "theoretical" | "false_positive" | "error";
}

/** Prepared request with URL, optional body, and extra headers for payload injection. */
export interface PreparedRequest {
  url: string;
  body?: string;
  headers?: Record<string, string>;
}

/**
 * Build a PreparedRequest that injects the payload into the correct location
 * (URL query param, JSON body, header, cookie, or path segment).
 */
export function buildPayloadRequest(ctx: PayloadExecutionContext, payloadValue: string): PreparedRequest {
  switch (ctx.parameterLocation) {
    case "url_param": {
      const url = new URL(ctx.targetUrl);
      url.searchParams.set(ctx.parameterName, payloadValue);
      return { url: url.toString() };
    }
    case "body_param":
      return {
        url: ctx.targetUrl,
        body: JSON.stringify({ [ctx.parameterName]: payloadValue }),
        headers: { "Content-Type": "application/json" },
      };
    case "header":
      return {
        url: ctx.targetUrl,
        headers: { [ctx.parameterName]: payloadValue },
      };
    case "cookie":
      return {
        url: ctx.targetUrl,
        headers: { Cookie: `${ctx.parameterName}=${payloadValue}` },
      };
    case "path":
      return { url: ctx.targetUrl.replace(/\/[^/]*$/, `/${payloadValue}`) };
    default:
      return { url: ctx.targetUrl };
  }
}

export function generatePayloadId(category: PayloadCategory, technique: PayloadTechnique, index: number): string {
  return `${category}-${technique}-${String(index).padStart(3, "0")}`;
}
