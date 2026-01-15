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

export function generatePayloadId(category: PayloadCategory, technique: PayloadTechnique, index: number): string {
  return `${category}-${technique}-${String(index).padStart(3, "0")}`;
}
