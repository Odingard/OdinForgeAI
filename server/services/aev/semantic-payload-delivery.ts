/**
 * Semantic Payload Delivery — endpoint typing, gating, and request shaping.
 *
 * Classifies discovered endpoints by type (GraphQL, JSON API, auth, form, file, HTML)
 * and builds exploit requests that match each endpoint's expected input format.
 *
 * Used by ActiveExploitEngine.executeExploits() to stop sending
 * the wrong kind of request to every endpoint.
 */

export type SemanticEndpointType =
  | "graphql"
  | "json_api"
  | "auth_api"
  | "html"
  | "form_post"
  | "file"
  | "unknown";

export type SemanticEndpoint = {
  url: string;
  method: string;
  contentType?: string;
  params?: string[];
  formFields?: string[];
  jsonKeys?: string[];
  type: SemanticEndpointType;
};

export type SemanticPayload = {
  value: string;
  vulnClass: string;
  requiresBody?: boolean;
};

export type BuiltSemanticRequest = {
  method: string;
  headers: Record<string, string>;
  url: string;
  body?: string;
  skip?: boolean;
  skipReason?: string;
};

const AUTH_HINTS = ["auth", "login", "token", "session", "signin", "signup", "oauth"];
const FILE_HINTS = [".env", ".config", ".ini", ".yaml", ".yml", ".git/"];
const GRAPHQL_HINTS = ["/graphql", "/gql", "/graphiql"];

// ── Endpoint Classifier ──────────────────────────────────────────────────────

export function classifyEndpoint(input: {
  url: string;
  method?: string;
  contentType?: string;
  responseBody?: string;
  formFields?: string[];
  jsonKeys?: string[];
}): SemanticEndpointType {
  const url = input.url.toLowerCase();
  const ct = (input.contentType || "").toLowerCase();
  const body = (input.responseBody || "").toLowerCase();

  if (GRAPHQL_HINTS.some((h) => url.includes(h))) return "graphql";
  if (AUTH_HINTS.some((h) => url.includes(h))) return "auth_api";
  if (FILE_HINTS.some((h) => url.includes(h))) return "file";
  if (input.formFields && input.formFields.length > 0) return "form_post";
  if (ct.includes("application/json") || url.includes("/api/")) return "json_api";
  if (ct.includes("text/html")) return "html";
  if (body.includes("__schema") || body.includes("graphql")) return "graphql";

  return "unknown";
}

// ── Exploit Attempt Gating ───────────────────────────────────────────────────

/** Valid vuln classes per endpoint type. Everything else is skipped. */
const ENDPOINT_EXPLOIT_MATRIX: Record<SemanticEndpointType, string[]> = {
  graphql:   ["api_abuse", "auth_bypass", "sqli"],
  json_api:  ["sqli", "xss", "ssrf", "idor", "api_abuse", "command_injection", "auth_bypass", "business_logic"],
  auth_api:  ["auth_bypass", "jwt_abuse", "sqli", "idor"],
  form_post: ["sqli", "xss", "command_injection", "path_traversal", "auth_bypass"],
  html:      ["xss"],
  file:      [], // classification only — no exploit attempts
  unknown:   ["sqli", "xss", "ssrf", "command_injection", "path_traversal"],
};

export function gateAttempt(
  endpoint: SemanticEndpoint,
  payload: SemanticPayload
): { allowed: boolean; reason?: string } {
  // File/config endpoints: classification only, no exploit spam
  if (endpoint.type === "file") {
    return { allowed: false, reason: "file/config endpoint — classification only" };
  }

  // Check the exploit matrix
  const allowedClasses = ENDPOINT_EXPLOIT_MATRIX[endpoint.type] || ENDPOINT_EXPLOIT_MATRIX.unknown;
  if (!allowedClasses.includes(payload.vulnClass)) {
    return { allowed: false, reason: `${payload.vulnClass} not applicable to ${endpoint.type} endpoint` };
  }

  // Don't send body payloads to GET-only endpoints
  if (endpoint.method.toUpperCase() === "GET" && payload.requiresBody) {
    return { allowed: false, reason: "GET endpoint — body payload not applicable" };
  }

  // SPA login shells: skip, the real target is the auth API
  if (endpoint.type === "html" && AUTH_HINTS.some(h => endpoint.url.toLowerCase().includes(h))) {
    return { allowed: false, reason: "html login shell — target auth API instead" };
  }

  return { allowed: true };
}

// ── Semantic Request Builder ─────────────────────────────────────────────────

export function buildSemanticRequest(
  endpoint: SemanticEndpoint,
  payload: SemanticPayload
): BuiltSemanticRequest {
  const method = endpoint.method.toUpperCase();
  const gate = gateAttempt(endpoint, payload);

  if (!gate.allowed) {
    return {
      method,
      headers: {},
      url: endpoint.url,
      skip: true,
      skipReason: gate.reason,
    };
  }

  // GraphQL: wrap payload in valid query structure
  if (endpoint.type === "graphql") {
    if (payload.vulnClass === "api_abuse") {
      // Introspection probe
      return {
        method: "POST",
        url: endpoint.url,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: `{ __schema { types { name fields { name type { name } } } } }`,
        }),
      };
    }
    // SQLi/auth_bypass inside GraphQL query arguments
    return {
      method: "POST",
      url: endpoint.url,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: `{ search(input: "${payload.value}") { id } }`,
      }),
    };
  }

  // Auth API: send credential-shaped body
  if (endpoint.type === "auth_api") {
    return {
      method: method === "GET" ? "POST" : method,
      url: endpoint.url,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: payload.value,
        password: payload.value,
        username: payload.value,
      }),
    };
  }

  // JSON API: inject into discovered JSON keys
  if (endpoint.type === "json_api") {
    const keys = endpoint.jsonKeys?.length
      ? endpoint.jsonKeys
      : endpoint.params?.length
        ? endpoint.params
        : ["input"];

    const body: Record<string, string> = {};
    for (const key of keys) body[key] = payload.value;

    return {
      method: method === "GET" ? "POST" : method,
      url: endpoint.url,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    };
  }

  // Form POST: inject into form fields
  if (endpoint.type === "form_post") {
    const fields = endpoint.formFields?.length ? endpoint.formFields : ["input"];
    const params = new URLSearchParams();
    for (const f of fields) params.set(f, payload.value);

    return {
      method: method === "GET" ? "POST" : method,
      url: endpoint.url,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    };
  }

  // HTML / unknown: query param injection
  return {
    method: "GET",
    url: `${endpoint.url}${endpoint.url.includes("?") ? "&" : "?"}input=${encodeURIComponent(payload.value)}`,
    headers: {},
  };
}
