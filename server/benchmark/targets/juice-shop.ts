import type { BenchmarkTarget } from "./types";

const juiceShop: BenchmarkTarget = {
  name: "juice-shop",
  displayName: "OWASP Juice Shop",
  version: "v17.1.1",
  dockerImage: "bkimminich/juice-shop:v17.1.1",
  port: 3000,
  healthCheck: "/",
  expectedVulns: [
    { name: "SQL Injection", keywords: ["sqli", "sql injection", "sql", "injection"] },
    { name: "Cross-Site Scripting (XSS)", keywords: ["xss", "cross-site scripting", "script injection"] },
    { name: "Authentication Bypass", keywords: ["auth", "authentication", "bypass", "login", "credential", "auth_bypass", "authentication bypass"] },
    { name: "Path Traversal", keywords: ["path traversal", "directory traversal", "lfi", "file inclusion", "../", "path_traversal"] },
    { name: "SSRF", keywords: ["ssrf", "server-side request forgery", "request forgery"] },
    { name: "Command Injection", keywords: ["command injection", "os command", "rce", "remote code"] },
    { name: "Security Misconfiguration", keywords: ["misconfiguration", "header", "cors", "csp", "security header"] },
    { name: "Sensitive Data Exposure", keywords: ["sensitive data", "information disclosure", "exposure", "leak"] },
  ],
  scenarios: [
    {
      id: "js-search-sqli",
      name: "Search Parameter SQL Injection",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nWeb application with search functionality at ${targetUrl}/rest/products/search?q=test\nThe search parameter 'q' is passed to a database query. Test for SQL injection.\nKnown endpoints: GET /rest/products/search?q=, GET /api/Products, POST /rest/user/login (email/password)`,
      targetEndpoints: ["/rest/products/search?q=test"],
      expectedVulnTypes: ["sqli"],
    },
    {
      id: "js-login-auth",
      name: "Login Authentication Bypass",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nWeb application with login at ${targetUrl}/rest/user/login accepting JSON body { "email": "...", "password": "..." }\nThe login endpoint may be vulnerable to SQL injection in the email field allowing authentication bypass.\nAlso test for: default credentials, credential stuffing patterns, broken auth.\nKnown endpoints: POST /rest/user/login, GET /rest/user/whoami, GET /api/SecurityQuestions`,
      targetEndpoints: ["/rest/user/login"],
      expectedVulnTypes: ["sqli", "auth_bypass"],
    },
    {
      id: "js-api-surface",
      name: "API Attack Surface Analysis",
      exposureType: "configuration_weakness",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nWeb application running at ${targetUrl}. Analyze the full attack surface.\nKnown API endpoints:\n- GET /rest/products/search?q= (search, potential SQLi)\n- GET /api/Products (product listing)\n- POST /rest/user/login (authentication)\n- GET /rest/user/whoami (user info, may leak data)\n- GET /api/Feedbacks (user feedback, potential XSS storage)\n- POST /api/Feedbacks (submit feedback, potential stored XSS)\n- GET /api/Complaints (file upload endpoint)\n- GET /rest/admin/application-version (version disclosure)\n- GET /ftp (directory listing, sensitive files)\n- GET /api/SecurityQuestions (enumeration)\nFingerprint the application, scan ports, check TLS, and validate vulnerabilities.`,
      targetEndpoints: ["/rest/products/search", "/api/Products", "/rest/user/login"],
      expectedVulnTypes: ["sqli", "xss", "auth_bypass", "path_traversal", "misconfiguration"],
    },
    {
      id: "js-xss-feedback",
      name: "Stored XSS via Feedback",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nWeb application with a feedback submission form.\nPOST /api/Feedbacks accepts JSON: { "comment": "...", "rating": 5 }\nThe comment field may be rendered without sanitization on the admin page.\nTest for stored XSS, reflected XSS in search (GET /rest/products/search?q=), and DOM-based XSS.`,
      targetEndpoints: ["/api/Feedbacks", "/rest/products/search"],
      expectedVulnTypes: ["xss"],
    },
    {
      id: "js-file-traversal",
      name: "Path Traversal & File Access",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nWeb application with an FTP-like file server.\nGET /ftp — lists downloadable files (directory listing).\nGET /ftp/legal.md — serves a specific file by appending the filename to the /ftp/ path.\nThe file serving mechanism appends the filename directly to the path. Test for path traversal by injecting traversal payloads AS THE PATH SEGMENT after /ftp/.\nUse test_payloads with url="${targetUrl}/ftp", parameter="file", parameter_location="path", vuln_categories=["path_traversal"].\nKnown bypass technique: poison null byte (%2500) to bypass extension whitelist, e.g. /ftp/../../etc/passwd%2500.md\nAlso check: /api/Complaints endpoint accepts file uploads that could be exploited.`,
      targetEndpoints: ["/ftp", "/api/Complaints"],
      expectedVulnTypes: ["path_traversal"],
    },
  ],
};

export default juiceShop;
