import type { BenchmarkTarget } from "./types";

const webgoat: BenchmarkTarget = {
  name: "webgoat",
  displayName: "OWASP WebGoat",
  version: "v2023.8",
  dockerImage: "webgoat/webgoat:v2023.8",
  port: 8080,
  healthCheck: "/WebGoat",
  expectedVulns: [
    { name: "SQL Injection", keywords: ["sqli", "sql injection", "sql", "injection"] },
    { name: "JWT Manipulation", keywords: ["jwt", "json web token", "token", "jwt manipulation", "algorithm"] },
    { name: "Path Traversal", keywords: ["path traversal", "directory traversal", "lfi", "file inclusion", "../", "path_traversal"] },
    { name: "Cross-Site Scripting (XSS)", keywords: ["xss", "cross-site scripting", "script injection", "dom xss"] },
  ],
  scenarios: [
    {
      id: "wg-sqli",
      name: "WebGoat SQL Injection",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nOWASP WebGoat training application with SQL injection lessons.\nThe application at ${targetUrl}/WebGoat/SqlInjection/attack accepts POST requests with user input concatenated into SQL queries without parameterization.\nTest for SQL injection in form parameters.\nAlso check: ${targetUrl}/WebGoat/SqlInjectionAdvanced/ for advanced injection techniques.`,
      targetEndpoints: ["/WebGoat/SqlInjection/attack"],
      expectedVulnTypes: ["sqli"],
    },
    {
      id: "wg-jwt",
      name: "WebGoat JWT Manipulation",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nOWASP WebGoat JWT lesson at ${targetUrl}/WebGoat/JWT/\nThe application uses JSON Web Tokens that may be vulnerable to:\n- Algorithm confusion (none algorithm bypass)\n- Weak signing keys\n- Token forgery via header manipulation\nTest the /WebGoat/JWT/votings endpoint for JWT-based authentication bypass.`,
      targetEndpoints: ["/WebGoat/JWT/"],
      expectedVulnTypes: ["jwt"],
    },
    {
      id: "wg-path-traversal",
      name: "WebGoat Path Traversal",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nOWASP WebGoat path traversal exercise at ${targetUrl}/WebGoat/PathTraversal/\nThe application serves files with insufficient path validation. File parameters may allow reading arbitrary files via ../ sequences.\nTest for directory traversal and local file inclusion.`,
      targetEndpoints: ["/WebGoat/PathTraversal/"],
      expectedVulnTypes: ["path_traversal"],
    },
    {
      id: "wg-xss",
      name: "WebGoat Cross-Site Scripting",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nOWASP WebGoat XSS lesson at ${targetUrl}/WebGoat/CrossSiteScripting/\nEndpoints reflect or store user input without proper encoding.\nTest for reflected XSS, stored XSS, and DOM-based XSS via URL fragment manipulation.`,
      targetEndpoints: ["/WebGoat/CrossSiteScripting/"],
      expectedVulnTypes: ["xss"],
    },
  ],
};

export default webgoat;
