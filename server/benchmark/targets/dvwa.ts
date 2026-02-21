import type { BenchmarkTarget } from "./types";

const dvwa: BenchmarkTarget = {
  name: "dvwa",
  displayName: "Damn Vulnerable Web Application",
  version: "latest",
  dockerImage: "vulnerables/web-dvwa:latest",
  port: 80,
  healthCheck: "/login.php",
  setup: async (targetUrl: string) => {
    // DVWA requires database initialization before use
    const resp = await fetch(`${targetUrl}/setup.php`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "create_db=Create+%2F+Reset+Database",
      redirect: "follow",
    });
    if (!resp.ok) {
      throw new Error(`DVWA setup failed: ${resp.status}`);
    }
    console.log("  DVWA database initialized");
  },
  expectedVulns: [
    { name: "SQL Injection", keywords: ["sqli", "sql injection", "sql", "injection"] },
    { name: "Cross-Site Scripting (XSS)", keywords: ["xss", "cross-site scripting", "script injection", "reflected xss", "stored xss"] },
    { name: "Command Injection", keywords: ["command injection", "os command", "rce", "remote code", "command_injection"] },
    { name: "File Inclusion", keywords: ["file inclusion", "lfi", "rfi", "local file", "remote file", "path traversal", "file_inclusion"] },
  ],
  scenarios: [
    {
      id: "dvwa-sqli",
      name: "DVWA SQL Injection",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nVulnerable web application (DVWA) with SQL injection at ${targetUrl}/vulnerabilities/sqli/?id=1\nThe 'id' parameter is passed directly to a SQL query without sanitization.\nTest for error-based, union-based, and blind SQL injection.\nCredentials: admin/password. Login at ${targetUrl}/login.php\nSecurity level is set to low.`,
      targetEndpoints: ["/vulnerabilities/sqli/?id=1"],
      expectedVulnTypes: ["sqli"],
    },
    {
      id: "dvwa-xss-reflected",
      name: "DVWA Reflected XSS",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nVulnerable web application (DVWA) with reflected XSS at ${targetUrl}/vulnerabilities/xss_r/?name=test\nThe 'name' parameter is reflected in the page output without sanitization.\nTest for reflected cross-site scripting.\nCredentials: admin/password. Login at ${targetUrl}/login.php`,
      targetEndpoints: ["/vulnerabilities/xss_r/?name=test"],
      expectedVulnTypes: ["xss"],
    },
    {
      id: "dvwa-command-injection",
      name: "DVWA Command Injection",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nVulnerable web application (DVWA) with command injection at ${targetUrl}/vulnerabilities/exec/\nPOST with 'ip' parameter is passed to a shell command (ping). The parameter can be chained with ; or | to execute arbitrary OS commands.\nCredentials: admin/password. Login at ${targetUrl}/login.php`,
      targetEndpoints: ["/vulnerabilities/exec/"],
      expectedVulnTypes: ["command_injection"],
    },
    {
      id: "dvwa-file-inclusion",
      name: "DVWA File Inclusion",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nVulnerable web application (DVWA) with local file inclusion at ${targetUrl}/vulnerabilities/fi/?page=include.php\nThe 'page' parameter allows including arbitrary files via path traversal (e.g., ../../etc/passwd).\nCredentials: admin/password. Login at ${targetUrl}/login.php`,
      targetEndpoints: ["/vulnerabilities/fi/?page=include.php"],
      expectedVulnTypes: ["file_inclusion"],
    },
    {
      id: "dvwa-xss-stored",
      name: "DVWA Stored XSS",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nVulnerable web application (DVWA) with stored XSS at ${targetUrl}/vulnerabilities/xss_s/\nThe guestbook form accepts 'txtName' and 'mtxMessage' fields and stores user input. The stored content is rendered without sanitization.\nCredentials: admin/password. Login at ${targetUrl}/login.php`,
      targetEndpoints: ["/vulnerabilities/xss_s/"],
      expectedVulnTypes: ["xss"],
    },
  ],
};

export default dvwa;
