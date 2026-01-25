export interface RedirectTestResult {
  testName: string;
  description: string;
  vulnerability: string;
  passed: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  details: string;
  testedUrl: string;
  redirectLocation?: string;
  serverResponse?: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
  };
  mitreAttackId?: string;
  recommendation?: string;
}

export interface RedirectTestConfig {
  authorizationEndpoint: string;
  clientId: string;
  originalRedirectUri: string;
  state?: string;
  scope?: string;
  responseType?: string;
  additionalParams?: Record<string, string>;
  timeoutMs?: number;
  testTypes?: RedirectTestType[];
}

export type RedirectTestType = 
  | "open_redirect"
  | "subdomain_takeover"
  | "path_traversal"
  | "parameter_pollution"
  | "fragment_injection"
  | "protocol_downgrade"
  | "unicode_normalization"
  | "state_parameter";

interface RedirectPayload {
  name: string;
  payload: string;
  type: RedirectTestType;
  expectedBehavior: "reject" | "accept_with_warning";
  severity: "critical" | "high" | "medium" | "low";
}

class OAuthRedirectTester {
  private payloads: RedirectPayload[] = [];

  constructor() {
    this.initializePayloads();
  }

  private initializePayloads() {
    this.payloads = [
      { name: "External Domain", payload: "https://evil.com/callback", type: "open_redirect", expectedBehavior: "reject", severity: "critical" },
      { name: "External with Path Match", payload: "https://evil.com/legitimate.com/callback", type: "open_redirect", expectedBehavior: "reject", severity: "critical" },
      { name: "Subdomain Injection", payload: "https://evil.legitimate.com/callback", type: "subdomain_takeover", expectedBehavior: "reject", severity: "high" },
      { name: "Protocol-less URL", payload: "//evil.com/callback", type: "open_redirect", expectedBehavior: "reject", severity: "critical" },
      { name: "Backslash Confusion", payload: "https://legitimate.com\\@evil.com/callback", type: "open_redirect", expectedBehavior: "reject", severity: "high" },
      { name: "At Symbol Confusion", payload: "https://legitimate.com@evil.com/callback", type: "open_redirect", expectedBehavior: "reject", severity: "critical" },
      { name: "Null Byte Injection", payload: "https://legitimate.com/callback%00.evil.com", type: "open_redirect", expectedBehavior: "reject", severity: "high" },
      { name: "Path Traversal", payload: "https://legitimate.com/../../../evil.com", type: "path_traversal", expectedBehavior: "reject", severity: "high" },
      { name: "Double URL Encoding", payload: "https%253A%252F%252Fevil.com", type: "open_redirect", expectedBehavior: "reject", severity: "medium" },
      { name: "Unicode Domain", payload: "https://lеgitimate.com/callback", type: "unicode_normalization", expectedBehavior: "reject", severity: "high" },
      { name: "IPv4 Address", payload: "https://192.168.1.1/callback", type: "open_redirect", expectedBehavior: "reject", severity: "medium" },
      { name: "IPv6 Address", payload: "https://[::1]/callback", type: "open_redirect", expectedBehavior: "reject", severity: "medium" },
      { name: "Localhost Redirect", payload: "http://localhost/callback", type: "open_redirect", expectedBehavior: "reject", severity: "medium" },
      { name: "JavaScript Protocol", payload: "javascript:alert(document.domain)", type: "protocol_downgrade", expectedBehavior: "reject", severity: "critical" },
      { name: "Data Protocol", payload: "data:text/html,<script>alert(1)</script>", type: "protocol_downgrade", expectedBehavior: "reject", severity: "critical" },
      { name: "File Protocol", payload: "file:///etc/passwd", type: "protocol_downgrade", expectedBehavior: "reject", severity: "high" },
      { name: "HTTP Downgrade", payload: "http://legitimate.com/callback", type: "protocol_downgrade", expectedBehavior: "reject", severity: "medium" },
      { name: "Fragment Injection", payload: "https://legitimate.com/callback#evil.com", type: "fragment_injection", expectedBehavior: "accept_with_warning", severity: "low" },
      { name: "Query Pollution", payload: "https://legitimate.com/callback?redirect=evil.com", type: "parameter_pollution", expectedBehavior: "accept_with_warning", severity: "medium" },
      { name: "Double Redirect Param", payload: "https://legitimate.com/callback?redirect_uri=https://evil.com", type: "parameter_pollution", expectedBehavior: "reject", severity: "high" },
    ];
  }

  async runAllTests(config: RedirectTestConfig): Promise<RedirectTestResult[]> {
    const results: RedirectTestResult[] = [];

    results.push(...await this.testStateParameter(config));

    const testTypes = config.testTypes || [
      "open_redirect",
      "subdomain_takeover", 
      "path_traversal",
      "parameter_pollution",
      "fragment_injection",
      "protocol_downgrade",
      "unicode_normalization",
    ];

    for (const payload of this.payloads) {
      if (testTypes.includes(payload.type)) {
        const result = await this.testRedirectPayload(config, payload);
        results.push(result);
      }
    }

    results.push(...await this.testDynamicPayloads(config));

    return results;
  }

  private async testStateParameter(config: RedirectTestConfig): Promise<RedirectTestResult[]> {
    const results: RedirectTestResult[] = [];

    const noStateUrl = this.buildAuthUrl(config, { state: undefined });
    const noStateResponse = await this.testUrl(noStateUrl, config);

    results.push({
      testName: "State Parameter - Missing",
      description: "Tests if OAuth flow works without state parameter",
      vulnerability: "CSRF in OAuth Flow",
      passed: noStateResponse.statusCode >= 400,
      severity: "high",
      details: noStateResponse.statusCode < 400
        ? "OAuth flow accepted without state parameter - vulnerable to CSRF"
        : "Server correctly requires state parameter",
      testedUrl: noStateUrl,
      serverResponse: noStateResponse,
      mitreAttackId: "T1557",
      recommendation: "Always require and validate state parameter to prevent CSRF attacks",
    });

    const emptyStateUrl = this.buildAuthUrl(config, { state: "" });
    const emptyStateResponse = await this.testUrl(emptyStateUrl, config);

    results.push({
      testName: "State Parameter - Empty",
      description: "Tests if OAuth flow accepts empty state parameter",
      vulnerability: "CSRF in OAuth Flow",
      passed: emptyStateResponse.statusCode >= 400,
      severity: "medium",
      details: emptyStateResponse.statusCode < 400
        ? "OAuth flow accepted with empty state parameter"
        : "Server correctly rejects empty state parameter",
      testedUrl: emptyStateUrl,
      serverResponse: emptyStateResponse,
      mitreAttackId: "T1557",
      recommendation: "Validate that state parameter has sufficient entropy",
    });

    const weakStates = ["1", "abc", "state", "test", "12345"];
    for (const weakState of weakStates) {
      const weakStateUrl = this.buildAuthUrl(config, { state: weakState });
      const weakStateResponse = await this.testUrl(weakStateUrl, config);

      if (weakStateResponse.statusCode < 400) {
        results.push({
          testName: `State Parameter - Weak Value (${weakState})`,
          description: "Tests if OAuth flow accepts weak/predictable state values",
          vulnerability: "Weak State Parameter",
          passed: false,
          severity: "medium",
          details: `OAuth flow accepted weak state value "${weakState}" - may be vulnerable to CSRF`,
          testedUrl: weakStateUrl,
          serverResponse: weakStateResponse,
          mitreAttackId: "T1557",
          recommendation: "Use cryptographically random state values with sufficient entropy",
        });
        break;
      }
    }

    return results;
  }

  private async testRedirectPayload(
    config: RedirectTestConfig,
    payload: RedirectPayload
  ): Promise<RedirectTestResult> {
    const testUrl = this.buildAuthUrl(config, { redirect_uri: payload.payload });
    const response = await this.testUrl(testUrl, config);

    const wasAccepted = response.statusCode >= 200 && response.statusCode < 400;
    const wasRedirected = response.statusCode >= 300 && response.statusCode < 400;
    const redirectedToEvil = wasRedirected && 
      response.headers["location"]?.includes("evil") || 
      response.headers["location"]?.includes(payload.payload);

    const passed = payload.expectedBehavior === "reject" 
      ? !wasAccepted || !redirectedToEvil
      : true;

    return {
      testName: `Redirect URI - ${payload.name}`,
      description: `Tests if malicious redirect URI "${payload.payload.slice(0, 50)}..." is accepted`,
      vulnerability: `OAuth ${payload.type.replace(/_/g, " ")}`,
      passed,
      severity: payload.severity,
      details: wasAccepted && redirectedToEvil
        ? `Server accepted malicious redirect URI - vulnerable to ${payload.type}`
        : wasAccepted
        ? `Server returned success but did not redirect to malicious URL`
        : "Server correctly rejected malicious redirect URI",
      testedUrl: testUrl,
      redirectLocation: response.headers["location"],
      serverResponse: response,
      mitreAttackId: "T1557",
      recommendation: payload.type === "open_redirect"
        ? "Implement strict redirect URI validation with exact match or registered URI patterns"
        : `Implement protection against ${payload.type} attacks`,
    };
  }

  private async testDynamicPayloads(config: RedirectTestConfig): Promise<RedirectTestResult[]> {
    const results: RedirectTestResult[] = [];
    
    const originalUri = new URL(config.originalRedirectUri);

    const subdomainPayload = `${originalUri.protocol}//evil.${originalUri.hostname}${originalUri.pathname}`;
    const subdomainResult = await this.testSinglePayload(config, {
      name: "Dynamic Subdomain Injection",
      payload: subdomainPayload,
      type: "subdomain_takeover",
      expectedBehavior: "reject",
      severity: "high",
    });
    results.push(subdomainResult);

    const portPayload = `${originalUri.protocol}//${originalUri.hostname}:8080${originalUri.pathname}`;
    const portResult = await this.testSinglePayload(config, {
      name: "Port Injection",
      payload: portPayload,
      type: "open_redirect",
      expectedBehavior: "reject",
      severity: "medium",
    });
    results.push(portResult);

    const pathPayload = `${originalUri.protocol}//${originalUri.hostname}/malicious${originalUri.pathname}`;
    const pathResult = await this.testSinglePayload(config, {
      name: "Path Modification",
      payload: pathPayload,
      type: "path_traversal",
      expectedBehavior: "reject",
      severity: "medium",
    });
    results.push(pathResult);

    return results;
  }

  private async testSinglePayload(
    config: RedirectTestConfig,
    payload: RedirectPayload
  ): Promise<RedirectTestResult> {
    return this.testRedirectPayload(config, payload);
  }

  private buildAuthUrl(
    config: RedirectTestConfig,
    overrides: Partial<{
      redirect_uri: string;
      state: string | undefined;
      client_id: string;
      response_type: string;
      scope: string;
    }> = {}
  ): string {
    const url = new URL(config.authorizationEndpoint);
    
    url.searchParams.set("client_id", overrides.client_id ?? config.clientId);
    url.searchParams.set("response_type", overrides.response_type ?? config.responseType ?? "code");
    url.searchParams.set("redirect_uri", overrides.redirect_uri ?? config.originalRedirectUri);
    
    if (overrides.scope !== undefined || config.scope) {
      url.searchParams.set("scope", overrides.scope ?? config.scope ?? "openid");
    }
    
    if (overrides.state !== undefined) {
      if (overrides.state !== "") {
        url.searchParams.set("state", overrides.state);
      }
    } else if (config.state) {
      url.searchParams.set("state", config.state);
    }

    if (config.additionalParams) {
      for (const [key, value] of Object.entries(config.additionalParams)) {
        url.searchParams.set(key, value);
      }
    }

    return url.toString();
  }

  private async testUrl(
    url: string,
    config: RedirectTestConfig
  ): Promise<{ statusCode: number; headers: Record<string, string>; body?: string }> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs || 10000);

      const response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      let body: string | undefined;
      try {
        body = await response.text();
        body = body.slice(0, 1000);
      } catch {
      }

      return { statusCode: response.status, headers, body };
    } catch (error: any) {
      return { 
        statusCode: 0, 
        headers: {}, 
        body: `Error: ${error.message}` 
      };
    }
  }

  generateReport(results: RedirectTestResult[]): string {
    const lines: string[] = [
      "# OAuth Redirect URI Security Test Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Tests | ${results.length} |`,
      `| Passed | ${results.filter(r => r.passed).length} |`,
      `| Failed | ${results.filter(r => !r.passed).length} |`,
      `| Critical Issues | ${results.filter(r => !r.passed && r.severity === "critical").length} |`,
      `| High Issues | ${results.filter(r => !r.passed && r.severity === "high").length} |`,
      "",
    ];

    const criticals = results.filter(r => !r.passed && r.severity === "critical");
    if (criticals.length > 0) {
      lines.push("## Critical Vulnerabilities", "");
      for (const finding of criticals) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Tested URL:** \`${finding.testedUrl.slice(0, 100)}...\``);
        if (finding.redirectLocation) {
          lines.push(`- **Redirect Location:** \`${finding.redirectLocation}\``);
        }
        lines.push(`- **Recommendation:** ${finding.recommendation}`);
        lines.push("");
      }
    }

    const highs = results.filter(r => !r.passed && r.severity === "high");
    if (highs.length > 0) {
      lines.push("## High Severity Issues", "");
      for (const finding of highs) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Recommendation:** ${finding.recommendation}`);
        lines.push("");
      }
    }

    lines.push("## All Test Results", "");
    lines.push("| Test | Status | Severity |");
    lines.push("|------|--------|----------|");
    for (const result of results) {
      const status = result.passed ? "PASS" : "FAIL";
      lines.push(`| ${result.testName} | ${status} | ${result.severity} |`);
    }

    return lines.join("\n");
  }
}

export const oauthRedirectTester = new OAuthRedirectTester();
