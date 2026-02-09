import { FuzzTestCase, FuzzResult, FuzzPayload } from "./fuzzing-engine";

export interface FuzzExecutionConfig {
  targetBaseUrl: string;
  concurrency: number;
  timeoutMs: number;
  delayBetweenRequests: number;
  headers?: Record<string, string>;
  authentication?: {
    type: "bearer" | "basic" | "apiKey";
    token?: string;
    username?: string;
    password?: string;
    apiKeyHeader?: string;
    apiKeyValue?: string;
  };
  stopOnCritical?: boolean;
  maxTestCases?: number;
}

export interface FuzzExecutionProgress {
  totalTestCases: number;
  completedTestCases: number;
  anomaliesFound: number;
  criticalFindings: number;
  highFindings: number;
  currentEndpoint?: string;
  elapsedMs: number;
}

export interface FuzzExecutionResult {
  sessionId: string;
  targetBaseUrl: string;
  startedAt: Date;
  completedAt: Date;
  totalTestCases: number;
  completedTestCases: number;
  results: FuzzResult[];
  anomalies: FuzzResult[];
  summary: {
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    infoFindings: number;
    errorRate: number;
    averageResponseTime: number;
  };
}

class FuzzingExecutor {
  async executeTestCases(
    testCases: FuzzTestCase[],
    config: FuzzExecutionConfig,
    onProgress?: (progress: FuzzExecutionProgress) => void
  ): Promise<FuzzExecutionResult> {
    const sessionId = `fuzz-session-${Date.now()}`;
    const startedAt = new Date();
    const results: FuzzResult[] = [];
    const anomalies: FuzzResult[] = [];

    const casesToRun = config.maxTestCases 
      ? testCases.slice(0, config.maxTestCases) 
      : testCases;

    let completedCount = 0;

    for (let i = 0; i < casesToRun.length; i += config.concurrency) {
      const batch = casesToRun.slice(i, i + config.concurrency);
      
      const batchResults = await Promise.all(
        batch.map(tc => this.executeTestCase(tc, config))
      );

      for (const result of batchResults) {
        results.push(result);
        completedCount++;

        if (result.anomalyDetected) {
          anomalies.push(result);

          if (config.stopOnCritical && result.severity === "critical") {
            break;
          }
        }
      }

      if (onProgress) {
        onProgress({
          totalTestCases: casesToRun.length,
          completedTestCases: completedCount,
          anomaliesFound: anomalies.length,
          criticalFindings: anomalies.filter(a => a.severity === "critical").length,
          highFindings: anomalies.filter(a => a.severity === "high").length,
          currentEndpoint: batch[0]?.endpointPath,
          elapsedMs: Date.now() - startedAt.getTime(),
        });
      }

      if (config.stopOnCritical && anomalies.some(a => a.severity === "critical")) {
        break;
      }

      if (config.delayBetweenRequests > 0 && i + config.concurrency < casesToRun.length) {
        await this.delay(config.delayBetweenRequests);
      }
    }

    const completedAt = new Date();
    const responseTimes = results.map(r => r.responseTime).filter(t => t > 0);

    return {
      sessionId,
      targetBaseUrl: config.targetBaseUrl,
      startedAt,
      completedAt,
      totalTestCases: casesToRun.length,
      completedTestCases: completedCount,
      results,
      anomalies,
      summary: {
        criticalFindings: anomalies.filter(a => a.severity === "critical").length,
        highFindings: anomalies.filter(a => a.severity === "high").length,
        mediumFindings: anomalies.filter(a => a.severity === "medium").length,
        lowFindings: anomalies.filter(a => a.severity === "low").length,
        infoFindings: anomalies.filter(a => a.severity === "info").length,
        errorRate: results.filter(r => r.statusCode >= 500).length / results.length,
        averageResponseTime: responseTimes.length > 0 
          ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
          : 0,
      },
    };
  }

  private async executeTestCase(
    testCase: FuzzTestCase,
    config: FuzzExecutionConfig
  ): Promise<FuzzResult> {
    const startTime = Date.now();
    
    try {
      const url = this.buildUrl(testCase, config);
      const requestOptions = this.buildRequestOptions(testCase, config);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs);

      let response: Response;
      try {
        response = await fetch(url, {
          ...requestOptions,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      const responseTime = Date.now() - startTime;
      const responseBody = await this.safeReadBody(response);
      const responseHeaders = Object.fromEntries(response.headers.entries());

      const anomalyAnalysis = this.analyzeResponse(
        testCase,
        response.status,
        responseBody,
        responseHeaders,
        responseTime
      );

      return {
        testCaseId: testCase.id,
        endpointPath: testCase.endpointPath,
        method: testCase.method,
        parameter: testCase.parameter.name,
        payload: testCase.payload,
        statusCode: response.status,
        responseTime,
        responseBody: responseBody.slice(0, 5000),
        responseHeaders,
        anomalyDetected: anomalyAnalysis.detected,
        anomalyType: anomalyAnalysis.type,
        anomalyDetails: anomalyAnalysis.details,
        severity: anomalyAnalysis.severity,
      };
    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      
      return {
        testCaseId: testCase.id,
        endpointPath: testCase.endpointPath,
        method: testCase.method,
        parameter: testCase.parameter.name,
        payload: testCase.payload,
        statusCode: 0,
        responseTime,
        responseBody: `Error: ${error.message}`,
        anomalyDetected: error.name === "AbortError",
        anomalyType: error.name === "AbortError" ? "timeout" : "connection_error",
        anomalyDetails: error.message,
        severity: "info",
      };
    }
  }

  private buildUrl(testCase: FuzzTestCase, config: FuzzExecutionConfig): string {
    let path = testCase.endpointPath;
    const normalizedBase = config.targetBaseUrl.replace(/\/+$/, "");

    if (testCase.parameter.in === "path") {
      path = path.replace(`{${testCase.parameter.name}}`, String(testCase.payload.value));
    }

    const url = new URL(path.startsWith("/") ? path : `/${path}`, normalizedBase);

    if (testCase.parameter.in === "query") {
      url.searchParams.set(testCase.parameter.name, String(testCase.payload.value));
    }

    return url.toString();
  }

  private buildRequestOptions(
    testCase: FuzzTestCase,
    config: FuzzExecutionConfig
  ): RequestInit {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...config.headers,
    };

    if (config.authentication) {
      switch (config.authentication.type) {
        case "bearer":
          headers["Authorization"] = `Bearer ${config.authentication.token}`;
          break;
        case "basic":
          const credentials = Buffer.from(
            `${config.authentication.username}:${config.authentication.password}`
          ).toString("base64");
          headers["Authorization"] = `Basic ${credentials}`;
          break;
        case "apiKey":
          if (config.authentication.apiKeyHeader && config.authentication.apiKeyValue) {
            headers[config.authentication.apiKeyHeader] = config.authentication.apiKeyValue;
          }
          break;
      }
    }

    if (testCase.parameter.in === "header") {
      headers[testCase.parameter.name] = String(testCase.payload.value);
    }

    const options: RequestInit = {
      method: testCase.method,
      headers,
    };

    if (["POST", "PUT", "PATCH"].includes(testCase.method) && testCase.parameter.in === "body") {
      const body: Record<string, any> = {};
      this.setNestedValue(body, testCase.parameter.name, testCase.payload.value);
      options.body = JSON.stringify(body);
    }

    return options;
  }

  private setNestedValue(obj: Record<string, any>, path: string, value: any): void {
    const keys = path.split(".");
    let current = obj;

    for (let i = 0; i < keys.length - 1; i++) {
      if (!(keys[i] in current)) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }

    current[keys[keys.length - 1]] = value;
  }

  private async safeReadBody(response: Response): Promise<string> {
    try {
      return await response.text();
    } catch {
      return "";
    }
  }

  private analyzeResponse(
    testCase: FuzzTestCase,
    statusCode: number,
    responseBody: string,
    _responseHeaders: Record<string, string>,
    responseTime: number
  ): { detected: boolean; type?: string; details?: string; severity?: FuzzResult["severity"] } {
    const payload = testCase.payload;
    const bodyLower = responseBody.toLowerCase();

    if (statusCode === 500) {
      const errorPatterns = [
        { pattern: /sql|mysql|postgresql|oracle|sqlite/i, type: "sql_error", severity: "critical" as const },
        { pattern: /syntax error|parse error/i, type: "syntax_error", severity: "high" as const },
        { pattern: /stack trace|traceback/i, type: "stack_trace", severity: "high" as const },
        { pattern: /exception|error/i, type: "server_error", severity: "medium" as const },
      ];

      for (const { pattern, type, severity } of errorPatterns) {
        if (pattern.test(responseBody)) {
          return {
            detected: true,
            type,
            details: `Server returned 500 with ${type} indicators. Payload: ${JSON.stringify(payload.value).slice(0, 100)}`,
            severity,
          };
        }
      }

      return {
        detected: true,
        type: "internal_server_error",
        details: `Server returned 500 error. Payload category: ${payload.category}`,
        severity: "medium",
      };
    }

    if (payload.category === "injection") {
      const reflectionPatterns = [
        { pattern: /<script>/i, type: "xss_reflection", severity: "critical" as const },
        { pattern: /onerror\s*=/i, type: "xss_reflection", severity: "critical" as const },
        { pattern: /onload\s*=/i, type: "xss_reflection", severity: "critical" as const },
      ];

      const payloadStr = String(payload.value).toLowerCase();
      if (bodyLower.includes(payloadStr.slice(0, 20))) {
        for (const { pattern, type, severity } of reflectionPatterns) {
          if (pattern.test(responseBody)) {
            return {
              detected: true,
              type,
              details: `Injection payload reflected in response without sanitization`,
              severity,
            };
          }
        }
      }

      const sqlErrorPatterns = [
        /you have an error in your sql syntax/i,
        /unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /ORA-\d+/,
        /PG::SyntaxError/,
        /sqlite3\.OperationalError/i,
      ];

      for (const pattern of sqlErrorPatterns) {
        if (pattern.test(responseBody)) {
          return {
            detected: true,
            type: "sql_injection_error",
            details: `SQL error message detected in response`,
            severity: "critical",
          };
        }
      }
    }

    if (responseTime > 5000 && payload.subcategory?.includes("sleep")) {
      return {
        detected: true,
        type: "time_based_injection",
        details: `Response time (${responseTime}ms) suggests time-based injection vulnerability`,
        severity: "critical",
      };
    }

    if (payload.category === "boundary_value" && statusCode === 200) {
      if (payload.subcategory?.includes("overflow") || payload.subcategory?.includes("max")) {
        return {
          detected: true,
          type: "boundary_accepted",
          details: `Boundary value accepted without validation: ${payload.description}`,
          severity: "medium",
        };
      }
    }

    if (payload.category === "null_injection" && statusCode === 200) {
      if (payload.value === null || payload.value === undefined) {
        return {
          detected: true,
          type: "null_accepted",
          details: `Null/undefined value accepted for required field`,
          severity: "medium",
        };
      }
    }

    const sensitivePatterns = [
      { pattern: /password\s*[:=]\s*["'][^"']+["']/i, type: "password_disclosure" },
      { pattern: /api[_-]?key\s*[:=]\s*["'][^"']+["']/i, type: "api_key_disclosure" },
      { pattern: /secret\s*[:=]\s*["'][^"']+["']/i, type: "secret_disclosure" },
      { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: "email_disclosure" },
    ];

    for (const { pattern, type } of sensitivePatterns) {
      if (pattern.test(responseBody) && statusCode >= 400) {
        return {
          detected: true,
          type,
          details: `Sensitive information potentially disclosed in error response`,
          severity: "high",
        };
      }
    }

    return { detected: false };
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  generateReport(result: FuzzExecutionResult): string {
    const lines: string[] = [
      "# API Fuzzing Report",
      "",
      `**Target:** ${result.targetBaseUrl}`,
      `**Session ID:** ${result.sessionId}`,
      `**Started:** ${result.startedAt.toISOString()}`,
      `**Completed:** ${result.completedAt.toISOString()}`,
      `**Duration:** ${(result.completedAt.getTime() - result.startedAt.getTime()) / 1000}s`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Test Cases | ${result.totalTestCases} |`,
      `| Completed | ${result.completedTestCases} |`,
      `| Anomalies Found | ${result.anomalies.length} |`,
      `| Critical | ${result.summary.criticalFindings} |`,
      `| High | ${result.summary.highFindings} |`,
      `| Medium | ${result.summary.mediumFindings} |`,
      `| Low | ${result.summary.lowFindings} |`,
      `| Error Rate | ${(result.summary.errorRate * 100).toFixed(1)}% |`,
      `| Avg Response Time | ${result.summary.averageResponseTime.toFixed(0)}ms |`,
      "",
    ];

    if (result.summary.criticalFindings > 0) {
      lines.push("## Critical Findings", "");
      const criticals = result.anomalies.filter(a => a.severity === "critical");
      for (const finding of criticals) {
        lines.push(`### ${finding.anomalyType}`);
        lines.push(`- **Endpoint:** ${finding.method} ${finding.endpointPath}`);
        lines.push(`- **Parameter:** ${finding.parameter}`);
        lines.push(`- **Payload Category:** ${finding.payload.category}`);
        lines.push(`- **Details:** ${finding.anomalyDetails}`);
        lines.push("");
      }
    }

    if (result.summary.highFindings > 0) {
      lines.push("## High Findings", "");
      const highs = result.anomalies.filter(a => a.severity === "high");
      for (const finding of highs) {
        lines.push(`### ${finding.anomalyType}`);
        lines.push(`- **Endpoint:** ${finding.method} ${finding.endpointPath}`);
        lines.push(`- **Parameter:** ${finding.parameter}`);
        lines.push(`- **Payload Category:** ${finding.payload.category}`);
        lines.push(`- **Details:** ${finding.anomalyDetails}`);
        lines.push("");
      }
    }

    lines.push("## All Anomalies by Endpoint", "");
    
    const byEndpoint = new Map<string, FuzzResult[]>();
    for (const anomaly of result.anomalies) {
      const key = `${anomaly.method} ${anomaly.endpointPath}`;
      if (!byEndpoint.has(key)) {
        byEndpoint.set(key, []);
      }
      byEndpoint.get(key)!.push(anomaly);
    }

    for (const [endpoint, findings] of Array.from(byEndpoint)) {
      lines.push(`### ${endpoint}`);
      lines.push("");
      lines.push("| Parameter | Type | Severity | Details |");
      lines.push("|-----------|------|----------|---------|");
      for (const f of findings) {
        lines.push(`| ${f.parameter} | ${f.anomalyType} | ${f.severity} | ${f.anomalyDetails?.slice(0, 50)}... |`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }
}

export const fuzzingExecutor = new FuzzingExecutor();
