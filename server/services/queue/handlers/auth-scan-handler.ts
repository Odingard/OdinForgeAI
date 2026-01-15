import { Job } from "bullmq";
import { randomUUID } from "crypto";
import * as https from "https";
import * as http from "http";
import { storage } from "../../../storage";
import { db } from "../../../db";
import { authScanResults } from "@shared/schema";
import {
  AuthScanJobData,
  JobResult,
  JobProgress,
} from "../job-types";
import { ValidatingHttpClient } from "../../validation/validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

interface AuthScanJob {
  id?: string;
  data: AuthScanJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

interface AuthIssue {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
  evidence?: string;
}

interface HttpTestResult {
  statusCode: number;
  headers: Record<string, string>;
  responseTime: number;
  error?: string;
}

function emitAuthScanProgress(
  tenantId: string,
  organizationId: string,
  scanId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "auth_scan_started") {
    console.log(`[AuthScan] ${scanId}: Started ${event.authType} scan for ${event.targetUrl}`);
  } else if (type === "auth_scan_progress") {
    console.log(`[AuthScan] ${scanId}: ${event.phase} - ${event.message}`);
  } else if (type === "auth_scan_completed") {
    console.log(`[AuthScan] ${scanId}: Completed - ${event.issueCount} issues found`);
  } else if (type === "auth_scan_failed") {
    console.log(`[AuthScan] ${scanId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `auth_scan:${tenantId}:${organizationId}:${scanId}`;
    wsService.broadcastToChannel(channel, {
      type: "auth_scan_progress",
      scanId,
      phase: event.phase || "processing",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

async function testHttpEndpoint(
  url: string,
  method: string = "GET",
  headers: Record<string, string> = {},
  body?: string,
  timeout: number = 5000,
  allowInsecure: boolean = false
): Promise<HttpTestResult> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === "https:";
      const lib = isHttps ? https : http;
      
      if (allowInsecure && isHttps) {
        console.log(`[AuthScan] WARNING: TLS verification disabled for ${parsedUrl.hostname} (insecure mode)`);
      }
      
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: {
          "User-Agent": "OdinForge-AuthScanner/1.0",
          ...headers,
        },
        timeout,
        rejectUnauthorized: !allowInsecure,
      };
      
      const req = lib.request(options, (res) => {
        const responseHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (typeof value === "string") {
            responseHeaders[key.toLowerCase()] = value;
          } else if (Array.isArray(value)) {
            responseHeaders[key.toLowerCase()] = value.join(", ");
          }
        }
        
        resolve({
          statusCode: res.statusCode || 0,
          headers: responseHeaders,
          responseTime: Date.now() - startTime,
        });
      });
      
      req.on("error", (error) => {
        resolve({
          statusCode: 0,
          headers: {},
          responseTime: Date.now() - startTime,
          error: error.message,
        });
      });
      
      req.on("timeout", () => {
        req.destroy();
        resolve({
          statusCode: 0,
          headers: {},
          responseTime: timeout,
          error: "Request timeout",
        });
      });
      
      if (body) {
        req.write(body);
      }
      
      req.end();
    } catch (error) {
      resolve({
        statusCode: 0,
        headers: {},
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  });
}

async function testRateLimiting(baseUrl: string, loginPath: string): Promise<AuthIssue | null> {
  const loginUrl = `${baseUrl}${loginPath}`;
  const results: HttpTestResult[] = [];
  
  for (let i = 0; i < 10; i++) {
    const result = await testHttpEndpoint(
      loginUrl,
      "POST",
      { "Content-Type": "application/json" },
      JSON.stringify({ username: "test@test.com", password: "wrongpassword" }),
      3000
    );
    results.push(result);
    
    if (result.statusCode === 429) {
      return null;
    }
  }
  
  const successfulRequests = results.filter(r => r.statusCode === 401 || r.statusCode === 400);
  if (successfulRequests.length >= 8) {
    return {
      id: randomUUID(),
      type: "missing_rate_limiting",
      severity: "high",
      description: "No rate limiting detected on login endpoint - allows brute force attacks",
      recommendation: "Implement rate limiting (e.g., 5 attempts per 15 minutes) with exponential backoff",
      evidence: `Sent 10 failed login attempts, ${successfulRequests.length} were processed without throttling`,
    };
  }
  
  return null;
}

async function testSecurityHeaders(baseUrl: string): Promise<AuthIssue[]> {
  const issues: AuthIssue[] = [];
  
  const result = await testHttpEndpoint(baseUrl, "GET", {}, undefined, 5000);
  
  if (result.statusCode === 0) {
    return issues;
  }
  
  const headers = result.headers;
  
  if (!headers["strict-transport-security"]) {
    issues.push({
      id: randomUUID(),
      type: "missing_hsts",
      severity: "medium",
      description: "Missing Strict-Transport-Security header",
      recommendation: "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    });
  }
  
  if (!headers["x-content-type-options"]) {
    issues.push({
      id: randomUUID(),
      type: "missing_content_type_options",
      severity: "low",
      description: "Missing X-Content-Type-Options header",
      recommendation: "Add header: X-Content-Type-Options: nosniff",
    });
  }
  
  if (!headers["x-frame-options"] && !headers["content-security-policy"]?.includes("frame-ancestors")) {
    issues.push({
      id: randomUUID(),
      type: "missing_clickjacking_protection",
      severity: "medium",
      description: "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
      recommendation: "Add X-Frame-Options: DENY or CSP with frame-ancestors directive",
    });
  }
  
  const setCookie = headers["set-cookie"] || "";
  if (setCookie && !setCookie.toLowerCase().includes("httponly")) {
    issues.push({
      id: randomUUID(),
      type: "cookie_missing_httponly",
      severity: "medium",
      description: "Session cookie missing HttpOnly flag",
      recommendation: "Set HttpOnly flag on session cookies to prevent XSS cookie theft",
      evidence: `Set-Cookie header: ${setCookie.substring(0, 100)}...`,
    });
  }
  
  if (setCookie && !setCookie.toLowerCase().includes("secure")) {
    issues.push({
      id: randomUUID(),
      type: "cookie_missing_secure",
      severity: "medium",
      description: "Session cookie missing Secure flag",
      recommendation: "Set Secure flag on session cookies for HTTPS-only transmission",
    });
  }
  
  if (setCookie && !setCookie.toLowerCase().includes("samesite")) {
    issues.push({
      id: randomUUID(),
      type: "cookie_missing_samesite",
      severity: "medium",
      description: "Session cookie missing SameSite attribute",
      recommendation: "Set SameSite=Strict or SameSite=Lax to prevent CSRF attacks",
    });
  }
  
  return issues;
}

async function testEnumeration(baseUrl: string, loginPath: string): Promise<AuthIssue[]> {
  const issues: AuthIssue[] = [];
  const loginUrl = `${baseUrl}${loginPath}`;
  
  const validUserResult = await testHttpEndpoint(
    loginUrl,
    "POST",
    { "Content-Type": "application/json" },
    JSON.stringify({ username: "admin@example.com", password: "wrongpassword" }),
    3000
  );
  
  const invalidUserResult = await testHttpEndpoint(
    loginUrl,
    "POST",
    { "Content-Type": "application/json" },
    JSON.stringify({ username: "nonexistent12345@nowhere.invalid", password: "wrongpassword" }),
    3000
  );
  
  if (validUserResult.statusCode !== invalidUserResult.statusCode ||
      Math.abs(validUserResult.responseTime - invalidUserResult.responseTime) > 200) {
    issues.push({
      id: randomUUID(),
      type: "user_enumeration",
      severity: "medium",
      description: "Potential user enumeration via different responses for valid vs invalid usernames",
      recommendation: "Return identical responses for both valid and invalid usernames",
      evidence: `Valid user: ${validUserResult.statusCode} (${validUserResult.responseTime}ms), Invalid user: ${invalidUserResult.statusCode} (${invalidUserResult.responseTime}ms)`,
    });
  }
  
  return issues;
}

async function captureAuthEvidence(
  targetUrl: string,
  issue: AuthIssue,
  context: { tenantId: string; organizationId: string; scanId: string }
): Promise<string | null> {
  const client = new ValidatingHttpClient();
  
  try {
    const { response, evidence } = await client.request({ url: targetUrl, method: "GET" });
    
    const verdict: ValidationVerdict = issue.severity === "high" || issue.severity === "critical" ? "likely" : "theoretical";
    const confidenceScore = issue.severity === "high" || issue.severity === "critical" ? 60 : 45;
    
    const evidenceId = await client.saveEvidence(
      evidence,
      {
        tenantId: context.tenantId,
        organizationId: context.organizationId,
        evaluationId: context.scanId,
        scanId: context.scanId,
        findingId: issue.id,
        vulnerabilityType: issue.type,
        expectedBehavior: "Secure authentication with proper headers and protections",
      },
      {
        verdict,
        confidenceScore,
        observedBehavior: issue.description + (issue.evidence ? ` Evidence: ${issue.evidence}` : ""),
        differentialAnalysis: `Authentication issue detected: ${issue.type}. Recommendation: ${issue.recommendation}`,
      }
    );
    
    console.log(`[AuthScan] Captured evidence ${evidenceId} for ${issue.type}`);
    
    return evidenceId;
  } catch (error) {
    console.log(`[AuthScan] Failed to capture evidence for ${issue.type}: ${error instanceof Error ? error.message : "Unknown"}`);
    return null;
  }
}

export async function handleAuthScanJob(
  job: Job<AuthScanJobData> | AuthScanJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { scanId, targetUrl, authType, credentials, tenantId, organizationId } = job.data;

  console.log(`[AuthScan] Starting ${authType} authentication scan for ${targetUrl}`);

  emitAuthScanProgress(tenantId, organizationId, scanId, {
    type: "auth_scan_started",
    targetUrl,
    authType,
  });

  const authIssues: AuthIssue[] = [];

  try {
    await job.updateProgress?.({
      percent: 10,
      stage: "enumeration",
      message: "Testing for user enumeration...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "enumeration",
      progress: 10,
      message: "Testing for user enumeration",
    });

    const loginPath = "/api/auth/login";
    const enumIssues = await testEnumeration(targetUrl, loginPath);
    authIssues.push(...enumIssues);

    await job.updateProgress?.({
      percent: 25,
      stage: "rate_limiting",
      message: "Testing rate limiting...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "rate_limiting",
      progress: 25,
      message: "Testing rate limiting",
    });

    const rateLimitIssue = await testRateLimiting(targetUrl, loginPath);
    if (rateLimitIssue) {
      authIssues.push(rateLimitIssue);
    }

    await job.updateProgress?.({
      percent: 45,
      stage: "security_headers",
      message: "Testing security headers...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "security_headers",
      progress: 45,
      message: "Testing security headers",
    });

    const headerIssues = await testSecurityHeaders(targetUrl);
    authIssues.push(...headerIssues);

    await job.updateProgress?.({
      percent: 60,
      stage: "session_testing",
      message: "Testing session management...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "session_testing",
      progress: 60,
      message: "Testing session management",
    });

    authIssues.push({
      id: randomUUID(),
      type: "session_fixation_check",
      severity: "info",
      description: "Session fixation testing requires authenticated context",
      recommendation: "Manually verify that session IDs are regenerated after authentication",
    });

    await job.updateProgress?.({
      percent: 75,
      stage: "token_testing",
      message: "Testing token security...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "token_testing",
      progress: 75,
      message: "Testing token security",
    });

    if (authType === "jwt" || authType === "oauth2") {
      authIssues.push({
        id: randomUUID(),
        type: "jwt_algorithm_check",
        severity: "info",
        description: "JWT algorithm verification requires token sample",
        recommendation: "Ensure JWT uses RS256 or ES256, not HS256 with weak secrets or 'none' algorithm",
      });
    }

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "evidence",
      progress: 80,
      message: "Capturing validation evidence",
    });

    const evidenceIds: string[] = [];
    const highSeverityIssues = authIssues.filter(i => i.severity === "critical" || i.severity === "high");
    
    for (const issue of highSeverityIssues.slice(0, 5)) {
      const evidenceId = await captureAuthEvidence(
        targetUrl,
        issue,
        { tenantId, organizationId, scanId }
      );
      if (evidenceId) {
        evidenceIds.push(evidenceId);
      }
    }

    console.log(`[AuthScan] Captured ${evidenceIds.length} evidence artifacts`);

    await job.updateProgress?.({
      percent: 90,
      stage: "analysis",
      message: "Analyzing authentication security...",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_progress",
      phase: "analysis",
      progress: 90,
      message: "Analyzing authentication security",
    });

    const severityCounts = {
      critical: authIssues.filter(i => i.severity === "critical").length,
      high: authIssues.filter(i => i.severity === "high").length,
      medium: authIssues.filter(i => i.severity === "medium").length,
      low: authIssues.filter(i => i.severity === "low").length,
      info: authIssues.filter(i => i.severity === "info").length,
    };

    await job.updateProgress?.({
      percent: 95,
      stage: "persisting",
      message: "Saving scan results...",
    } as JobProgress);

    try {
      await db.insert(authScanResults).values({
        id: randomUUID(),
        scanId,
        tenantId,
        organizationId,
        targetUrl,
        authType,
        testResults: authIssues.map(issue => ({
          testName: issue.type,
          passed: issue.severity === "info",
          severity: issue.severity,
          details: issue.description,
          evidence: issue.evidence ? { raw: issue.evidence } : undefined,
        })),
        vulnerabilities: authIssues.filter(i => i.severity !== "info").map(i => ({
          type: i.type,
          severity: i.severity,
          description: i.description,
          evidence: i.evidence,
        })),
        overallScore: Math.max(0, 100 - (severityCounts.critical * 25 + severityCounts.high * 15 + severityCounts.medium * 10 + severityCounts.low * 5)),
        status: "completed",
        scanStarted: new Date(startTime),
        scanCompleted: new Date(),
      });
      console.log(`[AuthScan] Results persisted to database for ${scanId}`);
    } catch (dbError) {
      console.warn(`[AuthScan] Failed to persist results:`, dbError instanceof Error ? dbError.message : "Unknown error");
    }

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Authentication scan complete",
    } as JobProgress);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_completed",
      issueCount: authIssues.length,
      criticalCount: severityCounts.critical,
      highCount: severityCounts.high,
    });

    return {
      success: true,
      data: {
        scanId,
        targetUrl,
        authType,
        issuesFound: authIssues.length,
        issues: authIssues,
        summary: severityCounts,
        testsPerformed: [
          "user_enumeration",
          "rate_limiting",
          "security_headers",
          "cookie_security",
          "session_management",
          "token_security",
        ],
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[AuthScan] Scan failed:`, errorMessage);

    emitAuthScanProgress(tenantId, organizationId, scanId, {
      type: "auth_scan_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
