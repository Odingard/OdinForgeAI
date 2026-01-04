/**
 * App Logic Analyzer - Deterministic IDOR/BOLA/Mass Assignment/Rate Limit Detection
 * 
 * This module provides fast, zero-LLM-cost analysis for common application logic vulnerabilities.
 * It uses structured endpoint metadata to detect:
 * - IDOR/BOLA (Insecure Direct Object Reference / Broken Object Level Authorization)
 * - Privilege boundary bypass
 * - Mass assignment vulnerabilities
 * - Rate limiting gaps on auth endpoints
 */

import type { AppLogicExposureData } from "@shared/schema";
import type { AEVAnalysisResult } from "./aev";

export interface AppLogicAnalysisInput {
  assetId: string;
  description: string;
  data: AppLogicExposureData;
}

interface DetectionResult {
  detected: boolean;
  confidence: number;
  impact: "critical" | "high" | "medium" | "low";
  attackSteps: string[];
  recommendation: string;
  technique: string;
}

/**
 * Analyze app logic exposure deterministically (no LLM call)
 */
export function analyzeAppLogicExposure(input: AppLogicAnalysisInput): AEVAnalysisResult {
  const { assetId, description, data } = input;
  
  const endpoint = data.endpoint || "";
  const method = (data.method || "GET").toUpperCase();
  const authRequired = data.authRequired ?? true;
  const roleRequired = data.roleRequired || null;
  const pathParams = data.pathParams || [];
  const objectIdParam = data.objectIdParam || "id";
  const ownershipEnforced = data.ownershipEnforced;
  const rateLimit = data.rateLimit || null;
  const sensitiveFields = data.sensitiveFields || [];
  const acceptsUserInput = data.acceptsUserInput ?? true;
  
  const detections: DetectionResult[] = [];
  
  // 1. IDOR/BOLA Detection
  const idorResult = detectIDOR(endpoint, pathParams, objectIdParam, ownershipEnforced, authRequired);
  if (idorResult.detected) {
    detections.push(idorResult);
  }
  
  // 2. Privilege Boundary Bypass Detection
  const privBypassResult = detectPrivilegeBoundaryBypass(roleRequired, ownershipEnforced);
  if (privBypassResult.detected) {
    detections.push(privBypassResult);
  }
  
  // 3. Mass Assignment Detection
  const massAssignResult = detectMassAssignment(acceptsUserInput, sensitiveFields, method);
  if (massAssignResult.detected) {
    detections.push(massAssignResult);
  }
  
  // 4. Rate Limit Gap Detection
  const rateLimitResult = detectRateLimitGap(endpoint, rateLimit);
  if (rateLimitResult.detected) {
    detections.push(rateLimitResult);
  }
  
  // Aggregate results
  if (detections.length === 0) {
    return buildNonExploitableResult(assetId, description);
  }
  
  return buildExploitableResult(assetId, description, detections);
}

function detectIDOR(
  endpoint: string,
  pathParams: string[],
  objectIdParam: string,
  ownershipEnforced: boolean | null | undefined,
  authRequired: boolean
): DetectionResult {
  // Check if there's an object ID in the path
  const idInPath = 
    pathParams.includes(objectIdParam) ||
    endpoint.includes("{id}") ||
    endpoint.includes("/:id") ||
    endpoint.includes(`{${objectIdParam}}`) ||
    endpoint.includes(`:${objectIdParam}`);
  
  if (idInPath && (ownershipEnforced === false || ownershipEnforced === null || ownershipEnforced === undefined)) {
    const confidence = authRequired ? 0.70 : 0.85;
    return {
      detected: true,
      confidence,
      impact: "high",
      attackSteps: [
        "Enumerate valid object IDs through other endpoints or predictable patterns",
        "Craft request with target object ID",
        "Access or modify object without authorization check"
      ],
      recommendation: "Enforce object-level authorization (BOLA/IDOR). Validate ownership/permissions server-side for every object access. Use indirect references or verify user has access to the specific resource.",
      technique: "T1078.004"  // Valid Accounts: Cloud Accounts (proxy for API auth bypass)
    };
  }
  
  return { detected: false, confidence: 0, impact: "low", attackSteps: [], recommendation: "", technique: "" };
}

function detectPrivilegeBoundaryBypass(
  roleRequired: string | null,
  ownershipEnforced: boolean | null | undefined
): DetectionResult {
  // If a role is required but ownership/authorization is unclear
  if (roleRequired && (ownershipEnforced === null || ownershipEnforced === undefined)) {
    return {
      detected: true,
      confidence: 0.65,
      impact: "high",
      attackSteps: [
        "Authenticate as lower-privileged user",
        "Attempt to access role-restricted endpoint",
        "Probe for missing authorization checks"
      ],
      recommendation: "Enforce role-based access controls server-side. Add authorization checks for privileged routes and verify scopes/claims. Use middleware to validate role requirements.",
      technique: "T1548"  // Abuse Elevation Control Mechanism
    };
  }
  
  return { detected: false, confidence: 0, impact: "low", attackSteps: [], recommendation: "", technique: "" };
}

function detectMassAssignment(
  acceptsUserInput: boolean,
  sensitiveFields: string[],
  method: string
): DetectionResult {
  // Mass assignment risk on write methods with sensitive fields
  const writeMethods = ["POST", "PUT", "PATCH"];
  
  if (acceptsUserInput && sensitiveFields.length > 0 && writeMethods.includes(method)) {
    return {
      detected: true,
      confidence: 0.60,
      impact: "medium",
      attackSteps: [
        "Inspect API request/response to identify hidden fields",
        "Add sensitive fields to request payload (e.g., role, isAdmin, permissions)",
        "Submit modified request to elevate privileges or modify protected data"
      ],
      recommendation: `Implement allow-lists for writable fields. Reject unexpected fields: ${sensitiveFields.join(", ")}. Validate payload schemas strictly and use DTOs to control what can be written.`,
      technique: "T1574"  // Hijack Execution Flow (proxy for data manipulation)
    };
  }
  
  return { detected: false, confidence: 0, impact: "low", attackSteps: [], recommendation: "", technique: "" };
}

function detectRateLimitGap(endpoint: string, rateLimit: string | null): DetectionResult {
  // Check for weak/missing rate limits on auth endpoints
  const isAuthEndpoint = 
    endpoint.includes("/login") ||
    endpoint.includes("/auth") ||
    endpoint.includes("/signin") ||
    endpoint.includes("/password") ||
    endpoint.includes("/reset") ||
    endpoint.includes("/verify") ||
    endpoint.includes("/otp") ||
    endpoint.includes("/token");
  
  if (isAuthEndpoint && (rateLimit === "none" || rateLimit === "weak")) {
    return {
      detected: true,
      confidence: 0.60,
      impact: "medium",
      attackSteps: [
        "Identify authentication endpoint lacking rate limiting",
        "Prepare credential list for stuffing attack",
        "Execute automated login attempts without throttling"
      ],
      recommendation: "Add strong rate limiting (e.g., 5 attempts per minute), implement CAPTCHA or step-up auth after failed attempts, and add account lockout policies for auth endpoints.",
      technique: "T1110"  // Brute Force
    };
  }
  
  return { detected: false, confidence: 0, impact: "low", attackSteps: [], recommendation: "", technique: "" };
}

function buildNonExploitableResult(assetId: string, description: string): AEVAnalysisResult {
  return {
    exploitable: false,
    confidence: 40,
    score: 25,
    attackPath: [
      {
        id: 1,
        title: "Logic Validation Review",
        description: "Endpoint analyzed for common app-logic vulnerabilities. No immediate risks detected based on provided metadata.",
        technique: "T1592",
        severity: "low"
      }
    ],
    impact: "No immediate exploitability detected. Continue manual review for edge cases.",
    recommendations: [
      {
        id: "rec-1",
        title: "Review Authorization Logic",
        description: "Review endpoint authorization and business logic. Add tests for BOLA/IDOR, role boundaries, and input validation.",
        priority: "low",
        type: "preventive"
      }
    ]
  };
}

function buildExploitableResult(
  assetId: string,
  description: string,
  detections: DetectionResult[]
): AEVAnalysisResult {
  // Find highest impact and confidence
  const impactOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const sorted = detections.sort((a, b) => impactOrder[b.impact] - impactOrder[a.impact]);
  
  const highestImpact = sorted[0].impact;
  const maxConfidence = Math.max(...detections.map(d => d.confidence));
  
  // Build attack path from all detections
  let stepId = 1;
  const attackPath = detections.flatMap(d => 
    d.attackSteps.map(step => ({
      id: stepId++,
      title: step.split(" ").slice(0, 4).join(" ") + "...",
      description: step,
      technique: d.technique,
      severity: d.impact
    }))
  );
  
  // Add final step
  attackPath.push({
    id: stepId,
    title: "Validate Persistence",
    description: "Verify unauthorized access persists and data/actions remain affected",
    technique: "T1098",
    severity: highestImpact
  });
  
  // Build recommendations
  const recommendations = detections.map((d, i) => ({
    id: `rec-${i + 1}`,
    title: getRecommendationTitle(d),
    description: d.recommendation,
    priority: d.impact,
    type: "remediation" as const
  }));
  
  // Calculate score
  const score = calculateScore(maxConfidence, highestImpact, true);
  
  return {
    exploitable: true,
    confidence: Math.round(maxConfidence * 100),
    score,
    attackPath,
    impact: buildImpactStatement(detections),
    recommendations
  };
}

function getRecommendationTitle(detection: DetectionResult): string {
  if (detection.technique === "T1078.004") return "Fix IDOR/BOLA Vulnerability";
  if (detection.technique === "T1548") return "Enforce Privilege Boundaries";
  if (detection.technique === "T1574") return "Prevent Mass Assignment";
  if (detection.technique === "T1110") return "Strengthen Rate Limiting";
  return "Mitigate Application Logic Flaw";
}

function buildImpactStatement(detections: DetectionResult[]): string {
  const issues = detections.map(d => {
    if (d.technique === "T1078.004") return "unauthorized access to user data";
    if (d.technique === "T1548") return "privilege escalation";
    if (d.technique === "T1574") return "data manipulation via mass assignment";
    if (d.technique === "T1110") return "credential stuffing attacks";
    return "application logic abuse";
  });
  
  return `Potential for ${issues.join(", ")}. This could lead to data breach, unauthorized actions, or account compromise.`;
}

function calculateScore(confidence: number, impact: string, exploitable: boolean): number {
  const impactWeight: Record<string, number> = { 
    critical: 1.0, 
    high: 0.85, 
    medium: 0.65, 
    low: 0.35 
  };
  
  const w = impactWeight[impact] || 0.5;
  let base = confidence * w;
  
  // Exploitability multiplier
  base *= exploitable ? 1.25 : 0.35;
  
  const final = base * 100;
  return Math.min(100, Math.round(final * 100) / 100);
}

/**
 * Auto-detect API patterns in evaluation description
 * Returns true if description contains API endpoint patterns
 */
export function detectsApiPatterns(description: string): boolean {
  if (!description) return false;
  
  const text = description.toLowerCase();
  
  // Check for API endpoint patterns
  const patterns = [
    /\/api\//,                           // /api/ paths
    /\/v\d+\//,                          // Versioned paths like /v1/, /v2/
    /\/(users|accounts|orders|products|items|posts|comments|messages|files|uploads|documents|resources|data)\//i,
    /\{[\w]+\}/,                         // Path params like {id}, {userId}
    /:[\w]+/,                            // Express-style params like :id
    /rest\s*api/i,                       // "REST API"
    /graphql/i,                          // GraphQL
    /endpoint/i,                         // Mentions endpoint
    /(GET|POST|PUT|PATCH|DELETE)\s+\//,  // HTTP methods with paths
    /authentication.*endpoint/i,          // Auth endpoints
    /login.*api/i,                       // Login API
    /authorization.*check/i,             // Auth checks mentioned
    /object.*id/i,                       // Object ID references
    /user.*data/i,                       // User data access
  ];
  
  return patterns.some(p => p.test(description));
}

/**
 * Extract API endpoint metadata from evaluation description
 * Attempts to parse endpoint info for automatic app-logic analysis
 */
export function extractEndpointMetadata(description: string): AppLogicExposureData | null {
  if (!description) return null;
  
  const text = description;
  
  // Try to extract endpoint path
  const pathPatterns = [
    /(?:endpoint|path|route|url)[:\s]+([\/\w\-\{\}:]+)/i,
    /(\/api\/[\w\-\/\{\}:]+)/i,
    /(\/v\d+\/[\w\-\/\{\}:]+)/i,
    /(\/[\w\-]+\/[\w\-\/\{\}:]+)/i,
  ];
  
  let endpoint = "";
  for (const pattern of pathPatterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      endpoint = match[1].trim();
      break;
    }
  }
  
  // Extract HTTP method
  const methodMatch = text.match(/(GET|POST|PUT|PATCH|DELETE)/i);
  const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";
  
  // Detect auth requirement hints
  const requiresAuth = /auth(entication|orization)?\s*(required|needed|enabled)/i.test(text) ||
                       /logged\s*in/i.test(text) ||
                       /protected/i.test(text) ||
                       !/public|unauthenticated|anonymous/i.test(text);
  
  // Detect ownership enforcement hints
  let ownershipEnforced: boolean | null = null;
  if (/ownership\s*(check|enforced|verified)/i.test(text) || 
      /user\s*can\s*only\s*access\s*(their|own)/i.test(text)) {
    ownershipEnforced = true;
  } else if (/no\s*ownership\s*check/i.test(text) ||
             /any\s*(user|authenticated)\s*can\s*access/i.test(text) ||
             /idor|bola/i.test(text)) {
    ownershipEnforced = false;
  }
  
  // Detect rate limiting hints
  let rateLimit: "none" | "weak" | "strong" | null = null;
  if (/no\s*rate\s*limit/i.test(text) || /unlimited\s*requests/i.test(text)) {
    rateLimit = "none";
  } else if (/weak\s*rate\s*limit/i.test(text) || /basic\s*throttl/i.test(text)) {
    rateLimit = "weak";
  } else if (/rate\s*limit(ed|ing)?/i.test(text) || /throttl(ed|ing)/i.test(text)) {
    rateLimit = "strong";
  }
  
  // Extract path params
  const pathParamMatches = endpoint.match(/\{(\w+)\}|:(\w+)/g) || [];
  const pathParams = pathParamMatches.map(p => p.replace(/[{}:]/g, ""));
  
  // Detect sensitive fields mentioned
  const sensitiveFieldPatterns = /(?:role|admin|isAdmin|permissions?|balance|credits?|password|secret|token|privilege)/gi;
  const sensitiveMatches = text.match(sensitiveFieldPatterns) || [];
  const sensitiveFields = Array.from(new Set(sensitiveMatches.map(s => s.toLowerCase())));
  
  // Only return if we found a valid endpoint path - require concrete evidence
  if (!endpoint || endpoint.length < 3) {
    return null;
  }
  
  return {
    endpoint,
    method,
    authRequired: requiresAuth,
    pathParams,
    objectIdParam: pathParams[0] || "id",
    ownershipEnforced,
    rateLimit,
    sensitiveFields,
    acceptsUserInput: ["POST", "PUT", "PATCH"].includes(method),
  };
}

/**
 * Try to auto-analyze description for app logic issues
 * Returns null if no API patterns detected
 */
export function tryAutoAnalyze(assetId: string, description: string): AEVAnalysisResult | null {
  if (!detectsApiPatterns(description)) {
    return null;
  }
  
  const metadata = extractEndpointMetadata(description);
  if (!metadata) {
    return null;
  }
  
  // Run analysis with extracted metadata
  return analyzeAppLogicExposure({
    assetId,
    description,
    data: metadata,
  });
}
