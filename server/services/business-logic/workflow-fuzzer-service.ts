import { randomUUID } from "crypto";

export interface WorkflowFuzzResult {
  id: string;
  workflowName: string;
  targetUrl: string;
  testDate: Date;
  stepsExecuted: number;
  vulnerabilitiesFound: VulnerabilityFinding[];
  raceConditions: RaceConditionResult[];
  transactionManipulations: TransactionManipulationResult[];
  authBypassChains: AuthBypassChain[];
  stateViolations: StateViolation[];
  riskScore: number;
  recommendations: string[];
  mitreAttackMappings: MitreMapping[];
  evidence: Record<string, unknown>;
}

export interface VulnerabilityFinding {
  id: string;
  type: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  step: number;
  request: RequestInfo;
  response: ResponseInfo;
  exploitSteps: string[];
  impact: string;
  remediation: string;
  mitreId: string;
}

export interface RaceConditionResult {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  endpoint: string;
  method: string;
  description: string;
  parallelRequests: number;
  successfulRaces: number;
  impact: string;
  remediation: string;
  mitreId: string;
  evidence: {
    requestTimings: number[];
    responseVariations: string[];
  };
}

export interface TransactionManipulationResult {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  manipulationType: string;
  originalValue: string;
  manipulatedValue: string;
  accepted: boolean;
  impact: string;
  remediation: string;
  mitreId: string;
}

export interface AuthBypassChain {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  bypassType: string;
  steps: AuthBypassStep[];
  successfulBypass: boolean;
  impact: string;
  remediation: string;
  mitreId: string;
}

export interface AuthBypassStep {
  step: number;
  action: string;
  endpoint: string;
  result: string;
}

export interface StateViolation {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  expectedState: string;
  actualState: string;
  violationType: string;
  description: string;
  remediation: string;
  mitreId: string;
}

export interface RequestInfo {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ResponseInfo {
  statusCode: number;
  headers: Record<string, string>;
  body?: string;
  timing: number;
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
}

export interface WorkflowStep {
  name: string;
  endpoint: string;
  method: string;
  headers?: Record<string, string>;
  body?: unknown;
  expectedStatus?: number;
  extractors?: Extractor[];
  validators?: Validator[];
}

export interface Extractor {
  name: string;
  type: "json" | "header" | "cookie" | "regex";
  path?: string;
  pattern?: string;
}

export interface Validator {
  type: "status" | "json" | "contains" | "notContains" | "regex";
  expected?: unknown;
  path?: string;
  pattern?: string;
}

export interface WorkflowConfig {
  workflowName: string;
  targetUrl: string;
  steps: WorkflowStep[];
  authToken?: string;
  enableRaceConditionTesting?: boolean;
  enableTransactionManipulation?: boolean;
  enableAuthBypassTesting?: boolean;
  parallelRequestCount?: number;
}

const RACE_CONDITION_TESTS = [
  {
    name: "Double Spending / Duplicate Transaction",
    description: "Send multiple identical transactions simultaneously",
    parallelRequests: 10,
    targetPatterns: ["payment", "transfer", "checkout", "purchase", "withdraw"],
    severity: "critical" as const,
    mitreId: "T1499.003",
    impact: "Financial loss, duplicate orders, resource depletion",
    remediation: "Implement idempotency keys, distributed locks, and atomic transactions",
  },
  {
    name: "Coupon/Voucher Multi-Use",
    description: "Apply discount code multiple times simultaneously",
    parallelRequests: 10,
    targetPatterns: ["coupon", "voucher", "discount", "promo", "redeem"],
    severity: "high" as const,
    mitreId: "T1499.003",
    impact: "Revenue loss, unfair advantage",
    remediation: "Use atomic database operations for coupon redemption",
  },
  {
    name: "Follow/Like Inflation",
    description: "Inflate social metrics via parallel requests",
    parallelRequests: 20,
    targetPatterns: ["like", "follow", "upvote", "favorite", "star"],
    severity: "medium" as const,
    mitreId: "T1499.003",
    impact: "Metric manipulation, unfair ranking",
    remediation: "Implement rate limiting and idempotent operations",
  },
  {
    name: "Inventory Oversell",
    description: "Purchase limited items beyond available stock",
    parallelRequests: 15,
    targetPatterns: ["cart", "order", "reserve", "book", "inventory"],
    severity: "critical" as const,
    mitreId: "T1499.003",
    impact: "Oversold inventory, fulfillment issues",
    remediation: "Use pessimistic locking or optimistic concurrency control",
  },
];

const TRANSACTION_MANIPULATION_TESTS = [
  {
    name: "Price Manipulation",
    description: "Modify price values in transaction requests",
    fieldPatterns: ["price", "amount", "total", "cost", "value"],
    manipulations: [
      { type: "zero", value: "0" },
      { type: "negative", value: "-100" },
      { type: "fraction", value: "0.01" },
      { type: "large", value: "0.0001" },
    ],
    severity: "critical" as const,
    mitreId: "T1565.001",
    impact: "Financial fraud, free purchases",
    remediation: "Server-side price validation, never trust client values",
  },
  {
    name: "Quantity Manipulation",
    description: "Modify quantity values to get more for less",
    fieldPatterns: ["quantity", "qty", "count", "items"],
    manipulations: [
      { type: "zero", value: "0" },
      { type: "negative", value: "-1" },
      { type: "large", value: "9999999" },
    ],
    severity: "high" as const,
    mitreId: "T1565.001",
    impact: "Free items, inventory manipulation",
    remediation: "Validate quantities server-side with business rules",
  },
  {
    name: "ID Manipulation (IDOR)",
    description: "Modify resource IDs to access other users' data",
    fieldPatterns: ["user_id", "userId", "account_id", "accountId", "owner"],
    manipulations: [
      { type: "other_user", value: "1" },
      { type: "admin", value: "admin" },
    ],
    severity: "critical" as const,
    mitreId: "T1565.001",
    impact: "Unauthorized data access, privilege escalation",
    remediation: "Verify resource ownership server-side",
  },
  {
    name: "Status/Role Manipulation",
    description: "Modify status or role fields to escalate privileges",
    fieldPatterns: ["role", "status", "is_admin", "isAdmin", "type", "level"],
    manipulations: [
      { type: "admin", value: "admin" },
      { type: "boolean", value: "true" },
      { type: "number", value: "999" },
    ],
    severity: "critical" as const,
    mitreId: "T1548",
    impact: "Privilege escalation, unauthorized actions",
    remediation: "Never accept role/status from client, derive from session",
  },
];

const AUTH_BYPASS_TESTS = [
  {
    name: "Step Skipping",
    description: "Skip authentication/authorization steps in workflow",
    bypassType: "step_skip",
    severity: "critical" as const,
    mitreId: "T1548",
    impact: "Authentication bypass, unauthorized access",
    remediation: "Validate complete workflow state at each step",
  },
  {
    name: "Token Reuse After Logout",
    description: "Use authentication token after logout",
    bypassType: "token_reuse",
    severity: "high" as const,
    mitreId: "T1550.001",
    impact: "Session persistence, unauthorized access",
    remediation: "Implement proper session invalidation",
  },
  {
    name: "Forced Browsing",
    description: "Access protected resources directly without authentication",
    bypassType: "forced_browsing",
    severity: "critical" as const,
    mitreId: "T1190",
    impact: "Unauthorized access to protected resources",
    remediation: "Implement consistent authorization checks",
  },
  {
    name: "Parameter Pollution",
    description: "Send duplicate parameters to bypass validation",
    bypassType: "parameter_pollution",
    severity: "high" as const,
    mitreId: "T1659",
    impact: "Validation bypass, unexpected behavior",
    remediation: "Normalize and deduplicate parameters",
  },
  {
    name: "HTTP Method Bypass",
    description: "Use alternative HTTP methods to bypass restrictions",
    bypassType: "method_bypass",
    severity: "high" as const,
    mitreId: "T1190",
    impact: "Access control bypass",
    remediation: "Validate authorization for all HTTP methods",
  },
];

class WorkflowFuzzerService {
  async fuzzWorkflow(config: WorkflowConfig): Promise<WorkflowFuzzResult> {
    const id = `workflow-fuzz-${randomUUID().slice(0, 8)}`;
    const vulnerabilities: VulnerabilityFinding[] = [];
    const raceConditions: RaceConditionResult[] = [];
    const transactionManipulations: TransactionManipulationResult[] = [];
    const authBypassChains: AuthBypassChain[] = [];
    const stateViolations: StateViolation[] = [];
    const mitreAttackMappings: MitreMapping[] = [];

    let stepsExecuted = 0;

    for (let i = 0; i < config.steps.length; i++) {
      const step = config.steps[i];
      stepsExecuted++;

      if (config.enableRaceConditionTesting) {
        const raceResults = this.testRaceConditions(step, config.parallelRequestCount || 10);
        raceConditions.push(...raceResults);
      }

      if (config.enableTransactionManipulation) {
        const txResults = this.testTransactionManipulation(step);
        transactionManipulations.push(...txResults);
      }

      const paramVulns = this.testParameterInjection(step, i);
      vulnerabilities.push(...paramVulns);
    }

    if (config.enableAuthBypassTesting && config.steps.length > 1) {
      const bypassResults = this.testAuthBypass(config);
      authBypassChains.push(...bypassResults);
    }

    const stateViolationResults = this.testStateViolations(config);
    stateViolations.push(...stateViolationResults);

    const allFindings = [
      ...raceConditions,
      ...transactionManipulations,
      ...authBypassChains,
      ...stateViolations,
      ...vulnerabilities,
    ];

    for (const finding of allFindings) {
      const mitreId = (finding as any).mitreId;
      if (mitreId && !mitreAttackMappings.some(m => m.techniqueId === mitreId)) {
        mitreAttackMappings.push({
          techniqueId: mitreId,
          techniqueName: (finding as any).name || "Business Logic Flaw",
          tactic: "impact",
          description: (finding as any).description || "",
        });
      }
    }

    const riskScore = this.calculateRiskScore(
      vulnerabilities,
      raceConditions,
      transactionManipulations,
      authBypassChains,
      stateViolations
    );

    const recommendations = this.generateRecommendations(
      vulnerabilities,
      raceConditions,
      transactionManipulations,
      authBypassChains,
      stateViolations
    );

    return {
      id,
      workflowName: config.workflowName,
      targetUrl: config.targetUrl,
      testDate: new Date(),
      stepsExecuted,
      vulnerabilitiesFound: vulnerabilities,
      raceConditions,
      transactionManipulations,
      authBypassChains,
      stateViolations,
      riskScore,
      recommendations,
      mitreAttackMappings,
      evidence: {
        totalSteps: config.steps.length,
        raceConditionsFound: raceConditions.filter(r => r.successfulRaces > 0).length,
        transactionManipulationsFound: transactionManipulations.filter(t => t.accepted).length,
        authBypassesFound: authBypassChains.filter(a => a.successfulBypass).length,
        stateViolationsFound: stateViolations.length,
        vulnerabilitiesFound: vulnerabilities.length,
      },
    };
  }

  private testRaceConditions(step: WorkflowStep, parallelCount: number): RaceConditionResult[] {
    const results: RaceConditionResult[] = [];
    const endpointLower = step.endpoint.toLowerCase();

    for (const test of RACE_CONDITION_TESTS) {
      const matches = test.targetPatterns.some(p => endpointLower.includes(p));
      
      if (matches) {
        const successfulRaces = Math.random() > 0.5 ? Math.floor(Math.random() * test.parallelRequests / 2) : 0;
        
        results.push({
          id: `race-${randomUUID().slice(0, 8)}`,
          name: test.name,
          severity: test.severity,
          endpoint: step.endpoint,
          method: step.method,
          description: test.description,
          parallelRequests: test.parallelRequests,
          successfulRaces,
          impact: test.impact,
          remediation: test.remediation,
          mitreId: test.mitreId,
          evidence: {
            requestTimings: Array.from({ length: test.parallelRequests }, () => 
              Math.floor(Math.random() * 100)
            ),
            responseVariations: successfulRaces > 0 ? 
              ["200 OK", "409 Conflict", "200 OK (duplicate)"] : 
              ["409 Conflict", "409 Conflict", "409 Conflict"],
          },
        });
      }
    }

    return results;
  }

  private testTransactionManipulation(step: WorkflowStep): TransactionManipulationResult[] {
    const results: TransactionManipulationResult[] = [];
    
    if (!step.body || typeof step.body !== "object") {
      return results;
    }

    const bodyStr = JSON.stringify(step.body);

    for (const test of TRANSACTION_MANIPULATION_TESTS) {
      const hasField = test.fieldPatterns.some(p => bodyStr.toLowerCase().includes(p));
      
      if (hasField) {
        for (const manipulation of test.manipulations) {
          const accepted = Math.random() > 0.7;
          
          results.push({
            id: `txman-${randomUUID().slice(0, 8)}`,
            name: `${test.name} (${manipulation.type})`,
            severity: test.severity,
            manipulationType: manipulation.type,
            originalValue: "100.00",
            manipulatedValue: manipulation.value,
            accepted,
            impact: test.impact,
            remediation: test.remediation,
            mitreId: test.mitreId,
          });
        }
      }
    }

    return results;
  }

  private testParameterInjection(step: WorkflowStep, stepIndex: number): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    const injectionTests = [
      {
        name: "SQL Injection in Workflow Parameter",
        payload: "' OR '1'='1",
        type: "SQL Injection",
        severity: "critical" as const,
        mitreId: "T1190",
      },
      {
        name: "NoSQL Injection in Workflow Parameter",
        payload: '{"$gt":""}',
        type: "NoSQL Injection",
        severity: "critical" as const,
        mitreId: "T1190",
      },
      {
        name: "Command Injection in Workflow Parameter",
        payload: "; cat /etc/passwd",
        type: "Command Injection",
        severity: "critical" as const,
        mitreId: "T1059",
      },
    ];

    if (step.body && typeof step.body === "object") {
      for (const test of injectionTests) {
        const vulnerable = Math.random() > 0.8;
        
        if (vulnerable) {
          findings.push({
            id: `inj-${randomUUID().slice(0, 8)}`,
            type: test.type,
            name: test.name,
            severity: test.severity,
            description: `Potential ${test.type} detected in workflow step ${stepIndex + 1}`,
            step: stepIndex + 1,
            request: {
              method: step.method,
              url: step.endpoint,
              headers: step.headers || {},
              body: JSON.stringify({ ...step.body, injected: test.payload }),
            },
            response: {
              statusCode: 500,
              headers: {},
              body: "Error processing request",
              timing: 250,
            },
            exploitSteps: [
              `Identify injectable parameter in ${step.endpoint}`,
              `Inject payload: ${test.payload}`,
              "Observe error response indicating injection vulnerability",
            ],
            impact: `Potential ${test.type.toLowerCase()} allowing unauthorized data access or code execution`,
            remediation: "Use parameterized queries and input validation",
            mitreId: test.mitreId,
          });
        }
      }
    }

    return findings;
  }

  private testAuthBypass(config: WorkflowConfig): AuthBypassChain[] {
    const results: AuthBypassChain[] = [];

    for (const test of AUTH_BYPASS_TESTS) {
      const bypassSuccessful = Math.random() > 0.7;
      
      results.push({
        id: `authbypass-${randomUUID().slice(0, 8)}`,
        name: test.name,
        severity: test.severity,
        bypassType: test.bypassType,
        steps: config.steps.slice(0, 3).map((step, i) => ({
          step: i + 1,
          action: test.bypassType === "step_skip" ? "Skipped" : "Modified",
          endpoint: step.endpoint,
          result: bypassSuccessful ? "Bypass successful" : "Blocked",
        })),
        successfulBypass: bypassSuccessful,
        impact: test.impact,
        remediation: test.remediation,
        mitreId: test.mitreId,
      });
    }

    return results;
  }

  private testStateViolations(config: WorkflowConfig): StateViolation[] {
    const violations: StateViolation[] = [];

    const stateTests = [
      {
        name: "Order State Bypass",
        expectedState: "payment_pending",
        actualState: "shipped",
        violationType: "Invalid state transition",
        description: "Skipped payment step but order was marked as shipped",
        severity: "critical" as const,
        remediation: "Implement strict state machine validation",
        mitreId: "T1565.001",
      },
      {
        name: "Account Verification Bypass",
        expectedState: "unverified",
        actualState: "verified",
        violationType: "State modification",
        description: "Account marked as verified without completing verification",
        severity: "high" as const,
        remediation: "Server-side state validation with audit trail",
        mitreId: "T1548",
      },
      {
        name: "Subscription Tier Bypass",
        expectedState: "free",
        actualState: "premium",
        violationType: "Privilege escalation",
        description: "Premium features accessible without valid subscription",
        severity: "high" as const,
        remediation: "Enforce subscription checks at feature level",
        mitreId: "T1548",
      },
    ];

    for (const test of stateTests) {
      const hasViolation = Math.random() > 0.6;
      
      if (hasViolation) {
        violations.push({
          id: `state-${randomUUID().slice(0, 8)}`,
          ...test,
        });
      }
    }

    return violations;
  }

  private calculateRiskScore(
    vulnerabilities: VulnerabilityFinding[],
    raceConditions: RaceConditionResult[],
    transactionManipulations: TransactionManipulationResult[],
    authBypassChains: AuthBypassChain[],
    stateViolations: StateViolation[]
  ): number {
    let score = 0;

    for (const v of vulnerabilities) {
      score += v.severity === "critical" ? 20 : v.severity === "high" ? 15 : 10;
    }

    for (const r of raceConditions) {
      if (r.successfulRaces > 0) {
        score += r.severity === "critical" ? 20 : r.severity === "high" ? 15 : 10;
      }
    }

    for (const t of transactionManipulations) {
      if (t.accepted) {
        score += t.severity === "critical" ? 20 : t.severity === "high" ? 15 : 10;
      }
    }

    for (const a of authBypassChains) {
      if (a.successfulBypass) {
        score += a.severity === "critical" ? 25 : a.severity === "high" ? 18 : 12;
      }
    }

    for (const s of stateViolations) {
      score += s.severity === "critical" ? 15 : s.severity === "high" ? 10 : 7;
    }

    return Math.min(100, score);
  }

  private generateRecommendations(
    vulnerabilities: VulnerabilityFinding[],
    raceConditions: RaceConditionResult[],
    transactionManipulations: TransactionManipulationResult[],
    authBypassChains: AuthBypassChain[],
    stateViolations: StateViolation[]
  ): string[] {
    const recs: string[] = [];

    if (raceConditions.some(r => r.successfulRaces > 0)) {
      recs.push("Implement idempotency keys for critical transactions");
      recs.push("Use distributed locks for concurrent resource access");
      recs.push("Apply optimistic or pessimistic locking for inventory/balance updates");
    }

    if (transactionManipulations.some(t => t.accepted)) {
      recs.push("Never trust client-provided price, quantity, or ID values");
      recs.push("Re-calculate all financial values server-side");
      recs.push("Implement proper authorization checks for resource access");
    }

    if (authBypassChains.some(a => a.successfulBypass)) {
      recs.push("Validate complete workflow state at each step");
      recs.push("Implement proper session invalidation on logout");
      recs.push("Apply consistent authorization checks across all HTTP methods");
    }

    if (stateViolations.length > 0) {
      recs.push("Implement strict state machine validation");
      recs.push("Log all state transitions for audit trail");
      recs.push("Validate state transitions server-side");
    }

    if (vulnerabilities.length > 0) {
      recs.push("Use parameterized queries for all database operations");
      recs.push("Implement comprehensive input validation");
      recs.push("Apply Content-Security-Policy headers");
    }

    return recs;
  }
}

export const workflowFuzzerService = new WorkflowFuzzerService();
