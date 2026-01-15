/**
 * Business Logic Attack Engine
 * 
 * Orchestrates business logic vulnerability testing with configurable
 * scenario templates and step-by-step execution.
 */

import { createHash } from "crypto";
import { IdorTestModule } from "./idor-tests";
import { RaceConditionModule } from "./race-conditions";
import { WorkflowBypassModule } from "./workflow-bypass";
import { ValidatingHttpClient, type ValidationContext } from "../../validation/validating-http-client";

export interface BusinessLogicScenario {
  id: string;
  name: string;
  description: string;
  category: "idor" | "race_condition" | "price_manipulation" | "workflow_bypass" | "mass_assignment" | "privilege_escalation";
  riskLevel: "low" | "medium" | "high" | "critical";
  steps: ScenarioStep[];
  requiredContext: string[];
  expectedImpact: string;
}

export interface ScenarioStep {
  id: string;
  name: string;
  action: "request" | "compare" | "verify" | "extract" | "manipulate";
  config: StepConfig;
  expectedResult?: string;
  abortOnFailure?: boolean;
}

interface StepConfig {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  endpoint?: string;
  body?: Record<string, any>;
  headers?: Record<string, string>;
  extractField?: string;
  compareWith?: string;
  manipulation?: ManipulationConfig;
}

interface ManipulationConfig {
  type: "increment" | "decrement" | "swap" | "modify" | "remove" | "add";
  field: string;
  value?: any;
}

export interface ScenarioResult {
  scenarioId: string;
  success: boolean;
  vulnerabilityFound: boolean;
  severity?: "low" | "medium" | "high" | "critical";
  stepResults: StepResult[];
  evidence: string;
  proofArtifacts: ProofArtifact[];
  businessImpact?: string;
  executionTimeMs: number;
}

interface StepResult {
  stepId: string;
  success: boolean;
  output?: any;
  error?: string;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

export interface EngineConfig {
  baseUrl: string;
  authToken?: string;
  sessionCookie?: string;
  userId?: string;
  headers?: Record<string, string>;
}

export class BusinessLogicEngine {
  private config: EngineConfig;
  private idorModule: IdorTestModule;
  private raceModule: RaceConditionModule;
  private workflowModule: WorkflowBypassModule;
  private httpClient: ValidatingHttpClient;
  private contextData: Map<string, any> = new Map();
  private validationContext?: ValidationContext;

  constructor(config: EngineConfig, validationContext?: ValidationContext) {
    this.config = config;
    this.validationContext = validationContext;
    this.idorModule = new IdorTestModule();
    this.raceModule = new RaceConditionModule();
    this.workflowModule = new WorkflowBypassModule();
    this.httpClient = new ValidatingHttpClient({ timeout: 10000 });
  }

  async runScenario(scenario: BusinessLogicScenario): Promise<ScenarioResult> {
    const startTime = Date.now();
    const stepResults: StepResult[] = [];
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];

    let vulnerabilityFound = false;
    let severity: ScenarioResult["severity"];

    for (const step of scenario.steps) {
      try {
        const result = await this.executeStep(step);
        stepResults.push(result);

        if (result.success && result.output) {
          this.contextData.set(step.id, result.output);
        }

        if (!result.success && step.abortOnFailure) {
          evidence.push(`Step ${step.name} failed: ${result.error}`);
          break;
        }
      } catch (err) {
        const error = err instanceof Error ? err.message : "Unknown error";
        stepResults.push({
          stepId: step.id,
          success: false,
          error,
        });
        
        if (step.abortOnFailure) {
          evidence.push(`Step ${step.name} threw error: ${error}`);
          break;
        }
      }
    }

    const successfulSteps = stepResults.filter(r => r.success);
    vulnerabilityFound = successfulSteps.length === scenario.steps.length;

    if (vulnerabilityFound) {
      severity = scenario.riskLevel;
      evidence.push(`${scenario.name} vulnerability confirmed`);
      
      proofArtifacts.push({
        type: "scenario_execution",
        description: scenario.description,
        data: JSON.stringify(stepResults),
        hash: createHash("sha256").update(JSON.stringify(stepResults)).digest("hex"),
        capturedAt: new Date(),
      });
    }

    return {
      scenarioId: scenario.id,
      success: true,
      vulnerabilityFound,
      severity,
      stepResults,
      evidence: evidence.join("; "),
      proofArtifacts,
      businessImpact: vulnerabilityFound ? scenario.expectedImpact : undefined,
      executionTimeMs: Date.now() - startTime,
    };
  }

  async runCategoryTests(
    category: BusinessLogicScenario["category"],
    customConfig?: Partial<EngineConfig>
  ): Promise<ScenarioResult[]> {
    const config = { ...this.config, ...customConfig };
    const results: ScenarioResult[] = [];

    switch (category) {
      case "idor":
        const idorResult = await this.idorModule.runFullTest({
          baseUrl: config.baseUrl,
          authToken: config.authToken,
          targetUserId: config.userId,
          headers: config.headers,
        });
        results.push(this.convertToScenarioResult("idor", idorResult));
        break;

      case "race_condition":
        const raceResult = await this.raceModule.runFullTest({
          targetUrl: config.baseUrl,
          authToken: config.authToken,
          headers: config.headers,
        });
        results.push(this.convertToScenarioResult("race_condition", raceResult));
        break;

      case "workflow_bypass":
        const workflowResult = await this.workflowModule.runFullTest({
          baseUrl: config.baseUrl,
          authToken: config.authToken,
          headers: config.headers,
        });
        results.push(this.convertToScenarioResult("workflow_bypass", workflowResult));
        break;

      default:
        break;
    }

    return results;
  }

  private async executeStep(step: ScenarioStep): Promise<StepResult> {
    switch (step.action) {
      case "request":
        return this.executeRequest(step);
      case "compare":
        return this.executeCompare(step);
      case "verify":
        return this.executeVerify(step);
      case "extract":
        return this.executeExtract(step);
      case "manipulate":
        return this.executeManipulate(step);
      default:
        return { stepId: step.id, success: false, error: "Unknown action" };
    }
  }

  private async executeRequest(step: ScenarioStep): Promise<StepResult> {
    const { config } = step;
    if (!config.endpoint) {
      return { stepId: step.id, success: false, error: "No endpoint specified" };
    }

    try {
      const url = new URL(config.endpoint, this.config.baseUrl);
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...this.config.headers,
        ...config.headers,
      };

      if (this.config.authToken) {
        headers["Authorization"] = `Bearer ${this.config.authToken}`;
      }
      if (this.config.sessionCookie) {
        headers["Cookie"] = this.config.sessionCookie;
      }

      const { response, evidence } = await this.httpClient.request(
        {
          method: config.method || "GET",
          url: url.toString(),
          headers,
          body: config.body ? JSON.stringify(config.body) : undefined,
        },
        this.validationContext
      );

      let parsed: any;
      try {
        parsed = JSON.parse(response.body);
      } catch {
        parsed = response.body;
      }

      return {
        stepId: step.id,
        success: response.statusCode >= 200 && response.statusCode < 400,
        output: {
          statusCode: response.statusCode,
          body: parsed,
          headers: response.headers,
          evidence: evidence,
        },
      };
    } catch (err) {
      return {
        stepId: step.id,
        success: false,
        error: err instanceof Error ? err.message : "Request failed",
      };
    }
  }

  private async executeCompare(step: ScenarioStep): Promise<StepResult> {
    const { config } = step;
    if (!config.compareWith) {
      return { stepId: step.id, success: false, error: "No comparison target" };
    }

    const contextValues = Array.from(this.contextData.entries());
    const lastEntry = contextValues[contextValues.length - 1];
    const current = lastEntry ? lastEntry[1] : undefined;
    const previous = this.contextData.get(config.compareWith);

    if (!current || !previous) {
      return { stepId: step.id, success: false, error: "Missing comparison data - ensure prior steps executed" };
    }

    const isDifferent = JSON.stringify(current) !== JSON.stringify(previous);

    return {
      stepId: step.id,
      success: true,
      output: { isDifferent, current, previous },
    };
  }

  private async executeVerify(step: ScenarioStep): Promise<StepResult> {
    const { expectedResult } = step;
    if (!expectedResult) {
      return { stepId: step.id, success: true, output: "No verification needed" };
    }

    const lastResult = Array.from(this.contextData.values()).pop();
    if (!lastResult) {
      return { stepId: step.id, success: false, error: "No data to verify" };
    }

    const verified = JSON.stringify(lastResult).includes(expectedResult);

    return {
      stepId: step.id,
      success: verified,
      output: { verified, expected: expectedResult },
    };
  }

  private async executeExtract(step: ScenarioStep): Promise<StepResult> {
    const { config } = step;
    if (!config.extractField) {
      return { stepId: step.id, success: false, error: "No field to extract" };
    }

    const lastResult = Array.from(this.contextData.values()).pop();
    if (!lastResult?.body) {
      return { stepId: step.id, success: false, error: "No data to extract from" };
    }

    const fields = config.extractField.split(".");
    let value = lastResult.body;
    for (const field of fields) {
      value = value?.[field];
    }

    return {
      stepId: step.id,
      success: value !== undefined,
      output: { field: config.extractField, value },
    };
  }

  private async executeManipulate(step: ScenarioStep): Promise<StepResult> {
    const { config } = step;
    if (!config.manipulation) {
      return { stepId: step.id, success: false, error: "No manipulation config" };
    }

    const lastResult = Array.from(this.contextData.values()).pop();
    if (!lastResult?.body) {
      return { stepId: step.id, success: false, error: "No data to manipulate" };
    }

    const modified = { ...lastResult.body };
    const { type, field, value } = config.manipulation;

    switch (type) {
      case "increment":
        modified[field] = (modified[field] || 0) + (value || 1);
        break;
      case "decrement":
        modified[field] = (modified[field] || 0) - (value || 1);
        break;
      case "modify":
        modified[field] = value;
        break;
      case "remove":
        delete modified[field];
        break;
      case "add":
        modified[field] = value;
        break;
      default:
        break;
    }

    return {
      stepId: step.id,
      success: true,
      output: { original: lastResult.body, modified },
    };
  }

  private convertToScenarioResult(
    category: string,
    moduleResult: any
  ): ScenarioResult {
    return {
      scenarioId: `${category}-test`,
      success: moduleResult.success,
      vulnerabilityFound: moduleResult.vulnerabilities?.some((v: any) => v.exploitable) ?? false,
      severity: moduleResult.vulnerabilities?.find((v: any) => v.exploitable)?.severity,
      stepResults: [],
      evidence: moduleResult.evidence || "",
      proofArtifacts: moduleResult.proofArtifacts || [],
      businessImpact: moduleResult.businessImpact,
      executionTimeMs: moduleResult.executionTimeMs || 0,
    };
  }

  setContextData(key: string, value: any): void {
    this.contextData.set(key, value);
  }

  getContextData(key: string): any {
    return this.contextData.get(key);
  }

  clearContext(): void {
    this.contextData.clear();
  }
}

export const SCENARIO_TEMPLATES: BusinessLogicScenario[] = [
  {
    id: "idor-user-profile",
    name: "IDOR User Profile Access",
    description: "Test if users can access other users' profiles by modifying ID",
    category: "idor",
    riskLevel: "high",
    requiredContext: ["currentUserId", "targetUserId"],
    expectedImpact: "Unauthorized access to other users' personal data",
    steps: [
      {
        id: "fetch-own-profile",
        name: "Fetch Own Profile",
        action: "request",
        config: {
          method: "GET",
          endpoint: "/api/users/{currentUserId}",
        },
        abortOnFailure: true,
      },
      {
        id: "fetch-other-profile",
        name: "Fetch Other User Profile",
        action: "request",
        config: {
          method: "GET",
          endpoint: "/api/users/{targetUserId}",
        },
      },
      {
        id: "verify-access",
        name: "Verify Unauthorized Access",
        action: "verify",
        config: {},
        expectedResult: "email",
      },
    ],
  },
  {
    id: "price-manipulation",
    name: "Price Manipulation Attack",
    description: "Test if product prices can be manipulated in cart/checkout",
    category: "price_manipulation",
    riskLevel: "critical",
    requiredContext: ["productId"],
    expectedImpact: "Financial loss through price tampering",
    steps: [
      {
        id: "get-product",
        name: "Get Product Details",
        action: "request",
        config: {
          method: "GET",
          endpoint: "/api/products/{productId}",
        },
        abortOnFailure: true,
      },
      {
        id: "extract-price",
        name: "Extract Original Price",
        action: "extract",
        config: {
          extractField: "price",
        },
      },
      {
        id: "add-to-cart",
        name: "Add to Cart with Modified Price",
        action: "request",
        config: {
          method: "POST",
          endpoint: "/api/cart",
          body: {
            productId: "{productId}",
            quantity: 1,
            price: 0.01,
          },
        },
      },
      {
        id: "verify-manipulation",
        name: "Verify Price Was Accepted",
        action: "verify",
        config: {},
        expectedResult: "0.01",
      },
    ],
  },
  {
    id: "workflow-bypass-checkout",
    name: "Checkout Workflow Bypass",
    description: "Test if checkout steps can be skipped",
    category: "workflow_bypass",
    riskLevel: "high",
    requiredContext: ["cartId"],
    expectedImpact: "Order completion without payment or validation",
    steps: [
      {
        id: "skip-to-confirm",
        name: "Skip to Order Confirmation",
        action: "request",
        config: {
          method: "POST",
          endpoint: "/api/orders/confirm",
          body: {
            cartId: "{cartId}",
            skipPayment: true,
          },
        },
      },
      {
        id: "verify-bypass",
        name: "Verify Order Created",
        action: "verify",
        config: {},
        expectedResult: "orderId",
      },
    ],
  },
  {
    id: "mass-assignment-role",
    name: "Mass Assignment Role Escalation",
    description: "Test if role/admin fields can be set via API",
    category: "mass_assignment",
    riskLevel: "critical",
    requiredContext: [],
    expectedImpact: "Privilege escalation to admin role",
    steps: [
      {
        id: "update-profile-with-role",
        name: "Update Profile with Admin Role",
        action: "request",
        config: {
          method: "PATCH",
          endpoint: "/api/users/me",
          body: {
            name: "Test User",
            role: "admin",
            isAdmin: true,
          },
        },
      },
      {
        id: "verify-role",
        name: "Verify Role Change",
        action: "request",
        config: {
          method: "GET",
          endpoint: "/api/users/me",
        },
      },
      {
        id: "check-admin",
        name: "Check Admin Access",
        action: "verify",
        config: {},
        expectedResult: "admin",
      },
    ],
  },
];
