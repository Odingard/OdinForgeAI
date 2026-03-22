/**
 * Workflow Bypass Test Module
 * 
 * Tests for business logic vulnerabilities where workflow steps can be skipped.
 */

import { createHash } from "crypto";

export interface WorkflowBypassConfig {
  baseUrl: string;
  authToken?: string;
  headers?: Record<string, string>;
  workflows?: WorkflowDefinition[];
}

export interface WorkflowDefinition {
  id: string;
  name: string;
  steps: WorkflowStep[];
  finalEndpoint: string;
  requiredSteps: string[];
}

interface WorkflowStep {
  id: string;
  name: string;
  endpoint: string;
  method: "GET" | "POST" | "PUT" | "PATCH";
  requiredData?: string[];
}

export interface WorkflowVulnerability {
  workflowId: string;
  type: "step_skip" | "state_manipulation" | "direct_access" | "parameter_tampering";
  severity: "medium" | "high" | "critical";
  exploitable: boolean;
  proof?: string;
  skippedSteps?: string[];
}

export interface WorkflowBypassResult {
  success: boolean;
  vulnerabilities: WorkflowVulnerability[];
  testedWorkflows: number;
  evidence: string;
  proofArtifacts: ProofArtifact[];
  businessImpact?: string;
  executionTimeMs: number;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

const DEFAULT_WORKFLOWS: WorkflowDefinition[] = [
  {
    id: "checkout",
    name: "E-commerce Checkout",
    steps: [
      { id: "cart", name: "Add to Cart", endpoint: "/api/cart", method: "POST" },
      { id: "shipping", name: "Enter Shipping", endpoint: "/api/checkout/shipping", method: "POST" },
      { id: "payment", name: "Enter Payment", endpoint: "/api/checkout/payment", method: "POST" },
      { id: "confirm", name: "Confirm Order", endpoint: "/api/checkout/confirm", method: "POST" },
    ],
    finalEndpoint: "/api/orders",
    requiredSteps: ["cart", "shipping", "payment"],
  },
  {
    id: "registration",
    name: "User Registration",
    steps: [
      { id: "signup", name: "Create Account", endpoint: "/api/auth/signup", method: "POST" },
      { id: "verify", name: "Email Verification", endpoint: "/api/auth/verify", method: "POST" },
      { id: "profile", name: "Complete Profile", endpoint: "/api/users/profile", method: "POST" },
    ],
    finalEndpoint: "/api/users/me",
    requiredSteps: ["signup", "verify"],
  },
  {
    id: "approval",
    name: "Request Approval",
    steps: [
      { id: "submit", name: "Submit Request", endpoint: "/api/requests", method: "POST" },
      { id: "review", name: "Manager Review", endpoint: "/api/requests/{id}/review", method: "POST" },
      { id: "approve", name: "Final Approval", endpoint: "/api/requests/{id}/approve", method: "POST" },
    ],
    finalEndpoint: "/api/requests/{id}/status",
    requiredSteps: ["submit", "review"],
  },
];

export class WorkflowBypassModule {
  async testDirectAccess(
    config: WorkflowBypassConfig,
    workflow: WorkflowDefinition
  ): Promise<WorkflowVulnerability> {
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    try {
      const url = new URL(workflow.finalEndpoint, config.baseUrl);
      const response = await fetch(url.toString(), {
        method: "POST",
        headers,
        body: JSON.stringify({ bypass: true }),
      });

      if (response.status >= 200 && response.status < 400) {
        return {
          workflowId: workflow.id,
          type: "direct_access",
          severity: "critical",
          exploitable: true,
          proof: `Direct access to ${workflow.finalEndpoint} succeeded without completing workflow`,
          skippedSteps: workflow.requiredSteps,
        };
      }

      return {
        workflowId: workflow.id,
        type: "direct_access",
        severity: "critical",
        exploitable: false,
        proof: `Direct access properly blocked: ${response.status}`,
      };
    } catch {
      return {
        workflowId: workflow.id,
        type: "direct_access",
        severity: "critical",
        exploitable: false,
        proof: "Error testing direct access",
      };
    }
  }

  async testStepSkip(
    config: WorkflowBypassConfig,
    workflow: WorkflowDefinition
  ): Promise<WorkflowVulnerability> {
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const skippedSteps: string[] = [];

    try {
      const firstStep = workflow.steps[0];
      const url = new URL(firstStep.endpoint, config.baseUrl);
      await fetch(url.toString(), {
        method: firstStep.method,
        headers,
        body: JSON.stringify({ test: true }),
      });

      if (workflow.steps.length > 2) {
        for (let i = 1; i < workflow.steps.length - 1; i++) {
          skippedSteps.push(workflow.steps[i].id);
        }

        const lastStep = workflow.steps[workflow.steps.length - 1];
        const lastUrl = new URL(lastStep.endpoint, config.baseUrl);
        const response = await fetch(lastUrl.toString(), {
          method: lastStep.method,
          headers,
          body: JSON.stringify({ skipValidation: true }),
        });

        if (response.status >= 200 && response.status < 400) {
          return {
            workflowId: workflow.id,
            type: "step_skip",
            severity: "high",
            exploitable: true,
            proof: `Skipped ${skippedSteps.length} intermediate steps`,
            skippedSteps,
          };
        }
      }

      return {
        workflowId: workflow.id,
        type: "step_skip",
        severity: "high",
        exploitable: false,
        proof: "Step sequence properly enforced",
      };
    } catch {
      return {
        workflowId: workflow.id,
        type: "step_skip",
        severity: "high",
        exploitable: false,
        proof: "Error testing step skip",
      };
    }
  }

  async testStateManipulation(
    config: WorkflowBypassConfig,
    workflow: WorkflowDefinition
  ): Promise<WorkflowVulnerability> {
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const manipulationPayloads = [
      { state: "completed", status: "approved" },
      { currentStep: workflow.steps.length, stepComplete: true },
      { workflowState: "final", allStepsComplete: true },
      { _state: "done", _skipValidation: true },
    ];

    for (const payload of manipulationPayloads) {
      try {
        const url = new URL(workflow.finalEndpoint, config.baseUrl);
        const response = await fetch(url.toString(), {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
        });

        if (response.status >= 200 && response.status < 400) {
          return {
            workflowId: workflow.id,
            type: "state_manipulation",
            severity: "critical",
            exploitable: true,
            proof: `State manipulation accepted: ${JSON.stringify(payload)}`,
          };
        }
      } catch {
        continue;
      }
    }

    return {
      workflowId: workflow.id,
      type: "state_manipulation",
      severity: "critical",
      exploitable: false,
      proof: "State manipulation attempts rejected",
    };
  }

  async testParameterTampering(
    config: WorkflowBypassConfig,
    workflow: WorkflowDefinition
  ): Promise<WorkflowVulnerability> {
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const tamperPayloads = [
      { price: 0, amount: 0.01 },
      { discount: 100, couponCode: "BYPASS100" },
      { isAdmin: true, role: "admin" },
      { verified: true, emailVerified: true },
      { approved: true, managerApproval: true },
    ];

    for (const step of workflow.steps) {
      for (const payload of tamperPayloads) {
        try {
          const url = new URL(step.endpoint, config.baseUrl);
          const response = await fetch(url.toString(), {
            method: step.method,
            headers,
            body: JSON.stringify(payload),
          });

          if (response.status >= 200 && response.status < 400) {
            const body = await response.json().catch(() => ({}));
            
            const tampered = Object.keys(payload).some(key =>
              JSON.stringify(body).toLowerCase().includes(key.toLowerCase())
            );

            if (tampered) {
              return {
                workflowId: workflow.id,
                type: "parameter_tampering",
                severity: "high",
                exploitable: true,
                proof: `Parameter tampering at ${step.endpoint}: ${JSON.stringify(payload)}`,
              };
            }
          }
        } catch {
          continue;
        }
      }
    }

    return {
      workflowId: workflow.id,
      type: "parameter_tampering",
      severity: "high",
      exploitable: false,
      proof: "Parameter tampering attempts rejected",
    };
  }

  async runFullTest(config: WorkflowBypassConfig): Promise<WorkflowBypassResult> {
    const startTime = Date.now();
    const vulnerabilities: WorkflowVulnerability[] = [];
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];

    const workflows = config.workflows || DEFAULT_WORKFLOWS;

    for (const workflow of workflows) {
      const directResult = await this.testDirectAccess(config, workflow);
      vulnerabilities.push(directResult);
      if (directResult.exploitable) {
        evidence.push(`${workflow.name}: ${directResult.proof}`);
        proofArtifacts.push({
          type: "workflow_direct_access",
          description: `Direct access bypass in ${workflow.name}`,
          data: JSON.stringify({
            workflow: workflow.id,
            skippedSteps: directResult.skippedSteps,
          }),
          hash: createHash("sha256").update(workflow.id + "direct").digest("hex"),
          capturedAt: new Date(),
        });
      }

      const skipResult = await this.testStepSkip(config, workflow);
      vulnerabilities.push(skipResult);
      if (skipResult.exploitable) {
        evidence.push(`${workflow.name}: ${skipResult.proof}`);
      }

      const stateResult = await this.testStateManipulation(config, workflow);
      vulnerabilities.push(stateResult);
      if (stateResult.exploitable) {
        evidence.push(`${workflow.name}: ${stateResult.proof}`);
        proofArtifacts.push({
          type: "workflow_state_manipulation",
          description: `State manipulation in ${workflow.name}`,
          data: stateResult.proof || "",
          hash: createHash("sha256").update(workflow.id + "state").digest("hex"),
          capturedAt: new Date(),
        });
      }

      const tamperResult = await this.testParameterTampering(config, workflow);
      vulnerabilities.push(tamperResult);
      if (tamperResult.exploitable) {
        evidence.push(`${workflow.name}: ${tamperResult.proof}`);
      }
    }

    const exploitable = vulnerabilities.filter(v => v.exploitable);
    const success = exploitable.length > 0;

    const businessImpact = success
      ? this.assessBusinessImpact(exploitable)
      : undefined;

    return {
      success,
      vulnerabilities,
      testedWorkflows: workflows.length,
      evidence: evidence.join("; "),
      proofArtifacts,
      businessImpact,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private assessBusinessImpact(vulnerabilities: WorkflowVulnerability[]): string {
    const types = vulnerabilities.map(v => v.type);
    const workflowIds = Array.from(new Set(vulnerabilities.map(v => v.workflowId)));

    if (types.includes("direct_access") && workflowIds.includes("checkout")) {
      return "Order completion without payment";
    }

    if (types.includes("state_manipulation")) {
      return "Workflow state can be manipulated to bypass validation";
    }

    if (types.includes("step_skip")) {
      return "Critical workflow steps can be bypassed";
    }

    if (types.includes("parameter_tampering")) {
      return "Business parameters can be tampered (prices, roles, etc.)";
    }

    return "Business workflow integrity compromised";
  }
}
