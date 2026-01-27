import OpenAI from "openai";
import type { 
  AgentMemory, 
  AgentResult, 
  BusinessLogicFindings,
  EnhancedBusinessLogicFindings,
  PaymentFlowVulnerability,
  StateTransitionViolation,
  InferredWorkflow
} from "./types";
import type { BusinessLogicFinding, WorkflowStateMachine, BusinessLogicCategory } from "@shared/schema";
import { businessLogicCategories } from "@shared/schema";
import { wrapAgentError } from "./error-classifier";
import { formatExecutionModeConstraints } from "./policy-context";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

type ProgressCallback = (stage: string, progress: number, message: string) => void;

const BUSINESS_LOGIC_EXPOSURE_TYPES = [
  "api_sequence_abuse",
  "payment_flow", 
  "subscription_bypass",
  "state_machine",
  "privilege_boundary",
  "workflow_desync",
  "order_lifecycle"
];

function isBusinessLogicExposure(exposureType: string): boolean {
  return BUSINESS_LOGIC_EXPOSURE_TYPES.includes(exposureType);
}

export async function runBusinessLogicAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<BusinessLogicFindings>> {
  const startTime = Date.now();
  
  onProgress?.("business_logic", 70, "Analyzing business logic flaws...");

  const previousContext = `
Recon Findings:
${memory.recon ? `- API Endpoints: ${memory.recon.apiEndpoints.join(", ")}
- Auth Mechanisms: ${memory.recon.authMechanisms.join(", ")}` : "None"}

Exploit Findings:
${memory.exploit ? `- Exploitable: ${memory.exploit.exploitable}
- Misconfigurations: ${memory.exploit.misconfigurations.join(", ")}` : "None"}

Lateral Movement Findings:
${memory.lateral ? `- Privilege Escalation: ${memory.lateral.privilegeEscalation.map((p) => p.target).join(", ")}` : "None"}
`;

  const policyContext = memory.context.policyContext || "";
  const executionModeConstraints = formatExecutionModeConstraints(memory.context.executionMode || "safe");

  const systemPrompt = `You are the BUSINESS LOGIC AGENT, a specialized AI system for analyzing application logic vulnerabilities for OdinForge AI.

Your mission is to identify business logic flaws that could be exploited:
1. Workflow abuse - bypassing intended application flows
2. State manipulation - exploiting state management issues
3. Race conditions - TOCTOU and concurrency issues
4. Authorization bypass - accessing resources without proper authorization
5. Critical flows - business-critical processes that could be abused

Think like an application security expert looking for logic flaws that automated scanners miss.
${executionModeConstraints}
${policyContext}`;

  const userPrompt = `Analyze business logic vulnerabilities for this exposure:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}
${previousContext}

Provide your business logic analysis as a JSON object with this structure:
{
  "workflowAbuse": ["list of workflow bypass opportunities"],
  "stateManipulation": ["list of state manipulation vulnerabilities"],
  "raceConditions": ["list of race condition opportunities"],
  "authorizationBypass": ["list of authorization bypass methods"],
  "criticalFlows": ["list of critical business flows that could be abused"]
}`;

  try {
    onProgress?.("business_logic", 75, "Detecting race conditions...");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    onProgress?.("business_logic", 80, "Analyzing authorization flows...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Business Logic Agent");
    }

    const findings = JSON.parse(content) as BusinessLogicFindings;
    
    const validatedFindings: BusinessLogicFindings = {
      workflowAbuse: Array.isArray(findings.workflowAbuse) ? findings.workflowAbuse : [],
      stateManipulation: Array.isArray(findings.stateManipulation) ? findings.stateManipulation : [],
      raceConditions: Array.isArray(findings.raceConditions) ? findings.raceConditions : [],
      authorizationBypass: Array.isArray(findings.authorizationBypass) ? findings.authorizationBypass : [],
      criticalFlows: Array.isArray(findings.criticalFlows) ? findings.criticalFlows : [],
    };

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Business Logic Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    throw wrapAgentError("Business Logic Agent", error);
  }
}

export async function runEnhancedBusinessLogicEngine(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<EnhancedBusinessLogicFindings>> {
  const startTime = Date.now();
  
  onProgress?.("business_logic_engine", 70, "Initializing Business Logic Engine...");

  const basicResult = await runBusinessLogicAgent(memory, onProgress);
  
  onProgress?.("business_logic_engine", 73, "Inferring application workflows...");
  const inferredWorkflows = await inferWorkflows(memory);
  
  onProgress?.("business_logic_engine", 76, "Analyzing state machine transitions...");
  const workflowAnalysis = await analyzeStateMachine(memory, inferredWorkflows);
  
  onProgress?.("business_logic_engine", 79, "Detecting state transition violations...");
  const stateTransitionViolations = await detectStateTransitionViolations(memory, workflowAnalysis);
  
  onProgress?.("business_logic_engine", 82, "Analyzing payment flows...");
  const paymentFlowVulnerabilities = await analyzePaymentFlows(memory);
  
  onProgress?.("business_logic_engine", 85, "Generating detailed findings...");
  const detailedFindings = await generateDetailedFindings(
    memory, 
    basicResult.findings, 
    stateTransitionViolations, 
    paymentFlowVulnerabilities,
    workflowAnalysis
  );

  const enhancedFindings: EnhancedBusinessLogicFindings = {
    basicFindings: basicResult.findings,
    detailedFindings,
    workflowAnalysis,
    paymentFlowVulnerabilities,
    stateTransitionViolations,
    inferredWorkflows,
  };

  return {
    success: true,
    findings: enhancedFindings,
    agentName: "Business Logic Engine",
    processingTime: Date.now() - startTime,
  };
}

async function inferWorkflows(memory: AgentMemory): Promise<InferredWorkflow[]> {
  const systemPrompt = `You are a WORKFLOW INFERENCE ENGINE for OdinForge AI.

Your task is to analyze the target system and infer the application's business workflows based on:
1. API endpoints discovered during reconnaissance
2. Authentication mechanisms in place
3. The exposure type and description provided

For each workflow, identify:
- The intended sequence of steps
- Security checkpoints (authentication, authorization, validation)
- Potential bypass opportunities

Focus on high-value workflows: authentication, payment, order processing, subscription management, admin operations.`;

  const userPrompt = `Infer the application workflows for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${memory.recon ? `Discovered API Endpoints: ${memory.recon.apiEndpoints.join(", ")}
Auth Mechanisms: ${memory.recon.authMechanisms.join(", ")}
Technologies: ${memory.recon.technologies.join(", ")}` : ""}

Return a JSON object with this structure:
{
  "workflows": [
    {
      "name": "workflow name",
      "description": "what this workflow does",
      "steps": ["step1", "step2", "step3"],
      "securityCheckpoints": ["where security checks occur"],
      "potentialBypasses": ["ways to bypass security in this workflow"]
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.workflows) ? result.workflows : [];
  } catch (error) {
    console.error("Workflow inference error:", error);
    return [];
  }
}

async function analyzeStateMachine(
  memory: AgentMemory, 
  inferredWorkflows: InferredWorkflow[]
): Promise<WorkflowStateMachine | null> {
  const systemPrompt = `You are a STATE MACHINE ANALYZER for OdinForge AI.

Your task is to model the application's state machine based on inferred workflows.
Create a formal state machine representation that captures:
1. All possible states in the application workflow
2. Valid transitions between states
3. Security boundaries and privilege requirements
4. Critical transitions that require special authorization

Focus on identifying states where unauthorized transitions could lead to security vulnerabilities.`;

  const workflowContext = inferredWorkflows.length > 0 
    ? `Inferred Workflows:\n${inferredWorkflows.map(w => 
        `- ${w.name}: ${w.steps.join(" -> ")}`
      ).join("\n")}`
    : "No workflows inferred yet";

  const userPrompt = `Analyze the state machine for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${workflowContext}

Return a JSON object with this structure:
{
  "name": "Application State Machine",
  "states": [
    {
      "id": "state_id",
      "name": "State Name",
      "type": "initial|intermediate|terminal|error",
      "requiredAuth": "none|user|admin|system"
    }
  ],
  "transitions": [
    {
      "id": "transition_id",
      "from": "from_state_id",
      "to": "to_state_id",
      "trigger": "what triggers this transition",
      "guard": "condition that must be true",
      "isSecurityCritical": true
    }
  ],
  "securityBoundaries": [
    {
      "name": "boundary name",
      "statesWithin": ["state_ids"],
      "requiredPrivilege": "privilege level"
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return null;

    const result = JSON.parse(content);
    return result as WorkflowStateMachine;
  } catch (error) {
    console.error("State machine analysis error:", error);
    return null;
  }
}

async function detectStateTransitionViolations(
  memory: AgentMemory,
  stateMachine: WorkflowStateMachine | null
): Promise<StateTransitionViolation[]> {
  if (!stateMachine) return [];

  const systemPrompt = `You are a STATE TRANSITION VIOLATION DETECTOR for OdinForge AI.

Your task is to identify potential state transition violations that could be exploited:
1. SKIP violations - jumping over required intermediate states
2. REVERSE violations - going backward in a one-way flow
3. UNAUTHORIZED violations - transitioning without proper authorization
4. RACE CONDITION violations - exploiting timing issues in state transitions

For each violation, assess its severity and exploitability.`;

  const userPrompt = `Detect state transition violations for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

State Machine:
States: ${stateMachine.states.map(s => `${s.id}(${s.name})`).join(", ")}
Transitions: ${stateMachine.transitions.map(t => `${t.from}->${t.to}[${t.trigger}]`).join(", ")}
Security Boundaries: ${stateMachine.securityBoundaries?.map(b => `${b.name}: ${b.statesWithin.join(", ")}`).join("; ") || "none"}

Return a JSON object with this structure:
{
  "violations": [
    {
      "id": "violation_id",
      "fromState": "state_id",
      "toState": "target_state_id",
      "expectedTransitions": ["list of valid transitions"],
      "actualTransition": "the invalid transition being attempted",
      "violationType": "skip|reverse|unauthorized|race_condition",
      "severity": "critical|high|medium|low",
      "exploitability": "description of how this can be exploited"
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.violations) ? result.violations : [];
  } catch (error) {
    console.error("State transition violation detection error:", error);
    return [];
  }
}

async function analyzePaymentFlows(memory: AgentMemory): Promise<PaymentFlowVulnerability[]> {
  const isPaymentRelated = [
    "payment_flow",
    "subscription_bypass", 
    "order_lifecycle"
  ].includes(memory.context.exposureType);

  const hasPaymentEndpoints = memory.recon?.apiEndpoints.some(ep => 
    /payment|checkout|order|cart|subscription|billing|stripe|paypal/i.test(ep)
  );

  if (!isPaymentRelated && !hasPaymentEndpoints) {
    return [];
  }

  const systemPrompt = `You are a PAYMENT FLOW VULNERABILITY ANALYZER for OdinForge AI.

Your task is to identify vulnerabilities in payment and financial transaction flows:
1. Payment bypass - skipping payment steps entirely
2. Subscription abuse - trial extension, plan switching exploits
3. Order manipulation - price tampering, quantity abuse
4. Price tampering - modifying prices in requests
5. Coupon abuse - stacking coupons, expired coupon reuse

For each vulnerability, assess financial impact and provide exploit steps.`;

  const userPrompt = `Analyze payment flow vulnerabilities for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${memory.recon ? `Payment-related endpoints: ${memory.recon.apiEndpoints.filter(ep => 
  /payment|checkout|order|cart|subscription|billing/i.test(ep)
).join(", ")}` : ""}

Return a JSON object with this structure:
{
  "vulnerabilities": [
    {
      "id": "vuln_id",
      "category": "payment_bypass|subscription_abuse|order_manipulation|price_tampering|coupon_abuse",
      "title": "Vulnerability title",
      "description": "Detailed description",
      "severity": "critical|high|medium|low",
      "affectedFlow": ["step1", "step2"],
      "exploitSteps": ["step1", "step2", "step3"],
      "financialImpact": "Estimated financial impact",
      "validatedExploit": false
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.vulnerabilities) ? result.vulnerabilities : [];
  } catch (error) {
    console.error("Payment flow analysis error:", error);
    return [];
  }
}

async function generateDetailedFindings(
  memory: AgentMemory,
  basicFindings: BusinessLogicFindings,
  stateViolations: StateTransitionViolation[],
  paymentVulns: PaymentFlowVulnerability[],
  stateMachine: WorkflowStateMachine | null
): Promise<BusinessLogicFinding[]> {
  const findings: BusinessLogicFinding[] = [];
  let findingId = 1;

  for (const violation of stateViolations) {
    findings.push({
      id: `bl-${findingId++}`,
      category: "state_transition" as BusinessLogicCategory,
      title: `State Transition Violation: ${violation.fromState} -> ${violation.toState}`,
      description: violation.exploitability,
      severity: violation.severity,
      intendedWorkflow: violation.expectedTransitions,
      actualWorkflow: [violation.actualTransition],
      stateViolations: [{
        fromState: violation.fromState,
        toState: violation.toState,
        expectedTransitions: violation.expectedTransitions,
        actualTransition: violation.actualTransition,
        isViolation: true,
      }],
      exploitSteps: [`Attempt transition from ${violation.fromState} directly to ${violation.toState}`],
      impact: `${violation.violationType} violation allows bypassing security controls`,
      validatedExploit: false,
    });
  }

  for (const vuln of paymentVulns) {
    const category = mapPaymentCategoryToBusinessLogic(vuln.category);
    findings.push({
      id: `bl-${findingId++}`,
      category,
      title: vuln.title,
      description: vuln.description,
      severity: vuln.severity,
      intendedWorkflow: vuln.affectedFlow,
      actualWorkflow: vuln.exploitSteps,
      exploitSteps: vuln.exploitSteps,
      impact: vuln.financialImpact,
      businessImpact: {
        financialLoss: vuln.financialImpact,
      },
      validatedExploit: vuln.validatedExploit,
    });
  }

  for (const abuse of basicFindings.workflowAbuse) {
    findings.push({
      id: `bl-${findingId++}`,
      category: "workflow_bypass" as BusinessLogicCategory,
      title: `Workflow Bypass: ${abuse.substring(0, 50)}...`,
      description: abuse,
      severity: "medium",
      intendedWorkflow: stateMachine?.states.map(s => s.name) || [],
      actualWorkflow: [],
      exploitSteps: [abuse],
      impact: "Potential bypass of intended workflow controls",
      validatedExploit: false,
    });
  }

  for (const race of basicFindings.raceConditions) {
    findings.push({
      id: `bl-${findingId++}`,
      category: "race_condition" as BusinessLogicCategory,
      title: `Race Condition: ${race.substring(0, 50)}...`,
      description: race,
      severity: "high",
      intendedWorkflow: [],
      actualWorkflow: [],
      exploitSteps: [race],
      impact: "TOCTOU or double-spend vulnerability",
      validatedExploit: false,
    });
  }

  for (const bypass of basicFindings.authorizationBypass) {
    findings.push({
      id: `bl-${findingId++}`,
      category: "privilege_escalation" as BusinessLogicCategory,
      title: `Authorization Bypass: ${bypass.substring(0, 50)}...`,
      description: bypass,
      severity: "high",
      intendedWorkflow: [],
      actualWorkflow: [],
      exploitSteps: [bypass],
      impact: "Unauthorized access to protected resources",
      validatedExploit: false,
    });
  }

  return findings;
}

function mapPaymentCategoryToBusinessLogic(
  category: PaymentFlowVulnerability["category"]
): BusinessLogicCategory {
  const mapping: Record<PaymentFlowVulnerability["category"], BusinessLogicCategory> = {
    "payment_bypass": "payment_bypass",
    "subscription_abuse": "subscription_abuse",
    "order_manipulation": "order_manipulation",
    "price_tampering": "parameter_tampering",
    "coupon_abuse": "payment_bypass",
  };
  return mapping[category];
}

export function shouldRunEnhancedEngine(exposureType: string): boolean {
  return isBusinessLogicExposure(exposureType);
}
