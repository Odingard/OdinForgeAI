import OpenAI from "openai";
import type { AgentMemory, AgentResult, ProgressCallback, ExploitFindings, LateralFindings, BusinessLogicFindings, MultiVectorFindings } from "./types";
import { wrapAgentError } from "./error-classifier";
import { formatExecutionModeConstraints } from "./policy-context";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export interface DefenderFindings {
  detectedAttacks: DetectedAttack[];
  defensiveControls: DefensiveControl[];
  mitigationActions: MitigationAction[];
  blockedPaths: BlockedPath[];
  alertsGenerated: Alert[];
  defenseEffectiveness: number;
  gapsIdentified: string[];
  recommendedImprovements: string[];
}

export interface DetectedAttack {
  id: string;
  attackType: string;
  detectionMethod: string;
  confidence: number;
  timeToDetect: string;
  severity: "critical" | "high" | "medium" | "low";
  mitreTechnique?: string;
}

export interface DefensiveControl {
  id: string;
  controlType: "preventive" | "detective" | "corrective" | "compensating";
  name: string;
  description: string;
  effectiveness: number;
  coverage: string[];
  limitations: string[];
}

export interface MitigationAction {
  id: string;
  action: string;
  target: string;
  automationLevel: "manual" | "semi-automated" | "fully-automated";
  timeToExecute: string;
  effectiveness: number;
  sideEffects: string[];
}

export interface BlockedPath {
  id: string;
  attackPath: string;
  blockedAt: string;
  blockingControl: string;
  bypassPossible: boolean;
  bypassDifficulty?: "trivial" | "low" | "medium" | "high" | "expert";
}

export interface Alert {
  id: string;
  alertType: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  triggerCondition: string;
  falsePositiveRisk: "low" | "medium" | "high";
}

export async function runDefenderAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<DefenderFindings>> {
  const startTime = Date.now();
  
  onProgress?.("Defender Agent", "defense", 5, "Initializing defensive analysis...");

  const attackContext = buildAttackContext(memory);
  const policyContext = memory.context.policyContext || "";
  const executionModeConstraints = formatExecutionModeConstraints(memory.context.executionMode || "safe");

  const systemPrompt = `You are the DEFENDER AGENT, an AI-powered blue team security system for OdinForge AI.

Your mission is to simulate how a mature security operations center (SOC) would detect and respond to the attacks identified by the red team agents. You must:

1. DETECT: Identify which attacks would be detected by typical security controls (SIEM, EDR, WAF, CSPM, etc.)
2. PREVENT: Determine which attack paths would be blocked by preventive controls
3. RESPOND: Propose automated and manual incident response actions
4. ASSESS: Evaluate the overall defensive posture and identify gaps

Think like an experienced security defender. Be realistic about detection capabilities and response times.
Consider both technical controls and process-based defenses.
${executionModeConstraints}
${policyContext}`;

  const userPrompt = `Analyze the defensive posture against these identified attacks:

Asset: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}

${attackContext}

Provide your defensive analysis as a JSON object with this structure:
{
  "detectedAttacks": [
    {
      "id": "detect-1",
      "attackType": "Type of attack detected",
      "detectionMethod": "How it would be detected (SIEM rule, EDR alert, etc.)",
      "confidence": 0.85,
      "timeToDetect": "Estimated time (e.g., 'minutes', 'hours', 'days')",
      "severity": "critical" | "high" | "medium" | "low",
      "mitreTechnique": "T1190 (optional)"
    }
  ],
  "defensiveControls": [
    {
      "id": "control-1",
      "controlType": "preventive" | "detective" | "corrective" | "compensating",
      "name": "Control name",
      "description": "What the control does",
      "effectiveness": 0.75,
      "coverage": ["list of attack types covered"],
      "limitations": ["list of limitations"]
    }
  ],
  "mitigationActions": [
    {
      "id": "action-1",
      "action": "Specific action to take",
      "target": "What to target",
      "automationLevel": "manual" | "semi-automated" | "fully-automated",
      "timeToExecute": "Estimated time",
      "effectiveness": 0.90,
      "sideEffects": ["potential side effects"]
    }
  ],
  "blockedPaths": [
    {
      "id": "block-1",
      "attackPath": "Description of blocked attack path",
      "blockedAt": "Where in the kill chain",
      "blockingControl": "What blocked it",
      "bypassPossible": true,
      "bypassDifficulty": "medium"
    }
  ],
  "alertsGenerated": [
    {
      "id": "alert-1",
      "alertType": "SIEM/EDR/WAF/Custom",
      "severity": "high",
      "message": "Alert message",
      "triggerCondition": "What triggers this alert",
      "falsePositiveRisk": "low" | "medium" | "high"
    }
  ],
  "defenseEffectiveness": 0.65,
  "gapsIdentified": ["List of defensive gaps"],
  "recommendedImprovements": ["List of recommended improvements"]
}`;

  try {
    onProgress?.("Defender Agent", "detection", 20, "Analyzing detection capabilities...");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    onProgress?.("Defender Agent", "controls", 40, "Evaluating defensive controls...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Defender Agent");
    }

    const findings = JSON.parse(content) as DefenderFindings;
    
    onProgress?.("Defender Agent", "mitigation", 60, "Planning mitigation actions...");

    const validatedFindings: DefenderFindings = {
      detectedAttacks: Array.isArray(findings.detectedAttacks) ? findings.detectedAttacks : [],
      defensiveControls: Array.isArray(findings.defensiveControls) ? findings.defensiveControls : [],
      mitigationActions: Array.isArray(findings.mitigationActions) ? findings.mitigationActions : [],
      blockedPaths: Array.isArray(findings.blockedPaths) ? findings.blockedPaths : [],
      alertsGenerated: Array.isArray(findings.alertsGenerated) ? findings.alertsGenerated : [],
      defenseEffectiveness: typeof findings.defenseEffectiveness === "number" ? findings.defenseEffectiveness : 0.5,
      gapsIdentified: Array.isArray(findings.gapsIdentified) ? findings.gapsIdentified : [],
      recommendedImprovements: Array.isArray(findings.recommendedImprovements) ? findings.recommendedImprovements : [],
    };

    onProgress?.("Defender Agent", "complete", 100, "Defensive analysis complete");

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Defender Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    throw wrapAgentError("Defender Agent", error);
  }
}

function buildAttackContext(memory: AgentMemory): string {
  const sections: string[] = [];

  if (memory.exploit) {
    sections.push(`
EXPLOIT FINDINGS:
- Exploitable: ${memory.exploit.exploitable}
- Exploit Chains: ${memory.exploit.exploitChains.map(c => `${c.name} (${c.technique})`).join(", ")}
- CVEs: ${memory.exploit.cveReferences.join(", ")}
- Misconfigurations: ${memory.exploit.misconfigurations.join(", ")}`);
  }

  if (memory.lateral) {
    sections.push(`
LATERAL MOVEMENT:
- Pivot Paths: ${memory.lateral.pivotPaths.map(p => `${p.from} -> ${p.to} via ${p.method}`).join("; ")}
- Privilege Escalation: ${memory.lateral.privilegeEscalation.map(p => `${p.target} (${p.likelihood})`).join(", ")}
- Token Reuse Opportunities: ${memory.lateral.tokenReuse.join(", ")}`);
  }

  if (memory.businessLogic) {
    sections.push(`
BUSINESS LOGIC ATTACKS:
- Workflow Abuse: ${memory.businessLogic.workflowAbuse.join(", ")}
- State Manipulation: ${memory.businessLogic.stateManipulation.join(", ")}
- Race Conditions: ${memory.businessLogic.raceConditions.join(", ")}
- Authorization Bypass: ${memory.businessLogic.authorizationBypass.join(", ")}`);
  }

  if (memory.multiVector) {
    sections.push(`
MULTI-VECTOR ATTACKS:
- Cloud Findings: ${memory.multiVector.cloudFindings.length} issues
- IAM Findings: ${memory.multiVector.iamFindings.length} issues
- SaaS Findings: ${memory.multiVector.saasFindings.length} issues
- Chained Attack Paths: ${memory.multiVector.chainedAttackPaths.map(p => p.name).join(", ")}`);
  }

  return sections.join("\n") || "No specific attack findings available.";
}
