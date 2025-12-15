import OpenAI from "openai";
import type { AgentMemory } from "./types";
import type { AttackPathStep, Recommendation } from "@shared/schema";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

interface SynthesisResult {
  exploitable: boolean;
  confidence: number;
  score: number;
  attackPath: AttackPathStep[];
  impact: string;
  recommendations: Recommendation[];
}

export async function synthesizeResults(memory: AgentMemory): Promise<SynthesisResult> {
  const allFindings = `
=== RECON AGENT FINDINGS ===
Attack Surface: ${memory.recon?.attackSurface.join(", ") || "None"}
Entry Points: ${memory.recon?.entryPoints.join(", ") || "None"}
API Endpoints: ${memory.recon?.apiEndpoints.join(", ") || "None"}
Auth Mechanisms: ${memory.recon?.authMechanisms.join(", ") || "None"}
Technologies: ${memory.recon?.technologies.join(", ") || "None"}
Potential Vulnerabilities: ${memory.recon?.potentialVulnerabilities.join(", ") || "None"}

=== EXPLOIT AGENT FINDINGS ===
Exploitable: ${memory.exploit?.exploitable || false}
Exploit Chains: ${memory.exploit?.exploitChains.map((c) => `${c.name} (${c.technique}, ${c.success_likelihood})`).join("; ") || "None"}
CVE References: ${memory.exploit?.cveReferences.join(", ") || "None"}
Misconfigurations: ${memory.exploit?.misconfigurations.join(", ") || "None"}

=== LATERAL MOVEMENT AGENT FINDINGS ===
Pivot Paths: ${memory.lateral?.pivotPaths.map((p) => `${p.from} -> ${p.to} via ${p.method}`).join("; ") || "None"}
Privilege Escalation: ${memory.lateral?.privilegeEscalation.map((e) => `${e.target} (${e.likelihood})`).join("; ") || "None"}
Token Reuse: ${memory.lateral?.tokenReuse.join(", ") || "None"}

=== BUSINESS LOGIC AGENT FINDINGS ===
Workflow Abuse: ${memory.businessLogic?.workflowAbuse.join(", ") || "None"}
State Manipulation: ${memory.businessLogic?.stateManipulation.join(", ") || "None"}
Race Conditions: ${memory.businessLogic?.raceConditions.join(", ") || "None"}
Authorization Bypass: ${memory.businessLogic?.authorizationBypass.join(", ") || "None"}
Critical Flows: ${memory.businessLogic?.criticalFlows.join(", ") || "None"}

=== IMPACT AGENT FINDINGS ===
Data Exposure: ${memory.impact?.dataExposure.types.join(", ") || "None"} (Severity: ${memory.impact?.dataExposure.severity || "Unknown"}, Records: ${memory.impact?.dataExposure.estimatedRecords || "Unknown"})
Financial Impact: ${memory.impact?.financialImpact.estimate || "Unknown"} - Factors: ${memory.impact?.financialImpact.factors.join(", ") || "None"}
Compliance Impact: ${memory.impact?.complianceImpact.join(", ") || "None"}
Reputational Risk: ${memory.impact?.reputationalRisk || "Unknown"}
`;

  const systemPrompt = `You are the SYNTHESIS ENGINE for OdinForge AI, a multi-agent security validation platform.

Your mission is to synthesize findings from 5 specialized AI agents into a cohesive security assessment:
1. Combine all agent findings into a unified attack path
2. Calculate overall exploitability confidence and score
3. Generate prioritized remediation recommendations
4. Provide executive-level impact summary

Create a comprehensive, actionable report that security teams can use immediately.`;

  const userPrompt = `Synthesize these multi-agent findings into a final assessment:

Target: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}

${allFindings}

Provide your synthesis as a JSON object with this structure:
{
  "exploitable": boolean (true if the target is exploitable based on all agent findings),
  "confidence": number (0-100, confidence in the overall assessment),
  "score": number (0-100, overall exploitability severity score),
  "attackPath": [
    {
      "id": number (sequential step number),
      "title": string (brief title for this attack step),
      "description": string (detailed description of this attack step),
      "technique": string (MITRE ATT&CK technique ID, e.g., "T1190"),
      "severity": "critical" | "high" | "medium" | "low",
      "discoveredBy": "recon" | "exploit" | "lateral" | "business-logic" | "impact" (which agent discovered this step)
    }
  ],
  "impact": string (comprehensive impact summary based on Impact Agent findings),
  "recommendations": [
    {
      "id": string (unique ID like "rec-1"),
      "title": string (brief title),
      "description": string (detailed remediation steps),
      "priority": "critical" | "high" | "medium" | "low",
      "type": "remediation" | "compensating" | "preventive"
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
      max_completion_tokens: 4096,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Synthesizer");
    }

    const result = JSON.parse(content) as SynthesisResult;

    return {
      exploitable: Boolean(result.exploitable),
      confidence: Math.min(100, Math.max(0, Number(result.confidence) || 50)),
      score: Math.min(100, Math.max(0, Number(result.score) || 50)),
      attackPath: Array.isArray(result.attackPath)
        ? result.attackPath.map((step, index) => ({
            id: step.id || index + 1,
            title: String(step.title || "Attack Step"),
            description: String(step.description || ""),
            technique: step.technique ? String(step.technique) : undefined,
            severity: validateSeverity(step.severity),
            discoveredBy: validateAgentName(step.discoveredBy),
          }))
        : [],
      impact: String(result.impact || "Impact assessment pending"),
      recommendations: Array.isArray(result.recommendations)
        ? result.recommendations.map((rec, index) => ({
            id: String(rec.id || `rec-${index + 1}`),
            title: String(rec.title || "Recommendation"),
            description: String(rec.description || ""),
            priority: validateSeverity(rec.priority),
            type: validateRecType(rec.type),
          }))
        : [],
    };
  } catch (error) {
    console.error("Synthesizer error:", error);
    throw error;
  }
}

function validateSeverity(severity: unknown): "critical" | "high" | "medium" | "low" {
  const valid = ["critical", "high", "medium", "low"];
  return valid.includes(String(severity)) ? (severity as "critical" | "high" | "medium" | "low") : "medium";
}

function validateRecType(type: unknown): "remediation" | "compensating" | "preventive" {
  const valid = ["remediation", "compensating", "preventive"];
  return valid.includes(String(type)) ? (type as "remediation" | "compensating" | "preventive") : "remediation";
}

function validateAgentName(name: unknown): "recon" | "exploit" | "lateral" | "business-logic" | "impact" | undefined {
  const valid = ["recon", "exploit", "lateral", "business-logic", "impact"];
  return valid.includes(String(name)) ? (name as "recon" | "exploit" | "lateral" | "business-logic" | "impact") : undefined;
}
