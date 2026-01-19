import OpenAI from "openai";
import type { AgentMemory, AgentResult, ImpactFindings } from "./types";
import { generateAdversaryPromptContext } from "./adversary-profile";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

type ProgressCallback = (stage: string, progress: number, message: string) => void;

export async function runImpactAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<ImpactFindings>> {
  const startTime = Date.now();
  
  onProgress?.("impact", 85, "Assessing data exposure risk...");

  const adversaryContext = memory.context.adversaryProfile 
    ? generateAdversaryPromptContext(memory.context.adversaryProfile)
    : "";

  const previousContext = `
Recon Findings:
${memory.recon ? `- Attack Surface: ${memory.recon.attackSurface.join(", ")}
- Potential Vulnerabilities: ${memory.recon.potentialVulnerabilities.join(", ")}` : "None"}

Exploit Findings:
${memory.exploit ? `- Exploitable: ${memory.exploit.exploitable}
- Exploit Chains: ${memory.exploit.exploitChains.map((c) => `${c.name} (${c.success_likelihood})`).join(", ")}
- CVEs: ${memory.exploit.cveReferences.join(", ")}` : "None"}

Lateral Movement:
${memory.lateral ? `- Pivot Paths: ${memory.lateral.pivotPaths.length}
- Privilege Escalation: ${memory.lateral.privilegeEscalation.map((p) => p.target).join(", ")}` : "None"}

Business Logic:
${memory.businessLogic ? `- Workflow Abuse: ${memory.businessLogic.workflowAbuse.join(", ")}
- Authorization Bypass: ${memory.businessLogic.authorizationBypass.join(", ")}` : "None"}
`;

  const systemPrompt = `You are the IMPACT AGENT, a specialized AI system for assessing business impact of security vulnerabilities for OdinForge AI.

Your mission is to assess the potential impact if the vulnerability is exploited:
1. Data exposure - what data could be accessed and how severe
2. Financial impact - estimated monetary impact and contributing factors
3. Compliance impact - which regulations could be violated
4. Reputational risk - brand and customer trust impact

Think like a risk analyst providing executive-level impact assessment. Be realistic and data-driven.
${adversaryContext}`;

  const userPrompt = `Assess the business impact for this exposure:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}
${previousContext}

Provide your impact assessment as a JSON object with this structure:
{
  "dataExposure": {
    "types": ["list of data types that could be exposed"],
    "severity": "critical" | "high" | "medium" | "low",
    "estimatedRecords": "estimated number or range of records affected"
  },
  "financialImpact": {
    "estimate": "estimated financial impact range",
    "factors": ["list of factors contributing to financial impact"]
  },
  "complianceImpact": ["list of compliance frameworks/regulations affected"],
  "reputationalRisk": "critical" | "high" | "medium" | "low"
}`;

  try {
    onProgress?.("impact", 90, "Calculating financial exposure...");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    onProgress?.("impact", 92, "Mapping compliance requirements...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Impact Agent");
    }

    const findings = JSON.parse(content) as ImpactFindings;
    
    const validatedFindings: ImpactFindings = {
      dataExposure: {
        types: Array.isArray(findings.dataExposure?.types) ? findings.dataExposure.types : [],
        severity: validateSeverity(findings.dataExposure?.severity),
        estimatedRecords: String(findings.dataExposure?.estimatedRecords || "Unknown"),
      },
      financialImpact: {
        estimate: String(findings.financialImpact?.estimate || "Unknown"),
        factors: Array.isArray(findings.financialImpact?.factors) ? findings.financialImpact.factors : [],
      },
      complianceImpact: Array.isArray(findings.complianceImpact) ? findings.complianceImpact : [],
      reputationalRisk: validateSeverity(findings.reputationalRisk),
    };

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Impact Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    console.error("Impact Agent error:", error);
    throw error;
  }
}

function validateSeverity(severity: unknown): "critical" | "high" | "medium" | "low" {
  const valid = ["critical", "high", "medium", "low"];
  return valid.includes(String(severity)) ? (severity as "critical" | "high" | "medium" | "low") : "medium";
}
