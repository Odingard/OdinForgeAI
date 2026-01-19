import OpenAI from "openai";
import type { AgentMemory, AgentResult, LateralFindings, LateralShadowAdminIndicator } from "./types";
import { generateAdversaryPromptContext } from "./adversary-profile";
import { wrapAgentError } from "./error-classifier";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

type ProgressCallback = (stage: string, progress: number, message: string) => void;

export async function runLateralAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<LateralFindings>> {
  const startTime = Date.now();
  
  onProgress?.("lateral", 50, "Mapping lateral movement paths...");

  const previousContext = `
Recon Findings:
${memory.recon ? `- Technologies: ${memory.recon.technologies.join(", ")}
- Auth Mechanisms: ${memory.recon.authMechanisms.join(", ")}` : "None"}

Exploit Findings:
${memory.exploit ? `- Exploitable: ${memory.exploit.exploitable}
- Exploit Chains: ${memory.exploit.exploitChains.map((c) => c.name).join(", ")}` : "None"}
`;

  const adversaryContext = memory.context.adversaryProfile 
    ? generateAdversaryPromptContext(memory.context.adversaryProfile)
    : "";

  const systemPrompt = `You are the LATERAL MOVEMENT AGENT, a specialized AI system for analyzing post-exploitation movement opportunities for OdinForge AI.
${adversaryContext}

Your mission is to analyze how an attacker could move laterally after initial compromise:
1. Pivot paths - how to move from one system/asset to another
2. Privilege escalation opportunities
3. Token reuse and credential harvesting opportunities
4. Shadow admin discovery - identify users/accounts with admin-equivalent privileges who:
   - Don't appear in official admin groups
   - Have accumulated permissions over time through delegated/inherited access
   - Can perform privileged actions through indirect paths (role assumption, service accounts)
   - Control critical resources without proper oversight

Use MITRE ATT&CK lateral movement techniques (TA0008). Think like a red team operator planning post-exploitation.
For cloud and SaaS environments, focus on IAM abuse paths and shadow admin indicators.`;

  const userPrompt = `Analyze lateral movement opportunities for this exposure:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}
${previousContext}

Provide your lateral movement analysis as a JSON object with this structure:
{
  "pivotPaths": [
    {
      "from": "Starting point/asset",
      "to": "Target asset",
      "method": "How to pivot",
      "technique": "MITRE ATT&CK technique ID"
    }
  ],
  "privilegeEscalation": [
    {
      "target": "Target privilege level or system",
      "method": "How to escalate",
      "likelihood": "high" | "medium" | "low"
    }
  ],
  "tokenReuse": ["list of token/credential reuse opportunities"],
  "shadowAdminIndicators": [
    {
      "principal": "User or service account identifier",
      "platform": "AWS|GCP|Azure|Google Workspace|Microsoft 365|etc",
      "indicatorType": "excessive_permissions|dormant_admin|service_account_abuse|delegated_admin|hidden_role",
      "evidence": ["evidence of shadow admin status"],
      "riskLevel": "critical|high|medium|low"
    }
  ]
}`;

  try {
    onProgress?.("lateral", 55, "Analyzing privilege escalation paths...");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    onProgress?.("lateral", 60, "Mapping network pivot opportunities...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Lateral Movement Agent");
    }

    const findings = JSON.parse(content) as LateralFindings;
    
    const validatedFindings: LateralFindings = {
      pivotPaths: Array.isArray(findings.pivotPaths)
        ? findings.pivotPaths.map((path) => ({
            from: String(path.from || "Initial Access"),
            to: String(path.to || "Unknown"),
            method: String(path.method || ""),
            technique: String(path.technique || "T1021"),
          }))
        : [],
      privilegeEscalation: Array.isArray(findings.privilegeEscalation)
        ? findings.privilegeEscalation.map((esc) => ({
            target: String(esc.target || ""),
            method: String(esc.method || ""),
            likelihood: validateLikelihood(esc.likelihood),
          }))
        : [],
      tokenReuse: Array.isArray(findings.tokenReuse) ? findings.tokenReuse : [],
      shadowAdminIndicators: Array.isArray(findings.shadowAdminIndicators)
        ? findings.shadowAdminIndicators.map((ind): LateralShadowAdminIndicator => ({
            principal: String(ind.principal || ""),
            platform: String(ind.platform || ""),
            indicatorType: validateIndicatorType(ind.indicatorType),
            evidence: Array.isArray(ind.evidence) ? ind.evidence.map(String) : [],
            riskLevel: validateRiskLevel(ind.riskLevel),
          }))
        : [],
    };

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Lateral Movement Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    throw wrapAgentError("Lateral Movement Agent", error);
  }
}

function validateLikelihood(likelihood: unknown): "high" | "medium" | "low" {
  const valid = ["high", "medium", "low"];
  return valid.includes(String(likelihood)) ? (likelihood as "high" | "medium" | "low") : "medium";
}

function validateRiskLevel(level: unknown): "critical" | "high" | "medium" | "low" {
  const valid = ["critical", "high", "medium", "low"];
  return valid.includes(String(level)) ? (level as "critical" | "high" | "medium" | "low") : "medium";
}

function validateIndicatorType(type: unknown): LateralShadowAdminIndicator["indicatorType"] {
  const valid = ["excessive_permissions", "dormant_admin", "service_account_abuse", "delegated_admin", "hidden_role"];
  return valid.includes(String(type)) ? (type as LateralShadowAdminIndicator["indicatorType"]) : "excessive_permissions";
}
