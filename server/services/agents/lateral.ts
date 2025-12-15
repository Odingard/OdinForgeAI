import OpenAI from "openai";
import type { AgentMemory, AgentResult, LateralFindings } from "./types";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
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

  const systemPrompt = `You are the LATERAL MOVEMENT AGENT, a specialized AI system for analyzing post-exploitation movement opportunities for OdinForge AI.

Your mission is to analyze how an attacker could move laterally after initial compromise:
1. Pivot paths - how to move from one system/asset to another
2. Privilege escalation opportunities
3. Token reuse and credential harvesting opportunities

Use MITRE ATT&CK lateral movement techniques (TA0008). Think like a red team operator planning post-exploitation.`;

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
  "tokenReuse": ["list of token/credential reuse opportunities"]
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
    };

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Lateral Movement Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    console.error("Lateral Movement Agent error:", error);
    throw error;
  }
}

function validateLikelihood(likelihood: unknown): "high" | "medium" | "low" {
  const valid = ["high", "medium", "low"];
  return valid.includes(String(likelihood)) ? (likelihood as "high" | "medium" | "low") : "medium";
}
