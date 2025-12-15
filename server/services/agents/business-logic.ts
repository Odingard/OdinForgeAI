import OpenAI from "openai";
import type { AgentMemory, AgentResult, BusinessLogicFindings } from "./types";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

type ProgressCallback = (stage: string, progress: number, message: string) => void;

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

  const systemPrompt = `You are the BUSINESS LOGIC AGENT, a specialized AI system for analyzing application logic vulnerabilities for OdinForge AI.

Your mission is to identify business logic flaws that could be exploited:
1. Workflow abuse - bypassing intended application flows
2. State manipulation - exploiting state management issues
3. Race conditions - TOCTOU and concurrency issues
4. Authorization bypass - accessing resources without proper authorization
5. Critical flows - business-critical processes that could be abused

Think like an application security expert looking for logic flaws that automated scanners miss.`;

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
    console.error("Business Logic Agent error:", error);
    throw error;
  }
}
