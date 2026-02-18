import type { AgentMemory, AgentResult, ReconFindings } from "./types";
import { generateAdversaryPromptContext } from "./adversary-profile";
import { wrapAgentError } from "./error-classifier";
import { formatExecutionModeConstraints } from "./policy-context";
import { openai } from "./openai-client";
import { buildReconGroundTruth, buildTelemetryGroundTruth } from "./scan-data-loader";

type ProgressCallback = (stage: string, progress: number, message: string) => void;

export async function runReconAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<ReconFindings>> {
  const startTime = Date.now();
  
  onProgress?.("recon", 10, "Mapping attack surface...");

  const adversaryContext = memory.context.adversaryProfile 
    ? generateAdversaryPromptContext(memory.context.adversaryProfile)
    : "";
  
  const policyContext = memory.context.policyContext || "";
  const executionModeConstraints = formatExecutionModeConstraints(memory.context.executionMode || "safe");

  const systemPrompt = `You are the RECON AGENT, a specialized AI security reconnaissance system for OdinForge AI.

Your mission is to perform comprehensive reconnaissance on the target asset to identify:
1. Attack surface - all potential entry points and exposed interfaces
2. Entry points - specific URLs, endpoints, ports that could be exploited
3. API endpoints - REST, GraphQL, WebSocket, and other API interfaces
4. Authentication mechanisms - OAuth, JWT, session-based, API keys
5. Technologies - frameworks, libraries, infrastructure components
6. Potential vulnerabilities - based on reconnaissance findings

Think like a penetration tester performing initial reconnaissance. Be thorough but realistic.
${adversaryContext}
${executionModeConstraints}
${policyContext}`;

  // Inject ground-truth scan data when available
  const groundTruthContext = memory.groundTruth
    ? [buildReconGroundTruth(memory.groundTruth), buildTelemetryGroundTruth(memory.groundTruth)].filter(Boolean).join("\n\n")
    : "";

  const userPrompt = `Perform reconnaissance analysis on this security exposure:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}
${groundTruthContext ? `\n${groundTruthContext}\n` : ""}
Provide your reconnaissance findings as a JSON object with this structure:
{
  "attackSurface": ["list of attack surface elements discovered"],
  "entryPoints": ["list of potential entry points"],
  "apiEndpoints": ["list of API endpoints or interfaces found"],
  "authMechanisms": ["list of authentication mechanisms identified"],
  "technologies": ["list of technologies/frameworks detected"],
  "potentialVulnerabilities": ["list of potential vulnerabilities based on recon"]
}`;

  try {
    onProgress?.("recon", 15, "Analyzing attack vectors...");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    onProgress?.("recon", 20, "Processing reconnaissance data...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Recon Agent");
    }

    const findings = JSON.parse(content) as ReconFindings;
    
    const validatedFindings: ReconFindings = {
      attackSurface: Array.isArray(findings.attackSurface) ? findings.attackSurface : [],
      entryPoints: Array.isArray(findings.entryPoints) ? findings.entryPoints : [],
      apiEndpoints: Array.isArray(findings.apiEndpoints) ? findings.apiEndpoints : [],
      authMechanisms: Array.isArray(findings.authMechanisms) ? findings.authMechanisms : [],
      technologies: Array.isArray(findings.technologies) ? findings.technologies : [],
      potentialVulnerabilities: Array.isArray(findings.potentialVulnerabilities) ? findings.potentialVulnerabilities : [],
    };

    return {
      success: true,
      findings: validatedFindings,
      agentName: "Recon Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    throw wrapAgentError("Recon Agent", error);
  }
}
