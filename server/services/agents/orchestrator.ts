import type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
} from "./types";
import { runReconAgent } from "./recon";
import { runExploitAgent } from "./exploit";
import { runLateralAgent } from "./lateral";
import { runBusinessLogicAgent } from "./business-logic";
import { runImpactAgent } from "./impact";
import { synthesizeResults } from "./synthesizer";

export async function runAgentOrchestrator(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  evaluationId: string,
  onProgress?: ProgressCallback
): Promise<OrchestratorResult> {
  const startTime = Date.now();

  const context: AgentContext = {
    assetId,
    exposureType,
    priority,
    description,
    evaluationId,
  };

  const memory: AgentMemory = { context };

  onProgress?.("Recon Agent", "recon", 5, "Initializing reconnaissance...");
  const reconResult = await runReconAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Recon Agent", stage, progress, message);
  });
  memory.recon = reconResult.findings;

  onProgress?.("Exploit Agent", "exploit", 25, "Analyzing exploit chains...");
  const exploitResult = await runExploitAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Exploit Agent", stage, progress, message);
  });
  memory.exploit = exploitResult.findings;

  onProgress?.("Lateral Movement Agent", "lateral", 45, "Mapping lateral paths...");
  const lateralResult = await runLateralAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Lateral Movement Agent", stage, progress, message);
  });
  memory.lateral = lateralResult.findings;

  onProgress?.("Business Logic Agent", "business_logic", 65, "Analyzing business logic flaws...");
  const businessLogicResult = await runBusinessLogicAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Business Logic Agent", stage, progress, message);
  });
  memory.businessLogic = businessLogicResult.findings;

  onProgress?.("Impact Agent", "impact", 85, "Assessing business impact...");
  const impactResult = await runImpactAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Impact Agent", stage, progress, message);
  });
  memory.impact = impactResult.findings;

  onProgress?.("Synthesizer", "synthesis", 95, "Generating final report...");
  const result = await synthesizeResults(memory);

  const totalProcessingTime = Date.now() - startTime;

  onProgress?.("Complete", "complete", 100, "Analysis complete");

  return {
    ...result,
    agentFindings: {
      recon: memory.recon!,
      exploit: memory.exploit!,
      lateral: memory.lateral!,
      businessLogic: memory.businessLogic!,
      impact: memory.impact!,
    },
    totalProcessingTime,
  };
}
