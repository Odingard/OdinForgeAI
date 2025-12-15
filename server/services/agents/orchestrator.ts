import type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
} from "./types";
import { runReconAgent } from "./recon";
import { runExploitAgent } from "./exploit";
import { runLateralAgent } from "./lateral";
import { runBusinessLogicAgent, runEnhancedBusinessLogicEngine, shouldRunEnhancedEngine } from "./business-logic";
import { runMultiVectorAnalysisAgent, shouldRunMultiVectorAnalysis } from "./multi-vector";
import { runImpactAgent } from "./impact";
import { synthesizeResults } from "./synthesizer";
import { synthesizeAttackGraph } from "./graph-synthesizer";
import { generateEvidenceFromAnalysis } from "./evidence-collector";
import { generateIntelligentScore } from "./scoring-engine";
import { generateRemediationGuidance } from "./remediation-engine";

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

  onProgress?.("Business Logic Agent", "business_logic", 55, "Analyzing business logic flaws...");
  const businessLogicResult = await runBusinessLogicAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Business Logic Agent", stage, progress, message);
  });
  memory.businessLogic = businessLogicResult.findings;

  if (shouldRunEnhancedEngine(exposureType)) {
    onProgress?.("Business Logic Engine", "enhanced_business_logic", 60, "Running enhanced business logic analysis...");
    const enhancedResult = await runEnhancedBusinessLogicEngine(memory, (stage: string, progress: number, message: string) => {
      onProgress?.("Business Logic Engine", stage, progress, message);
    });
    memory.enhancedBusinessLogic = enhancedResult.findings;
  }

  if (shouldRunMultiVectorAnalysis(exposureType)) {
    onProgress?.("Multi-Vector Agent", "multi_vector", 70, "Analyzing multi-vector attack paths...");
    const multiVectorResult = await runMultiVectorAnalysisAgent(memory, (stage: string, progress: number, message: string) => {
      onProgress?.("Multi-Vector Agent", stage, progress, message);
    });
    memory.multiVector = multiVectorResult.findings;
  }

  onProgress?.("Impact Agent", "impact", 80, "Assessing business impact...");
  const impactResult = await runImpactAgent(memory, (stage: string, progress: number, message: string) => {
    onProgress?.("Impact Agent", stage, progress, message);
  });
  memory.impact = impactResult.findings;

  onProgress?.("Synthesizer", "synthesis", 90, "Generating final report...");
  const result = await synthesizeResults(memory);

  onProgress?.("Graph Synthesizer", "graph_synthesis", 92, "Building attack graph...");
  const graphResult = await synthesizeAttackGraph(memory);

  onProgress?.("Evidence Collector", "evidence", 95, "Capturing evidence artifacts...");
  const evidenceArtifacts = generateEvidenceFromAnalysis({
    evaluationId,
    assetId,
    exposureType,
    attackPath: result.attackPath,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
  });

  onProgress?.("Scoring Engine", "scoring", 93, "Calculating intelligent risk scores...");
  const intelligentScore = await generateIntelligentScore({
    assetId,
    exposureType,
    priority,
    description,
    exploitable: result.exploitable,
    attackPath: result.attackPath,
    attackGraph: graphResult.attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
  });

  onProgress?.("Remediation Engine", "remediation", 96, "Generating remediation guidance...");
  const remediationGuidance = await generateRemediationGuidance({
    assetId,
    exposureType,
    priority,
    description,
    exploitable: result.exploitable,
    attackPath: result.attackPath,
    attackGraph: graphResult.attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
    intelligentScore,
  }, evaluationId, (stage, progress, message) => {
    onProgress?.("Remediation Engine", stage, 96 + Math.floor(progress / 25), message);
  });

  const totalProcessingTime = Date.now() - startTime;

  onProgress?.("Complete", "complete", 100, "Analysis complete");

  return {
    ...result,
    attackGraph: graphResult.attackGraph,
    businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
    multiVectorFindings: memory.multiVector?.findings,
    workflowAnalysis: memory.enhancedBusinessLogic?.workflowAnalysis || undefined,
    evidenceArtifacts,
    intelligentScore,
    remediationGuidance,
    agentFindings: {
      recon: memory.recon!,
      exploit: memory.exploit!,
      lateral: memory.lateral!,
      businessLogic: memory.businessLogic!,
      enhancedBusinessLogic: memory.enhancedBusinessLogic,
      multiVector: memory.multiVector,
      impact: memory.impact!,
    },
    totalProcessingTime,
  };
}
