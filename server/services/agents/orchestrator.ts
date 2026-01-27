import type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
  SafetyDecision,
  ExploitFindings,
  LateralFindings,
} from "./types";
import type { AdversaryProfile, LLMValidationResult } from "@shared/schema";
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
import { runWithHeartbeat, updateAgentHeartbeat } from "./heartbeat-tracker";
import { validateOrchestratorFindings } from "../validation/findings-validator.js";
import { getAgentPolicyContext } from "./policy-context";
import { checkExploitChain, checkLateralMovement, createSafetyDecision, PolicyCheckResult } from "./policy-guardian";
import { wsService } from "../websocket";

export interface OrchestratorOptions {
  adversaryProfile?: AdversaryProfile;
  organizationId?: string;
  executionMode?: "safe" | "simulation" | "live";
}

export async function runAgentOrchestrator(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  evaluationId: string,
  onProgress?: ProgressCallback,
  options?: OrchestratorOptions
): Promise<OrchestratorResult> {
  const startTime = Date.now();
  
  onProgress?.("Policy Engine", "policy", 1, "Loading Rules of Engagement...");
  
  let policyContext = "";
  try {
    policyContext = await getAgentPolicyContext(
      "penetration testing",
      `${exposureType} assessment on ${assetId}`,
      {
        organizationId: options?.organizationId,
        executionMode: options?.executionMode || "safe",
        targetType: exposureType,
      }
    );
    console.log(`[Orchestrator] Loaded policy context (${policyContext.length} chars)`);
  } catch (err) {
    console.warn("[Orchestrator] Failed to load policy context:", err);
  }

  const context: AgentContext = {
    assetId,
    exposureType,
    priority,
    description,
    evaluationId,
    adversaryProfile: options?.adversaryProfile,
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    policyContext,
  };

  const memory: AgentMemory = { context, safetyDecisions: [] };
  
  const guardianContext = {
    organizationId: options?.organizationId,
    executionMode: options?.executionMode || "safe",
    targetType: exposureType,
    assetId,
    evaluationId,
  };

  onProgress?.("Recon Agent", "recon", 5, "Initializing reconnaissance...");
  const reconResult = await runWithHeartbeat(evaluationId, "Recon Agent", 
    () => runReconAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Recon Agent", stage, progress, message);
      onProgress?.("Recon Agent", stage, progress, message);
    })
  );
  memory.recon = reconResult.findings;

  onProgress?.("Exploit Agent", "exploit", 25, "Analyzing exploit chains...");
  const exploitResult = await runWithHeartbeat(evaluationId, "Exploit Agent",
    () => runExploitAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Exploit Agent", stage, progress, message);
      onProgress?.("Exploit Agent", stage, progress, message);
    })
  );
  
  onProgress?.("Policy Guardian", "policy_check", 35, "Validating exploit chains against policies...");
  const guardedExploitFindings = await runPolicyGuardianCheckLoop(
    exploitResult.findings,
    "Exploit Agent",
    guardianContext,
    evaluationId,
    memory,
    onProgress
  );
  memory.exploit = guardedExploitFindings;

  onProgress?.("Lateral Movement Agent", "lateral", 45, "Mapping lateral paths...");
  const lateralResult = await runWithHeartbeat(evaluationId, "Lateral Movement Agent",
    () => runLateralAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Lateral Movement Agent", stage, progress, message);
      onProgress?.("Lateral Movement Agent", stage, progress, message);
    })
  );
  
  onProgress?.("Policy Guardian", "policy_check", 50, "Validating lateral movements against policies...");
  const guardedLateralFindings = await runLateralGuardianCheckLoop(
    lateralResult.findings,
    guardianContext,
    evaluationId,
    memory,
    onProgress
  );
  memory.lateral = guardedLateralFindings;

  onProgress?.("Business Logic Agent", "business_logic", 55, "Analyzing business logic flaws...");
  const businessLogicResult = await runWithHeartbeat(evaluationId, "Business Logic Agent",
    () => runBusinessLogicAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Business Logic Agent", stage, progress, message);
      onProgress?.("Business Logic Agent", stage, progress, message);
    })
  );
  memory.businessLogic = businessLogicResult.findings;

  if (shouldRunEnhancedEngine(exposureType)) {
    onProgress?.("Business Logic Engine", "enhanced_business_logic", 60, "Running enhanced business logic analysis...");
    const enhancedResult = await runWithHeartbeat(evaluationId, "Business Logic Engine",
      () => runEnhancedBusinessLogicEngine(memory, (stage: string, progress: number, message: string) => {
        updateAgentHeartbeat(evaluationId, "Business Logic Engine", stage, progress, message);
        onProgress?.("Business Logic Engine", stage, progress, message);
      })
    );
    memory.enhancedBusinessLogic = enhancedResult.findings;
  }

  if (shouldRunMultiVectorAnalysis(exposureType)) {
    onProgress?.("Multi-Vector Agent", "multi_vector", 70, "Analyzing multi-vector attack paths...");
    const multiVectorResult = await runWithHeartbeat(evaluationId, "Multi-Vector Agent",
      () => runMultiVectorAnalysisAgent(memory, (stage: string, progress: number, message: string) => {
        updateAgentHeartbeat(evaluationId, "Multi-Vector Agent", stage, progress, message);
        onProgress?.("Multi-Vector Agent", stage, progress, message);
      })
    );
    memory.multiVector = multiVectorResult.findings;
  }

  onProgress?.("Impact Agent", "impact", 80, "Assessing business impact...");
  const impactResult = await runWithHeartbeat(evaluationId, "Impact Agent",
    () => runImpactAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Impact Agent", stage, progress, message);
      onProgress?.("Impact Agent", stage, progress, message);
    })
  );
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

  onProgress?.("LLM Validation", "llm_validation", 98, "Validating findings with LLM Judge...");
  const validatedFindings = await validateOrchestratorFindings(
    {
      attackPath: result.attackPath,
      businessLogicFindings: memory.enhancedBusinessLogic?.detailedFindings,
      multiVectorFindings: memory.multiVector?.findings,
    },
    {
      evaluationId,
      assetId,
      exposureType,
    },
    (stage, progress, message) => {
      onProgress?.("LLM Validation", stage, 98, message);
    }
  );

  const totalProcessingTime = Date.now() - startTime;

  onProgress?.("Complete", "complete", 100, "Analysis complete");

  return {
    ...result,
    attackPath: validatedFindings.attackPath,
    attackGraph: graphResult.attackGraph,
    businessLogicFindings: validatedFindings.businessLogicFindings,
    multiVectorFindings: validatedFindings.multiVectorFindings,
    workflowAnalysis: memory.enhancedBusinessLogic?.workflowAnalysis || undefined,
    evidenceArtifacts,
    intelligentScore,
    remediationGuidance,
    llmValidation: validatedFindings.llmValidation,
    llmValidationVerdict: validatedFindings.llmValidationVerdict,
    validationStats: validatedFindings.validationStats,
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
    safetyDecisions: memory.safetyDecisions,
  };
}

async function runPolicyGuardianCheckLoop(
  exploitFindings: ExploitFindings,
  agentName: string,
  guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  evaluationId: string,
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<ExploitFindings> {
  if (!exploitFindings.exploitChains || exploitFindings.exploitChains.length === 0) {
    return exploitFindings;
  }

  const allowedChains: typeof exploitFindings.exploitChains = [];
  let blockedCount = 0;
  let modifiedCount = 0;

  for (let i = 0; i < exploitFindings.exploitChains.length; i++) {
    const chain = exploitFindings.exploitChains[i];
    
    onProgress?.(
      "Policy Guardian",
      "policy_check",
      35 + Math.floor((i / exploitFindings.exploitChains.length) * 5),
      `Checking exploit chain ${i + 1}/${exploitFindings.exploitChains.length}: ${chain.name}`
    );

    try {
      const checkResult = await checkExploitChain(chain, guardianContext);
      
      const safetyDecision: SafetyDecision = {
        id: `sd-${Date.now()}-${i}`,
        evaluationId,
        agentName,
        originalAction: `${chain.name}: ${chain.description}`,
        decision: checkResult.decision,
        modifiedAction: checkResult.modifiedAction,
        reasoning: checkResult.reasoning,
        policyReferences: checkResult.relevantPolicies.map((p) => 
          `${p.metadata.filename || "policy"}: ${p.content.substring(0, 80)}...`
        ),
        timestamp: checkResult.timestamp,
      };
      
      memory.safetyDecisions?.push(safetyDecision);

      wsService.sendSafetyBlock(
        evaluationId,
        agentName,
        checkResult.decision,
        `${chain.name}: ${chain.description}`,
        checkResult.reasoning,
        checkResult.modifiedAction
      );

      switch (checkResult.decision) {
        case "ALLOW":
          allowedChains.push(chain);
          break;
        case "DENY":
          blockedCount++;
          console.log(`[Orchestrator] Blocked exploit chain: ${chain.name} - ${checkResult.reasoning}`);
          break;
        case "MODIFY":
          modifiedCount++;
          allowedChains.push({
            ...chain,
            name: `[MODIFIED] ${chain.name}`,
            description: checkResult.modifiedAction || chain.description,
          });
          console.log(`[Orchestrator] Modified exploit chain: ${chain.name}`);
          break;
      }
    } catch (error) {
      console.error(`[Orchestrator] Policy check failed for chain ${chain.name}:`, error);
      if (guardianContext.executionMode === "safe") {
        blockedCount++;
      } else {
        allowedChains.push(chain);
      }
    }
  }

  console.log(`[Orchestrator] Policy Guardian results: ${allowedChains.length} allowed, ${blockedCount} blocked, ${modifiedCount} modified`);

  return {
    ...exploitFindings,
    exploitChains: allowedChains,
    exploitable: allowedChains.length > 0 && exploitFindings.exploitable,
  };
}

async function runLateralGuardianCheckLoop(
  lateralFindings: LateralFindings,
  guardianContext: {
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    targetType?: string;
    assetId?: string;
    evaluationId?: string;
  },
  evaluationId: string,
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<LateralFindings> {
  if (!lateralFindings.pivotPaths || lateralFindings.pivotPaths.length === 0) {
    return lateralFindings;
  }

  const allowedPaths: typeof lateralFindings.pivotPaths = [];
  let blockedCount = 0;

  for (let i = 0; i < lateralFindings.pivotPaths.length; i++) {
    const path = lateralFindings.pivotPaths[i];
    
    onProgress?.(
      "Policy Guardian",
      "policy_check",
      50 + Math.floor((i / lateralFindings.pivotPaths.length) * 3),
      `Checking lateral path ${i + 1}/${lateralFindings.pivotPaths.length}: ${path.from} → ${path.to}`
    );

    try {
      const checkResult = await checkLateralMovement(path, guardianContext);
      
      const safetyDecision: SafetyDecision = {
        id: `sd-lat-${Date.now()}-${i}`,
        evaluationId,
        agentName: "Lateral Movement Agent",
        originalAction: `${path.from} → ${path.to}: ${path.method}`,
        decision: checkResult.decision,
        modifiedAction: checkResult.modifiedAction,
        reasoning: checkResult.reasoning,
        policyReferences: checkResult.relevantPolicies.map((p) => 
          `${p.metadata.filename || "policy"}: ${p.content.substring(0, 80)}...`
        ),
        timestamp: checkResult.timestamp,
      };
      
      memory.safetyDecisions?.push(safetyDecision);

      wsService.sendSafetyBlock(
        evaluationId,
        "Lateral Movement Agent",
        checkResult.decision,
        `${path.from} → ${path.to}: ${path.method}`,
        checkResult.reasoning,
        checkResult.modifiedAction
      );

      if (checkResult.decision === "ALLOW" || checkResult.decision === "MODIFY") {
        allowedPaths.push(path);
      } else {
        blockedCount++;
        console.log(`[Orchestrator] Blocked lateral path: ${path.from} → ${path.to}`);
      }
    } catch (error) {
      console.error(`[Orchestrator] Policy check failed for lateral path:`, error);
      if (guardianContext.executionMode === "safe") {
        blockedCount++;
      } else {
        allowedPaths.push(path);
      }
    }
  }

  console.log(`[Orchestrator] Lateral Guardian results: ${allowedPaths.length} allowed, ${blockedCount} blocked`);

  return {
    ...lateralFindings,
    pivotPaths: allowedPaths,
  };
}
