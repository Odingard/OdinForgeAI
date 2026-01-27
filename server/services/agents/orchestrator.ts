import type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
  SafetyDecision,
  ExploitFindings,
  LateralFindings,
  DebateSummary,
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
import { runDebateModule, filterVerifiedFindings, type DebateResult } from "./debate-module";
import { wsService } from "../websocket";
import { storage } from "../../storage";
import { createAuditLogger } from "../audit-logger";

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
  const executionId = `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  const auditLogger = createAuditLogger({
    executionId,
    evaluationId,
    organizationId: options?.organizationId || "default",
  });

  await auditLogger.logAgentDecision(
    "Orchestrator",
    "START_EVALUATION",
    `Starting evaluation for ${exposureType} on asset ${assetId}`,
    { assetId, exposureType, priority, description, executionMode: options?.executionMode }
  );
  
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
  wsService.sendReasoningTrace(evaluationId, "orchestrator", "Orchestrator", 
    "Initiating reconnaissance phase to discover attack surface and entry points");
  
  const reconResult = await runWithHeartbeat(evaluationId, "Recon Agent", 
    () => runReconAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Recon Agent", stage, progress, message);
      onProgress?.("Recon Agent", stage, progress, message);
    })
  );
  memory.recon = reconResult.findings;
  
  wsService.sendSharedMemoryUpdate(evaluationId, "recon_agent", "ReconAgent", "recon", 
    `Discovered ${reconResult.findings.attackSurface?.length || 0} attack surface elements`);

  onProgress?.("Exploit Agent", "exploit", 25, "Analyzing exploit chains...");
  wsService.sendReasoningTrace(evaluationId, "exploit_agent", "ExploitAgent", 
    "Analyzing potential exploit chains using discovered attack surface");
  
  const exploitResult = await runWithHeartbeat(evaluationId, "Exploit Agent",
    () => runExploitAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Exploit Agent", stage, progress, message);
      onProgress?.("Exploit Agent", stage, progress, message);
    })
  );
  
  wsService.sendSharedMemoryUpdate(evaluationId, "exploit_agent", "ExploitAgent", "exploit", 
    `Identified ${exploitResult.findings.exploitChains?.length || 0} potential exploit chains`);
  
  onProgress?.("Policy Guardian", "policy_check", 35, "Validating exploit chains against policies...");
  const guardedExploitFindings = await runPolicyGuardianCheckLoop(
    exploitResult.findings,
    "Exploit Agent",
    guardianContext,
    evaluationId,
    memory,
    onProgress
  );

  onProgress?.("Debate Module", "debate", 40, "CriticAgent challenging exploit findings...");
  wsService.sendReasoningTrace(evaluationId, "debate_module", "DebateModule", 
    `Initiating adversarial validation - CriticAgent will challenge ${guardedExploitFindings.exploitChains?.length || 0} exploit findings`);
  
  let debateSummary: DebateSummary | undefined;
  let debatedExploitFindings = guardedExploitFindings;
  
  try {
    const debateResult = await runDebateModule(
      memory,
      guardedExploitFindings,
      { model: "meta-llama/llama-3.3-70b-instruct" },
      (stage, progress, message) => {
        onProgress?.("Debate Module", stage, 40 + Math.floor(progress / 10), message);
        wsService.sendReasoningTrace(evaluationId, "critic_agent", "CriticAgent", message);
      }
    );
    
    debateSummary = {
      finalVerdict: debateResult.finalVerdict,
      consensusReached: debateResult.consensusReached,
      verifiedChains: debateResult.verifiedChains,
      adjustedConfidence: debateResult.adjustedConfidence,
      debateRounds: debateResult.debateRounds,
      criticModelUsed: debateResult.criticResult.modelUsed,
      criticReasoning: debateResult.criticResult.reasoning,
      processingTime: debateResult.processingTime,
    };
    
    debatedExploitFindings = filterVerifiedFindings(debateResult);
    
    const verifiedCount = debateResult.verifiedChains.filter(c => c.verificationStatus === "verified").length;
    const rejectedCount = debateResult.verifiedChains.filter(c => c.verificationStatus === "rejected").length;
    
    wsService.sendReasoningTrace(evaluationId, "debate_module", "DebateModule", 
      `Debate concluded: ${debateResult.finalVerdict} verdict. ${verifiedCount} verified, ${rejectedCount} rejected as false positives.`,
      { decision: debateResult.finalVerdict === "VERIFIED" ? "VERIFIED" : debateResult.finalVerdict === "FALSE_POSITIVE" ? "FALSE_POSITIVE" : "DISPUTED" }
    );
    
    console.log(`[Orchestrator] Debate complete: ${debateResult.finalVerdict} (${verifiedCount} verified, ${rejectedCount} rejected)`);
    
    wsService.broadcastToChannel(`evaluation:${evaluationId}`, {
      type: "debate_result",
      evaluationId,
      verdict: debateResult.finalVerdict,
      consensusReached: debateResult.consensusReached,
      verifiedCount: debateResult.verifiedChains.filter(c => c.verificationStatus === "verified").length,
      rejectedCount: debateResult.verifiedChains.filter(c => c.verificationStatus === "rejected").length,
    });
  } catch (err) {
    console.warn("[Orchestrator] Debate module failed, using unverified findings:", err);
  }
  
  memory.exploit = debatedExploitFindings;

  onProgress?.("Lateral Movement Agent", "lateral", 45, "Mapping lateral paths...");
  wsService.sendReasoningTrace(evaluationId, "lateral_agent", "LateralAgent", 
    "Mapping lateral movement paths and pivot opportunities from compromised positions");
  
  const lateralResult = await runWithHeartbeat(evaluationId, "Lateral Movement Agent",
    () => runLateralAgent(memory, (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, "Lateral Movement Agent", stage, progress, message);
      onProgress?.("Lateral Movement Agent", stage, progress, message);
    })
  );
  
  wsService.sendSharedMemoryUpdate(evaluationId, "lateral_agent", "LateralAgent", "lateral", 
    `Discovered ${lateralResult.findings.pivotPaths?.length || 0} lateral movement paths`);
  
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

  // Persist safety decisions to database for audit trail
  if (memory.safetyDecisions && memory.safetyDecisions.length > 0) {
    try {
      await storage.createSafetyDecisionsBatch(
        memory.safetyDecisions.map((sd) => ({
          id: sd.id,
          evaluationId: sd.evaluationId,
          organizationId: sd.organizationId || "default",
          agentName: sd.agentName,
          originalAction: sd.originalAction,
          decision: sd.decision,
          modifiedAction: sd.modifiedAction,
          reasoning: sd.reasoning,
          policyReferences: sd.policyReferences || [],
          executionMode: sd.executionMode || "safe",
        }))
      );
      console.log(`[Orchestrator] Persisted ${memory.safetyDecisions.length} safety decisions to database`);
    } catch (error) {
      console.error("[Orchestrator] Failed to persist safety decisions:", error);
      // Non-fatal: continue with evaluation completion
    }
  }

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
    debateSummary,
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
      
      const policyNames = checkResult.relevantPolicies.map((p) => 
        p.metadata.filename || p.metadata.policyType || "policy"
      );
      
      wsService.sendReasoningTrace(
        evaluationId, 
        "policy_guardian", 
        "PolicyGuardian", 
        `Evaluating "${chain.name}": ${checkResult.reasoning}`,
        {
          context: `Exploit chain: ${chain.technique || "unknown technique"}`,
          policiesChecked: policyNames.length > 0 ? policyNames : ["default-policy"],
          decision: checkResult.decision,
        }
      );
      
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
      
      const policyNames = checkResult.relevantPolicies.map((p) => 
        p.metadata.filename || p.metadata.policyType || "policy"
      );
      
      wsService.sendReasoningTrace(
        evaluationId, 
        "policy_guardian", 
        "PolicyGuardian", 
        `Evaluating lateral path "${path.from} → ${path.to}": ${checkResult.reasoning}`,
        {
          context: `Lateral movement via ${path.method}`,
          policiesChecked: policyNames.length > 0 ? policyNames : ["default-policy"],
          decision: checkResult.decision,
        }
      );
      
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
