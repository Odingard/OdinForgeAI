import type { ExploitFindings, AgentMemory } from "./types";
import { runCriticAgent, type CriticResult, type CriticVerdict } from "./critic";

export interface DebateResult {
  originalFindings: ExploitFindings;
  criticResult: CriticResult;
  finalVerdict: CriticVerdict;
  consensusReached: boolean;
  verifiedChains: Array<{
    name: string;
    technique: string;
    description: string;
    success_likelihood: "high" | "medium" | "low";
    verificationStatus: "verified" | "disputed" | "rejected";
    challengeNotes?: string;
  }>;
  adjustedConfidence: number;
  debateRounds: number;
  processingTime: number;
}

export interface DebateConfig {
  model?: string;
  maxRounds?: number;
  consensusThreshold?: number;
  autoRejectFalsePositives?: boolean;
}

type ProgressCallback = (stage: string, progress: number, message: string) => void;

const DEFAULT_CONFIG: Required<DebateConfig> = {
  model: "meta-llama/llama-3.3-70b-instruct",
  maxRounds: 1,
  consensusThreshold: 0.7,
  autoRejectFalsePositives: true,
};

export async function runDebateModule(
  memory: AgentMemory,
  exploitFindings: ExploitFindings,
  config: DebateConfig = {},
  onProgress?: ProgressCallback
): Promise<DebateResult> {
  const startTime = Date.now();
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };
  
  onProgress?.("debate", 45, "Initiating adversarial debate module...");

  if (!exploitFindings.exploitable || exploitFindings.exploitChains.length === 0) {
    return {
      originalFindings: exploitFindings,
      criticResult: {
        verdict: "verified",
        challenges: [],
        overallConfidence: 1.0,
        reasoning: "No exploitable findings to debate",
        modelUsed: mergedConfig.model,
        processingTime: 0,
      },
      finalVerdict: "verified",
      consensusReached: true,
      verifiedChains: [],
      adjustedConfidence: 1.0,
      debateRounds: 0,
      processingTime: Date.now() - startTime,
    };
  }

  const reconContext = memory.recon
    ? `Attack Surface: ${memory.recon.attackSurface.join(", ")}
Entry Points: ${memory.recon.entryPoints.join(", ")}
Technologies: ${memory.recon.technologies.join(", ")}`
    : undefined;

  onProgress?.("debate", 48, "CriticAgent challenging ExploitAgent findings...");

  const criticResult = await runCriticAgent(
    {
      assetId: memory.context.assetId,
      exposureType: memory.context.exposureType,
      description: memory.context.description,
      exploitFindings,
      reconContext,
      evaluationId: memory.context.evaluationId,
    },
    mergedConfig.model,
    onProgress
  );

  onProgress?.("debate", 65, "Evaluating consensus between agents...");

  const verifiedChains = exploitFindings.exploitChains.map((chain) => {
    const relevantChallenges = criticResult.challenges.filter(
      (c) => c.chainName.toLowerCase() === chain.name.toLowerCase() ||
             c.chainName.toLowerCase().includes(chain.name.toLowerCase()) ||
             chain.name.toLowerCase().includes(c.chainName.toLowerCase())
    );

    let status: "verified" | "disputed" | "rejected" = "verified";
    let challengeNotes: string | undefined;

    if (relevantChallenges.length > 0) {
      const maxConfidence = Math.max(...relevantChallenges.map((c) => c.confidence));
      
      if (criticResult.verdict === "false_positive" && maxConfidence >= mergedConfig.consensusThreshold) {
        status = "rejected";
        challengeNotes = relevantChallenges.map((c) => `[${c.challengeType}] ${c.reasoning}`).join("; ");
      } else if (maxConfidence >= 0.5) {
        status = "disputed";
        challengeNotes = relevantChallenges.map((c) => `[${c.challengeType}] ${c.reasoning}`).join("; ");
      }
    }

    return {
      ...chain,
      verificationStatus: status,
      challengeNotes,
    };
  });

  const verifiedCount = verifiedChains.filter((c) => c.verificationStatus === "verified").length;
  const disputedCount = verifiedChains.filter((c) => c.verificationStatus === "disputed").length;
  const rejectedCount = verifiedChains.filter((c) => c.verificationStatus === "rejected").length;

  let finalVerdict: CriticVerdict;
  let consensusReached = true;

  if (rejectedCount === verifiedChains.length) {
    finalVerdict = "false_positive";
  } else if (verifiedCount === verifiedChains.length) {
    finalVerdict = "verified";
  } else {
    finalVerdict = "disputed";
    consensusReached = false;
  }

  let adjustedConfidence = 1.0;
  if (finalVerdict === "verified") {
    adjustedConfidence = 1.0 - (criticResult.challenges.length * 0.05);
  } else if (finalVerdict === "disputed") {
    adjustedConfidence = 0.7 - (disputedCount / verifiedChains.length * 0.2);
  } else {
    adjustedConfidence = 0.2;
  }
  adjustedConfidence = Math.max(0.1, Math.min(1.0, adjustedConfidence));

  onProgress?.("debate", 70, `Debate complete: ${finalVerdict} (${verifiedCount} verified, ${disputedCount} disputed, ${rejectedCount} rejected)`);

  return {
    originalFindings: exploitFindings,
    criticResult,
    finalVerdict,
    consensusReached,
    verifiedChains,
    adjustedConfidence,
    debateRounds: 1,
    processingTime: Date.now() - startTime,
  };
}

export function filterVerifiedFindings(debateResult: DebateResult): ExploitFindings {
  const verifiedChains = debateResult.verifiedChains
    .filter((c) => c.verificationStatus !== "rejected")
    .map(({ verificationStatus, challengeNotes, ...chain }) => chain);

  return {
    ...debateResult.originalFindings,
    exploitChains: verifiedChains,
    exploitable: verifiedChains.length > 0,
  };
}
