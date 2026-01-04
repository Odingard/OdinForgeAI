import OpenAI from "openai";
import type { AgentMemory, AgentContext, OrchestratorResult, ProgressCallback } from "./types";
import { runDefenderAgent, DefenderFindings } from "./defender";
import { runAgentOrchestrator } from "./orchestrator";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

export interface SimulationRound {
  roundNumber: number;
  attackerFindings: OrchestratorResult;
  defenderFindings: DefenderFindings;
  attackSuccess: number;
  defenseSuccess: number;
  roundSummary: string;
}

export interface PurpleTeamFeedback {
  attackerAdaptations: string[];
  defenderAdaptations: string[];
  newAttackVectors: string[];
  newDefensiveControls: string[];
  overallInsight: string;
}

export interface AISimulationResult {
  simulationId: string;
  assetId: string;
  exposureType: string;
  totalRounds: number;
  rounds: SimulationRound[];
  purpleTeamFeedback: PurpleTeamFeedback;
  finalAttackScore: number;
  finalDefenseScore: number;
  winner: "attacker" | "defender" | "draw";
  recommendations: SimulationRecommendation[];
  executiveSummary: string;
  totalProcessingTime: number;
}

export interface SimulationRecommendation {
  id: string;
  type: "offensive" | "defensive" | "process";
  priority: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  effort: "low" | "medium" | "high";
  impact: "low" | "medium" | "high";
}

export type SimulationProgressCallback = (
  phase: string,
  round: number,
  progress: number,
  message: string
) => void;

// Live scan data that can be injected into simulations
export interface LiveScanInput {
  targetHost: string;
  resolvedIp?: string;
  ports: Array<{
    port: number;
    state: string;
    service?: string;
    banner?: string;
    version?: string;
  }>;
  vulnerabilities: Array<{
    port: number;
    service: string;
    severity: string;
    title: string;
    description: string;
    cveIds?: string[];
    remediation?: string;
  }>;
}

export async function runAISimulation(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  evaluationId: string,
  rounds: number = 3,
  onProgress?: SimulationProgressCallback,
  liveScanData?: LiveScanInput
): Promise<AISimulationResult> {
  const startTime = Date.now();
  const simulationRounds: SimulationRound[] = [];
  
  onProgress?.("initialization", 0, 5, "Initializing AI vs AI simulation...");

  // Build enhanced description with live scan data if available
  let enhancedDescription = description;
  if (liveScanData) {
    const liveReconData = buildLiveScanReconData(liveScanData);
    enhancedDescription = `${description}

LIVE RECONNAISSANCE DATA (from actual network scan):
${liveReconData}

Use this real network data as the foundation for attack planning.`;
    onProgress?.("initialization", 0, 8, `Injecting live scan data: ${liveScanData.ports.length} ports, ${liveScanData.vulnerabilities.length} vulnerabilities`);
  }

  const context: AgentContext = {
    assetId,
    exposureType,
    priority,
    description: enhancedDescription,
    evaluationId,
  };

  let cumulativeAttackScore = 0;
  let cumulativeDefenseScore = 0;
  let previousDefenderFindings: DefenderFindings | null = null;

  for (let round = 1; round <= rounds; round++) {
    const roundProgress = Math.floor((round - 1) / rounds * 80) + 10;
    onProgress?.("attack", round, roundProgress, `Round ${round}: Attacker phase...`);

    const attackerContext = buildAttackerContext(context, previousDefenderFindings, round);
    
    const attackerResult = await runAgentOrchestrator(
      attackerContext.assetId,
      attackerContext.exposureType,
      attackerContext.priority,
      attackerContext.description,
      evaluationId,
      (agentName, stage, progress, message) => {
        const scaledProgress = roundProgress + Math.floor(progress * 0.3);
        onProgress?.("attack", round, scaledProgress, `[Attacker] ${agentName}: ${message}`);
      }
    );

    onProgress?.("defense", round, roundProgress + 35, `Round ${round}: Defender phase...`);

    const memory: AgentMemory = {
      context,
      recon: attackerResult.agentFindings.recon,
      exploit: attackerResult.agentFindings.exploit,
      lateral: attackerResult.agentFindings.lateral,
      businessLogic: attackerResult.agentFindings.businessLogic,
      enhancedBusinessLogic: attackerResult.agentFindings.enhancedBusinessLogic,
      multiVector: attackerResult.agentFindings.multiVector,
      impact: attackerResult.agentFindings.impact,
    };

    const defenderResult = await runDefenderAgent(memory, (agentName, stage, progress, message) => {
      const scaledProgress = roundProgress + 35 + Math.floor(progress * 0.3);
      onProgress?.("defense", round, scaledProgress, `[Defender] ${message}`);
    });

    const attackSuccess = calculateAttackSuccess(attackerResult, defenderResult.findings);
    const defenseSuccess = defenderResult.findings.defenseEffectiveness;

    cumulativeAttackScore += attackSuccess;
    cumulativeDefenseScore += defenseSuccess;

    const roundSummary = await generateRoundSummary(round, attackerResult, defenderResult.findings);

    simulationRounds.push({
      roundNumber: round,
      attackerFindings: attackerResult,
      defenderFindings: defenderResult.findings,
      attackSuccess,
      defenseSuccess,
      roundSummary,
    });

    previousDefenderFindings = defenderResult.findings;
  }

  onProgress?.("synthesis", rounds, 90, "Generating purple team feedback...");

  const purpleTeamFeedback = await generatePurpleTeamFeedback(simulationRounds);

  onProgress?.("finalization", rounds, 95, "Generating final recommendations...");

  const finalAttackScore = cumulativeAttackScore / rounds;
  const finalDefenseScore = cumulativeDefenseScore / rounds;
  const winner = determineWinner(finalAttackScore, finalDefenseScore);

  const recommendations = await generateSimulationRecommendations(simulationRounds, purpleTeamFeedback);
  const executiveSummary = await generateExecutiveSummary(
    assetId, 
    exposureType, 
    simulationRounds, 
    finalAttackScore, 
    finalDefenseScore, 
    winner
  );

  onProgress?.("complete", rounds, 100, "AI vs AI simulation complete");

  return {
    simulationId: `sim-${Date.now()}`,
    assetId,
    exposureType,
    totalRounds: rounds,
    rounds: simulationRounds,
    purpleTeamFeedback,
    finalAttackScore,
    finalDefenseScore,
    winner,
    recommendations,
    executiveSummary,
    totalProcessingTime: Date.now() - startTime,
  };
}

function buildAttackerContext(
  context: AgentContext,
  previousDefenderFindings: DefenderFindings | null,
  round: number
): AgentContext {
  if (!previousDefenderFindings || round === 1) {
    return context;
  }

  const adaptedDescription = `${context.description}

ATTACKER ADAPTATION (Round ${round}):
The defender has implemented the following controls that the attacker is now aware of:
- Blocked Paths: ${previousDefenderFindings.blockedPaths.map(p => p.attackPath).join("; ")}
- Detection Methods: ${previousDefenderFindings.detectedAttacks.map(d => d.detectionMethod).join("; ")}
- Active Controls: ${previousDefenderFindings.defensiveControls.map(c => c.name).join("; ")}

The attacker must now attempt to evade these defenses or find alternative attack paths.`;

  return {
    ...context,
    description: adaptedDescription,
  };
}

function buildLiveScanReconData(liveScanData: LiveScanInput): string {
  const sections: string[] = [];
  
  // Target information
  sections.push(`Target: ${liveScanData.targetHost}${liveScanData.resolvedIp ? ` (${liveScanData.resolvedIp})` : ""}`);
  
  // Open ports and services
  if (liveScanData.ports.length > 0) {
    const openPorts = liveScanData.ports.filter(p => p.state === "open");
    sections.push(`\nOpen Ports (${openPorts.length} discovered):`);
    for (const port of openPorts) {
      let portInfo = `  - ${port.port}/${port.service || "unknown"}`;
      if (port.version) portInfo += ` (${port.version})`;
      if (port.banner) portInfo += ` - Banner: "${port.banner.slice(0, 50)}..."`;
      sections.push(portInfo);
    }
  }
  
  // Known vulnerabilities
  if (liveScanData.vulnerabilities.length > 0) {
    sections.push(`\nConfirmed Vulnerabilities (${liveScanData.vulnerabilities.length} found):`);
    for (const vuln of liveScanData.vulnerabilities) {
      sections.push(`  - [${vuln.severity.toUpperCase()}] ${vuln.title}`);
      sections.push(`    Port: ${vuln.port} | Service: ${vuln.service}`);
      sections.push(`    Description: ${vuln.description}`);
      if (vuln.cveIds && vuln.cveIds.length > 0) {
        sections.push(`    CVEs: ${vuln.cveIds.join(", ")}`);
      }
    }
  }
  
  return sections.join("\n");
}

function calculateAttackSuccess(
  attackerResult: OrchestratorResult,
  defenderFindings: DefenderFindings
): number {
  const baseAttackScore = attackerResult.score / 100;
  
  const blockedPathsPenalty = Math.min(defenderFindings.blockedPaths.length * 0.1, 0.3);
  const detectionPenalty = Math.min(defenderFindings.detectedAttacks.length * 0.05, 0.2);
  
  const adjustedScore = Math.max(0, baseAttackScore - blockedPathsPenalty - detectionPenalty);
  
  const exploitBonus = attackerResult.exploitable ? 0.1 : 0;
  
  return Math.min(1, adjustedScore + exploitBonus);
}

function determineWinner(attackScore: number, defenseScore: number): "attacker" | "defender" | "draw" {
  const threshold = 0.1;
  if (attackScore > defenseScore + threshold) {
    return "attacker";
  } else if (defenseScore > attackScore + threshold) {
    return "defender";
  }
  return "draw";
}

async function generateRoundSummary(
  round: number,
  attackerResult: OrchestratorResult,
  defenderFindings: DefenderFindings
): Promise<string> {
  const exploitCount = attackerResult.agentFindings.exploit.exploitChains.length;
  const detectedCount = defenderFindings.detectedAttacks.length;
  const blockedCount = defenderFindings.blockedPaths.length;
  
  return `Round ${round}: Attacker identified ${exploitCount} exploit chains. ` +
         `Defender detected ${detectedCount} attacks and blocked ${blockedCount} paths. ` +
         `Defense effectiveness: ${Math.round(defenderFindings.defenseEffectiveness * 100)}%`;
}

async function generatePurpleTeamFeedback(rounds: SimulationRound[]): Promise<PurpleTeamFeedback> {
  const roundsSummary = rounds.map(r => ({
    round: r.roundNumber,
    attackSuccess: r.attackSuccess,
    defenseSuccess: r.defenseSuccess,
    exploitsUsed: r.attackerFindings.agentFindings.exploit.exploitChains.map(e => e.name),
    detectedAttacks: r.defenderFindings.detectedAttacks.map(d => d.attackType),
    gaps: r.defenderFindings.gapsIdentified,
  }));

  const systemPrompt = `You are a PURPLE TEAM ANALYST synthesizing attack and defense simulation results.
Provide actionable feedback that helps both red and blue teams improve.`;

  const userPrompt = `Analyze these simulation rounds and provide purple team feedback:

${JSON.stringify(roundsSummary, null, 2)}

Provide feedback as JSON:
{
  "attackerAdaptations": ["How the attacker adapted between rounds"],
  "defenderAdaptations": ["How the defender adapted between rounds"],
  "newAttackVectors": ["Novel attack vectors that should be tested"],
  "newDefensiveControls": ["New controls that should be implemented"],
  "overallInsight": "Key insight from the simulation"
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 1024,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Purple Team Analyst");
    }

    return JSON.parse(content) as PurpleTeamFeedback;
  } catch (error) {
    console.error("Purple team feedback error:", error);
    return {
      attackerAdaptations: ["Unable to generate adaptations"],
      defenderAdaptations: ["Unable to generate adaptations"],
      newAttackVectors: [],
      newDefensiveControls: [],
      overallInsight: "Simulation completed but feedback generation failed.",
    };
  }
}

async function generateSimulationRecommendations(
  rounds: SimulationRound[],
  feedback: PurpleTeamFeedback
): Promise<SimulationRecommendation[]> {
  const lastRound = rounds[rounds.length - 1];
  const recommendations: SimulationRecommendation[] = [];
  let idCounter = 1;

  for (const gap of lastRound.defenderFindings.gapsIdentified.slice(0, 3)) {
    recommendations.push({
      id: `rec-${idCounter++}`,
      type: "defensive",
      priority: "high",
      title: `Address defensive gap: ${gap.slice(0, 50)}`,
      description: gap,
      effort: "medium",
      impact: "high",
    });
  }

  for (const improvement of lastRound.defenderFindings.recommendedImprovements.slice(0, 2)) {
    recommendations.push({
      id: `rec-${idCounter++}`,
      type: "defensive",
      priority: "medium",
      title: `Implement improvement: ${improvement.slice(0, 50)}`,
      description: improvement,
      effort: "medium",
      impact: "medium",
    });
  }

  for (const newVector of feedback.newAttackVectors.slice(0, 2)) {
    recommendations.push({
      id: `rec-${idCounter++}`,
      type: "offensive",
      priority: "medium",
      title: `Test new attack vector`,
      description: newVector,
      effort: "low",
      impact: "medium",
    });
  }

  for (const control of feedback.newDefensiveControls.slice(0, 2)) {
    recommendations.push({
      id: `rec-${idCounter++}`,
      type: "defensive",
      priority: "high",
      title: `Deploy new control`,
      description: control,
      effort: "high",
      impact: "high",
    });
  }

  return recommendations;
}

async function generateExecutiveSummary(
  assetId: string,
  exposureType: string,
  rounds: SimulationRound[],
  attackScore: number,
  defenseScore: number,
  winner: "attacker" | "defender" | "draw"
): Promise<string> {
  const winnerText = winner === "attacker" 
    ? "The attacker was able to successfully exploit vulnerabilities despite defensive measures."
    : winner === "defender"
    ? "The defender successfully mitigated the majority of attack attempts."
    : "Neither the attacker nor defender gained a decisive advantage.";

  return `AI vs AI Security Simulation Report for ${assetId}

Exposure Type: ${exposureType}
Simulation Rounds: ${rounds.length}

RESULTS:
- Attack Effectiveness: ${Math.round(attackScore * 100)}%
- Defense Effectiveness: ${Math.round(defenseScore * 100)}%
- Outcome: ${winner.toUpperCase()} ${winner === "draw" ? "" : "WINS"}

${winnerText}

KEY FINDINGS:
${rounds.map(r => `Round ${r.roundNumber}: ${r.roundSummary}`).join("\n")}

This simulation provides actionable intelligence for improving your security posture by understanding both offensive and defensive perspectives.`;
}
