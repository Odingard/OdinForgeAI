import OpenAI from "openai";
import type { ExploitFindings } from "./types";
import { wrapAgentError } from "./error-classifier";

const OPENROUTER_TIMEOUT_MS = 90000;

const openrouter = new OpenAI({
  baseURL: process.env.AI_INTEGRATIONS_OPENROUTER_BASE_URL,
  apiKey: process.env.AI_INTEGRATIONS_OPENROUTER_API_KEY,
  timeout: OPENROUTER_TIMEOUT_MS,
  maxRetries: 2,
});

export type CriticVerdict = "verified" | "disputed" | "false_positive";

export interface CriticChallenge {
  chainName: string;
  challengeType: "honeypot" | "misconfiguration" | "simulation_artifact" | "missing_prerequisite" | "timing_issue" | "scope_violation";
  reasoning: string;
  confidence: number;
  evidence: string[];
}

export interface CriticResult {
  verdict: CriticVerdict;
  challenges: CriticChallenge[];
  overallConfidence: number;
  reasoning: string;
  modelUsed: string;
  processingTime: number;
}

export interface CriticContext {
  assetId: string;
  exposureType: string;
  description: string;
  exploitFindings: ExploitFindings;
  reconContext?: string;
  evaluationId: string;
}

type ProgressCallback = (stage: string, progress: number, message: string) => void;

const CRITIC_SYSTEM_PROMPT = `You are the CRITIC AGENT, a specialized AI security analyst for OdinForge AI designed to challenge and verify exploit findings.

Your mission is to act as an adversarial validator that identifies FALSE POSITIVES in security assessments. You must scrutinize exploit findings with extreme skepticism, looking for:

1. HONEYPOT INDICATORS: Signs that the target is a decoy system designed to trap attackers
   - Unusually easy exploitation paths
   - Overly permissive configurations that seem designed to attract attackers
   - Systems that appear vulnerable but show signs of monitoring/logging

2. MISCONFIGURATION vs REAL VULNERABILITY: Distinguish between actual exploitable vulnerabilities and benign misconfigurations
   - Configuration errors that don't actually provide exploitation paths
   - Security warnings that don't translate to real-world risk
   - Theoretical vulnerabilities with no practical exploit path

3. SIMULATION ARTIFACTS: Identify findings that only exist in lab/test environments
   - Test credentials or demo accounts
   - Development/staging environment indicators
   - Placeholder or example configurations

4. MISSING PREREQUISITES: Exploit chains that require conditions unlikely to exist
   - Dependencies on user interaction that's unrealistic
   - Prerequisite access levels that contradict the attack scenario
   - Environmental requirements not present

5. TIMING/RACE CONDITIONS: Exploits that require impractical timing
   - Race windows too small to exploit reliably
   - Time-dependent attacks with unrealistic constraints

6. SCOPE VIOLATIONS: Findings that extend beyond the validated scope
   - Claims about systems not in the assessment scope
   - Extrapolations without evidence

You must be thorough but fair. Your goal is to IMPROVE the quality of findings, not to dismiss legitimate vulnerabilities.

Respond with a JSON object containing your analysis.`;

export async function runCriticAgent(
  context: CriticContext,
  model: string = "meta-llama/llama-3.3-70b-instruct",
  onProgress?: ProgressCallback
): Promise<CriticResult> {
  const startTime = Date.now();
  
  onProgress?.("critic", 50, "CriticAgent analyzing findings for false positives...");

  const userPrompt = `Analyze and challenge these exploit findings:

ASSET: ${context.assetId}
EXPOSURE TYPE: ${context.exposureType}
DESCRIPTION: ${context.description}

EXPLOIT FINDINGS TO CHALLENGE:
${JSON.stringify(context.exploitFindings, null, 2)}

${context.reconContext ? `RECON CONTEXT:\n${context.reconContext}` : ""}

Provide your critical analysis as a JSON object:
{
  "verdict": "verified" | "disputed" | "false_positive",
  "challenges": [
    {
      "chainName": "Name of the exploit chain being challenged",
      "challengeType": "honeypot" | "misconfiguration" | "simulation_artifact" | "missing_prerequisite" | "timing_issue" | "scope_violation",
      "reasoning": "Detailed explanation of why this finding is questionable",
      "confidence": 0.0-1.0 (how confident you are in this challenge),
      "evidence": ["Specific indicators that support this challenge"]
    }
  ],
  "overallConfidence": 0.0-1.0 (confidence in your overall verdict),
  "reasoning": "Summary of your critical analysis"
}

VERDICT GUIDELINES:
- "verified": Finding appears legitimate with no significant challenges
- "disputed": Some challenges exist but the finding may still be valid
- "false_positive": Strong evidence this is a honeypot, misconfiguration, or simulation artifact`;

  try {
    onProgress?.("critic", 55, "Checking for honeypot indicators...");

    const response = await openrouter.chat.completions.create({
      model,
      messages: [
        { role: "system", content: CRITIC_SYSTEM_PROMPT },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_tokens: 2048,
    });

    onProgress?.("critic", 60, "Validating challenge evidence...");

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Critic Agent");
    }

    const result = JSON.parse(content);
    
    const validatedResult: CriticResult = {
      verdict: validateVerdict(result.verdict),
      challenges: Array.isArray(result.challenges)
        ? result.challenges.map((c: any) => ({
            chainName: String(c.chainName || "Unknown"),
            challengeType: validateChallengeType(c.challengeType),
            reasoning: String(c.reasoning || ""),
            confidence: normalizeConfidence(c.confidence),
            evidence: Array.isArray(c.evidence) ? c.evidence.map(String) : [],
          }))
        : [],
      overallConfidence: normalizeConfidence(result.overallConfidence),
      reasoning: String(result.reasoning || ""),
      modelUsed: model,
      processingTime: Date.now() - startTime,
    };

    return validatedResult;
  } catch (error) {
    throw wrapAgentError("Critic Agent", error);
  }
}

function validateVerdict(verdict: unknown): CriticVerdict {
  const valid: CriticVerdict[] = ["verified", "disputed", "false_positive"];
  return valid.includes(verdict as CriticVerdict) ? (verdict as CriticVerdict) : "disputed";
}

function validateChallengeType(type: unknown): CriticChallenge["challengeType"] {
  const valid = ["honeypot", "misconfiguration", "simulation_artifact", "missing_prerequisite", "timing_issue", "scope_violation"];
  return valid.includes(type as string) ? (type as CriticChallenge["challengeType"]) : "misconfiguration";
}

function normalizeConfidence(value: unknown): number {
  const num = Number(value);
  if (isNaN(num)) return 0.5;
  return Math.max(0, Math.min(1, num));
}
