import OpenAI from "openai";
import { type AttackPathStep, type Recommendation, type AppLogicExposureData } from "@shared/schema";
import { analyzeAppLogicExposure } from "./app-logic-analyzer";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export interface AEVAnalysisResult {
  exploitable: boolean;
  confidence: number;
  score: number;
  attackPath: AttackPathStep[];
  impact: string;
  recommendations: Recommendation[];
}

export type ProgressCallback = (stage: string, progress: number, message: string) => void;

export async function analyzeExposure(
  assetId: string,
  exposureType: string,
  priority: string,
  description: string,
  onProgress?: ProgressCallback,
  appLogicData?: AppLogicExposureData
): Promise<AEVAnalysisResult> {
  // For app_logic exposure type, use deterministic analyzer (no LLM cost)
  if (exposureType === "app_logic" && appLogicData) {
    onProgress?.("app_logic_analysis", 25, "Analyzing endpoint metadata...");
    onProgress?.("app_logic_analysis", 50, "Checking IDOR/BOLA patterns...");
    onProgress?.("app_logic_analysis", 75, "Evaluating authorization boundaries...");
    
    const result = analyzeAppLogicExposure({
      assetId,
      description,
      data: appLogicData
    });
    
    onProgress?.("app_logic_analysis", 100, "Analysis complete");
    return result;
  }
  const stages = [
    { name: "attack_surface", progress: 25, message: "Analyzing attack surface..." },
    { name: "exploit_chain", progress: 50, message: "Constructing exploit chain..." },
    { name: "impact", progress: 75, message: "Assessing impact potential..." },
    { name: "remediation", progress: 100, message: "Generating remediation recommendations..." },
  ];

  onProgress?.(stages[0].name, stages[0].progress, stages[0].message);

  const systemPrompt = `You are OdinForge AI (Autonomous Exploit Validation), an advanced AI security analyst specializing in adversarial exposure validation. Your task is to analyze security exposures and determine their exploitability through autonomous reasoning.

For each exposure, you must:
1. Analyze the attack surface and potential entry points
2. Construct a realistic attack path using MITRE ATT&CK techniques
3. Assess the potential impact if exploited
4. Generate actionable remediation recommendations

Always provide structured, actionable output in JSON format.`;

  const userPrompt = `Analyze this security exposure for exploitability:

Asset ID: ${assetId}
Exposure Type: ${exposureType}
Priority: ${priority}
Description: ${description}

Provide your analysis as a JSON object with this exact structure:
{
  "exploitable": boolean (true if the exposure can be exploited in real-world conditions),
  "confidence": number (0-100, your confidence level in the assessment),
  "score": number (0-100, exploitability severity score),
  "attackPath": [
    {
      "id": number (sequential step number),
      "title": string (brief title for this attack step),
      "description": string (detailed description of what happens),
      "technique": string (MITRE ATT&CK technique ID, e.g., "T1190"),
      "severity": "critical" | "high" | "medium" | "low"
    }
  ],
  "impact": string (description of potential business impact if exploited),
  "recommendations": [
    {
      "id": string (unique ID like "rec-1"),
      "title": string (brief title),
      "description": string (detailed remediation steps),
      "priority": "critical" | "high" | "medium" | "low",
      "type": "remediation" | "compensating" | "preventive"
    }
  ]
}`;

  try {
    onProgress?.(stages[1].name, stages[1].progress, stages[1].message);

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    onProgress?.(stages[2].name, stages[2].progress, stages[2].message);

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response content from AI");
    }

    const result = JSON.parse(content) as AEVAnalysisResult;

    onProgress?.(stages[3].name, stages[3].progress, stages[3].message);

    const validatedResult: AEVAnalysisResult = {
      exploitable: Boolean(result.exploitable),
      confidence: Math.min(100, Math.max(0, Number(result.confidence) || 50)),
      score: Math.min(100, Math.max(0, Number(result.score) || 50)),
      attackPath: Array.isArray(result.attackPath) 
        ? result.attackPath.map((step, index) => ({
            id: step.id || index + 1,
            title: String(step.title || "Attack Step"),
            description: String(step.description || ""),
            technique: step.technique ? String(step.technique) : undefined,
            severity: validateSeverity(step.severity),
          }))
        : [],
      impact: String(result.impact || "Impact assessment pending"),
      recommendations: Array.isArray(result.recommendations)
        ? result.recommendations.map((rec, index) => ({
            id: String(rec.id || `rec-${index + 1}`),
            title: String(rec.title || "Recommendation"),
            description: String(rec.description || ""),
            priority: validateSeverity(rec.priority),
            type: validateRecType(rec.type),
          }))
        : [],
    };

    return validatedResult;
  } catch (error) {
    console.error("AEV analysis error:", error);
    throw error;
  }
}

function validateSeverity(severity: unknown): "critical" | "high" | "medium" | "low" {
  const valid = ["critical", "high", "medium", "low"];
  return valid.includes(String(severity)) 
    ? (severity as "critical" | "high" | "medium" | "low") 
    : "medium";
}

function validateRecType(type: unknown): "remediation" | "compensating" | "preventive" {
  const valid = ["remediation", "compensating", "preventive"];
  return valid.includes(String(type)) 
    ? (type as "remediation" | "compensating" | "preventive") 
    : "remediation";
}
