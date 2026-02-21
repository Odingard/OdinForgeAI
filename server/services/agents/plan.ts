import type { AgentMemory, AgentResult, PlanFindings } from "./types";
import { wrapAgentError } from "./error-classifier";
import { openai } from "./openai-client";
import { buildReconGroundTruth } from "./scan-data-loader";
import { formatExternalRecon } from "./recon";

/**
 * PLAN AGENT (Tier 1.5)
 *
 * Single LLM call that takes recon data (external + LLM) and produces
 * a prioritized attack plan with per-chain turn budgets.
 * The exploit agent uses this plan to focus its tool calls.
 */

export async function runPlanAgent(
  memory: AgentMemory
): Promise<AgentResult<PlanFindings>> {
  const startTime = Date.now();

  // Build context from all available recon sources
  const reconSummary: string[] = [];

  if (memory.externalRecon) {
    const formatted = formatExternalRecon(memory.externalRecon);
    if (formatted) reconSummary.push(formatted);
  }

  if (memory.recon) {
    reconSummary.push(`LLM Recon Findings:
- Attack Surface: ${memory.recon.attackSurface.join(", ")}
- Entry Points: ${memory.recon.entryPoints.join(", ")}
- API Endpoints: ${memory.recon.apiEndpoints.join(", ")}
- Technologies: ${memory.recon.technologies.join(", ")}
- Potential Vulnerabilities: ${memory.recon.potentialVulnerabilities.join(", ")}`);
  }

  if (memory.groundTruth) {
    const gt = buildReconGroundTruth(memory.groundTruth);
    if (gt) reconSummary.push(gt);
  }

  if (memory.threatIntel) {
    const tiParts: string[] = [];
    if (memory.threatIntel.kevCves.length > 0) {
      tiParts.push(`CISA KEV CVEs (CONFIRMED actively exploited in the wild): ${memory.threatIntel.kevCves.join(", ")}`);
      tiParts.push("IMPORTANT: KEV-listed CVEs should receive HIGHEST priority — they are confirmed active threats.");
    }
    if (memory.threatIntel.epssScores.length > 0) {
      const sorted = [...memory.threatIntel.epssScores].sort((a, b) => b.epss - a.epss);
      const top5 = sorted.slice(0, 5);
      tiParts.push("EPSS Exploitation Probabilities (30-day window):");
      for (const e of top5) {
        tiParts.push(`  ${e.cve}: ${(e.epss * 100).toFixed(1)}% probability (P${Math.round(e.percentile * 100)})`);
      }
    }
    if (tiParts.length > 0) {
      reconSummary.push(`Threat Intelligence Context:\n${tiParts.join("\n")}`);
    }
  }

  const systemPrompt = `You are the PLAN AGENT for OdinForge AI.

Given reconnaissance data, produce a prioritized attack plan that the exploit agent will follow.

RULES:
- Rank chains by expected impact × likelihood of success
- Assign turn budgets proportional to complexity (1-4 turns each, total ≤12)
- Include MITRE ATT&CK technique IDs where applicable
- Skip vectors that are clearly low-value or unreachable
- Be concrete: specify exact endpoints, parameters, and techniques
- If external recon found open ports or missing security headers, prioritize those vectors`;

  const userPrompt = `Create an attack plan for:

Asset: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}

${reconSummary.length > 0 ? reconSummary.join("\n\n") : "No recon data available — produce a generic plan based on exposure type."}

Return a JSON object:
{
  "prioritizedChains": [
    {
      "rank": 1,
      "attackVector": "e.g. SQL Injection",
      "targetEndpoint": "/api/search?q=",
      "technique": "e.g. Union-based SQLi",
      "mitreId": "T1190",
      "confidence": 75,
      "rationale": "why this should be tested first",
      "turnBudget": 3
    }
  ],
  "totalTurnBudget": 12,
  "skippedVectors": ["vectors deemed low-value and why"]
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
      throw new Error("No response from Plan Agent");
    }

    const raw = JSON.parse(content);

    const findings: PlanFindings = {
      prioritizedChains: Array.isArray(raw.prioritizedChains)
        ? raw.prioritizedChains.map((c: any, i: number) => ({
            rank: typeof c.rank === "number" ? c.rank : i + 1,
            attackVector: String(c.attackVector || "Unknown"),
            targetEndpoint: String(c.targetEndpoint || ""),
            technique: String(c.technique || ""),
            mitreId: String(c.mitreId || "T0000"),
            confidence: typeof c.confidence === "number" ? c.confidence : 50,
            rationale: String(c.rationale || ""),
            turnBudget: typeof c.turnBudget === "number" ? Math.min(c.turnBudget, 4) : 2,
          }))
        : [],
      totalTurnBudget: typeof raw.totalTurnBudget === "number" ? Math.min(raw.totalTurnBudget, 12) : 12,
      skippedVectors: Array.isArray(raw.skippedVectors) ? raw.skippedVectors.map(String) : [],
    };

    return {
      success: true,
      findings,
      agentName: "Plan Agent",
      processingTime: Date.now() - startTime,
    };
  } catch (error) {
    throw wrapAgentError("Plan Agent", error);
  }
}
