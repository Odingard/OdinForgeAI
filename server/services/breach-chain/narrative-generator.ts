// Generates plain-English attack narratives from AttackGraph + phase results

import type { AttackGraph, AttackNode, AttackEdge } from "../../../shared/schema";

export interface NarrativeSection {
  stepNumber: number;
  heading: string;          // "Step 1: Finding the Door"
  body: string;             // Plain English paragraph
  technique: string;        // MITRE technique name
  techniqueId?: string;     // T1190 etc
  timeSpent: string;        // "~4 minutes"
  severity: "critical" | "high" | "medium" | "low";
  nodeId: string;
}

export interface ChainNarrative {
  headline: string;         // "Attacker reached customer database in 4 steps"
  riskSentence: string;     // one sentence summary
  attackerProfile: string;  // "Opportunistic external attacker, no insider knowledge required"
  sections: NarrativeSection[];
  totalTimeEstimate: string; // "~1h 47m total"
  readingTimeSeconds: number;
  generatedAt: string;
}

// Maps kill-chain tactic to a human-readable heading prefix
const tacticHeadingMap: Record<string, string> = {
  "reconnaissance":        "Scouting the Target",
  "resource-development":  "Preparing the Attack",
  "initial-access":        "Breaking In",
  "execution":             "Running the Attack",
  "persistence":           "Establishing a Foothold",
  "privilege-escalation":  "Gaining Higher Access",
  "defense-evasion":       "Hiding the Tracks",
  "credential-access":     "Stealing Credentials",
  "discovery":             "Mapping the Network",
  "lateral-movement":      "Spreading Through the Network",
  "collection":            "Gathering Intelligence",
  "command-and-control":   "Maintaining Control",
  "exfiltration":          "Taking the Data",
  "impact":                "The Damage Done",
};

function tacticToHeading(stepNumber: number, tactic: string): string {
  const label = tacticHeadingMap[tactic] ?? "Advancing the Attack";
  return `Step ${stepNumber}: ${label}`;
}

function compromiseLevelToSeverity(
  compromiseLevel: AttackNode["compromiseLevel"],
): "critical" | "high" | "medium" | "low" {
  switch (compromiseLevel) {
    case "system":
    case "admin":
      return "critical";
    case "user":
      return "high";
    case "limited":
      return "medium";
    case "none":
    default:
      return "low";
  }
}

/** Formats a millisecond duration into a human-readable string like "~4 minutes" or "~2 hours". */
function formatDuration(ms: number): string {
  if (ms < 60_000) {
    const secs = Math.round(ms / 1_000);
    return `~${secs} second${secs !== 1 ? "s" : ""}`;
  }
  if (ms < 3_600_000) {
    const mins = Math.round(ms / 60_000);
    return `~${mins} minute${mins !== 1 ? "s" : ""}`;
  }
  const hours = Math.floor(ms / 3_600_000);
  const mins = Math.round((ms % 3_600_000) / 60_000);
  if (mins === 0) return `~${hours} hour${hours !== 1 ? "s" : ""}`;
  return `~${hours}h ${mins}m`;
}

/** Converts edge complexity enum to a prose description. */
function complexityToEffort(complexity: AttackEdge["complexity"]): string {
  switch (complexity) {
    case "trivial": return "minimal";
    case "low":     return "low";
    case "medium":  return "moderate";
    case "high":    return "significant";
    case "expert":  return "expert-level";
    default:        return "unknown";
  }
}

/**
 * Build a 2–3 sentence body paragraph for a narrative step.
 */
function buildBody(
  node: AttackNode,
  edge: AttackEdge | undefined,
  timeEstimate: string,
): string {
  const asset = node.assets?.[0] ?? "the application";
  const technique = edge?.technique ?? node.label;
  const effort = edge ? complexityToEffort(edge.complexity) : "unknown";

  const sentence1 = edge
    ? `Using a ${technique} vulnerability in ${asset}, the attacker was able to ${node.description.toLowerCase().replace(/\.$/, "")}.`
    : `The attacker exploited ${asset} to ${node.description.toLowerCase().replace(/\.$/, "")}.`;

  const sentence2 = `This step required ${effort} effort and took approximately ${timeEstimate}.`;

  const sentence3 = edge?.description
    ? edge.description.charAt(0).toUpperCase() + edge.description.slice(1).replace(/\.$/, "") + "."
    : "";

  return [sentence1, sentence2, sentence3].filter(Boolean).join(" ");
}

export function generateNarrative(
  graph: AttackGraph,
  targetName: string,
  chainName: string,
): ChainNarrative {
  const nodeMap = new Map<string, AttackNode>(graph.nodes.map((n) => [n.id, n]));

  // Build edge lookup: target node id → edge leading to it
  const edgeByTarget = new Map<string, AttackEdge>();
  for (const edge of graph.edges) {
    // prefer primary edges; only set if not already set by a primary one
    if (!edgeByTarget.has(edge.target) || edge.edgeType === "primary") {
      edgeByTarget.set(edge.target, edge);
    }
  }

  const criticalPath = graph.criticalPath;
  const sections: NarrativeSection[] = [];
  let totalMs = 0;

  for (let i = 0; i < criticalPath.length; i++) {
    const nodeId = criticalPath[i];
    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const edge = i > 0 ? edgeByTarget.get(nodeId) : undefined;
    const edgeMs = edge?.timeEstimate ?? 0;
    totalMs += edgeMs;

    const timeSpent = edge ? formatDuration(edgeMs) : "~0 minutes";
    const stepNumber = i + 1;

    sections.push({
      stepNumber,
      heading: tacticToHeading(stepNumber, node.tactic),
      body: buildBody(node, edge, timeSpent),
      technique: edge?.technique ?? node.label,
      techniqueId: edge?.techniqueId,
      timeSpent,
      severity: compromiseLevelToSeverity(node.compromiseLevel),
      nodeId,
    });
  }

  // Objective node: last node on the critical path, or the first objectiveNodeId
  const objectiveNodeId =
    criticalPath[criticalPath.length - 1] ?? graph.objectiveNodeIds[0];
  const objectiveNode = nodeMap.get(objectiveNodeId);
  const objectiveLabel = objectiveNode?.label ?? targetName;

  const headline = `Attacker reached ${objectiveLabel} in ${sections.length} step${sections.length !== 1 ? "s" : ""}`;

  const ttc = graph.timeToCompromise;
  const riskSentence = `A skilled attacker could compromise this system in ${ttc.expected} ${ttc.unit}.`;

  let attackerProfile: string;
  const cs = graph.complexityScore;
  if (cs <= 30) {
    attackerProfile = "Opportunistic attacker, no special skills required";
  } else if (cs <= 60) {
    attackerProfile = "Skilled attacker with moderate technical knowledge";
  } else if (cs <= 80) {
    attackerProfile = "Advanced threat actor with targeted knowledge";
  } else {
    attackerProfile = "Nation-state level adversary";
  }

  const totalTimeEstimate = totalMs > 0 ? formatDuration(totalMs) : `${ttc.expected} ${ttc.unit}`;

  // Estimate reading time: ~200 words/min, count words across all bodies
  const wordCount = sections.reduce((sum, s) => sum + s.body.split(/\s+/).length, 0);
  const readingTimeSeconds = Math.max(10, Math.round((wordCount / 200) * 60));

  return {
    headline,
    riskSentence,
    attackerProfile,
    sections,
    totalTimeEstimate,
    readingTimeSeconds,
    generatedAt: new Date().toISOString(),
  };
}
