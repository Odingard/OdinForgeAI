import type { AgentMemory } from "./types";
import type { AttackGraph, AttackNode, AttackEdge, KillChainTactic, killChainTactics } from "@shared/schema";
import { openai } from "./openai-client";

interface GraphSynthesisResult {
  attackGraph: AttackGraph;
}

export async function synthesizeAttackGraph(memory: AgentMemory): Promise<GraphSynthesisResult> {
  const allFindings = formatAgentFindings(memory);

  const systemPrompt = `You are the ATTACK GRAPH SYNTHESIZER for OdinForge AI, a multi-agent security validation platform.

Your mission is to synthesize findings from 5 specialized AI agents into a comprehensive ATTACK GRAPH that shows all possible attack paths, their relationships, and conditional branches.

You must create a directed graph where:
- NODES represent states/positions in the attack (entry points, pivot points, objectives, dead-ends)
- EDGES represent techniques/transitions between states with success probabilities

Key responsibilities:
1. Identify the ENTRY NODE (initial access point)
2. Map all discovered attack paths as connected nodes and edges
3. Identify OBJECTIVE NODES (final targets/goals)
4. Calculate the CRITICAL PATH (most likely successful attack chain)
5. Identify ALTERNATIVE PATHS (backup attack routes)
6. Map each step to MITRE ATT&CK tactics (kill chain coverage)
7. Score overall complexity and estimate time-to-compromise

The graph should be realistic and based on the actual findings from the agents.`;

  const userPrompt = `Synthesize these multi-agent findings into an attack graph:

Target: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Priority: ${memory.context.priority}
Description: ${memory.context.description}

${allFindings}

Generate a JSON attack graph with this exact structure:
{
  "nodes": [
    {
      "id": "node-1",
      "label": "Initial Access via API",
      "description": "Detailed description of this attack state",
      "nodeType": "entry" | "pivot" | "objective" | "dead-end",
      "tactic": "initial-access" (one of: reconnaissance, resource-development, initial-access, execution, persistence, privilege-escalation, defense-evasion, credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact),
      "compromiseLevel": "none" | "limited" | "user" | "admin" | "system",
      "assets": ["asset1", "asset2"],
      "discoveredBy": "recon" | "exploit" | "lateral" | "business-logic" | "impact"
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "node-1",
      "target": "node-2",
      "technique": "SQL Injection",
      "techniqueId": "T1190",
      "description": "Exploit SQL injection to gain database access",
      "successProbability": 85,
      "complexity": "trivial" | "low" | "medium" | "high" | "expert",
      "timeEstimate": 30,
      "prerequisites": ["Database access", "Valid input field"],
      "alternatives": ["edge-3"],
      "edgeType": "primary" | "alternative" | "fallback",
      "discoveredBy": "recon" | "exploit" | "lateral" | "business-logic" | "impact"
    }
  ],
  "entryNodeId": "node-1",
  "objectiveNodeIds": ["node-5", "node-6"],
  "criticalPath": ["node-1", "node-2", "node-4", "node-5"],
  "alternativePaths": [["node-1", "node-3", "node-5"]],
  "killChainCoverage": ["initial-access", "execution", "privilege-escalation", "impact"],
  "complexityScore": 65,
  "timeToCompromise": {
    "minimum": 2,
    "expected": 6,
    "maximum": 24,
    "unit": "hours"
  },
  "chainedExploits": [
    {
      "name": "SQL-to-Admin Chain",
      "techniques": ["T1190", "T1078", "T1068"],
      "combinedImpact": "Full system compromise via chained vulnerabilities"
    }
  ]
}

Requirements:
- Create at least 3 nodes minimum (entry, pivot(s), objective)
- Every node except entry must be reachable via edges
- Critical path must be a valid path from entry to an objective
- timeEstimate in edges is in minutes
- complexityScore is 0-100 (higher = more complex)
- Ensure all node IDs in edges exist in nodes array`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from Graph Synthesizer");
    }

    const rawGraph = JSON.parse(content);
    const attackGraph = validateAndNormalizeGraph(rawGraph);

    return { attackGraph };
  } catch (error) {
    console.error("Graph Synthesizer error:", error);
    return { attackGraph: createFallbackGraph(memory) };
  }
}

function formatAgentFindings(memory: AgentMemory): string {
  return `
=== RECON AGENT FINDINGS ===
Attack Surface: ${memory.recon?.attackSurface.join(", ") || "None"}
Entry Points: ${memory.recon?.entryPoints.join(", ") || "None"}
API Endpoints: ${memory.recon?.apiEndpoints.join(", ") || "None"}
Auth Mechanisms: ${memory.recon?.authMechanisms.join(", ") || "None"}
Technologies: ${memory.recon?.technologies.join(", ") || "None"}
Potential Vulnerabilities: ${memory.recon?.potentialVulnerabilities.join(", ") || "None"}

=== EXPLOIT AGENT FINDINGS ===
Exploitable: ${memory.exploit?.exploitable || false}
Exploit Chains: ${memory.exploit?.exploitChains.map((c) => `${c.name} (${c.technique}, ${c.success_likelihood})`).join("; ") || "None"}
CVE References: ${memory.exploit?.cveReferences.join(", ") || "None"}
Misconfigurations: ${memory.exploit?.misconfigurations.join(", ") || "None"}

=== LATERAL MOVEMENT AGENT FINDINGS ===
Pivot Paths: ${memory.lateral?.pivotPaths.map((p) => `${p.from} -> ${p.to} via ${p.method}`).join("; ") || "None"}
Privilege Escalation: ${memory.lateral?.privilegeEscalation.map((e) => `${e.target} (${e.likelihood})`).join("; ") || "None"}
Token Reuse: ${memory.lateral?.tokenReuse.join(", ") || "None"}

=== BUSINESS LOGIC AGENT FINDINGS ===
Workflow Abuse: ${memory.businessLogic?.workflowAbuse.join(", ") || "None"}
State Manipulation: ${memory.businessLogic?.stateManipulation.join(", ") || "None"}
Race Conditions: ${memory.businessLogic?.raceConditions.join(", ") || "None"}
Authorization Bypass: ${memory.businessLogic?.authorizationBypass.join(", ") || "None"}
Critical Flows: ${memory.businessLogic?.criticalFlows.join(", ") || "None"}

=== IMPACT AGENT FINDINGS ===
Data Exposure: ${memory.impact?.dataExposure.types.join(", ") || "None"} (Severity: ${memory.impact?.dataExposure.severity || "Unknown"}, Records: ${memory.impact?.dataExposure.estimatedRecords || "Unknown"})
Financial Impact: ${memory.impact?.financialImpact.estimate || "Unknown"} - Factors: ${memory.impact?.financialImpact.factors.join(", ") || "None"}
Compliance Impact: ${memory.impact?.complianceImpact.join(", ") || "None"}
Reputational Risk: ${memory.impact?.reputationalRisk || "Unknown"}
`;
}

function validateAndNormalizeGraph(raw: unknown): AttackGraph {
  const graph = raw as Record<string, unknown>;
  
  const validTactics: KillChainTactic[] = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
  ];

  const nodes: AttackNode[] = Array.isArray(graph.nodes)
    ? graph.nodes.map((n: Record<string, unknown>, i: number) => ({
        id: String(n.id || `node-${i + 1}`),
        label: String(n.label || "Attack Node"),
        description: String(n.description || ""),
        nodeType: validateNodeType(n.nodeType),
        tactic: validateTactic(n.tactic, validTactics),
        compromiseLevel: validateCompromiseLevel(n.compromiseLevel),
        assets: Array.isArray(n.assets) ? n.assets.map(String) : undefined,
        discoveredBy: validateAgentName(n.discoveredBy),
      }))
    : [];

  const edges: AttackEdge[] = Array.isArray(graph.edges)
    ? graph.edges.map((e: Record<string, unknown>, i: number) => ({
        id: String(e.id || `edge-${i + 1}`),
        source: String(e.source || ""),
        target: String(e.target || ""),
        technique: String(e.technique || "Unknown Technique"),
        techniqueId: e.techniqueId ? String(e.techniqueId) : undefined,
        description: String(e.description || ""),
        successProbability: Math.min(100, Math.max(0, Number(e.successProbability) || 50)),
        complexity: validateComplexity(e.complexity),
        timeEstimate: Math.max(1, Number(e.timeEstimate) || 30),
        prerequisites: Array.isArray(e.prerequisites) ? e.prerequisites.map(String) : undefined,
        alternatives: Array.isArray(e.alternatives) ? e.alternatives.map(String) : undefined,
        edgeType: validateEdgeType(e.edgeType),
        discoveredBy: validateAgentName(e.discoveredBy),
      }))
    : [];

  const entryNodeId = String(graph.entryNodeId || nodes[0]?.id || "node-1");
  const objectiveNodeIds = Array.isArray(graph.objectiveNodeIds)
    ? graph.objectiveNodeIds.map(String)
    : nodes.filter(n => n.nodeType === "objective").map(n => n.id);

  const criticalPath = Array.isArray(graph.criticalPath)
    ? graph.criticalPath.map(String)
    : [entryNodeId, ...(objectiveNodeIds.length > 0 ? [objectiveNodeIds[0]] : [])];

  const alternativePaths = Array.isArray(graph.alternativePaths)
    ? graph.alternativePaths.map((path: unknown[]) => 
        Array.isArray(path) ? path.map(String) : []
      )
    : undefined;

  const killChainCoverage = Array.isArray(graph.killChainCoverage)
    ? graph.killChainCoverage
        .map((t: unknown) => validateTactic(t, validTactics))
        .filter((t, i, arr) => arr.indexOf(t) === i)
    : extractKillChainFromNodes(nodes, validTactics);

  const complexityScore = Math.min(100, Math.max(0, Number(graph.complexityScore) || calculateComplexity(edges)));

  const timeToCompromise = graph.timeToCompromise && typeof graph.timeToCompromise === 'object'
    ? {
        minimum: Math.max(1, Number((graph.timeToCompromise as Record<string, unknown>).minimum) || 1),
        expected: Math.max(1, Number((graph.timeToCompromise as Record<string, unknown>).expected) || 4),
        maximum: Math.max(1, Number((graph.timeToCompromise as Record<string, unknown>).maximum) || 24),
        unit: validateTimeUnit((graph.timeToCompromise as Record<string, unknown>).unit),
      }
    : calculateTimeToCompromise(edges);

  const chainedExploits = Array.isArray(graph.chainedExploits)
    ? graph.chainedExploits.map((c: Record<string, unknown>) => ({
        name: String(c.name || "Exploit Chain"),
        techniques: Array.isArray(c.techniques) ? c.techniques.map(String) : [],
        combinedImpact: String(c.combinedImpact || "Combined exploitation impact"),
      }))
    : undefined;

  return {
    nodes,
    edges,
    entryNodeId,
    objectiveNodeIds,
    criticalPath,
    alternativePaths,
    killChainCoverage,
    complexityScore,
    timeToCompromise,
    chainedExploits,
  };
}

function validateNodeType(type: unknown): "entry" | "pivot" | "objective" | "dead-end" {
  const valid = ["entry", "pivot", "objective", "dead-end"];
  return valid.includes(String(type)) ? (type as "entry" | "pivot" | "objective" | "dead-end") : "pivot";
}

function validateTactic(tactic: unknown, validTactics: KillChainTactic[]): KillChainTactic {
  return validTactics.includes(String(tactic) as KillChainTactic)
    ? (tactic as KillChainTactic)
    : "initial-access";
}

function validateCompromiseLevel(level: unknown): "none" | "limited" | "user" | "admin" | "system" {
  const valid = ["none", "limited", "user", "admin", "system"];
  return valid.includes(String(level)) ? (level as "none" | "limited" | "user" | "admin" | "system") : "limited";
}

function validateComplexity(complexity: unknown): "trivial" | "low" | "medium" | "high" | "expert" {
  const valid = ["trivial", "low", "medium", "high", "expert"];
  return valid.includes(String(complexity)) ? (complexity as "trivial" | "low" | "medium" | "high" | "expert") : "medium";
}

function validateEdgeType(type: unknown): "primary" | "alternative" | "fallback" {
  const valid = ["primary", "alternative", "fallback"];
  return valid.includes(String(type)) ? (type as "primary" | "alternative" | "fallback") : "primary";
}

function validateTimeUnit(unit: unknown): "minutes" | "hours" | "days" {
  const valid = ["minutes", "hours", "days"];
  return valid.includes(String(unit)) ? (unit as "minutes" | "hours" | "days") : "hours";
}

function validateAgentName(name: unknown): "recon" | "exploit" | "lateral" | "business-logic" | "impact" | undefined {
  const valid = ["recon", "exploit", "lateral", "business-logic", "impact"];
  return valid.includes(String(name)) ? (name as "recon" | "exploit" | "lateral" | "business-logic" | "impact") : undefined;
}

function extractKillChainFromNodes(nodes: AttackNode[], validTactics: KillChainTactic[]): KillChainTactic[] {
  const tactics = nodes.map(n => n.tactic).filter(t => validTactics.includes(t));
  return Array.from(new Set(tactics));
}

function calculateComplexity(edges: AttackEdge[]): number {
  if (edges.length === 0) return 50;
  
  const complexityWeights = { trivial: 10, low: 25, medium: 50, high: 75, expert: 95 };
  const avgComplexity = edges.reduce((sum, e) => sum + complexityWeights[e.complexity], 0) / edges.length;
  const pathLengthFactor = Math.min(edges.length * 5, 30);
  
  return Math.min(100, Math.round(avgComplexity + pathLengthFactor));
}

function calculateTimeToCompromise(edges: AttackEdge[]): { minimum: number; expected: number; maximum: number; unit: "minutes" | "hours" | "days" } {
  if (edges.length === 0) {
    return { minimum: 1, expected: 4, maximum: 24, unit: "hours" };
  }

  const totalMinutes = edges.reduce((sum, e) => sum + e.timeEstimate, 0);
  
  if (totalMinutes < 60) {
    return {
      minimum: Math.max(5, Math.round(totalMinutes * 0.5)),
      expected: totalMinutes,
      maximum: Math.round(totalMinutes * 2),
      unit: "minutes",
    };
  } else if (totalMinutes < 1440) {
    const hours = totalMinutes / 60;
    return {
      minimum: Math.max(1, Math.round(hours * 0.5)),
      expected: Math.round(hours),
      maximum: Math.round(hours * 2),
      unit: "hours",
    };
  } else {
    const days = totalMinutes / 1440;
    return {
      minimum: Math.max(1, Math.round(days * 0.5)),
      expected: Math.round(days),
      maximum: Math.round(days * 2),
      unit: "days",
    };
  }
}

export function createFallbackGraph(memory: AgentMemory): AttackGraph {
  const entryNode: AttackNode = {
    id: "node-entry",
    label: "Initial Access Point",
    description: `Entry point for ${memory.context.exposureType} targeting ${memory.context.assetId}`,
    nodeType: "entry",
    tactic: "initial-access",
    compromiseLevel: "none",
    discoveredBy: "recon",
  };

  const pivotNode: AttackNode = {
    id: "node-pivot",
    label: "Exploitation Phase",
    description: "Exploitation of identified vulnerability",
    nodeType: "pivot",
    tactic: "execution",
    compromiseLevel: "user",
    discoveredBy: "exploit",
  };

  const objectiveNode: AttackNode = {
    id: "node-objective",
    label: "Attack Objective",
    description: "Target objective based on impact assessment",
    nodeType: "objective",
    tactic: "impact",
    compromiseLevel: "admin",
    discoveredBy: "impact",
  };

  const edge1: AttackEdge = {
    id: "edge-1",
    source: "node-entry",
    target: "node-pivot",
    technique: "Exploit Public-Facing Application",
    techniqueId: "T1190",
    description: "Initial exploitation of entry point",
    successProbability: 70,
    complexity: "medium",
    timeEstimate: 30,
    edgeType: "primary",
    discoveredBy: "exploit",
  };

  const edge2: AttackEdge = {
    id: "edge-2",
    source: "node-pivot",
    target: "node-objective",
    technique: "Privilege Escalation",
    techniqueId: "T1068",
    description: "Escalate privileges to achieve objective",
    successProbability: 60,
    complexity: "high",
    timeEstimate: 60,
    edgeType: "primary",
    discoveredBy: "lateral",
  };

  return {
    nodes: [entryNode, pivotNode, objectiveNode],
    edges: [edge1, edge2],
    entryNodeId: "node-entry",
    objectiveNodeIds: ["node-objective"],
    criticalPath: ["node-entry", "node-pivot", "node-objective"],
    killChainCoverage: ["initial-access", "execution", "impact"],
    complexityScore: 55,
    timeToCompromise: {
      minimum: 1,
      expected: 2,
      maximum: 6,
      unit: "hours",
    },
  };
}
