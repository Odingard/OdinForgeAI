// ═══════════════════════════════════════════════════════════════════════════════
//  AEV Mapper
//
//  Translates recon engine output (FullReconResult + AgentRunReport)
//  into AEV-compatible structures: AttackGraph, EvidenceArtifacts,
//  ReconFindings for AgentMemory, and ScoringContext inputs.
// ═══════════════════════════════════════════════════════════════════════════════

import { randomUUID } from "crypto";
import type {
  AttackGraph, AttackNode, AttackEdge, EvidenceArtifact,
  KillChainTactic,
} from "@shared/schema";
import type { FullReconResult } from "./index";
import type { AgentRunReport } from "./agents/orchestrator";
import type { AgentTask } from "./agents/agent-framework";
import type { RoutedFinding } from "./agents/finding-router";
import { extractAllFindings } from "./agents/finding-router";
import type { ReconFindings } from "../agents/types";

// ─── Finding → Node Mapping Table ───────────────────────────────────────────

interface NodeMapping {
  tactic: KillChainTactic;
  nodeType: "entry" | "pivot" | "objective" | "dead-end";
  compromiseLevel: "none" | "limited" | "user" | "admin" | "system";
}

const FINDING_NODE_MAP: Record<string, NodeMapping> = {
  "dns:zone-transfer":      { tactic: "reconnaissance",        nodeType: "entry", compromiseLevel: "none" },
  "dns:no-dnssec":          { tactic: "reconnaissance",        nodeType: "pivot", compromiseLevel: "none" },
  "dns:dangling-record":    { tactic: "resource-development",  nodeType: "entry", compromiseLevel: "none" },
  "dns:subdomain-takeover": { tactic: "resource-development",  nodeType: "entry", compromiseLevel: "limited" },
  "port:exposed-database":  { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "user" },
  "port:exposed-cache":     { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "admin" },
  "port:exposed-remote":    { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "user" },
  "port:exposed-admin":     { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "limited" },
  "port:debug-endpoint":    { tactic: "discovery",             nodeType: "pivot", compromiseLevel: "limited" },
  "ssl:expired-cert":       { tactic: "defense-evasion",       nodeType: "pivot", compromiseLevel: "none" },
  "ssl:self-signed":        { tactic: "defense-evasion",       nodeType: "pivot", compromiseLevel: "none" },
  "ssl:weak-protocol":      { tactic: "credential-access",     nodeType: "pivot", compromiseLevel: "none" },
  "ssl:weak-cipher":        { tactic: "credential-access",     nodeType: "pivot", compromiseLevel: "none" },
  "cors:origin-reflection": { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "limited" },
  "cors:wildcard-origin":   { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "limited" },
  "cors:credentials-leak":  { tactic: "credential-access",     nodeType: "entry", compromiseLevel: "limited" },
  "endpoint:auth-bypass":   { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "user" },
  "endpoint:no-auth":       { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "user" },
  "endpoint:weak-auth":     { tactic: "initial-access",        nodeType: "entry", compromiseLevel: "limited" },
  "endpoint:no-rate-limit": { tactic: "execution",             nodeType: "pivot", compromiseLevel: "limited" },
  "endpoint:info-disclosure":{ tactic: "discovery",            nodeType: "pivot", compromiseLevel: "none" },
  "endpoint:stale":         { tactic: "discovery",             nodeType: "pivot", compromiseLevel: "none" },
  "header:missing-csp":     { tactic: "execution",             nodeType: "pivot", compromiseLevel: "none" },
  "header:missing-hsts":    { tactic: "credential-access",     nodeType: "pivot", compromiseLevel: "none" },
  "header:missing-xframe":  { tactic: "execution",             nodeType: "pivot", compromiseLevel: "none" },
  "header:missing-xcto":    { tactic: "execution",             nodeType: "pivot", compromiseLevel: "none" },
  "header:insecure-cookie": { tactic: "credential-access",     nodeType: "pivot", compromiseLevel: "none" },
  "header:info-leak":       { tactic: "discovery",             nodeType: "pivot", compromiseLevel: "none" },
};

// ─── Complexity Mapping ─────────────────────────────────────────────────────

function severityToComplexity(severity: string): "trivial" | "low" | "medium" | "high" | "expert" {
  switch (severity) {
    case "critical": return "trivial";
    case "high": return "low";
    case "medium": return "medium";
    case "low": return "high";
    default: return "medium";
  }
}

// ─── Primary Mapper: FullReconResult + AgentRunReport → AttackGraph ─────────

export function mapReconToAttackGraph(
  recon: FullReconResult,
  agentReport: AgentRunReport,
): AttackGraph {
  const findings = extractAllFindings(recon);
  const nodes = mapFindingsToNodes(findings, agentReport.tasks);
  const edges = mapAgentTasksToEdges(agentReport.tasks, nodes);

  // Identify entry and objective nodes
  const entryNodes = nodes.filter(n => n.nodeType === "entry");
  const objectiveNodes = nodes.filter(n => n.nodeType === "objective");
  const entryNodeId = entryNodes[0]?.id ?? nodes[0]?.id ?? "root";
  const objectiveNodeIds = objectiveNodes.map(n => n.id);

  // Build critical path: entry → highest-severity exploitable nodes
  const criticalPath = buildCriticalPath(nodes, edges, entryNodeId, objectiveNodeIds);

  // Collect unique tactics covered
  const coveredTactics = Array.from(new Set(nodes.map(n => n.tactic)));

  // Compute complexity from average node severity
  const avgComplexity = nodes.length > 0
    ? Math.round(nodes.reduce((sum, n) => {
        const weight = n.nodeType === "objective" ? 20 : n.nodeType === "entry" ? 40 : 60;
        return sum + weight;
      }, 0) / nodes.length)
    : 50;

  // Time estimate based on finding count and agent report duration
  const agentDurationMin = Math.ceil(agentReport.duration / 60_000);
  const estimatedMinutes = Math.max(agentDurationMin, nodes.length * 2);

  return {
    nodes,
    edges,
    entryNodeId,
    objectiveNodeIds,
    criticalPath,
    killChainCoverage: coveredTactics,
    complexityScore: Math.min(100, avgComplexity),
    timeToCompromise: {
      minimum: Math.max(1, Math.floor(estimatedMinutes * 0.5)),
      expected: estimatedMinutes,
      maximum: estimatedMinutes * 3,
      unit: estimatedMinutes > 120 ? "hours" : "minutes",
    },
  };
}

// ─── Findings → AttackNodes ─────────────────────────────────────────────────

export function mapFindingsToNodes(
  findings: RoutedFinding[],
  agentTasks: AgentTask[],
): AttackNode[] {
  const nodes: AttackNode[] = [];
  const seenIds = new Set<string>();

  // Create a lookup: findingType+target → agentResult
  const taskLookup = new Map<string, AgentTask>();
  for (const task of agentTasks) {
    const key = `${task.findingType}::${task.target}`;
    // Keep the one with a result, or the first one
    if (!taskLookup.has(key) || task.result) {
      taskLookup.set(key, task);
    }
  }

  for (const finding of findings) {
    const mapping = FINDING_NODE_MAP[finding._findingType];
    if (!mapping) continue;

    const nodeId = `recon-${finding._findingType}-${finding._target}`.replace(/[^a-zA-Z0-9-]/g, "-");
    if (seenIds.has(nodeId)) continue;
    seenIds.add(nodeId);

    const task = taskLookup.get(`${finding._findingType}::${finding._target}`);
    const result = task?.result;

    // Upgrade to objective if agent confirmed it's exploitable and critical
    let nodeType = mapping.nodeType;
    let compromiseLevel = mapping.compromiseLevel;
    if (result?.exploitable && result.severity === "critical") {
      nodeType = "objective";
    }
    if (result?.exploitable && result.severity !== "info") {
      // Upgrade compromise level if agent verified exploitation
      if (compromiseLevel === "none") compromiseLevel = "limited";
      if (compromiseLevel === "limited" && result.severity === "critical") compromiseLevel = "user";
    }

    const label = finding._findingType.replace(/[:-]/g, " ").replace(/\b\w/g, c => c.toUpperCase());

    nodes.push({
      id: nodeId,
      label,
      description: buildNodeDescription(finding, result ?? null),
      nodeType,
      tactic: mapping.tactic,
      compromiseLevel,
      assets: [finding._target],
      discoveredBy: "recon",
    });
  }

  return nodes;
}

function buildNodeDescription(finding: RoutedFinding, result: AgentTask["result"]): string {
  const parts: string[] = [];
  parts.push(`${finding._findingType} on ${finding._target}`);
  if (finding.port) parts.push(`Port ${finding.port}`);
  if (finding.service) parts.push(`Service: ${finding.service}`);
  if (result?.verified) parts.push("Agent-verified");
  if (result?.exploitable) parts.push("Confirmed exploitable");
  if (result?.cweId) parts.push(result.cweId);
  if (result?.cvssScore) parts.push(`CVSS ${result.cvssScore}`);
  return parts.join(" | ");
}

// ─── Agent Tasks → AttackEdges ──────────────────────────────────────────────

export function mapAgentTasksToEdges(
  tasks: AgentTask[],
  nodes: AttackNode[],
): AttackEdge[] {
  const edges: AttackEdge[] = [];
  const nodeIds = new Set(nodes.map(n => n.id));

  // Build edges between related nodes (same target, different finding types)
  const nodesByTarget = new Map<string, AttackNode[]>();
  for (const node of nodes) {
    for (const asset of node.assets ?? []) {
      const existing = nodesByTarget.get(asset) ?? [];
      existing.push(node);
      nodesByTarget.set(asset, existing);
    }
  }

  for (const [assetTarget, targetNodes] of Array.from(nodesByTarget.entries())) {
    // Connect entry nodes to pivot/objective nodes on same target
    const entries = targetNodes.filter((n: AttackNode) => n.nodeType === "entry");
    const others = targetNodes.filter((n: AttackNode) => n.nodeType !== "entry");

    for (const entry of entries) {
      for (const other of others) {
        // Find the agent task that relates to either node
        const task = tasks.find((t: AgentTask) =>
          t.target === assetTarget &&
          (t.findingType.includes(entry.id.split("-")[1]) || t.findingType.includes(other.id.split("-")[1]))
        );

        const result = task?.result;
        edges.push({
          id: `edge-${entry.id}-${other.id}`,
          source: entry.id,
          target: other.id,
          technique: entry.label,
          description: `${entry.label} enables ${other.label}`,
          successProbability: result?.exploitable ? 85 : (result?.verified ? 60 : 30),
          complexity: severityToComplexity(result?.severity ?? "medium"),
          timeEstimate: task?.duration ?? 60_000,
          edgeType: "primary",
          discoveredBy: "recon",
        });
      }
    }
  }

  // Connect critical exploitable findings to other exploitable findings (chain potential)
  const exploitableNodes = nodes.filter(n => n.nodeType === "objective" || n.nodeType === "entry");
  for (let i = 0; i < exploitableNodes.length - 1; i++) {
    const a = exploitableNodes[i];
    const b = exploitableNodes[i + 1];
    // Only connect if they're on the same target or different stages
    if (a.tactic !== b.tactic && !edges.some(e => e.source === a.id && e.target === b.id)) {
      edges.push({
        id: `chain-${a.id}-${b.id}`,
        source: a.id,
        target: b.id,
        technique: `${a.label} → ${b.label}`,
        description: `Chain: ${a.tactic} → ${b.tactic}`,
        successProbability: 40,
        complexity: "medium",
        timeEstimate: 120_000,
        edgeType: "alternative",
        discoveredBy: "recon",
      });
    }
  }

  return edges;
}

// ─── Critical Path Builder ──────────────────────────────────────────────────

function buildCriticalPath(
  nodes: AttackNode[],
  edges: AttackEdge[],
  entryId: string,
  objectiveIds: string[],
): string[] {
  if (nodes.length === 0) return [];
  if (objectiveIds.length === 0) {
    // No objectives — critical path is entry → highest-severity nodes
    const sorted = [...nodes].sort((a, b) => {
      const typeOrder = { objective: 0, entry: 1, pivot: 2, "dead-end": 3 };
      return (typeOrder[a.nodeType] ?? 3) - (typeOrder[b.nodeType] ?? 3);
    });
    return sorted.slice(0, Math.min(5, sorted.length)).map(n => n.id);
  }

  // Simple BFS from entry to first reachable objective
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const existing = adjacency.get(edge.source) ?? [];
    existing.push(edge.target);
    adjacency.set(edge.source, existing);
  }

  const visited = new Set<string>();
  const parent = new Map<string, string>();
  const queue = [entryId];
  visited.add(entryId);

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (objectiveIds.includes(current)) {
      // Reconstruct path
      const path: string[] = [current];
      let node = current;
      while (parent.has(node)) {
        node = parent.get(node)!;
        path.unshift(node);
      }
      return path;
    }

    for (const neighbor of adjacency.get(current) ?? []) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        parent.set(neighbor, current);
        queue.push(neighbor);
      }
    }
  }

  // No path found — return entry + objectives as disconnected critical nodes
  return [entryId, ...objectiveIds];
}

// ─── Agent Evidence → AEV EvidenceArtifacts ─────────────────────────────────

export function mapAgentEvidenceToArtifacts(tasks: AgentTask[]): EvidenceArtifact[] {
  const artifacts: EvidenceArtifact[] = [];

  for (const task of tasks) {
    if (!task.result) continue;

    for (const evidence of task.result.evidence) {
      const id = `ev-${randomUUID().slice(0, 8)}`;

      switch (evidence.type) {
        case "request":
        case "response":
          artifacts.push({
            id,
            type: "request_response",
            timestamp: task.completedAt ?? new Date().toISOString(),
            title: evidence.label,
            description: `${task.agentName}: ${evidence.label}`,
            data: evidence.type === "request"
              ? { request: { method: "GET", url: task.target, body: evidence.content } }
              : { response: { statusCode: 200, body: evidence.content } },
            tags: [task.findingType, task.agentName],
            isSanitized: true,
          });
          break;

        case "log":
          artifacts.push({
            id,
            type: "log_capture",
            timestamp: task.completedAt ?? new Date().toISOString(),
            title: evidence.label,
            description: `${task.agentName}: ${evidence.label}`,
            data: {
              logs: [{
                timestamp: task.completedAt ?? new Date().toISOString(),
                level: "info",
                message: evidence.content,
                source: task.agentName,
              }],
            },
            tags: [task.findingType, task.agentName],
            isSanitized: true,
          });
          break;

        case "payload":
        case "diff":
          artifacts.push({
            id,
            type: "execution_trace",
            timestamp: task.completedAt ?? new Date().toISOString(),
            title: evidence.label,
            description: `${task.agentName}: ${evidence.label}`,
            data: {
              trace: [{
                step: 1,
                action: evidence.label,
                result: evidence.content,
              }],
            },
            tags: [task.findingType, task.agentName],
            isSanitized: true,
          });
          break;

        case "proof":
        case "screenshot":
          artifacts.push({
            id,
            type: evidence.type === "screenshot" ? "screenshot" : "data_sample",
            timestamp: task.completedAt ?? new Date().toISOString(),
            title: evidence.label,
            description: evidence.content,
            data: evidence.type === "screenshot"
              ? { screenshot: { caption: evidence.content } }
              : {},
            tags: [task.findingType, task.agentName],
            isSanitized: true,
          });
          break;
      }
    }

    // Also capture each agent step as a timeline event
    for (let i = 0; i < task.steps.length; i++) {
      const step = task.steps[i];
      if (!step.output) continue;

      artifacts.push({
        id: `ev-step-${task.id}-${i}`,
        type: "timeline_event",
        timestamp: step.completedAt ?? step.startedAt ?? new Date().toISOString(),
        title: `${task.agentName}: ${step.name}`,
        description: step.output.slice(0, 500),
        data: {
          trace: [{
            step: i + 1,
            action: step.name,
            result: step.output.slice(0, 1000),
            duration: step.duration,
          }],
        },
        tags: [task.findingType, step.status],
        isSanitized: true,
      });
    }
  }

  return artifacts;
}

// ─── Map Recon → AgentMemory.recon (for downstream AEV agents) ──────────────

export function mapReconToAgentMemory(recon: FullReconResult): ReconFindings {
  const attackSurface: string[] = [];
  const entryPoints: string[] = [];
  const apiEndpoints: string[] = [];
  const technologies: string[] = [];

  // Attack surface from ports
  for (const port of recon.ports.openPorts) {
    attackSurface.push(`${port.service} on port ${port.port} (${port.state})`);
  }

  // Subdomains as attack surface
  for (const sub of recon.subdomains.subdomains.filter(s => s.isAlive)) {
    attackSurface.push(`Subdomain: ${sub.subdomain} (${sub.ip})`);
  }

  // Entry points from findings
  if (recon.dns.zoneTransferVulnerable) entryPoints.push("DNS zone transfer enabled");
  for (const port of recon.ports.openPorts.filter(p => p.category === "database" || p.category === "remote")) {
    entryPoints.push(`${port.service} exposed on port ${port.port}`);
  }
  for (const issue of recon.ssl.issues.filter(i => i.severity === "critical")) {
    entryPoints.push(`SSL: ${issue.title}`);
  }

  // API endpoints
  for (const ep of recon.apiDiscovery.endpoints) {
    apiEndpoints.push(`${ep.method} ${ep.url}`);
  }

  // Technologies
  for (const t of recon.tech.technologies) {
    technologies.push(`${t.name}${t.version ? ` ${t.version}` : ""} (${t.confidence}% confidence)`);
  }

  // Auth mechanisms from endpoint checks
  const authMechanisms: string[] = [];
  for (const check of recon.endpointChecks) {
    if (check.auth.authType !== "none" && !authMechanisms.includes(check.auth.authType)) {
      authMechanisms.push(check.auth.authType);
    }
  }
  if (authMechanisms.length === 0) authMechanisms.push("No authentication detected");

  // Potential vulns from header + SSL + endpoint issues
  const potentialVulnerabilities: string[] = [];
  for (const issue of recon.headers.issues.filter(i => i.status !== "present")) {
    potentialVulnerabilities.push(`Missing/weak: ${issue.header}`);
  }
  for (const issue of recon.ssl.issues) {
    potentialVulnerabilities.push(`SSL: ${issue.title}`);
  }
  for (const check of recon.endpointChecks) {
    for (const issue of [...check.cors.issues, ...check.auth.issues].filter(i => i.severity === "critical" || i.severity === "high")) {
      potentialVulnerabilities.push(`${issue.title} on ${check.endpoint}`);
    }
  }

  return {
    attackSurface,
    entryPoints,
    apiEndpoints: apiEndpoints.slice(0, 50),
    authMechanisms,
    technologies,
    potentialVulnerabilities: potentialVulnerabilities.slice(0, 30),
  };
}

// ─── Incremental Graph Builder (for streaming progress) ─────────────────────

export function buildIncrementalGraph(
  existingGraph: AttackGraph | null,
  newFindings: RoutedFinding[],
  newTasks: AgentTask[],
): AttackGraph {
  const existingNodes = existingGraph?.nodes ?? [];
  const existingEdges = existingGraph?.edges ?? [];
  const existingNodeIds = new Set(existingNodes.map(n => n.id));

  const newNodes = mapFindingsToNodes(newFindings, newTasks)
    .filter(n => !existingNodeIds.has(n.id));

  const allNodes = [...existingNodes, ...newNodes];
  const allEdges = [...existingEdges, ...mapAgentTasksToEdges(newTasks, allNodes)];

  // Deduplicate edges
  const seenEdgeIds = new Set<string>();
  const dedupedEdges = allEdges.filter(e => {
    if (seenEdgeIds.has(e.id)) return false;
    seenEdgeIds.add(e.id);
    return true;
  });

  const entryNodes = allNodes.filter(n => n.nodeType === "entry");
  const objectiveNodes = allNodes.filter(n => n.nodeType === "objective");
  const entryNodeId = entryNodes[0]?.id ?? allNodes[0]?.id ?? "root";
  const objectiveNodeIds = objectiveNodes.map(n => n.id);

  const criticalPath = buildCriticalPath(allNodes, dedupedEdges, entryNodeId, objectiveNodeIds);
  const coveredTactics = Array.from(new Set(allNodes.map(n => n.tactic)));

  return {
    nodes: allNodes,
    edges: dedupedEdges,
    entryNodeId,
    objectiveNodeIds,
    criticalPath,
    killChainCoverage: coveredTactics,
    complexityScore: Math.min(100, allNodes.length * 5),
    timeToCompromise: {
      minimum: 5,
      expected: Math.max(10, allNodes.length * 3),
      maximum: allNodes.length * 10,
      unit: "minutes",
    },
  };
}

// ─── Breach Chain Context Seeding ───────────────────────────────────────────
// Maps exploitable recon findings into breach chain initial context so the
// chain starts with real verified entry points instead of LLM speculation.

export function mapReconToBreachContext(
  agentReport: AgentRunReport,
  target: string,
): {
  compromisedAssets: Array<{
    id: string;
    name: string;
    type: string;
    compromiseMethod: string;
    compromiseLevel: string;
  }>;
  domainsCompromised: string[];
  currentPrivilegeLevel: string;
} {
  const compromisedAssets = agentReport.topExploitable
    .filter(e => e.severity === "critical" || e.severity === "high")
    .map(e => ({
      id: `recon-${randomUUID().slice(0, 8)}`,
      name: e.target,
      type: "application",
      compromiseMethod: `${e.finding} (${e.agent})`,
      compromiseLevel: e.severity === "critical" ? "admin" : "user",
    }));

  const hasAdmin = compromisedAssets.some(a => a.compromiseLevel === "admin");

  return {
    compromisedAssets,
    domainsCompromised: [target],
    currentPrivilegeLevel: hasAdmin ? "admin" : compromisedAssets.length > 0 ? "user" : "none",
  };
}
