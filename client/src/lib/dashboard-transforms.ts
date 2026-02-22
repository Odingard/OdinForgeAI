/**
 * Pure data transform functions for the analytics dashboard.
 * No React, no side effects — just data in, data out.
 */

// ── Types ──────────────────────────────────────────────────────────────

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SankeyLink {
  source: string;       // asset group label
  target: string;       // severity label
  value: number;        // finding count
  severity: "critical" | "high" | "medium" | "low";
}

export interface SankeyData {
  leftNodes: { label: string; count: number }[];
  rightNodes: { label: string; count: number; severity: "critical" | "high" | "medium" | "low" }[];
  links: SankeyLink[];
}

export interface TimeseriesPoint {
  date: string;       // ISO date (YYYY-MM-DD)
  findings: number;
  resolved: number;
}

export interface OrgMetricRow {
  name: string;
  type: string;
  total: number;
  critical: number;
  open: number;
  mttr: string;        // "2.4d", "N/A"
}

// ── Severity Helpers ───────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export function severityColor(sev: string): string {
  return SEVERITY_COLORS[sev.toLowerCase()] ?? "#64748b";
}

export function severitySort(a: string, b: string): number {
  return (SEVERITY_ORDER[a.toLowerCase()] ?? 4) - (SEVERITY_ORDER[b.toLowerCase()] ?? 4);
}

// ── Evaluation Transforms ──────────────────────────────────────────────

export function countBySeverity(evaluations: any[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const e of evaluations) {
    const sev = (e.priority || e.severity || "medium").toLowerCase();
    if (sev in counts) counts[sev as keyof SeverityCounts]++;
  }
  return counts;
}

export function buildTimeseries(evaluations: any[], days = 30): TimeseriesPoint[] {
  const now = new Date();
  const buckets = new Map<string, { findings: number; resolved: number }>();

  // Initialize buckets
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    buckets.set(key, { findings: 0, resolved: 0 });
  }

  for (const e of evaluations) {
    const created = (e.createdAt || "").slice(0, 10);
    if (buckets.has(created)) {
      buckets.get(created)!.findings++;
    }
    if (e.status === "completed") {
      const completed = (e.updatedAt || e.createdAt || "").slice(0, 10);
      if (buckets.has(completed)) {
        buckets.get(completed)!.resolved++;
      }
    }
  }

  return Array.from(buckets.entries()).map(([date, v]) => ({
    date,
    findings: v.findings,
    resolved: v.resolved,
  }));
}

// ── Asset Transforms ───────────────────────────────────────────────────

export function groupAssetsByType(assets: any[]): Record<string, number> {
  const groups: Record<string, number> = {};
  for (const a of assets) {
    const type = a.assetType || a.type || "unknown";
    groups[type] = (groups[type] || 0) + 1;
  }
  return groups;
}

export function buildOrgMetrics(assets: any[], evaluations: any[]): OrgMetricRow[] {
  const byType = new Map<string, { assets: any[]; evals: any[] }>();

  for (const a of assets) {
    const type = a.assetType || a.type || "unknown";
    if (!byType.has(type)) byType.set(type, { assets: [], evals: [] });
    byType.get(type)!.assets.push(a);
  }

  for (const e of evaluations) {
    const asset = assets.find((a: any) => a.id === e.assetId);
    const type = asset?.assetType || asset?.type || "unknown";
    if (!byType.has(type)) byType.set(type, { assets: [], evals: [] });
    byType.get(type)!.evals.push(e);
  }

  return Array.from(byType.entries()).map(([type, { assets: typeAssets, evals }]) => {
    const critical = evals.filter((e: any) => (e.priority || "").toLowerCase() === "critical").length;
    const open = evals.filter((e: any) => e.status !== "completed").length;
    return {
      name: formatAssetType(type),
      type,
      total: typeAssets.length,
      critical,
      open,
      mttr: "N/A",
    };
  });
}

function formatAssetType(type: string): string {
  return type
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Sankey Transforms ──────────────────────────────────────────────────

export function buildSankeyData(assets: any[], evaluations: any[]): SankeyData {
  const assetMap = new Map<string, any>();
  for (const a of assets) assetMap.set(a.id, a);

  // Count: assetType × severity
  const matrix = new Map<string, Map<string, number>>();

  for (const e of evaluations) {
    const asset = assetMap.get(e.assetId);
    const type = formatAssetType(asset?.assetType || asset?.type || "unknown");
    const sev = (e.priority || e.severity || "medium").toLowerCase();

    if (!matrix.has(type)) matrix.set(type, new Map());
    const row = matrix.get(type)!;
    row.set(sev, (row.get(sev) || 0) + 1);
  }

  // Build nodes
  const leftNodes: SankeyData["leftNodes"] = [];
  const sevTotals: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const links: SankeyLink[] = [];

  for (const [type, sevMap] of Array.from(matrix.entries())) {
    let typeTotal = 0;
    for (const [sev, count] of Array.from(sevMap.entries())) {
      if (sev in sevTotals) {
        sevTotals[sev as keyof typeof sevTotals] += count;
        typeTotal += count;
        links.push({ source: type, target: sev, value: count, severity: sev as any });
      }
    }
    leftNodes.push({ label: type, count: typeTotal });
  }

  // Sort left nodes by count desc
  leftNodes.sort((a, b) => b.count - a.count);

  const allRightNodes: SankeyData["rightNodes"] = [
    { label: "Critical", count: sevTotals.critical, severity: "critical" as const },
    { label: "High", count: sevTotals.high, severity: "high" as const },
    { label: "Medium", count: sevTotals.medium, severity: "medium" as const },
    { label: "Low", count: sevTotals.low, severity: "low" as const },
  ];
  const rightNodes = allRightNodes.filter(n => n.count > 0);

  return { leftNodes, rightNodes, links };
}

// ── Risk Score ─────────────────────────────────────────────────────────

export function computeRiskScore(posture: any): number {
  if (posture?.overallScore != null) return Math.round(posture.overallScore);
  return 0;
}

export function riskScoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

export function riskScoreLabel(score: number): string {
  if (score >= 80) return "Good";
  if (score >= 60) return "Fair";
  if (score >= 40) return "Poor";
  return "Critical";
}
