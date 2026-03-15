/**
 * Breach Chain Replay — Engagement Package Component 5/5
 *
 * ADR-005: Generates a self-contained HTML file that replays the breach chain
 * step by step. No external dependencies — single HTML file with embedded CSS/JS.
 *
 * The replay visualizes:
 *   - Phase-by-phase progression with timing
 *   - Attack graph (nodes + edges)
 *   - Finding cards with evidence quality badges
 *   - Credential harvest and asset compromise timeline
 *
 * DETERMINISTIC — no LLM, no external requests at render time.
 */

import type {
  BreachChain,
  BreachPhaseResult,
  AttackGraph,
} from "@shared/schema";
import { reportIntegrityFilter } from "../report-integrity-filter";
import type { EvaluatedFinding } from "../evidence-quality-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ReplayManifest {
  engagementId: string;
  generatedAt: string;
  targetAssets: string[];
  phases: ReplayPhase[];
  attackGraph: AttackGraph | null;
  summary: {
    riskScore: number;
    domainsBreached: string[];
    maxPrivilege: string;
    totalFindings: number;
    customerFindings: number;
    durationMs: number;
  };
}

interface ReplayPhase {
  index: number;
  phase: string;
  displayName: string;
  status: string;
  durationMs: number;
  findings: ReplayFinding[];
  credentialsHarvested: number;
  assetsCompromised: number;
}

interface ReplayFinding {
  id: string;
  severity: string;
  title: string;
  description: string;
  evidenceQuality: string;
  technique: string | null;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const PHASE_DISPLAY_NAMES: Record<string, string> = {
  application_compromise: "Application Compromise",
  credential_extraction: "Credential Extraction",
  cloud_iam_escalation: "Cloud IAM Escalation",
  container_k8s_breakout: "Container/K8s Breakout",
  lateral_movement: "Lateral Movement",
  impact_assessment: "Impact Assessment",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
};

// ─── Manifest Builder ────────────────────────────────────────────────────────

export function buildReplayManifest(chain: BreachChain): ReplayManifest {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];

  const allFindings = phases.flatMap(p => p.findings ?? []);
  const evaluated: EvaluatedFinding[] = allFindings.map(f => ({
    ...f,
    id: f.id ?? "unknown",
    severity: f.severity ?? "medium",
    title: f.title ?? "Untitled",
    description: f.description ?? "",
  }));
  const filtered = reportIntegrityFilter.filter(evaluated);

  const replayPhases: ReplayPhase[] = phases.map((p, i) => ({
    index: i + 1,
    phase: p.phaseName,
    displayName: PHASE_DISPLAY_NAMES[p.phaseName] ?? p.phaseName,
    status: p.status,
    durationMs: p.durationMs ?? 0,
    findings: (p.findings ?? [])
      .filter(f => f.evidenceQuality === "proven" || f.evidenceQuality === "corroborated" || !f.evidenceQuality)
      .map(f => ({
        id: f.id ?? "unknown",
        severity: f.severity ?? "medium",
        title: f.title ?? "",
        description: (f.description ?? "").slice(0, 500),
        evidenceQuality: f.evidenceQuality ?? "unknown",
        technique: f.technique ?? null,
      })),
    credentialsHarvested: p.outputContext?.credentials?.length ?? 0,
    assetsCompromised: p.outputContext?.compromisedAssets?.length ?? 0,
  }));

  return {
    engagementId: chain.id,
    generatedAt: new Date().toISOString(),
    targetAssets: chain.assetIds as string[],
    phases: replayPhases,
    attackGraph: chain.unifiedAttackGraph ?? null,
    summary: {
      riskScore: chain.overallRiskScore ?? 0,
      domainsBreached: (chain.domainsBreached as string[] | null) ?? [],
      maxPrivilege: chain.maxPrivilegeAchieved ?? "none",
      totalFindings: filtered.audit.totalInput,
      customerFindings: filtered.audit.customerOutput,
      durationMs: chain.durationMs ?? 0,
    },
  };
}

// ─── HTML Generator ──────────────────────────────────────────────────────────

export function generateReplayHTML(chain: BreachChain): string {
  const manifest = buildReplayManifest(chain);
  const manifestJSON = JSON.stringify(manifest, null, 2);
  const targets = manifest.targetAssets.join(", ");
  const generatedAt = new Date().toISOString().split("T")[0];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OdinForge Breach Chain Replay — ${escapeHtml(targets)}</title>
<style>
  :root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; --accent: #3b82f6; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .header { text-align: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
  .header h1 { font-size: 1.5rem; color: var(--accent); }
  .header .meta { color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .kpi .value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
  .kpi .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .timeline { position: relative; padding-left: 2rem; }
  .timeline::before { content: ''; position: absolute; left: 0.75rem; top: 0; bottom: 0; width: 2px; background: var(--border); }
  .phase { position: relative; margin-bottom: 1.5rem; }
  .phase::before { content: ''; position: absolute; left: -1.35rem; top: 0.5rem; width: 12px; height: 12px; border-radius: 50%; background: var(--accent); border: 2px solid var(--bg); }
  .phase.skipped::before { background: var(--muted); }
  .phase-header { background: var(--surface); border: 1px solid var(--border); border-radius: 8px 8px 0 0; padding: 0.75rem 1rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
  .phase-header h3 { font-size: 0.95rem; }
  .phase-header .badge { font-size: 0.7rem; padding: 2px 8px; border-radius: 99px; text-transform: uppercase; font-weight: 600; }
  .phase-body { background: var(--surface); border: 1px solid var(--border); border-top: none; border-radius: 0 0 8px 8px; padding: 0.75rem 1rem; display: none; }
  .phase.open .phase-body { display: block; }
  .finding { border-left: 3px solid var(--muted); padding: 0.5rem 0.75rem; margin: 0.5rem 0; background: rgba(0,0,0,0.2); border-radius: 0 4px 4px 0; }
  .finding .title { font-weight: 600; font-size: 0.85rem; }
  .finding .desc { font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; }
  .sev-critical { border-color: ${SEVERITY_COLORS.critical}; }
  .sev-high { border-color: ${SEVERITY_COLORS.high}; }
  .sev-medium { border-color: ${SEVERITY_COLORS.medium}; }
  .sev-low { border-color: ${SEVERITY_COLORS.low}; }
  .badge-critical { background: ${SEVERITY_COLORS.critical}22; color: ${SEVERITY_COLORS.critical}; }
  .badge-high { background: ${SEVERITY_COLORS.high}22; color: ${SEVERITY_COLORS.high}; }
  .badge-medium { background: ${SEVERITY_COLORS.medium}22; color: ${SEVERITY_COLORS.medium}; }
  .badge-low { background: ${SEVERITY_COLORS.low}22; color: ${SEVERITY_COLORS.low}; }
  .footer { text-align: center; margin-top: 3rem; color: var(--muted); font-size: 0.75rem; border-top: 1px solid var(--border); padding-top: 1rem; }
  .eq-badge { font-size: 0.65rem; padding: 1px 6px; border-radius: 4px; background: #22c55e22; color: #22c55e; font-weight: 600; margin-left: 0.5rem; }
  .eq-corroborated { background: #3b82f622; color: #3b82f6; }
</style>
</head>
<body>
<div class="header">
  <h1>OdinForge Breach Chain Replay</h1>
  <div class="meta">Engagement: ${escapeHtml(manifest.engagementId)} | Target: ${escapeHtml(targets)} | Generated: ${generatedAt}</div>
</div>

<div class="summary">
  <div class="kpi"><div class="value">${manifest.summary.riskScore}</div><div class="label">Risk Score</div></div>
  <div class="kpi"><div class="value">${manifest.summary.customerFindings}</div><div class="label">Confirmed Findings</div></div>
  <div class="kpi"><div class="value">${manifest.summary.domainsBreached.length}</div><div class="label">Domains Breached</div></div>
  <div class="kpi"><div class="value">${manifest.summary.maxPrivilege}</div><div class="label">Max Privilege</div></div>
  <div class="kpi"><div class="value">${(manifest.summary.durationMs / 1000).toFixed(0)}s</div><div class="label">Duration</div></div>
</div>

<div class="timeline" id="timeline"></div>

<div class="footer">
  OdinForge AEV — Adversarial Exposure Validation | All findings backed by sealed EvidenceContract (ADR-001)<br>
  PROVEN and CORROBORATED findings only — INFERRED/UNVERIFIABLE suppressed from customer output
</div>

<script>
const manifest = ${manifestJSON};

const timeline = document.getElementById('timeline');
let currentPhase = 0;

function renderPhase(phase, index) {
  const div = document.createElement('div');
  div.className = 'phase' + (phase.status === 'skipped' ? ' skipped' : '') + (index === 0 ? ' open' : '');

  const highestSev = phase.findings.reduce((max, f) => {
    const order = {critical:0, high:1, medium:2, low:3};
    return (order[f.severity]||3) < (order[max]||3) ? f.severity : max;
  }, 'low');

  div.innerHTML =
    '<div class="phase-header" onclick="this.parentElement.classList.toggle(\\'open\\')">' +
      '<h3>Phase ' + phase.index + ': ' + esc(phase.displayName) + '</h3>' +
      '<div>' +
        '<span class="badge badge-' + highestSev + '">' + phase.findings.length + ' finding(s)</span> ' +
        '<span style="color:#94a3b8;font-size:0.75rem">' + (phase.durationMs/1000).toFixed(1) + 's</span>' +
      '</div>' +
    '</div>' +
    '<div class="phase-body">' +
      (phase.findings.length === 0 ? '<div style="color:#94a3b8;font-size:0.85rem">No confirmed findings in this phase.</div>' :
        phase.findings.map(f =>
          '<div class="finding sev-' + f.severity + '">' +
            '<div class="title">' + esc(f.title) +
              '<span class="eq-badge' + (f.evidenceQuality === 'corroborated' ? ' eq-corroborated' : '') + '">' + f.evidenceQuality + '</span>' +
            '</div>' +
            '<div class="desc">' + esc(f.description) + '</div>' +
            (f.technique ? '<div class="desc" style="margin-top:0.25rem">MITRE: ' + esc(f.technique) + '</div>' : '') +
          '</div>'
        ).join('')) +
      (phase.credentialsHarvested > 0 ? '<div style="margin-top:0.5rem;font-size:0.8rem;color:#f59e0b">Credentials harvested: ' + phase.credentialsHarvested + '</div>' : '') +
      (phase.assetsCompromised > 0 ? '<div style="font-size:0.8rem;color:#ef4444">Assets compromised: ' + phase.assetsCompromised + '</div>' : '') +
    '</div>';

  timeline.appendChild(div);
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

manifest.phases.forEach((p, i) => renderPhase(p, i));
</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
