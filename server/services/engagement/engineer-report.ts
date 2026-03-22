/**
 * Engineer Report Generator — Engagement Package Component 2/5
 *
 * ADR-005: Generates the technical breach chain report with:
 *   - Full chain trace with evidence per phase
 *   - HTTP evidence (request/response) for proven findings
 *   - Remediation diff (before/after config changes)
 *   - MITRE ATT&CK mapping per finding
 *
 * This is a DETERMINISTIC report — no LLM involved.
 * Only PROVEN and CORROBORATED findings appear (ReportIntegrityFilter).
 */

import type {
  BreachChain,
  BreachPhaseResult,
  AttackGraph,
} from "@shared/schema";
import { reportIntegrityFilter } from "../report-integrity-filter";
import type { EvaluatedFinding } from "../evidence-quality-gate";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EngineerReport {
  // Branding
  companyName: string;
  companyTagline: string;
  logoPath: string;

  reportId: string;
  engagementId: string;
  generatedAt: string;
  organizationId: string;

  // Phase 14: Path-first report structure
  primaryAttackPath: any | null;
  supportingAttackPaths: any[];
  remediationPlan: any | null;

  chainTrace: ChainTraceEntry[];
  findingDetails: EngineerFindingDetail[];
  remediationDiffs: RemediationDiff[];
  attackGraph: AttackGraph | null;
  methodologySummary: MethodologySummary;
}

export interface ChainTraceEntry {
  phaseIndex: number;
  phase: string;
  displayName: string;
  status: string;
  durationMs: number;
  findingCount: number;
  credentialsHarvested: number;
  assetsCompromised: number;
  domain: string | null;
  gateResult: string;
}

export interface EngineerFindingDetail {
  id: string;
  phase: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  technique: string | null;
  mitreId: string | null;
  source: string | null;
  evidenceQuality: string;
  httpEvidence: HttpEvidenceBlock | null;
}

interface HttpEvidenceBlock {
  statusCode: number;
  responseBodyPreview: string;
}

export interface RemediationDiff {
  findingId: string;
  findingTitle: string;
  severity: string;
  phase: string;
  currentState: string;
  recommendedState: string;
  effort: "immediate" | "short-term" | "long-term";
  references: string[];
}

interface MethodologySummary {
  targetAssets: string[];
  executionMode: string;
  enabledPhases: string[];
  totalDurationMs: number;
  evidenceStandard: string;
  scoringMethodology: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const PHASE_DISPLAY_NAMES: Record<string, string> = {
  application_compromise: "Phase 1: Application Compromise",
  credential_extraction: "Phase 2: Credential Extraction",
  cloud_iam_escalation: "Phase 3: Cloud IAM Escalation",
  container_k8s_breakout: "Phase 4: Container/K8s Breakout",
  lateral_movement: "Phase 5: Lateral Movement",
  impact_assessment: "Phase 6: Impact Assessment",
};

// ─── Remediation Templates ───────────────────────────────────────────────────

const REMEDIATION_MAP: Record<string, { current: string; recommended: string; refs: string[] }> = {
  sqli: {
    current: "User input concatenated into SQL queries",
    recommended: "Use parameterized queries / prepared statements for all database operations",
    refs: ["CWE-89", "OWASP A03:2021"],
  },
  ssti: {
    current: "User input rendered in server-side templates without sanitization",
    recommended: "Use sandboxed template engines, disable code evaluation in templates, validate all template inputs",
    refs: ["CWE-1336", "OWASP A03:2021"],
  },
  xss: {
    current: "User input reflected in HTML output without encoding",
    recommended: "Apply context-aware output encoding (HTML/JS/URL/CSS), implement Content-Security-Policy header",
    refs: ["CWE-79", "OWASP A03:2021"],
  },
  cmdi: {
    current: "User input passed to OS command execution",
    recommended: "Avoid OS commands entirely — use language-native APIs. If unavoidable, use allowlists and parameterized execution",
    refs: ["CWE-78", "OWASP A03:2021"],
  },
  path_traversal: {
    current: "File paths constructed from user input without validation",
    recommended: "Canonicalize paths, enforce chroot/jail, validate against allowlist of permitted directories",
    refs: ["CWE-22", "OWASP A01:2021"],
  },
  idor: {
    current: "Direct object references without authorization checks",
    recommended: "Implement object-level authorization on every access, use indirect references (UUIDs)",
    refs: ["CWE-639", "OWASP A01:2021"],
  },
  auth_bypass: {
    current: "Authentication can be circumvented via token manipulation or header injection",
    recommended: "Validate tokens server-side with cryptographic verification, enforce MFA on sensitive operations",
    refs: ["CWE-287", "OWASP A07:2021"],
  },
  T1552: {
    current: "Credentials exposed in HTTP responses, headers, or error messages",
    recommended: "Remove credentials from responses, implement secrets management, rotate all exposed credentials immediately",
    refs: ["CWE-522", "MITRE T1552"],
  },
  T1613: {
    current: "Kubernetes API accessible without authentication",
    recommended: "Enable RBAC, disable anonymous auth, restrict API server network access, use NetworkPolicies",
    refs: ["CIS Kubernetes 1.2.1", "MITRE T1613"],
  },
  "T1552.007": {
    current: "Kubernetes secrets readable without credentials",
    recommended: "Enable encryption at rest for etcd, restrict secret access via RBAC, use external secret management (Vault, AWS SM)",
    refs: ["CIS Kubernetes 1.2.6", "MITRE T1552.007"],
  },
  T1046: {
    current: "Infrastructure ports exposed to public internet",
    recommended: "Restrict access via firewall rules, use VPN/bastion hosts for management ports, implement network segmentation",
    refs: ["CWE-200", "MITRE T1046"],
  },
};

function getRemediation(technique: string | null | undefined): typeof REMEDIATION_MAP[string] | null {
  if (!technique) return null;
  return REMEDIATION_MAP[technique] ?? REMEDIATION_MAP[technique.split(".")[0]] ?? null;
}

// ─── Chain Trace Builder ─────────────────────────────────────────────────────

function buildChainTrace(phases: BreachPhaseResult[]): ChainTraceEntry[] {
  return phases.map((p, i) => ({
    phaseIndex: i + 1,
    phase: p.phaseName,
    displayName: PHASE_DISPLAY_NAMES[p.phaseName] ?? p.phaseName,
    status: p.status,
    durationMs: p.durationMs ?? 0,
    findingCount: p.findings?.length ?? 0,
    credentialsHarvested: p.outputContext?.credentials?.length ?? 0,
    assetsCompromised: p.outputContext?.compromisedAssets?.length ?? 0,
    domain: p.outputContext?.domainsCompromised?.[0] ?? null,
    gateResult: "passed",
  }));
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function generateEngineerReport(
  chain: BreachChain,
  primaryAttackPath?: any,
  supportingAttackPaths?: any[],
  remediationPlan?: any
): EngineerReport {
  const phases = (chain.phaseResults as BreachPhaseResult[] | null) ?? [];
  const config = chain.config as any;

  // Filter findings through integrity gate
  const allFindings = phases.flatMap(p =>
    (p.findings ?? []).map(f => ({ ...f, _phase: p.phaseName }))
  );
  const evaluated: (EvaluatedFinding & { _phase: string })[] = allFindings.map(f => ({
    ...f,
    id: f.id ?? "unknown",
    severity: f.severity ?? "medium",
    title: f.title ?? "Untitled",
    description: f.description ?? "",
    _phase: (f as any)._phase,
  }));

  const filtered = reportIntegrityFilter.filter(evaluated);

  // Build finding details with HTTP evidence
  const findingDetails: EngineerFindingDetail[] = filtered.customerFindings.map(f => {
    const phase = (f as any)._phase ?? "unknown";
    return {
      id: f.id,
      phase,
      severity: f.severity as "critical" | "high" | "medium" | "low",
      title: f.title,
      description: f.description,
      technique: (f as any).technique ?? null,
      mitreId: (f as any).mitreId ?? null,
      source: (f as any).source ?? null,
      evidenceQuality: (f as any).evidenceQuality ?? "unknown",
      httpEvidence: (f as any).statusCode
        ? {
            statusCode: (f as any).statusCode,
            responseBodyPreview: ((f as any).responseBody ?? "").slice(0, 500),
          }
        : null,
    };
  });

  // Build remediation diffs
  const remediationDiffs: RemediationDiff[] = [];
  for (const f of findingDetails) {
    const remediation = getRemediation(f.technique);
    if (!remediation) continue;
    remediationDiffs.push({
      findingId: f.id,
      findingTitle: f.title,
      severity: f.severity,
      phase: f.phase,
      currentState: remediation.current,
      recommendedState: remediation.recommended,
      effort: f.severity === "critical" ? "immediate" : f.severity === "high" ? "short-term" : "long-term",
      references: remediation.refs,
    });
  }

  return {
    // Branding
    companyName: "Odingard Security",
    companyTagline: "by Six Sense Enterprise Services",
    logoPath: "/odingard-logo.png",

    reportId: `eng-${chain.id}`,
    engagementId: chain.id,
    generatedAt: new Date().toISOString(),
    organizationId: chain.organizationId,
    // Phase 14: Path-first sections
    primaryAttackPath: primaryAttackPath || null,
    supportingAttackPaths: supportingAttackPaths || [],
    remediationPlan: remediationPlan || null,
    // Phase-by-phase detail
    chainTrace: buildChainTrace(phases),
    findingDetails,
    remediationDiffs,
    attackGraph: chain.unifiedAttackGraph ?? null,
    methodologySummary: {
      targetAssets: chain.assetIds as string[],
      executionMode: config?.executionMode ?? "live",
      enabledPhases: config?.enabledPhases ?? [],
      totalDurationMs: chain.durationMs ?? 0,
      evidenceStandard: "ADR-001: All findings require sealed EvidenceContract. PROVEN and CORROBORATED only.",
      scoringMethodology: "OdinForge Deterministic v3.0 | EPSS (45%) + CVSS (35%) + Agent Exploitability (20%)",
    },
  };
}
