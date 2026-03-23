/**
 * Launch Readiness Evaluator — Go/No-Go Gate
 *
 * Deterministic, pure-function evaluator that assesses completed OdinForge runs
 * and produces GO / HOLD / NO_GO verdicts.
 *
 * Rules:
 *   - NO async external calls
 *   - NO model/router imports
 *   - NO writes to engine state
 *   - Pure evaluation only — this is a gatekeeper, not an assistant
 */

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type CheckStatus = "PASS" | "RISK" | "FAIL";

export interface LaunchCheck {
  id: string;
  section: string;
  description: string;
  status: CheckStatus;
  evidence?: string;
}

export interface SectionResult {
  section: string;
  status: CheckStatus;
  checks: LaunchCheck[];
}

export interface LaunchReadinessReport {
  sections: SectionResult[];
  summary: { pass: number; risk: number; fail: number };
  finalVerdict: "GO" | "HOLD" | "NO_GO";
}

/**
 * EngineRunContext — the complete snapshot of an engine run,
 * assembled from ActiveExploitResult + orchestrator data.
 */
export interface EngineRunContext {
  discoveredEndpoints: Array<{
    url: string;
    method?: string;
    discoverySource?: string;
    contentType?: string;
  }>;
  validatedFindings: Array<{
    id: string;
    severity: string;
    title: string;
    evidenceQuality?: string;
    statusCode?: number;
    responseBody?: string;
    technique?: string;
  }>;
  attempts: number;
  replayStats: {
    attempted: number;
    succeeded: number;
    budgetUsed: number;
    budgetTotal: number;
  };
  attackPaths: Array<{
    name: string;
    steps: Array<Record<string, unknown>>;
    confidence?: string;
    score?: number;
  }>;
  llmMetrics: {
    endpointTyperCalls: number;
    requestShaperCalls: number;
    plannerCalls: number;
    plannerHighValue: number;
    totalLlmTime: number;
    reasoningCalls: number;
  };
  executionMetrics: {
    runtimeMs: number;
    discoveryRequests: number;
    exploitRequests: number;
    exploitBudget: number;
    replayBudget: number;
  };
  safetyEvents: {
    outOfScope: number;
    destructiveBlocked: number;
    budgetExhausted: boolean;
  };
  reportData: {
    hasPrimaryPath: boolean;
    hasBusinessImpact: boolean;
    hasRemediation: boolean;
    findingCount: number;
  };
  baseline?: {
    endpointCount?: number;
    findingCount?: number;
    primaryPathPresent?: boolean;
  };
  config?: {
    safeMode?: boolean;
    hasAuth?: boolean;
    targetType?: string;
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function check(
  id: string,
  section: string,
  description: string,
  status: CheckStatus,
  evidence?: string,
): LaunchCheck {
  return { id, section, description, status, evidence };
}

function urlContains(url: string, ...patterns: string[]): boolean {
  const lower = url.toLowerCase();
  return patterns.some((p) => lower.includes(p));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Discovery (D1-D6)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateDiscovery(run: EngineRunContext): SectionResult {
  const eps = run.discoveredEndpoints;
  const checks: LaunchCheck[] = [];

  // D1: Auth endpoints discovered
  const authEps = eps.filter(
    (e) =>
      urlContains(e.url, "login", "auth", "oauth", "token", "session", "signup", "register") ||
      urlContains(e.contentType ?? "", "jwt"),
  );
  if (authEps.length >= 1) {
    checks.push(
      check("D1", "Discovery", "Auth endpoints discovered", "PASS", `${authEps.length} auth endpoint(s) found`),
    );
  } else if (run.config?.hasAuth === false) {
    checks.push(
      check("D1", "Discovery", "Auth endpoints discovered", "PASS", "Target has no auth (config confirms)"),
    );
  } else {
    checks.push(
      check("D1", "Discovery", "Auth endpoints discovered", "RISK", "No auth endpoints found — coverage gap possible"),
    );
  }

  // D2: Admin/config endpoints
  const adminEps = eps.filter((e) =>
    urlContains(e.url, "admin", "config", "settings", "manage", "dashboard", "internal"),
  );
  if (adminEps.length >= 1) {
    checks.push(
      check("D2", "Discovery", "Admin/config endpoints discovered", "PASS", `${adminEps.length} admin/config endpoint(s)`),
    );
  } else {
    checks.push(
      check("D2", "Discovery", "Admin/config endpoints discovered", "RISK", "No admin/config endpoints found"),
    );
  }

  // D3: GraphQL endpoints
  const graphqlEps = eps.filter(
    (e) => urlContains(e.url, "graphql", "gql") || urlContains(e.contentType ?? "", "graphql"),
  );
  checks.push(
    graphqlEps.length > 0
      ? check("D3", "Discovery", "GraphQL endpoints discovered", "PASS", `${graphqlEps.length} GraphQL endpoint(s)`)
      : check("D3", "Discovery", "GraphQL endpoints discovered", "PASS", "No GraphQL surface (not applicable)"),
  );

  // D4: Headless/JS-discovered endpoints
  const headlessEps = eps.filter(
    (e) =>
      e.discoverySource === "headless" ||
      e.discoverySource === "js_extract" ||
      e.discoverySource === "js-route-extractor",
  );
  if (headlessEps.length > 0) {
    checks.push(
      check("D4", "Discovery", "Headless/JS discovery active", "PASS", `${headlessEps.length} endpoint(s) from JS/headless`),
    );
  } else if (eps.length > 20) {
    // Lots of endpoints found via other means — headless wasn't needed
    checks.push(
      check("D4", "Discovery", "Headless/JS discovery active", "PASS", "Sufficient coverage from crawl alone"),
    );
  } else {
    checks.push(
      check("D4", "Discovery", "Headless/JS discovery active", "RISK", "No headless/JS endpoints — SPA coverage gap"),
    );
  }

  // D5: No known misses (basic endpoint count sanity)
  if (eps.length >= 3) {
    checks.push(
      check("D5", "Discovery", "No known endpoint coverage misses", "PASS", `${eps.length} endpoints discovered`),
    );
  } else if (eps.length >= 1) {
    checks.push(
      check("D5", "Discovery", "No known endpoint coverage misses", "RISK", `Only ${eps.length} endpoint(s) — low coverage`),
    );
  } else {
    checks.push(
      check("D5", "Discovery", "No known endpoint coverage misses", "FAIL", "Zero endpoints discovered"),
    );
  }

  // D6: Baseline stability (skip gracefully if no baseline)
  if (run.baseline?.endpointCount != null) {
    const diff = Math.abs(eps.length - run.baseline.endpointCount);
    const pct = run.baseline.endpointCount > 0 ? diff / run.baseline.endpointCount : 0;
    if (pct <= 0.2) {
      checks.push(
        check(
          "D6",
          "Discovery",
          "Baseline endpoint stability",
          "PASS",
          `${eps.length} endpoints vs baseline ${run.baseline.endpointCount} (${(pct * 100).toFixed(0)}% drift)`,
        ),
      );
    } else if (pct <= 0.5) {
      checks.push(
        check(
          "D6",
          "Discovery",
          "Baseline endpoint stability",
          "RISK",
          `${eps.length} endpoints vs baseline ${run.baseline.endpointCount} (${(pct * 100).toFixed(0)}% drift)`,
        ),
      );
    } else {
      checks.push(
        check(
          "D6",
          "Discovery",
          "Baseline endpoint stability",
          "FAIL",
          `${eps.length} endpoints vs baseline ${run.baseline.endpointCount} (${(pct * 100).toFixed(0)}% drift — major instability)`,
        ),
      );
    }
  } else {
    checks.push(
      check("D6", "Discovery", "Baseline endpoint stability", "PASS", "No baseline present — first run"),
    );
  }

  return { section: "Discovery", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Validation (V1-V4)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateValidation(run: EngineRunContext): SectionResult {
  const findings = run.validatedFindings;
  const checks: LaunchCheck[] = [];

  // V1: Evidence present on validated findings
  // Only check PROVEN findings for HTTP evidence — INFERRED findings (impact synthesis) don't have it by design
  const provenFindings = findings.filter(f => f.evidenceQuality === "proven");
  const provenWithEvidence = provenFindings.filter(f => f.statusCode != null && f.statusCode > 0);
  const totalRequiringEvidence = provenFindings.length;
  if (findings.length === 0) {
    checks.push(
      check("V1", "Validation", "Evidence present on validated findings", "PASS", "No findings to validate (clean target)"),
    );
  } else if (totalRequiringEvidence === 0) {
    checks.push(
      check("V1", "Validation", "Evidence present on validated findings", "PASS", `${findings.length} findings — none require HTTP evidence (all inferred/corroborated)`),
    );
  } else if (provenWithEvidence.length === totalRequiringEvidence) {
    checks.push(
      check("V1", "Validation", "Evidence present on validated findings", "PASS", `${provenWithEvidence.length}/${totalRequiringEvidence} proven findings have HTTP evidence`),
    );
  } else {
    const missing = totalRequiringEvidence - provenWithEvidence.length;
    checks.push(
      check("V1", "Validation", "Evidence present on validated findings", "FAIL", `${missing} proven finding(s) missing HTTP evidence`),
    );
  }

  // V2: No severity conflicts (e.g., same endpoint listed as both critical and low)
  const endpointSeverities = new Map<string, Set<string>>();
  for (const f of findings) {
    const key = f.title.replace(/\[VALIDATED\]\s*/, "").trim();
    if (!endpointSeverities.has(key)) endpointSeverities.set(key, new Set());
    endpointSeverities.get(key)!.add(f.severity);
  }
  const conflicted = Array.from(endpointSeverities.values()).filter((s) => s.size > 1);
  if (conflicted.length === 0) {
    checks.push(
      check("V2", "Validation", "No severity conflicts in findings", "PASS", "No severity conflicts detected"),
    );
  } else {
    checks.push(
      check("V2", "Validation", "No severity conflicts in findings", "RISK", `${conflicted.length} finding(s) with conflicting severities`),
    );
  }

  // V3: No weak evidence (INFERRED/UNVERIFIABLE)
  const weakFindings = findings.filter(
    (f) => f.evidenceQuality === "inferred" || f.evidenceQuality === "unverifiable",
  );
  if (weakFindings.length === 0) {
    checks.push(
      check("V3", "Validation", "No weak evidence in output", "PASS", "All findings have strong evidence quality"),
    );
  } else if (weakFindings.length <= 2) {
    checks.push(
      check("V3", "Validation", "No weak evidence in output", "RISK", `${weakFindings.length} finding(s) with weak evidence`),
    );
  } else {
    checks.push(
      check("V3", "Validation", "No weak evidence in output", "FAIL", `${weakFindings.length} findings with weak evidence — integrity risk`),
    );
  }

  // V4: Validation threshold respected (attempts vs validated ratio)
  // Use exploit budget as denominator (total payloads fired), not request count
  const totalAttempts = run.executionMetrics.exploitBudget > 0
    ? run.executionMetrics.exploitBudget
    : run.attempts;
  const provenCount = findings.filter(f => f.evidenceQuality === "proven").length;
  if (totalAttempts === 0 || provenCount === 0) {
    checks.push(
      check("V4", "Validation", "Validation threshold respected", "PASS", `${provenCount} proven findings — validation selective`),
    );
  } else {
    const rate = provenCount / totalAttempts;
    if (rate <= 0.1) {
      checks.push(
        check("V4", "Validation", "Validation threshold respected", "PASS", `${provenCount}/${totalAttempts} proven (${(rate * 100).toFixed(1)}% rate — selective)`),
      );
    } else if (rate <= 0.3) {
      checks.push(
        check("V4", "Validation", "Validation threshold respected", "RISK", `${provenCount}/${totalAttempts} proven (${(rate * 100).toFixed(1)}% — review recommended)`),
      );
    } else {
      checks.push(
        check("V4", "Validation", "Validation threshold respected", "FAIL", `${provenCount}/${totalAttempts} proven (${(rate * 100).toFixed(1)}% — suspiciously high)`),
      );
    }
  }

  return { section: "Validation", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Replay (R1-R5)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateReplay(run: EngineRunContext): SectionResult {
  const rs = run.replayStats;
  const checks: LaunchCheck[] = [];

  // R1: Replay attempted
  if (rs.attempted > 0) {
    checks.push(
      check("R1", "Replay", "Replay phase attempted", "PASS", `${rs.attempted} replay attempt(s) executed`),
    );
  } else if (run.validatedFindings.length === 0) {
    // No findings → nothing to replay — this is OK
    checks.push(
      check("R1", "Replay", "Replay phase attempted", "PASS", "No findings to replay (clean target)"),
    );
  } else {
    checks.push(
      check("R1", "Replay", "Replay phase attempted", "FAIL", "No replay attempts despite validated findings"),
    );
  }

  // R2: Replay not starved (budget utilization)
  if (rs.budgetTotal === 0 || rs.attempted === 0) {
    checks.push(
      check("R2", "Replay", "Replay not budget-starved", "PASS", "No replay budget needed"),
    );
  } else {
    const utilization = rs.budgetUsed / rs.budgetTotal;
    if (utilization <= 0.9) {
      checks.push(
        check("R2", "Replay", "Replay not budget-starved", "PASS", `${(utilization * 100).toFixed(0)}% of replay budget used`),
      );
    } else {
      checks.push(
        check("R2", "Replay", "Replay not budget-starved", "RISK", `${(utilization * 100).toFixed(0)}% of replay budget exhausted — may have missed chains`),
      );
    }
  }

  // R3: Attack paths produced
  if (run.attackPaths.length > 0) {
    checks.push(
      check("R3", "Replay", "Attack paths produced", "PASS", `${run.attackPaths.length} attack path(s) assembled`),
    );
  } else if (run.validatedFindings.length === 0) {
    checks.push(
      check("R3", "Replay", "Attack paths produced", "PASS", "No paths expected (clean target)"),
    );
  } else {
    checks.push(
      check("R3", "Replay", "Attack paths produced", "RISK", "Validated findings exist but no attack paths assembled"),
    );
  }

  // R4: Primary path progression
  const primaryPath = run.attackPaths.find((p) => p.confidence === "high" || (p.score != null && p.score >= 50));
  if (primaryPath) {
    checks.push(
      check(
        "R4",
        "Replay",
        "Primary path has multi-step progression",
        primaryPath.steps.length >= 2 ? "PASS" : "RISK",
        `Primary path "${primaryPath.name}" has ${primaryPath.steps.length} step(s)`,
      ),
    );
  } else if (run.attackPaths.length > 0) {
    checks.push(
      check("R4", "Replay", "Primary path has multi-step progression", "RISK", "Attack paths exist but none reached high confidence"),
    );
  } else if (run.validatedFindings.length === 0) {
    checks.push(
      check("R4", "Replay", "Primary path has multi-step progression", "PASS", "No paths expected (clean target)"),
    );
  } else {
    checks.push(
      check("R4", "Replay", "Primary path has multi-step progression", "RISK", "No attack paths to evaluate"),
    );
  }

  // R5: Path evidence (each path has at least one step with evidence)
  if (run.attackPaths.length === 0) {
    checks.push(
      check("R5", "Replay", "Path steps have evidence", "PASS", "No paths to validate"),
    );
  } else {
    const pathsWithEvidence = run.attackPaths.filter(
      (p) => p.steps.length > 0 && p.steps.some((s: Record<string, unknown>) => s.evidence != null),
    );
    if (pathsWithEvidence.length === run.attackPaths.length) {
      checks.push(
        check("R5", "Replay", "Path steps have evidence", "PASS", `All ${run.attackPaths.length} path(s) have step evidence`),
      );
    } else {
      checks.push(
        check(
          "R5",
          "Replay",
          "Path steps have evidence",
          "RISK",
          `${pathsWithEvidence.length}/${run.attackPaths.length} path(s) have step evidence`,
        ),
      );
    }
  }

  return { section: "Replay", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: AI Control (A1-A5)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateAIControl(run: EngineRunContext): SectionResult {
  const lm = run.llmMetrics;
  const checks: LaunchCheck[] = [];

  // A1: LLM does not influence truth — only PROVEN findings must have HTTP evidence.
  // INFERRED/CORROBORATED findings (impact synthesis) are expected not to have raw HTTP evidence.
  const provenFindings = run.validatedFindings.filter(f => f.evidenceQuality === "proven");
  const provenWithoutEvidence = provenFindings.filter(f => f.statusCode == null && !f.responseBody);
  if (provenWithoutEvidence.length === 0) {
    checks.push(
      check("A1", "AI Control", "LLM does not influence finding truth", "PASS",
        `All ${provenFindings.length} proven finding(s) backed by HTTP evidence`),
    );
  } else {
    checks.push(
      check("A1", "AI Control", "LLM does not influence finding truth", "FAIL",
        `${provenWithoutEvidence.length} proven finding(s) lack HTTP evidence`),
    );
  }

  // A2: Endpoint typer bounded
  if (lm.endpointTyperCalls <= 50) {
    checks.push(
      check("A2", "AI Control", "Endpoint typer bounded", "PASS", `${lm.endpointTyperCalls} endpoint typer calls (limit 50)`),
    );
  } else if (lm.endpointTyperCalls <= 75) {
    checks.push(
      check("A2", "AI Control", "Endpoint typer bounded", "RISK", `${lm.endpointTyperCalls} endpoint typer calls (over soft limit 50)`),
    );
  } else {
    checks.push(
      check("A2", "AI Control", "Endpoint typer bounded", "FAIL", `${lm.endpointTyperCalls} endpoint typer calls (exceeded limit)`),
    );
  }

  // A3: Request shaper useful
  if (lm.requestShaperCalls === 0) {
    checks.push(
      check("A3", "AI Control", "Request shaper useful", "PASS", "Request shaper not invoked (deterministic payloads sufficient)"),
    );
  } else if (lm.requestShaperCalls <= 150) {
    checks.push(
      check("A3", "AI Control", "Request shaper useful", "PASS", `${lm.requestShaperCalls} request shaper calls within budget`),
    );
  } else {
    checks.push(
      check("A3", "AI Control", "Request shaper useful", "RISK", `${lm.requestShaperCalls} request shaper calls — over budget`),
    );
  }

  // A4: Planner not in hot path (PASS if demoted to advisory-only)
  if (lm.plannerCalls === 0) {
    checks.push(
      check("A4", "AI Control", "Planner demoted from hot path", "PASS", "Planner not invoked — fully deterministic"),
    );
  } else if (lm.plannerHighValue > 0 && lm.plannerHighValue >= lm.plannerCalls * 0.3) {
    checks.push(
      check("A4", "AI Control", "Planner demoted from hot path", "PASS", `Planner advisory: ${lm.plannerCalls} calls, ${lm.plannerHighValue} high-value outcomes`),
    );
  } else if (lm.plannerCalls <= 10) {
    checks.push(
      check("A4", "AI Control", "Planner demoted from hot path", "PASS", `Planner demoted: ${lm.plannerCalls} advisory calls (limit 10)`),
    );
  } else {
    checks.push(
      check("A4", "AI Control", "Planner demoted from hot path", "RISK", `Planner made ${lm.plannerCalls} calls — may be in hot path`),
    );
  }

  // A5: Reasoning not required for finding production
  if (lm.reasoningCalls === 0) {
    checks.push(
      check("A5", "AI Control", "Reasoning not required for findings", "PASS", "No reasoning calls — pure deterministic"),
    );
  } else {
    // Reasoning is observational, not causal. Always passes unless unreasonably high.
    if (lm.reasoningCalls <= 100) {
      checks.push(
        check("A5", "AI Control", "Reasoning not required for findings", "PASS", `${lm.reasoningCalls} reasoning events (observational only)`),
      );
    } else {
      checks.push(
        check("A5", "AI Control", "Reasoning not required for findings", "RISK", `${lm.reasoningCalls} reasoning events — excessive observational overhead`),
      );
    }
  }

  return { section: "AI Control", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 5: Safety (S1-S5)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateSafety(run: EngineRunContext): SectionResult {
  const se = run.safetyEvents;
  const checks: LaunchCheck[] = [];

  // S1: Scope enforced
  if (se.outOfScope === 0) {
    checks.push(
      check("S1", "Safety", "Scope enforced — no out-of-scope requests", "PASS", "Zero out-of-scope events"),
    );
  } else if (se.outOfScope <= 3) {
    checks.push(
      check("S1", "Safety", "Scope enforced — no out-of-scope requests", "RISK", `${se.outOfScope} out-of-scope event(s) blocked`),
    );
  } else {
    checks.push(
      check("S1", "Safety", "Scope enforced — no out-of-scope requests", "FAIL", `${se.outOfScope} out-of-scope events — scope enforcement weak`),
    );
  }

  // S2: No destructive actions
  if (se.destructiveBlocked === 0) {
    checks.push(
      check("S2", "Safety", "No destructive actions attempted", "PASS", "Zero destructive requests blocked"),
    );
  } else {
    checks.push(
      check(
        "S2",
        "Safety",
        "No destructive actions attempted",
        se.destructiveBlocked <= 2 ? "RISK" : "FAIL",
        `${se.destructiveBlocked} destructive request(s) blocked by safety layer`,
      ),
    );
  }

  // S3: Request limits respected
  const totalRequests = run.executionMetrics.discoveryRequests + run.executionMetrics.exploitRequests;
  const requestBudget = run.executionMetrics.exploitBudget + 500; // discovery gets separate budget
  if (totalRequests <= requestBudget) {
    checks.push(
      check("S3", "Safety", "Request limits respected", "PASS", `${totalRequests} total requests within budget`),
    );
  } else {
    checks.push(
      check("S3", "Safety", "Request limits respected", "FAIL", `${totalRequests} requests exceeded budget of ${requestBudget}`),
    );
  }

  // S4: Replay bounded
  if (run.replayStats.budgetTotal === 0 || run.replayStats.budgetUsed <= run.replayStats.budgetTotal) {
    checks.push(
      check("S4", "Safety", "Replay budget bounded", "PASS", `Replay used ${run.replayStats.budgetUsed}/${run.replayStats.budgetTotal || "N/A"}`),
    );
  } else {
    checks.push(
      check("S4", "Safety", "Replay budget bounded", "FAIL", `Replay exceeded budget: ${run.replayStats.budgetUsed}/${run.replayStats.budgetTotal}`),
    );
  }

  // S5: Auth handling (if auth is configured, verify safe mode compliance)
  if (run.config?.hasAuth) {
    if (run.config.safeMode) {
      checks.push(
        check("S5", "Safety", "Auth handling in safe mode", "PASS", "Safe mode active with auth — credential handling bounded"),
      );
    } else {
      checks.push(
        check("S5", "Safety", "Auth handling in safe mode", "PASS", "Auth present, live mode — credential testing enabled"),
      );
    }
  } else {
    checks.push(
      check("S5", "Safety", "Auth handling in safe mode", "PASS", "No auth configured"),
    );
  }

  return { section: "Safety", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 6: Performance (P1-P4)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluatePerformance(run: EngineRunContext): SectionResult {
  const em = run.executionMetrics;
  const lm = run.llmMetrics;
  const checks: LaunchCheck[] = [];

  // P1: Runtime threshold (5 min warning, 10 min fail)
  const runtimeSec = em.runtimeMs / 1000;
  if (runtimeSec <= 300) {
    checks.push(
      check("P1", "Performance", "Runtime within threshold", "PASS", `Runtime ${runtimeSec.toFixed(1)}s (under 5m)`),
    );
  } else if (runtimeSec <= 600) {
    checks.push(
      check("P1", "Performance", "Runtime within threshold", "RISK", `Runtime ${runtimeSec.toFixed(1)}s (5-10m range)`),
    );
  } else {
    checks.push(
      check("P1", "Performance", "Runtime within threshold", "FAIL", `Runtime ${runtimeSec.toFixed(1)}s exceeds 10m threshold`),
    );
  }

  // P2: LLM time bounded (under 45s total)
  if (lm.totalLlmTime <= 45000) {
    checks.push(
      check("P2", "Performance", "LLM time bounded", "PASS", `LLM time ${(lm.totalLlmTime / 1000).toFixed(1)}s under 45s threshold`),
    );
  } else if (lm.totalLlmTime <= 90000) {
    checks.push(
      check("P2", "Performance", "LLM time bounded", "RISK", `LLM time ${(lm.totalLlmTime / 1000).toFixed(1)}s above 45s soft limit`),
    );
  } else {
    checks.push(
      check("P2", "Performance", "LLM time bounded", "FAIL", `LLM time ${(lm.totalLlmTime / 1000).toFixed(1)}s — excessive`),
    );
  }

  // P3: No runaway recursion (discovery requests bounded)
  if (em.discoveryRequests <= 500) {
    checks.push(
      check("P3", "Performance", "No runaway recursion", "PASS", `${em.discoveryRequests} discovery requests (bounded)`),
    );
  } else if (em.discoveryRequests <= 1000) {
    checks.push(
      check("P3", "Performance", "No runaway recursion", "RISK", `${em.discoveryRequests} discovery requests — near runaway threshold`),
    );
  } else {
    checks.push(
      check("P3", "Performance", "No runaway recursion", "FAIL", `${em.discoveryRequests} discovery requests — runaway detected`),
    );
  }

  // P4: No excessive retries (exploit attempts vs validated ratio check)
  if (run.attempts === 0) {
    checks.push(
      check("P4", "Performance", "No excessive retries", "PASS", "No exploit attempts (clean run)"),
    );
  } else if (run.attempts <= em.exploitBudget) {
    checks.push(
      check("P4", "Performance", "No excessive retries", "PASS", `${run.attempts} attempts within exploit budget of ${em.exploitBudget}`),
    );
  } else {
    checks.push(
      check("P4", "Performance", "No excessive retries", "RISK", `${run.attempts} attempts exceeded exploit budget of ${em.exploitBudget}`),
    );
  }

  return { section: "Performance", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 7: Report Quality (Q1-Q4)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateReport(run: EngineRunContext): SectionResult {
  const rd = run.reportData;
  const checks: LaunchCheck[] = [];

  // Q1: Primary path exists
  if (rd.hasPrimaryPath) {
    checks.push(
      check("Q1", "Report", "Primary attack path exists in report", "PASS", "Primary path documented"),
    );
  } else if (run.validatedFindings.length === 0) {
    checks.push(
      check("Q1", "Report", "Primary attack path exists in report", "PASS", "No path expected (clean target)"),
    );
  } else {
    checks.push(
      check("Q1", "Report", "Primary attack path exists in report", "RISK", "Findings exist but no primary path designated"),
    );
  }

  // Q2: Business impact
  if (rd.hasBusinessImpact) {
    checks.push(
      check("Q2", "Report", "Business impact documented", "PASS", "Business impact section present"),
    );
  } else if (run.validatedFindings.length === 0) {
    checks.push(
      check("Q2", "Report", "Business impact documented", "PASS", "No impact to document (clean target)"),
    );
  } else {
    checks.push(
      check("Q2", "Report", "Business impact documented", "RISK", "Findings exist but no business impact documented"),
    );
  }

  // Q3: Remediation
  if (rd.hasRemediation) {
    checks.push(
      check("Q3", "Report", "Remediation guidance present", "PASS", "Remediation guidance included"),
    );
  } else if (run.validatedFindings.length === 0) {
    checks.push(
      check("Q3", "Report", "Remediation guidance present", "PASS", "No remediation needed (clean target)"),
    );
  } else {
    checks.push(
      check("Q3", "Report", "Remediation guidance present", "FAIL", "Findings exist but no remediation guidance"),
    );
  }

  // Q4: Findings tied to path
  if (rd.findingCount === 0) {
    checks.push(
      check("Q4", "Report", "Findings tied to attack path", "PASS", "No findings to tie (clean target)"),
    );
  } else if (run.attackPaths.length > 0) {
    const stepsWithTechniques = run.attackPaths.flatMap((p) => p.steps);
    if (stepsWithTechniques.length >= rd.findingCount) {
      checks.push(
        check("Q4", "Report", "Findings tied to attack path", "PASS", `${rd.findingCount} finding(s) mapped to path steps`),
      );
    } else {
      checks.push(
        check("Q4", "Report", "Findings tied to attack path", "RISK", `${stepsWithTechniques.length} path steps vs ${rd.findingCount} findings — some findings may be orphaned`),
      );
    }
  } else {
    checks.push(
      check("Q4", "Report", "Findings tied to attack path", "RISK", `${rd.findingCount} finding(s) exist but no attack paths for mapping`),
    );
  }

  return { section: "Report", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 8: Trust (T1-T3)
// ═══════════════════════════════════════════════════════════════════════════════

function evaluateTrust(run: EngineRunContext): SectionResult {
  const checks: LaunchCheck[] = [];

  // T1: Defensible result
  const hasFindings = run.validatedFindings.length > 0;
  const hasPaths = run.attackPaths.length > 0;
  const discoveryWasThorough = run.discoveredEndpoints.length >= 3;

  if (hasFindings && hasPaths) {
    const proven = run.validatedFindings.filter(
      (f) => f.evidenceQuality === "proven" || (f.statusCode != null && f.statusCode >= 200 && f.statusCode < 600),
    );
    if (proven.length === run.validatedFindings.length) {
      checks.push(
        check("T1", "Trust", "Defensible result", "PASS", `${proven.length} finding(s) with proven evidence, ${run.attackPaths.length} path(s)`),
      );
    } else {
      checks.push(
        check("T1", "Trust", "Defensible result", "RISK", `${proven.length}/${run.validatedFindings.length} fully proven`),
      );
    }
  } else if (!hasFindings && discoveryWasThorough) {
    // Clean target with good coverage — defensible "no breach found" result
    checks.push(
      check(
        "T1",
        "Trust",
        "Defensible result",
        "PASS",
        "No confirmed breach path found within tested scope; coverage and validation completed successfully",
      ),
    );
  } else if (!hasFindings && !discoveryWasThorough) {
    checks.push(
      check("T1", "Trust", "Defensible result", "RISK", "No findings and low discovery coverage — cannot confidently defend result"),
    );
  } else {
    checks.push(
      check("T1", "Trust", "Defensible result", "RISK", "Findings exist but no attack paths assembled"),
    );
  }

  // T2: Repeatability
  if (run.baseline != null) {
    const findingDrift =
      run.baseline.findingCount != null
        ? Math.abs(run.validatedFindings.length - run.baseline.findingCount)
        : 0;
    const pathMatch =
      run.baseline.primaryPathPresent != null
        ? run.baseline.primaryPathPresent === run.reportData.hasPrimaryPath
        : true;

    if (findingDrift <= 2 && pathMatch) {
      checks.push(
        check("T2", "Trust", "Repeatability vs baseline", "PASS", `Finding drift ${findingDrift}, primary path ${pathMatch ? "matches" : "differs"}`),
      );
    } else {
      checks.push(
        check(
          "T2",
          "Trust",
          "Repeatability vs baseline",
          "RISK",
          `Finding drift ${findingDrift}, primary path ${pathMatch ? "matches" : "differs"} — results may not be stable`,
        ),
      );
    }
  } else {
    checks.push(
      check("T2", "Trust", "Repeatability vs baseline", "PASS", "No baseline — first run, repeatability not yet measurable"),
    );
  }

  // T3: No contradictions (e.g., budget exhausted but no attempts, or findings with no endpoints)
  const contradictions: string[] = [];
  if (run.safetyEvents.budgetExhausted && run.attempts === 0) {
    contradictions.push("Budget exhausted but zero attempts");
  }
  if (run.validatedFindings.length > 0 && run.discoveredEndpoints.length === 0) {
    contradictions.push("Findings exist but no endpoints discovered");
  }
  if (run.attackPaths.length > 0 && run.validatedFindings.length === 0) {
    contradictions.push("Attack paths exist but no validated findings");
  }
  if (run.replayStats.succeeded > run.replayStats.attempted) {
    contradictions.push("Replay successes exceed attempts");
  }

  if (contradictions.length === 0) {
    checks.push(
      check("T3", "Trust", "No internal contradictions", "PASS", "Run data is internally consistent"),
    );
  } else {
    checks.push(
      check(
        "T3",
        "Trust",
        "No internal contradictions",
        contradictions.length === 1 ? "RISK" : "FAIL",
        contradictions.join("; "),
      ),
    );
  }

  return { section: "Trust", status: resolveSectionStatus(checks), checks };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Aggregation
// ═══════════════════════════════════════════════════════════════════════════════

export function resolveSectionStatus(checks: LaunchCheck[]): CheckStatus {
  if (checks.some((c) => c.status === "FAIL")) return "FAIL";
  const riskCount = checks.filter((c) => c.status === "RISK").length;
  if (riskCount >= 2) return "RISK";
  if (riskCount === 1) return "RISK";
  return "PASS";
}

export function computeFinalVerdict(report: LaunchReadinessReport): "GO" | "HOLD" | "NO_GO" {
  const anyFail = report.sections.some((s) => s.status === "FAIL");
  if (anyFail) return "NO_GO";

  const totalRisk = report.sections.reduce(
    (sum, s) => sum + s.checks.filter((c) => c.status === "RISK").length,
    0,
  );
  if (totalRisk >= 3) return "NO_GO";
  if (totalRisk >= 1) return "HOLD";
  return "GO";
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════════════════

export function evaluateLaunchReadiness(run: EngineRunContext): LaunchReadinessReport {
  const sections: SectionResult[] = [
    evaluateDiscovery(run),
    evaluateValidation(run),
    evaluateReplay(run),
    evaluateAIControl(run),
    evaluateSafety(run),
    evaluatePerformance(run),
    evaluateReport(run),
    evaluateTrust(run),
  ];

  const summary = {
    pass: sections.reduce((sum, s) => sum + s.checks.filter((c) => c.status === "PASS").length, 0),
    risk: sections.reduce((sum, s) => sum + s.checks.filter((c) => c.status === "RISK").length, 0),
    fail: sections.reduce((sum, s) => sum + s.checks.filter((c) => c.status === "FAIL").length, 0),
  };

  const report: LaunchReadinessReport = {
    sections,
    summary,
    finalVerdict: "GO", // placeholder — computed below
  };

  report.finalVerdict = computeFinalVerdict(report);
  return report;
}
