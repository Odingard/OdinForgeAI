/**
 * CVSS Vector Parser
 *
 * Parses CVSS v2, v3.0, and v3.1 vector strings into structured types.
 * Computes base scores per FIRST specification.
 * Derives convenience fields for the scoring engine.
 */

// ============================================================================
// TYPES
// ============================================================================

export type CVSSVersion = "2.0" | "3.0" | "3.1";

export type AttackVector = "network" | "adjacent" | "local" | "physical";
export type AttackComplexity = "low" | "high";
export type PrivilegesRequired = "none" | "low" | "high";
export type UserInteraction = "none" | "required";
export type Scope = "unchanged" | "changed";
export type ImpactLevel = "none" | "low" | "high";

// CVSS v2 specific
export type AccessVector = "network" | "adjacent" | "local";
export type AccessComplexity = "low" | "medium" | "high";
export type Authentication = "none" | "single" | "multiple";

export type NetworkExposure = "internet" | "dmz" | "internal" | "isolated";
export type AuthRequired = "none" | "single" | "multi-factor" | "privileged";

export interface CVSSv3Metrics {
  attackVector: AttackVector;
  attackComplexity: AttackComplexity;
  privilegesRequired: PrivilegesRequired;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentialityImpact: ImpactLevel;
  integrityImpact: ImpactLevel;
  availabilityImpact: ImpactLevel;
}

export interface CVSSv2Metrics {
  accessVector: AccessVector;
  accessComplexity: AccessComplexity;
  authentication: Authentication;
  confidentialityImpact: ImpactLevel;
  integrityImpact: ImpactLevel;
  availabilityImpact: ImpactLevel;
}

export interface ParsedCVSS {
  version: CVSSVersion;
  vectorString: string;
  baseScore: number;
  severity: "none" | "low" | "medium" | "high" | "critical";
  metrics: {
    attackVector?: AttackVector;
    attackComplexity?: AttackComplexity | "medium";
    privilegesRequired?: PrivilegesRequired;
    userInteraction?: UserInteraction;
    scope?: Scope;
    confidentialityImpact?: ImpactLevel;
    integrityImpact?: ImpactLevel;
    availabilityImpact?: ImpactLevel;
  };
  // Derived convenience fields for scoring engine
  networkExposure: NetworkExposure;
  authRequired: AuthRequired;
}

// ============================================================================
// METRIC VALUE MAPS
// ============================================================================

const V3_AV: Record<string, AttackVector> = {
  N: "network", A: "adjacent", L: "local", P: "physical",
};
const V3_AC: Record<string, AttackComplexity> = {
  L: "low", H: "high",
};
const V3_PR: Record<string, PrivilegesRequired> = {
  N: "none", L: "low", H: "high",
};
const V3_UI: Record<string, UserInteraction> = {
  N: "none", R: "required",
};
const V3_S: Record<string, Scope> = {
  U: "unchanged", C: "changed",
};
const V3_CIA: Record<string, ImpactLevel> = {
  N: "none", L: "low", H: "high",
};

const V2_AV: Record<string, AccessVector> = {
  N: "network", A: "adjacent", L: "local",
};
const V2_AC: Record<string, "low" | "medium" | "high"> = {
  L: "low", M: "medium", H: "high",
};
const V2_AU: Record<string, Authentication> = {
  N: "none", S: "single", M: "multiple",
};
const V2_CIA: Record<string, ImpactLevel> = {
  N: "none", P: "low", C: "high",
};

// ============================================================================
// SCORE CALCULATION (CVSS v3.x per FIRST spec)
// ============================================================================

const V3_CIA_SCORES: Record<ImpactLevel, number> = {
  none: 0, low: 0.22, high: 0.56,
};

const V3_AV_SCORES: Record<AttackVector, number> = {
  network: 0.85, adjacent: 0.62, local: 0.55, physical: 0.20,
};

const V3_AC_SCORES: Record<AttackComplexity, number> = {
  low: 0.77, high: 0.44,
};

const V3_PR_SCORES_UNCHANGED: Record<PrivilegesRequired, number> = {
  none: 0.85, low: 0.62, high: 0.27,
};

const V3_PR_SCORES_CHANGED: Record<PrivilegesRequired, number> = {
  none: 0.85, low: 0.68, high: 0.50,
};

const V3_UI_SCORES: Record<UserInteraction, number> = {
  none: 0.85, required: 0.62,
};

function calculateV3BaseScore(metrics: CVSSv3Metrics): number {
  const iscC = 1 - V3_CIA_SCORES[metrics.confidentialityImpact];
  const iscI = 1 - V3_CIA_SCORES[metrics.integrityImpact];
  const iscA = 1 - V3_CIA_SCORES[metrics.availabilityImpact];
  const iss = 1 - iscC * iscI * iscA;

  let impact: number;
  if (metrics.scope === "unchanged") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  if (impact <= 0) return 0;

  const prScores = metrics.scope === "changed" ? V3_PR_SCORES_CHANGED : V3_PR_SCORES_UNCHANGED;
  const exploitability =
    8.22 *
    V3_AV_SCORES[metrics.attackVector] *
    V3_AC_SCORES[metrics.attackComplexity] *
    prScores[metrics.privilegesRequired] *
    V3_UI_SCORES[metrics.userInteraction];

  let baseScore: number;
  if (metrics.scope === "unchanged") {
    baseScore = Math.min(impact + exploitability, 10);
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  }

  return roundUp(baseScore);
}

// CVSS v2 base score (simplified per FIRST spec)
function calculateV2BaseScore(metrics: CVSSv2Metrics): number {
  const avScores: Record<AccessVector, number> = {
    network: 1.0, adjacent: 0.646, local: 0.395,
  };
  const acScores: Record<string, number> = {
    low: 0.71, medium: 0.61, high: 0.35,
  };
  const auScores: Record<Authentication, number> = {
    none: 0.704, single: 0.56, multiple: 0.45,
  };
  const ciaScores: Record<ImpactLevel, number> = {
    none: 0, low: 0.275, high: 0.660,
  };

  const impact =
    10.41 *
    (1 -
      (1 - ciaScores[metrics.confidentialityImpact]) *
      (1 - ciaScores[metrics.integrityImpact]) *
      (1 - ciaScores[metrics.availabilityImpact]));

  const exploitability =
    20 *
    avScores[metrics.accessVector] *
    acScores[metrics.accessComplexity] *
    auScores[metrics.authentication];

  const fImpact = impact === 0 ? 0 : 1.176;
  const baseScore = ((0.6 * impact + 0.4 * exploitability - 1.5) * fImpact);

  return Math.round(Math.max(0, Math.min(10, baseScore)) * 10) / 10;
}

/** CVSS v3 roundup: round to nearest tenth, ceiling */
function roundUp(x: number): number {
  return Math.ceil(x * 10) / 10;
}

// ============================================================================
// DERIVED FIELDS
// ============================================================================

function deriveNetworkExposure(av: AttackVector | AccessVector): NetworkExposure {
  switch (av) {
    case "network": return "internet";
    case "adjacent": return "dmz";
    case "local": return "internal";
    case "physical": return "isolated";
    default: return "dmz";
  }
}

function deriveAuthRequired(pr?: PrivilegesRequired, auth?: Authentication): AuthRequired {
  if (pr !== undefined) {
    switch (pr) {
      case "none": return "none";
      case "low": return "single";
      case "high": return "privileged";
    }
  }
  if (auth !== undefined) {
    switch (auth) {
      case "none": return "none";
      case "single": return "single";
      case "multiple": return "multi-factor";
    }
  }
  return "single";
}

function deriveSeverity(score: number, version: CVSSVersion): ParsedCVSS["severity"] {
  if (version === "2.0") {
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }
  // v3.x severity
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "none";
}

// ============================================================================
// MAIN PARSER
// ============================================================================

export function parseCVSSVector(vectorString: string): ParsedCVSS | null {
  if (!vectorString || typeof vectorString !== "string") return null;

  const trimmed = vectorString.trim();

  // Detect version
  if (trimmed.startsWith("CVSS:3.1/")) {
    return parseV3(trimmed, "3.1");
  }
  if (trimmed.startsWith("CVSS:3.0/")) {
    return parseV3(trimmed, "3.0");
  }
  // v2 vectors have no prefix — they start with AV: or (AV:
  if (trimmed.startsWith("AV:") || trimmed.startsWith("(AV:")) {
    return parseV2(trimmed);
  }
  // Also handle bare CVSS:3.1 without slash (some scanners omit it)
  if (trimmed.startsWith("CVSS:")) {
    const afterPrefix = trimmed.replace(/^CVSS:\d\.\d\/?/, "");
    if (trimmed.includes("3.1")) return parseV3(`CVSS:3.1/${afterPrefix}`, "3.1");
    if (trimmed.includes("3.0")) return parseV3(`CVSS:3.0/${afterPrefix}`, "3.0");
  }

  return null;
}

function parseV3(vectorString: string, version: "3.0" | "3.1"): ParsedCVSS | null {
  const parts = vectorString
    .replace(/^CVSS:\d\.\d\//, "")
    .split("/")
    .map(p => p.trim().split(":"));

  const map = new Map(parts.map(([k, v]) => [k, v]));

  const av = V3_AV[map.get("AV") || ""];
  const ac = V3_AC[map.get("AC") || ""];
  const pr = V3_PR[map.get("PR") || ""];
  const ui = V3_UI[map.get("UI") || ""];
  const s = V3_S[map.get("S") || ""];
  const c = V3_CIA[map.get("C") || ""];
  const i = V3_CIA[map.get("I") || ""];
  const a = V3_CIA[map.get("A") || ""];

  // All base metrics required
  if (!av || !ac || !pr || !ui || !s || c === undefined || i === undefined || a === undefined) {
    return null;
  }

  const v3Metrics: CVSSv3Metrics = {
    attackVector: av,
    attackComplexity: ac,
    privilegesRequired: pr,
    userInteraction: ui,
    scope: s,
    confidentialityImpact: c,
    integrityImpact: i,
    availabilityImpact: a,
  };

  const baseScore = calculateV3BaseScore(v3Metrics);

  return {
    version,
    vectorString,
    baseScore,
    severity: deriveSeverity(baseScore, version),
    metrics: {
      attackVector: av,
      attackComplexity: ac,
      privilegesRequired: pr,
      userInteraction: ui,
      scope: s,
      confidentialityImpact: c,
      integrityImpact: i,
      availabilityImpact: a,
    },
    networkExposure: deriveNetworkExposure(av),
    authRequired: deriveAuthRequired(pr),
  };
}

function parseV2(vectorString: string): ParsedCVSS | null {
  // Strip parentheses if present
  const cleaned = vectorString.replace(/^\(/, "").replace(/\)$/, "");
  const parts = cleaned.split("/").map(p => p.trim().split(":"));

  const map = new Map(parts.map(([k, v]) => [k, v]));

  const av = V2_AV[map.get("AV") || ""];
  const ac = V2_AC[map.get("AC") || ""];
  const au = V2_AU[map.get("Au") || map.get("AU") || ""];
  const c = V2_CIA[map.get("C") || ""];
  const i = V2_CIA[map.get("I") || ""];
  const a = V2_CIA[map.get("A") || ""];

  if (!av || !ac || !au || c === undefined || i === undefined || a === undefined) {
    return null;
  }

  const v2Metrics: CVSSv2Metrics = {
    accessVector: av,
    accessComplexity: ac,
    authentication: au,
    confidentialityImpact: c,
    integrityImpact: i,
    availabilityImpact: a,
  };

  const baseScore = calculateV2BaseScore(v2Metrics);

  // Map v2 metrics to unified metric shape
  const attackVector: AttackVector = av === "network" ? "network" : av === "adjacent" ? "adjacent" : "local";

  return {
    version: "2.0",
    vectorString,
    baseScore,
    severity: deriveSeverity(baseScore, "2.0"),
    metrics: {
      attackVector,
      attackComplexity: ac === "low" ? "low" : ac === "medium" ? "medium" as any : "high",
      privilegesRequired: au === "none" ? "none" : au === "single" ? "low" : "high",
      userInteraction: undefined, // v2 doesn't have UI
      scope: undefined, // v2 doesn't have S
      confidentialityImpact: c,
      integrityImpact: i,
      availabilityImpact: a,
    },
    networkExposure: deriveNetworkExposure(av),
    authRequired: deriveAuthRequired(undefined, au),
  };
}
