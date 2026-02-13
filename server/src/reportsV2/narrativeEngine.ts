/**
 * Narrative Engine Orchestrator
 * 
 * Pipeline for generating AI-powered narrative pentest reports.
 * Transforms evaluation data into human-grade security assessments
 * using role-based prompts and structured ENO generation.
 */

import OpenAI from "openai";
import { createHash } from "crypto";
import { ENO, enoSchema, validateENO, type ENOValidationResult } from "./eno.schema";
import { type ReportInputPayload } from "./reportInputBuilder";
import {
  ExecutiveReportV2,
  TechnicalReportV2,
  ComplianceReportV2,
  EvidencePackageV2,
  BreachValidationReportV2,
  executiveReportV2Schema,
  technicalReportV2Schema,
  complianceReportV2Schema,
  evidencePackageV2Schema,
  breachValidationReportV2Schema,
} from "./reportV2.schema";
import { loadPrompt, getAntiTemplateRules } from "./promptLoader";
import { antiTemplateLint, type LintResult } from "./antiTemplateLint";

let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI {
  if (!openaiClient) {
    const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error("OpenAI API key not configured. Set AI_INTEGRATIONS_OPENAI_API_KEY or OPENAI_API_KEY environment variable.");
    }
    openaiClient = new OpenAI({ 
      apiKey,
      baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
      timeout: 90000, // 90 second timeout to prevent hanging
      maxRetries: 2,
    });
  }
  return openaiClient;
}

export interface NarrativeEngineConfig {
  modelName?: string;
  temperature?: number;
  maxRetries?: number;
  enableLinting?: boolean;
}

export interface GenerationResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  warnings: string[];
  modelMeta: {
    modelName: string;
    promptHash: string;
    temperature: number;
    generationTimeMs: number;
  };
  lintResult?: LintResult;
}

export interface FullReportV2 {
  eno: ENO;
  executive?: ExecutiveReportV2;
  technical?: TechnicalReportV2;
  compliance?: ComplianceReportV2;
  evidence?: EvidencePackageV2;
  breach_validation?: BreachValidationReportV2;
}

const DEFAULT_CONFIG: Required<NarrativeEngineConfig> = {
  modelName: "gpt-4o",
  temperature: 0.7,
  maxRetries: 2,
  enableLinting: true,
};

/**
 * Normalize raw AI output to match ENO schema expectations.
 * GPT-4o often returns human-readable text where strict enums are expected.
 */
function normalizeENO(raw: any): any {
  if (!raw || typeof raw !== "object") return raw;

  // Phase name mapping: human-readable → snake_case enum
  const phaseMap: Record<string, string> = {
    "initial access": "initial_access",
    "privilege escalation": "privilege_escalation",
    "defense evasion": "defense_evasion",
    "credential access": "credential_access",
    "lateral movement": "lateral_movement",
    "execution": "execution",
    "persistence": "persistence",
    "discovery": "discovery",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
  };

  // Complexity mapping
  const complexityMap: Record<string, string> = {
    "low": "trivial", "trivial": "trivial", "easy": "trivial", "simple": "trivial",
    "moderate": "moderate", "medium": "moderate",
    "complex": "complex", "hard": "complex", "difficult": "complex", "high": "complex",
    "expert": "expert", "advanced": "expert", "very high": "expert",
  };

  // Risk level extraction: take first word if it's a valid enum
  function normalizeEnum(val: any, validValues: string[]): string {
    if (typeof val !== "string") return val;
    const lower = val.toLowerCase().trim();
    // Direct match
    if (validValues.includes(lower)) return lower;
    // First word match (handles "Critical, due to..." → "critical")
    const firstWord = lower.split(/[,.\s]/)[0];
    if (validValues.includes(firstWord)) return firstWord;
    // Fuzzy: check if any valid value is contained
    for (const v of validValues) {
      if (lower.startsWith(v)) return v;
    }
    return val;
  }

  // Ensure value is an array
  function ensureArray(val: any): any[] {
    if (Array.isArray(val)) return val;
    if (typeof val === "string") {
      // Try to split comma-separated or newline-separated
      const parts = val.split(/[,\n]/).map((s: string) => s.trim()).filter(Boolean);
      return parts.length > 0 ? parts : [val];
    }
    if (val != null) return [val];
    return [];
  }

  // Normalize confidence to a number 0-1
  function normalizeConfidence(val: any): number {
    if (typeof val === "number") return Math.min(1, Math.max(0, val > 1 ? val / 100 : val));
    if (typeof val === "string") {
      const num = parseFloat(val);
      if (!isNaN(num)) return Math.min(1, Math.max(0, num > 1 ? num / 100 : num));
    }
    return 0.7; // sensible default
  }

  // Normalize engagementOverview
  if (raw.engagementOverview) {
    const eo = raw.engagementOverview;
    eo.objectives = ensureArray(eo.objectives);
    eo.keyHighlights = ensureArray(eo.keyHighlights);
    eo.overallRiskLevel = normalizeEnum(eo.overallRiskLevel, ["critical", "high", "medium", "low"]);
    eo.confidence = normalizeConfidence(eo.confidence);

    // Normalize assetsAssessed to array of objects
    if (typeof eo.assetsAssessed === "string") {
      eo.assetsAssessed = [{ id: "asset-1", name: eo.assetsAssessed, type: "web_application", criticality: "high" }];
    } else if (Array.isArray(eo.assetsAssessed)) {
      eo.assetsAssessed = eo.assetsAssessed.map((a: any, i: number) => {
        if (typeof a === "string") return { id: `asset-${i + 1}`, name: a, type: "web_application", criticality: "high" };
        return {
          ...a,
          id: a.id || `asset-${i + 1}`,
          name: a.name || "Unknown",
          type: a.type || "web_application",
          criticality: normalizeEnum(a.criticality || "high", ["critical", "high", "medium", "low"]),
        };
      });
    }

    // Ensure timeframe exists
    if (!eo.timeframe) {
      const now = new Date().toISOString();
      eo.timeframe = { start: now, end: now };
    } else if (typeof eo.timeframe === "string") {
      const now = new Date().toISOString();
      eo.timeframe = { start: now, end: now };
    }
  }

  // Normalize attackStory
  if (Array.isArray(raw.attackStory)) {
    raw.attackStory = raw.attackStory.map((segment: any) => ({
      ...segment,
      phase: phaseMap[(segment.phase || "").toLowerCase().trim()] || segment.phase,
      complexity: normalizeEnum(
        complexityMap[(segment.complexity || "").toLowerCase().split(/[,.\s]/)[0]] || segment.complexity,
        ["trivial", "moderate", "complex", "expert"]
      ),
      confidence: normalizeConfidence(segment.confidence),
      techniques: ensureArray(segment.techniques),
      evidenceRefs: ensureArray(segment.evidenceRefs || []),
    }));
  }

  // Normalize defensiveGaps
  if (Array.isArray(raw.defensiveGaps)) {
    raw.defensiveGaps = raw.defensiveGaps.map((gap: any) => ({
      ...gap,
      category: normalizeEnum(gap.category, ["detection", "prevention", "response", "recovery", "visibility", "process", "training"]),
      affectedAssets: ensureArray(gap.affectedAssets || []),
      remediationEffort: normalizeEnum(gap.remediationEffort, ["low", "medium", "high"]),
      confidence: normalizeConfidence(gap.confidence),
    }));
  }

  // Normalize riskPrioritizationLogic
  if (Array.isArray(raw.riskPrioritizationLogic)) {
    raw.riskPrioritizationLogic = raw.riskPrioritizationLogic.map((entry: any) => ({
      ...entry,
      exploitLikelihood: normalizeEnum(entry.exploitLikelihood, ["certain", "highly_likely", "likely", "possible", "unlikely"]),
      confidence: normalizeConfidence(entry.confidence),
      priority: typeof entry.priority === "number" ? entry.priority : parseInt(entry.priority) || 1,
    }));
  }

  // Normalize overallAssessment
  if (raw.overallAssessment) {
    const oa = raw.overallAssessment;
    oa.verdict = normalizeEnum(oa.verdict, ["critical", "high", "medium", "low"]);
    oa.confidence = normalizeConfidence(oa.confidence);
    oa.strengthsObserved = ensureArray(oa.strengthsObserved || []);
    oa.criticalWeaknesses = ensureArray(oa.criticalWeaknesses || []);

    if (Array.isArray(oa.immediateActions)) {
      oa.immediateActions = oa.immediateActions.map((a: any) => ({
        ...a,
        priority: normalizeEnum(a.priority, ["immediate", "short_term", "medium_term"]),
        effort: normalizeEnum(a.effort, ["low", "medium", "high"]),
      }));
    }
  }

  // Normalize businessImpactAnalysis
  if (raw.businessImpactAnalysis) {
    raw.businessImpactAnalysis.confidence = normalizeConfidence(raw.businessImpactAnalysis.confidence);
    if (Array.isArray(raw.businessImpactAnalysis.primaryRisks)) {
      raw.businessImpactAnalysis.primaryRisks = raw.businessImpactAnalysis.primaryRisks.map((r: any) => ({
        ...r,
        potentialConsequences: ensureArray(r.potentialConsequences || []),
      }));
    }
  }

  // Normalize evidenceIndex
  if (Array.isArray(raw.evidenceIndex)) {
    raw.evidenceIndex = raw.evidenceIndex.map((e: any) => ({
      ...e,
      type: normalizeEnum(e.type, ["http_capture", "log_entry", "screenshot", "config_file", "network_trace", "command_output"]),
    }));
  }

  // Ensure validationStatus exists
  if (!raw.validationStatus) {
    raw.validationStatus = { passed: true, warnings: [], errors: [] };
  }

  return raw;
}

/**
 * Calculate hash of prompt content for traceability
 */
function hashPrompt(content: string): string {
  return createHash("sha256").update(content).digest("hex").substring(0, 16);
}

/**
 * Generate ENO (Engagement Narrative Object) from evaluation data
 */
export async function generateENO(
  input: ReportInputPayload,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<ENO>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  
  try {
    const systemPrompt = loadPrompt("leadPentester.system");
    const userPrompt = loadPrompt("eno.user");
    const antiTemplateRules = getAntiTemplateRules();
    
    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt.replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2));
    
    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);
    
    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });
    
    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;
    
    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    const parsed = JSON.parse(content);

    // Normalize AI output to match schema expectations
    const normalized = normalizeENO(parsed);

    // Add metadata
    normalized.version = "1.0";
    normalized.generatedAt = new Date().toISOString();
    normalized.modelMeta = {
      modelName: cfg.modelName,
      promptHash,
      temperature: cfg.temperature,
      generationTimeMs,
    };

    // Validate ENO
    const validation = validateENO(normalized);
    
    if (!validation.valid) {
      return {
        success: false,
        error: `ENO validation failed: ${validation.errors.join("; ")}`,
        warnings: validation.warnings,
        modelMeta: normalized.modelMeta,
      };
    }
    
    // Run anti-template linting if enabled
    let lintResult: LintResult | undefined;
    if (cfg.enableLinting) {
      lintResult = antiTemplateLint(validation.eno!);
      if (!lintResult.passed) {
        return {
          success: false,
          error: `Anti-template lint failed: ${lintResult.errors.join("; ")}`,
          warnings: lintResult.warnings,
          modelMeta: normalized.modelMeta,
          lintResult,
        };
      }
    }
    
    return {
      success: true,
      data: validation.eno,
      warnings: [...validation.warnings, ...(lintResult?.warnings || [])],
      modelMeta: normalized.modelMeta,
      lintResult,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error during ENO generation",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Generate Executive Report from ENO
 */
export async function generateExecutiveReport(
  eno: ENO,
  input: ReportInputPayload,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<ExecutiveReportV2>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  
  try {
    const systemPrompt = loadPrompt("executiveAdvisor.system");
    const userPrompt = loadPrompt("executive.user");
    const antiTemplateRules = getAntiTemplateRules();
    
    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt
      .replace("{{ENO}}", JSON.stringify(eno, null, 2))
      .replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2));
    
    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);
    
    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });
    
    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;
    
    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    const parsed = JSON.parse(content);
    const validation = executiveReportV2Schema.safeParse(parsed);
    
    if (!validation.success) {
      return {
        success: false,
        error: `Executive report validation failed: ${validation.error.errors.map(e => e.message).join("; ")}`,
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    return {
      success: true,
      data: validation.data,
      warnings: [],
      modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Generate Technical Report from ENO
 */
export async function generateTechnicalReport(
  eno: ENO,
  input: ReportInputPayload,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<TechnicalReportV2>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  
  try {
    const systemPrompt = loadPrompt("seniorEngineer.system");
    const userPrompt = loadPrompt("technical.user");
    const antiTemplateRules = getAntiTemplateRules();
    
    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt
      .replace("{{ENO}}", JSON.stringify(eno, null, 2))
      .replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2));
    
    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);
    
    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });
    
    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;
    
    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    const parsed = JSON.parse(content);
    const validation = technicalReportV2Schema.safeParse(parsed);
    
    if (!validation.success) {
      return {
        success: false,
        error: `Technical report validation failed: ${validation.error.errors.map(e => e.message).join("; ")}`,
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    return {
      success: true,
      data: validation.data,
      warnings: [],
      modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Generate Compliance Report from ENO
 */
export async function generateComplianceReport(
  eno: ENO,
  input: ReportInputPayload,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<ComplianceReportV2>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  
  try {
    const systemPrompt = loadPrompt("complianceAssessor.system");
    const userPrompt = loadPrompt("compliance.user");
    const antiTemplateRules = getAntiTemplateRules();
    
    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt
      .replace("{{ENO}}", JSON.stringify(eno, null, 2))
      .replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2));
    
    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);
    
    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });
    
    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;
    
    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    const parsed = JSON.parse(content);
    const validation = complianceReportV2Schema.safeParse(parsed);
    
    if (!validation.success) {
      return {
        success: false,
        error: `Compliance report validation failed: ${validation.error.errors.map(e => e.message).join("; ")}`,
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    return {
      success: true,
      data: validation.data,
      warnings: [],
      modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Generate Evidence Package from ENO
 */
export async function generateEvidencePackage(
  eno: ENO,
  input: ReportInputPayload,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<EvidencePackageV2>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  
  try {
    const systemPrompt = loadPrompt("incidentDoc.system");
    const userPrompt = loadPrompt("evidence.user");
    const antiTemplateRules = getAntiTemplateRules();
    
    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt
      .replace("{{ENO}}", JSON.stringify(eno, null, 2))
      .replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2));
    
    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);
    
    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });
    
    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;
    
    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    const parsed = JSON.parse(content);
    const validation = evidencePackageV2Schema.safeParse(parsed);
    
    if (!validation.success) {
      return {
        success: false,
        error: `Evidence package validation failed: ${validation.error.errors.map(e => e.message).join("; ")}`,
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }
    
    return {
      success: true,
      data: validation.data,
      warnings: [],
      modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Generate Breach Validation Report from ENO
 *
 * This is the OdinForge differentiator report — breach-first storytelling with
 * Breach Realization Score, validated attack paths, session replay evidence,
 * and remediation validation results. Replaces traditional vuln-list reports.
 */
export async function generateBreachValidationReport(
  eno: ENO,
  input: ReportInputPayload,
  breachScoreJson: string,
  config: NarrativeEngineConfig = {}
): Promise<GenerationResult<BreachValidationReportV2>> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();

  try {
    const systemPrompt = loadPrompt("breachValidator.system");
    const userPrompt = loadPrompt("breach_validation.user");
    const antiTemplateRules = getAntiTemplateRules();

    const fullSystemPrompt = `${systemPrompt}\n\n${antiTemplateRules}`;
    const fullUserPrompt = userPrompt
      .replace("{{ENO}}", JSON.stringify(eno, null, 2))
      .replace("{{INPUT_DATA}}", JSON.stringify(input, null, 2))
      .replace("{{BREACH_SCORE}}", breachScoreJson);

    const promptHash = hashPrompt(fullSystemPrompt + fullUserPrompt);

    const response = await getOpenAIClient().chat.completions.create({
      model: cfg.modelName,
      temperature: cfg.temperature,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: fullSystemPrompt },
        { role: "user", content: fullUserPrompt },
      ],
    });

    const generationTimeMs = Date.now() - startTime;
    const content = response.choices[0]?.message?.content;

    if (!content) {
      return {
        success: false,
        error: "No content returned from AI model",
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }

    const parsed = JSON.parse(content);
    const validation = breachValidationReportV2Schema.safeParse(parsed);

    if (!validation.success) {
      return {
        success: false,
        error: `Breach validation report validation failed: ${validation.error.errors.map(e => `${e.path.join(".")}: ${e.message}`).join("; ")}`,
        warnings: [],
        modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
      };
    }

    return {
      success: true,
      data: validation.data,
      warnings: [],
      modelMeta: { modelName: cfg.modelName, promptHash, temperature: cfg.temperature, generationTimeMs },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      warnings: [],
      modelMeta: {
        modelName: cfg.modelName,
        promptHash: "",
        temperature: cfg.temperature,
        generationTimeMs: Date.now() - startTime,
      },
    };
  }
}

/**
 * Full report generation pipeline
 * Generates ENO first, then all requested report sections
 */
export async function generateFullReport(
  input: ReportInputPayload,
  reportTypes: Array<"executive" | "technical" | "compliance" | "evidence" | "breach_validation">,
  config: NarrativeEngineConfig = {},
  breachScoreJson?: string
): Promise<{
  success: boolean;
  report?: FullReportV2;
  errors: string[];
  warnings: string[];
}> {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Step 1: Generate ENO
  const enoResult = await generateENO(input, config);

  if (!enoResult.success || !enoResult.data) {
    return {
      success: false,
      errors: [enoResult.error || "Failed to generate ENO"],
      warnings: enoResult.warnings,
    };
  }

  warnings.push(...enoResult.warnings);

  const report: FullReportV2 = { eno: enoResult.data };

  // Step 2: Generate requested report sections in parallel
  const sectionPromises: Promise<void>[] = [];

  if (reportTypes.includes("executive")) {
    sectionPromises.push(
      generateExecutiveReport(enoResult.data, input, config).then(result => {
        if (result.success && result.data) {
          report.executive = result.data;
        } else {
          errors.push(`Executive report: ${result.error}`);
        }
        warnings.push(...result.warnings);
      })
    );
  }

  if (reportTypes.includes("technical")) {
    sectionPromises.push(
      generateTechnicalReport(enoResult.data, input, config).then(result => {
        if (result.success && result.data) {
          report.technical = result.data;
        } else {
          errors.push(`Technical report: ${result.error}`);
        }
        warnings.push(...result.warnings);
      })
    );
  }

  if (reportTypes.includes("compliance")) {
    sectionPromises.push(
      generateComplianceReport(enoResult.data, input, config).then(result => {
        if (result.success && result.data) {
          report.compliance = result.data;
        } else {
          errors.push(`Compliance report: ${result.error}`);
        }
        warnings.push(...result.warnings);
      })
    );
  }

  if (reportTypes.includes("evidence")) {
    sectionPromises.push(
      generateEvidencePackage(enoResult.data, input, config).then(result => {
        if (result.success && result.data) {
          report.evidence = result.data;
        } else {
          errors.push(`Evidence package: ${result.error}`);
        }
        warnings.push(...result.warnings);
      })
    );
  }

  if (reportTypes.includes("breach_validation")) {
    const scoreJson = breachScoreJson || JSON.stringify({ overall: 0, dimensions: [], summary: "No breach chain data provided." });
    sectionPromises.push(
      generateBreachValidationReport(enoResult.data, input, scoreJson, config).then(result => {
        if (result.success && result.data) {
          report.breach_validation = result.data;
        } else {
          errors.push(`Breach validation report: ${result.error}`);
        }
        warnings.push(...result.warnings);
      })
    );
  }

  await Promise.all(sectionPromises);

  // If we have at least the ENO and one section, consider it a partial success
  const hasAnySections = !!(report.executive || report.technical || report.compliance || report.evidence || report.breach_validation);

  return {
    success: errors.length === 0 || hasAnySections,
    report: hasAnySections ? report : undefined,
    errors,
    warnings,
  };
}
