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
  executiveReportV2Schema,
  technicalReportV2Schema,
  complianceReportV2Schema,
  evidencePackageV2Schema
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
}

const DEFAULT_CONFIG: Required<NarrativeEngineConfig> = {
  modelName: "gpt-4o",
  temperature: 0.7,
  maxRetries: 2,
  enableLinting: true,
};

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
    
    // Add metadata
    parsed.version = "1.0";
    parsed.generatedAt = new Date().toISOString();
    parsed.modelMeta = {
      modelName: cfg.modelName,
      promptHash,
      temperature: cfg.temperature,
      generationTimeMs,
    };
    
    // Validate ENO
    const validation = validateENO(parsed);
    
    if (!validation.valid) {
      return {
        success: false,
        error: `ENO validation failed: ${validation.errors.join("; ")}`,
        warnings: validation.warnings,
        modelMeta: parsed.modelMeta,
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
          modelMeta: parsed.modelMeta,
          lintResult,
        };
      }
    }
    
    return {
      success: true,
      data: validation.eno,
      warnings: [...validation.warnings, ...(lintResult?.warnings || [])],
      modelMeta: parsed.modelMeta,
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
 * Full report generation pipeline
 * Generates ENO first, then all requested report sections
 */
export async function generateFullReport(
  input: ReportInputPayload,
  reportTypes: Array<"executive" | "technical" | "compliance" | "evidence">,
  config: NarrativeEngineConfig = {}
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
  
  await Promise.all(sectionPromises);
  
  // If we have at least the ENO and one section, consider it a partial success
  const hasAnySections = !!(report.executive || report.technical || report.compliance || report.evidence);
  
  return {
    success: errors.length === 0 || hasAnySections,
    report: hasAnySections ? report : undefined,
    errors,
    warnings,
  };
}
