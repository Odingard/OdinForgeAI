/**
 * Chain Orchestrator - True AEV Exploit Chain Execution
 * 
 * Orchestrates multi-step attack sequences with:
 * - Playbook-based execution
 * - Evidence collection at each step
 * - Confidence-gated progression
 * - Mode-aware safety controls
 */

import { ValidatingHttpClient, type ValidationContext } from "../validation/validating-http-client";
import { executionModeEnforcer, type ExecutionMode } from "../validation/execution-modes";
import { executeSandboxed, type SandboxedOperationType } from "../validation/sandbox-executor";
import { auditService } from "../validation/audit-service";
import type { ValidationVerdict } from "@shared/schema";

// ============================================================================
// PLAYBOOK SCHEMA TYPES
// ============================================================================

export type ExploitCategory =
  | "sqli"
  | "xss"
  | "command_injection"
  | "path_traversal"
  | "ssrf"
  | "auth_bypass"
  | "jwt_attack"
  | "session_attack"
  | "business_logic"
  | "lateral_movement"
  | "credential_attack"
  | "idor"
  | "race_condition"
  | "workflow_bypass"
  | "iam_escalation"
  | "cloud_storage_exposure"
  | "cloud_misconfig";

export type StepType = 
  | "validate"      // Initial vulnerability validation
  | "exploit"       // Active exploitation attempt
  | "exfiltrate"    // Data extraction proof
  | "escalate"      // Privilege escalation
  | "pivot"         // Lateral movement
  | "persist"       // Persistence mechanism
  | "cleanup";      // Post-exploitation cleanup

export interface PlaybookStep {
  id: string;
  name: string;
  description: string;
  type: StepType;
  category: ExploitCategory;
  
  // Execution control
  requiredMode: ExecutionMode;
  requiresApproval: boolean;
  timeout: number;                    // ms
  maxRetries: number;
  
  // Preconditions
  dependsOn?: string[];               // Step IDs that must succeed first
  requiredConfidence?: number;        // Min confidence from prior step (0-100)
  requiredEvidence?: string[];        // Evidence types required from prior steps
  
  // Safety controls
  safeMode?: {
    enabled: boolean;
    maxPayloads?: number;
    allowedTargets?: string[];
    blockedPatterns?: string[];
  };
  
  // Step-specific config
  config: Record<string, any>;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  version: string;
  category: ExploitCategory;
  
  // Metadata
  author?: string;
  mitreAttackIds?: string[];
  riskLevel: "low" | "medium" | "high" | "critical";
  
  // Execution requirements
  minimumMode: ExecutionMode;
  estimatedDuration: number;          // ms
  
  // Steps
  steps: PlaybookStep[];
  
  // Abort conditions
  abortOn?: {
    stepFailures?: number;            // Max consecutive failures
    confidenceBelow?: number;         // Min confidence to continue
    patterns?: string[];              // Response patterns that trigger abort
  };
}

// ============================================================================
// EXECUTION RESULT TYPES
// ============================================================================

export interface StepEvidence {
  type: string;
  data: any;
  hash?: string;
  capturedAt: Date;
  redacted?: boolean;
}

export interface StepResult {
  stepId: string;
  stepName: string;
  status: "success" | "failed" | "skipped" | "aborted" | "blocked";
  
  // Outcome
  verdict?: ValidationVerdict;
  confidence: number;                 // 0-100
  evidence: StepEvidence[];
  
  // Execution metadata
  startedAt: Date;
  completedAt: Date;
  durationMs: number;
  retryCount: number;
  
  // Error info
  error?: string;
  blockedReason?: string;
  
  // Chain context
  chainedFrom?: string;               // Previous step ID
  enabledSteps?: string[];            // Steps now unlocked
}

export interface ChainExecutionResult {
  playbookId: string;
  playbookName: string;
  
  // Overall status
  status: "completed" | "partial" | "failed" | "aborted";
  overallConfidence: number;
  overallVerdict: ValidationVerdict;
  
  // Step results
  stepsExecuted: number;
  stepsSucceeded: number;
  stepsFailed: number;
  stepsSkipped: number;
  stepResults: StepResult[];
  
  // Execution metadata
  executionMode: ExecutionMode;
  startedAt: Date;
  completedAt: Date;
  totalDurationMs: number;
  
  // Evidence summary
  criticalFindings: string[];
  proofArtifacts: StepEvidence[];
  
  // Attack chain visualization
  attackPath: {
    nodeId: string;
    technique: string;
    status: "success" | "failed" | "skipped";
    confidence: number;
  }[];
}

// ============================================================================
// CHAIN ORCHESTRATOR
// ============================================================================

export interface ChainOrchestratorConfig {
  maxConcurrentSteps: number;
  defaultTimeout: number;
  confidenceThreshold: number;
  collectAllEvidence: boolean;
  redactSensitiveData: boolean;
}

const DEFAULT_CONFIG: ChainOrchestratorConfig = {
  maxConcurrentSteps: 1,              // Sequential by default for safety
  defaultTimeout: 30000,
  confidenceThreshold: 50,
  collectAllEvidence: true,
  redactSensitiveData: true,
};

export class ChainOrchestrator {
  private config: ChainOrchestratorConfig;
  private httpClient: ValidatingHttpClient;
  private stepHandlers: Map<string, StepHandler>;
  private activeChains: Map<string, ChainExecutionContext>;
  
  constructor(config?: Partial<ChainOrchestratorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.httpClient = new ValidatingHttpClient({ timeout: this.config.defaultTimeout });
    this.stepHandlers = new Map();
    this.activeChains = new Map();
    
    this.registerBuiltinHandlers();
  }
  
  // ---------------------------------------------------------------------------
  // PLAYBOOK EXECUTION
  // ---------------------------------------------------------------------------
  
  async executePlaybook(
    playbook: Playbook,
    target: string,
    context: {
      tenantId: string;
      organizationId: string;
      evaluationId?: string;
      userId?: string;
      approvalId?: string;
    },
    onProgress?: (stepId: string, status: string, progress: number) => void
  ): Promise<ChainExecutionResult> {
    const executionId = `chain-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    
    // Check execution mode
    const currentMode = executionModeEnforcer.getMode(context.tenantId);
    if (this.getModeLevel(currentMode) < this.getModeLevel(playbook.minimumMode)) {
      return this.createBlockedResult(playbook, currentMode, 
        `Playbook requires ${playbook.minimumMode} mode, current mode is ${currentMode}`);
    }
    
    // Create execution context
    const execContext: ChainExecutionContext = {
      executionId,
      playbook,
      target,
      tenantId: context.tenantId,
      organizationId: context.organizationId,
      evaluationId: context.evaluationId,
      userId: context.userId,
      approvalId: context.approvalId,
      mode: currentMode,
      stepResults: new Map(),
      collectedEvidence: [],
      aborted: false,
    };
    
    this.activeChains.set(executionId, execContext);
    
    // Log chain start (non-blocking — allows benchmark mode without DB)
    try {
      await auditService.logValidationAction(
        "chain_executed",
        currentMode,
        {
          organizationId: context.organizationId,
          tenantId: context.tenantId,
          evaluationId: context.evaluationId,
          requestedBy: context.userId,
        },
        {
          targetHost: target,
          probeType: "exploit_chain",
          resultStatus: "success",
          metadata: {
            playbookId: playbook.id,
            playbookName: playbook.name,
            stepCount: playbook.steps.length,
            action: "chain_started",
          },
        }
      );
    } catch {
      // Audit logging is non-critical — continue without DB
    }
    
    const stepResults: StepResult[] = [];
    let consecutiveFailures = 0;
    
    try {
      // Execute steps in dependency order
      const executionOrder = this.resolveStepOrder(playbook.steps);
      
      for (let i = 0; i < executionOrder.length; i++) {
        if (execContext.aborted) {
          break;
        }
        
        const step = executionOrder[i];
        onProgress?.(step.id, "starting", (i / executionOrder.length) * 100);
        
        // Check if step should be skipped
        const skipReason = this.shouldSkipStep(step, execContext);
        if (skipReason) {
          const skipResult = this.createSkippedResult(step, skipReason);
          stepResults.push(skipResult);
          execContext.stepResults.set(step.id, skipResult);
          continue;
        }
        
        // Check mode requirements
        if (this.getModeLevel(currentMode) < this.getModeLevel(step.requiredMode)) {
          const blockedResult = this.createBlockedResult2(step, 
            `Step requires ${step.requiredMode} mode`);
          stepResults.push(blockedResult);
          execContext.stepResults.set(step.id, blockedResult);
          continue;
        }
        
        // Execute step with sandboxing
        const stepResult = await this.executeStep(step, execContext, onProgress);
        stepResults.push(stepResult);
        execContext.stepResults.set(step.id, stepResult);
        
        // Track failures for abort condition
        if (stepResult.status === "failed") {
          consecutiveFailures++;
          if (playbook.abortOn?.stepFailures && 
              consecutiveFailures >= playbook.abortOn.stepFailures) {
            execContext.aborted = true;
            break;
          }
        } else {
          consecutiveFailures = 0;
        }
        
        // Check confidence abort condition
        if (playbook.abortOn?.confidenceBelow && 
            stepResult.confidence < playbook.abortOn.confidenceBelow) {
          execContext.aborted = true;
          break;
        }
        
        onProgress?.(step.id, stepResult.status, ((i + 1) / executionOrder.length) * 100);
      }
    } finally {
      this.activeChains.delete(executionId);
    }
    
    // Build result
    const result = this.buildChainResult(playbook, execContext, stepResults, startTime);
    
    // Log chain completion (non-blocking — allows benchmark mode without DB)
    try {
      await auditService.logValidationAction(
        "chain_executed",
        currentMode,
        {
          organizationId: context.organizationId,
          tenantId: context.tenantId,
          evaluationId: context.evaluationId,
          requestedBy: context.userId,
        },
        {
          targetHost: target,
          probeType: "exploit_chain",
          resultStatus: result.status === "completed" || result.status === "partial" ? "success" : "failure",
          confidenceScore: result.overallConfidence,
          metadata: {
            playbookId: playbook.id,
            status: result.status,
            stepsExecuted: result.stepsExecuted,
            stepsSucceeded: result.stepsSucceeded,
            criticalFindings: result.criticalFindings,
            action: "chain_completed",
          },
        }
      );
    } catch {
      // Audit logging is non-critical — continue without DB
    }
    
    return result;
  }
  
  // ---------------------------------------------------------------------------
  // STEP EXECUTION
  // ---------------------------------------------------------------------------
  
  private async executeStep(
    step: PlaybookStep,
    context: ChainExecutionContext,
    onProgress?: (stepId: string, status: string, progress: number) => void
  ): Promise<StepResult> {
    const startTime = Date.now();
    let retryCount = 0;

    // PolicyGuardian per-step check
    try {
      const { checkAction } = await import("../../services/agents/policy-guardian");
      const actionDesc = `${step.category}:${step.type} — ${step.description}`;
      const guardResult = await Promise.race([
        checkAction(actionDesc, "ChainOrchestrator", {
          organizationId: context.organizationId,
          executionMode: context.mode,
          targetType: context.target,
        }),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 5_000)),
      ]);
      if (guardResult && guardResult.decision === "DENY") {
        return {
          stepId: step.id,
          stepName: step.name,
          status: "blocked",
          confidence: 0,
          evidence: [],
          startedAt: new Date(startTime),
          completedAt: new Date(),
          durationMs: Date.now() - startTime,
          retryCount: 0,
          blockedReason: `PolicyGuardian denied: ${guardResult.reasoning}`,
        };
      }
    } catch {
      // PolicyGuardian failure is non-fatal in simulation+ modes
      if (context.mode === "safe") {
        return {
          stepId: step.id, stepName: step.name, status: "blocked", confidence: 0, evidence: [],
          startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime,
          retryCount: 0, blockedReason: "PolicyGuardian check failed in safe mode",
        };
      }
    }

    while (retryCount <= step.maxRetries) {
      try {
        // Execute within sandbox
        const sandboxResult = await executeSandboxed<StepResult>(
          this.mapStepTypeToOperation(step.type),
          context.target,
          async (signal) => {
            const handler = this.stepHandlers.get(`${step.category}:${step.type}`);
            if (!handler) {
              throw new Error(`No handler for ${step.category}:${step.type}`);
            }
            
            return handler.execute(step, context, this.httpClient, signal);
          },
          {
            tenantId: context.tenantId,
            organizationId: context.organizationId,
            executionMode: context.mode,
            timeoutMs: step.timeout || this.config.defaultTimeout,
            approvalId: context.approvalId,
          }
        );
        
        if (!sandboxResult.success) {
          throw new Error(sandboxResult.error || "Sandbox execution failed");
        }
        
        const result = sandboxResult.result!;
        
        // Collect evidence
        if (this.config.collectAllEvidence) {
          context.collectedEvidence.push(...result.evidence);
        }
        
        // Redact sensitive data if needed
        if (this.config.redactSensitiveData) {
          result.evidence = result.evidence.map(e => this.redactEvidence(e));
        }
        
        return result;
        
      } catch (error) {
        retryCount++;
        if (retryCount > step.maxRetries) {
          return {
            stepId: step.id,
            stepName: step.name,
            status: "failed",
            confidence: 0,
            evidence: [],
            startedAt: new Date(startTime),
            completedAt: new Date(),
            durationMs: Date.now() - startTime,
            retryCount,
            error: error instanceof Error ? error.message : "Unknown error",
          };
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
      }
    }
    
    // Should never reach here
    return this.createFailedResult(step, startTime, "Max retries exceeded", retryCount);
  }
  
  // ---------------------------------------------------------------------------
  // STEP HANDLERS
  // ---------------------------------------------------------------------------
  
  registerHandler(category: ExploitCategory, type: StepType, handler: StepHandler): void {
    this.stepHandlers.set(`${category}:${type}`, handler);
  }
  
  private registerBuiltinHandlers(): void {
    // SQLi handlers
    this.registerHandler("sqli", "validate", new SqliValidateHandler());
    this.registerHandler("sqli", "exploit", new SqliExploitHandler());
    this.registerHandler("sqli", "exfiltrate", new SqliExfiltrateHandler());
    
    // Path traversal handlers
    this.registerHandler("path_traversal", "validate", new PathTraversalValidateHandler());
    this.registerHandler("path_traversal", "exfiltrate", new PathTraversalExfiltrateHandler());
    
    // Command injection handlers
    this.registerHandler("command_injection", "validate", new CommandInjectionValidateHandler());
    this.registerHandler("command_injection", "exploit", new CommandInjectionExploitHandler());
    
    // Auth bypass handlers
    this.registerHandler("auth_bypass", "validate", new AuthBypassValidateHandler());
    this.registerHandler("auth_bypass", "escalate", new AuthBypassEscalateHandler());
    
    // SSRF handlers
    this.registerHandler("ssrf", "validate", new SsrfValidateHandler());
    this.registerHandler("ssrf", "pivot", new SsrfPivotHandler());

    // IDOR handlers
    this.registerHandler("idor", "validate", new IdorValidateHandler());
    this.registerHandler("idor", "exploit", new IdorHorizontalHandler());
    this.registerHandler("idor", "escalate", new IdorVerticalHandler());

    // Race condition handlers
    this.registerHandler("race_condition", "validate", new RaceConditionValidateHandler());
    this.registerHandler("race_condition", "exploit", new RaceConditionExploitHandler());

    // Workflow bypass handlers
    this.registerHandler("workflow_bypass", "validate", new WorkflowBypassValidateHandler());
    this.registerHandler("workflow_bypass", "exploit", new WorkflowBypassExploitHandler());

    // Cloud IAM escalation handlers
    this.registerHandler("iam_escalation", "validate", new IAMValidateHandler());
    this.registerHandler("iam_escalation", "escalate", new IAMEscalateHandler());
    this.registerHandler("iam_escalation", "exploit", new IAMImpactHandler());

    // Cloud storage exposure handlers
    this.registerHandler("cloud_storage_exposure", "validate", new CloudStorageValidateHandler());
    this.registerHandler("cloud_storage_exposure", "exploit", new CloudStorageAccessHandler());
    this.registerHandler("cloud_storage_exposure", "exfiltrate", new CloudStorageExfilHandler());
  }
  
  // ---------------------------------------------------------------------------
  // HELPER METHODS
  // ---------------------------------------------------------------------------
  
  private resolveStepOrder(steps: PlaybookStep[]): PlaybookStep[] {
    // Topological sort based on dependencies
    const resolved: PlaybookStep[] = [];
    const unresolved = new Set(steps.map(s => s.id));
    const stepMap = new Map(steps.map(s => [s.id, s]));
    
    while (unresolved.size > 0) {
      let progress = false;
      
      const unresolvedIds = Array.from(unresolved);
      for (const id of unresolvedIds) {
        const step = stepMap.get(id)!;
        const deps = step.dependsOn || [];
        
        if (deps.every(d => !unresolved.has(d))) {
          resolved.push(step);
          unresolved.delete(id);
          progress = true;
        }
      }
      
      if (!progress) {
        // Circular dependency - just add remaining in order
        const remaining = Array.from(unresolved);
        for (const id of remaining) {
          resolved.push(stepMap.get(id)!);
        }
        break;
      }
    }
    
    return resolved;
  }
  
  private shouldSkipStep(step: PlaybookStep, context: ChainExecutionContext): string | null {
    // Check dependency results
    if (step.dependsOn) {
      for (const depId of step.dependsOn) {
        const depResult = context.stepResults.get(depId);
        if (!depResult) {
          return `Dependency ${depId} not executed`;
        }
        if (depResult.status !== "success") {
          return `Dependency ${depId} did not succeed`;
        }
        
        // Check confidence threshold
        if (step.requiredConfidence && depResult.confidence < step.requiredConfidence) {
          return `Dependency ${depId} confidence (${depResult.confidence}) below threshold (${step.requiredConfidence})`;
        }
      }
    }
    
    // Check required evidence
    if (step.requiredEvidence) {
      const availableEvidence = new Set(
        context.collectedEvidence.map(e => e.type)
      );
      for (const required of step.requiredEvidence) {
        if (!availableEvidence.has(required)) {
          return `Required evidence type '${required}' not available`;
        }
      }
    }
    
    return null;
  }
  
  private getModeLevel(mode: ExecutionMode): number {
    switch (mode) {
      case "safe": return 0;
      case "simulation": return 1;
      case "live": return 2;
      default: return 0;
    }
  }
  
  private mapStepTypeToOperation(type: StepType): SandboxedOperationType {
    switch (type) {
      case "exfiltrate": return "data_exfiltration";
      case "exploit":
      case "escalate":
      case "pivot":
      case "persist":
        return "exploit_execution";
      default:
        return "vulnerability_scan";
    }
  }
  
  private redactEvidence(evidence: StepEvidence): StepEvidence {
    const sensitivePatterns = [
      /password[\"']?\s*[:=]\s*[\"']?[^\"'\s]+/gi,
      /api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\"'\s]+/gi,
      /secret[\"']?\s*[:=]\s*[\"']?[^\"'\s]+/gi,
      /token[\"']?\s*[:=]\s*[\"']?[^\"'\s]+/gi,
      /bearer\s+[a-zA-Z0-9\-_\.]+/gi,
      /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    ];
    
    let dataStr = typeof evidence.data === "string" 
      ? evidence.data 
      : JSON.stringify(evidence.data);
    
    for (const pattern of sensitivePatterns) {
      dataStr = dataStr.replace(pattern, "[REDACTED]");
    }
    
    return {
      ...evidence,
      data: dataStr,
      redacted: true,
    };
  }
  
  private createBlockedResult(playbook: Playbook, mode: ExecutionMode, reason: string): ChainExecutionResult {
    return {
      playbookId: playbook.id,
      playbookName: playbook.name,
      status: "aborted",
      overallConfidence: 0,
      overallVerdict: "error",
      stepsExecuted: 0,
      stepsSucceeded: 0,
      stepsFailed: 0,
      stepsSkipped: playbook.steps.length,
      stepResults: [],
      executionMode: mode,
      startedAt: new Date(),
      completedAt: new Date(),
      totalDurationMs: 0,
      criticalFindings: [],
      proofArtifacts: [],
      attackPath: [],
    };
  }
  
  private createSkippedResult(step: PlaybookStep, reason: string): StepResult {
    return {
      stepId: step.id,
      stepName: step.name,
      status: "skipped",
      confidence: 0,
      evidence: [],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
      blockedReason: reason,
    };
  }
  
  private createBlockedResult2(step: PlaybookStep, reason: string): StepResult {
    return {
      stepId: step.id,
      stepName: step.name,
      status: "blocked",
      confidence: 0,
      evidence: [],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
      blockedReason: reason,
    };
  }
  
  private createFailedResult(step: PlaybookStep, startTime: number, error: string, retryCount: number): StepResult {
    return {
      stepId: step.id,
      stepName: step.name,
      status: "failed",
      confidence: 0,
      evidence: [],
      startedAt: new Date(startTime),
      completedAt: new Date(),
      durationMs: Date.now() - startTime,
      retryCount,
      error,
    };
  }
  
  private buildChainResult(
    playbook: Playbook,
    context: ChainExecutionContext,
    stepResults: StepResult[],
    startTime: number
  ): ChainExecutionResult {
    const succeeded = stepResults.filter(r => r.status === "success").length;
    const failed = stepResults.filter(r => r.status === "failed").length;
    const skipped = stepResults.filter(r => r.status === "skipped" || r.status === "blocked").length;
    
    // Calculate overall confidence (average of successful steps)
    const successfulResults = stepResults.filter(r => r.status === "success");
    const avgConfidence = successfulResults.length > 0
      ? successfulResults.reduce((sum, r) => sum + r.confidence, 0) / successfulResults.length
      : 0;
    
    // Determine overall verdict
    let overallVerdict: ValidationVerdict = "false_positive";
    if (avgConfidence >= 90) overallVerdict = "confirmed";
    else if (avgConfidence >= 70) overallVerdict = "likely";
    else if (avgConfidence >= 40) overallVerdict = "theoretical";
    
    // Extract critical findings
    const criticalFindings: string[] = [];
    for (const result of stepResults) {
      if (result.status === "success" && result.confidence >= 80) {
        criticalFindings.push(`${result.stepName}: ${result.verdict || "Exploitable"}`);
      }
    }
    
    // Build attack path
    const attackPath = stepResults.map(r => ({
      nodeId: r.stepId,
      technique: playbook.steps.find(s => s.id === r.stepId)?.name || r.stepName,
      status: r.status === "success" ? "success" as const : 
              r.status === "failed" ? "failed" as const : "skipped" as const,
      confidence: r.confidence,
    }));
    
    // Determine overall status
    let status: ChainExecutionResult["status"] = "completed";
    if (context.aborted) status = "aborted";
    else if (succeeded === 0) status = "failed";
    else if (failed > 0 || skipped > 0) status = "partial";
    
    return {
      playbookId: playbook.id,
      playbookName: playbook.name,
      status,
      overallConfidence: Math.round(avgConfidence),
      overallVerdict,
      stepsExecuted: stepResults.length - skipped,
      stepsSucceeded: succeeded,
      stepsFailed: failed,
      stepsSkipped: skipped,
      stepResults,
      executionMode: context.mode,
      startedAt: new Date(startTime),
      completedAt: new Date(),
      totalDurationMs: Date.now() - startTime,
      criticalFindings,
      proofArtifacts: context.collectedEvidence,
      attackPath,
    };
  }
  
  // ---------------------------------------------------------------------------
  // CHAIN MANAGEMENT
  // ---------------------------------------------------------------------------
  
  abortChain(executionId: string, reason: string): boolean {
    const context = this.activeChains.get(executionId);
    if (context) {
      context.aborted = true;
      context.abortReason = reason;
      return true;
    }
    return false;
  }
  
  getActiveChains(): string[] {
    return Array.from(this.activeChains.keys());
  }
}

// ============================================================================
// STEP HANDLER INTERFACE
// ============================================================================

interface ChainExecutionContext {
  executionId: string;
  playbook: Playbook;
  target: string;
  tenantId: string;
  organizationId: string;
  evaluationId?: string;
  userId?: string;
  approvalId?: string;
  mode: ExecutionMode;
  stepResults: Map<string, StepResult>;
  collectedEvidence: StepEvidence[];
  aborted: boolean;
  abortReason?: string;
}

export interface StepHandler {
  execute(
    step: PlaybookStep,
    context: ChainExecutionContext,
    httpClient: ValidatingHttpClient,
    signal: AbortSignal
  ): Promise<StepResult>;
}

// ============================================================================
// BUILTIN STEP HANDLERS (Stubs - implemented in separate files)
// ============================================================================

class SqliValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, signal: AbortSignal): Promise<StepResult> {
    const { SqliValidator } = await import("../validation/modules/sqli-validator");
    const validator = new SqliValidator();
    const result = await validator.validate({
      targetUrl: context.target,
      parameterName: step.config.parameter || "id",
      parameterLocation: step.config.parameterLocation || "url_param",
      originalValue: step.config.value || "1",
      httpMethod: step.config.method || "GET",
      headers: step.config.headers,
    });
    
    return {
      stepId: step.id,
      stepName: step.name,
      status: result.vulnerable ? "success" : "failed",
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: [{
        type: "sqli_validation",
        data: result.evidence,
        capturedAt: new Date(),
      }],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
    };
  }
}

class SqliExploitHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { SqliPostExploitModule } = await import("./post-exploitation/sqli-post-exploit");
      const module = new SqliPostExploitModule();
      const result = await module.runFullExploitation({
        targetUrl: context.target,
        parameterName: step.config.parameter || "id",
        parameterLocation: (step.config.parameterLocation || "url_param") as any,
        httpMethod: (step.config.method || "GET") as any,
        basePayload: step.config.basePayload || "' OR 1=1--",
        dbType: (step.config.dbType || "unknown") as any,
        headers: step.config.headers,
      }, { skipData: true, maxTables: 5 });
      return {
        stepId: step.id, stepName: step.name,
        status: result.success ? "success" : "failed",
        confidence: result.fingerprint?.confidence || (result.success ? 75 : 0),
        evidence: result.proofArtifacts.map((pa) => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class SqliExfiltrateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { SqliPostExploitModule } = await import("./post-exploitation/sqli-post-exploit");
      const module = new SqliPostExploitModule();
      const result = await module.runFullExploitation({
        targetUrl: context.target,
        parameterName: step.config.parameter || "id",
        parameterLocation: (step.config.parameterLocation || "url_param") as any,
        httpMethod: (step.config.method || "GET") as any,
        basePayload: step.config.basePayload || "' OR 1=1--",
        dbType: (step.config.dbType || "unknown") as any,
        headers: step.config.headers,
      }, { skipFingerprint: true, maxTables: step.config.maxTables || 3, maxRows: step.config.maxRows || 5, redact: true });
      return {
        stepId: step.id, stepName: step.name,
        status: result.success ? "success" : "failed",
        confidence: result.dataSamples && result.dataSamples.length > 0 ? 85 : (result.success ? 60 : 0),
        evidence: result.proofArtifacts.map((pa) => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class PathTraversalValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, signal: AbortSignal): Promise<StepResult> {
    const { PathTraversalValidator } = await import("../validation/modules/path-traversal-validator");
    const validator = new PathTraversalValidator();
    const result = await validator.validate({
      targetUrl: context.target,
      parameterName: step.config.parameter || "file",
      parameterLocation: step.config.parameterLocation || "url_param",
      originalValue: step.config.value || "test.txt",
      httpMethod: step.config.method || "GET",
      headers: step.config.headers,
    });
    
    return {
      stepId: step.id,
      stepName: step.name,
      status: result.vulnerable ? "success" : "failed",
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: [{
        type: "path_traversal_validation",
        data: result.evidence,
        capturedAt: new Date(),
      }],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
    };
  }
}

class PathTraversalExfiltrateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { PathTraversalPostExploitModule } = await import("./post-exploitation/path-traversal-post-exploit");
      const module = new PathTraversalPostExploitModule();
      const result = await module.runFullExploitation({
        targetUrl: context.target,
        parameterName: step.config.parameter || "file",
        parameterLocation: (step.config.parameterLocation || "url_param") as any,
        httpMethod: (step.config.method || "GET") as any,
        traversalPayload: step.config.traversalPayload || "../../../etc/passwd",
        detectedOs: (step.config.detectedOs || "unix") as any,
        headers: step.config.headers,
      }, { maxFiles: 5, includeContent: true });
      return {
        stepId: step.id, stepName: step.name,
        status: result.success ? "success" : "failed",
        confidence: result.osFingerprint?.confidence || (result.fileProofs.filter((f) => f.readable).length > 0 ? 80 : 0),
        evidence: result.proofArtifacts.map((pa) => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class CommandInjectionValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, signal: AbortSignal): Promise<StepResult> {
    const { CommandInjectionValidator } = await import("../validation/modules/command-injection-validator");
    const validator = new CommandInjectionValidator();
    const result = await validator.validate({
      targetUrl: context.target,
      parameterName: step.config.parameter || "cmd",
      parameterLocation: step.config.parameterLocation || "url_param",
      originalValue: step.config.value || "test",
      httpMethod: step.config.method || "GET",
      headers: step.config.headers,
    });
    
    return {
      stepId: step.id,
      stepName: step.name,
      status: result.vulnerable ? "success" : "failed",
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: [{
        type: "command_injection_validation",
        data: result.evidence,
        capturedAt: new Date(),
      }],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
    };
  }
}

class CommandInjectionExploitHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { CommandInjectionPostExploitModule } = await import("./post-exploitation/command-injection-post-exploit");
      const module = new CommandInjectionPostExploitModule();
      const result = await module.runFullExploitation({
        targetUrl: context.target,
        parameterName: step.config.parameter || "cmd",
        parameterLocation: (step.config.parameterLocation || "url_param") as any,
        httpMethod: (step.config.method || "GET") as any,
        injectionPayload: step.config.injectionPayload || "; id",
        detectedOs: (step.config.detectedOs || "unix") as any,
        headers: step.config.headers,
      }, { maxCommands: 5 });
      return {
        stepId: step.id, stepName: step.name,
        status: result.rceProven ? "success" : (result.success ? "success" : "failed"),
        confidence: result.systemFingerprint?.confidence || (result.rceProven ? 90 : result.success ? 70 : 0),
        evidence: result.proofArtifacts.map((pa) => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class AuthBypassValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, signal: AbortSignal): Promise<StepResult> {
    const { AuthBypassValidator } = await import("../validation/modules/auth-bypass-validator");
    const validator = new AuthBypassValidator();
    const result = await validator.validate({
      targetUrl: context.target,
      parameterName: step.config.parameter || "user",
      parameterLocation: step.config.parameterLocation || "url_param",
      originalValue: step.config.value || "admin",
      httpMethod: step.config.method || "GET",
      headers: step.config.headers,
    });
    
    return {
      stepId: step.id,
      stepName: step.name,
      status: result.vulnerable ? "success" : "failed",
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: [{
        type: "auth_bypass_validation",
        data: result.evidence,
        capturedAt: new Date(),
      }],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
    };
  }
}

class AuthBypassEscalateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const adminPaths = step.config.adminPaths || ["/admin", "/api/admin", "/dashboard", "/api/users"];
      const evidence: { type: string; data: any; capturedAt: Date }[] = [];
      let escalated = false;

      for (const path of adminPaths) {
        try {
          const url = new URL(path, context.target).toString();
          const resp = await fetch(url, {
            headers: step.config.headers || {},
            signal: AbortSignal.timeout(10_000),
          });
          const body = await resp.text().catch(() => "");
          if (resp.status >= 200 && resp.status < 400 && body.length > 100) {
            escalated = true;
            evidence.push({
              type: "privilege_escalation",
              data: { url, status: resp.status, bodyLength: body.length, snippet: body.slice(0, 200) },
              capturedAt: new Date(),
            });
          }
        } catch {
          // Path not accessible — expected
        }
      }

      return {
        stepId: step.id, stepName: step.name,
        status: escalated ? "success" : "failed",
        confidence: escalated ? 75 : 0,
        evidence,
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class SsrfValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, signal: AbortSignal): Promise<StepResult> {
    const { SsrfValidator } = await import("../validation/modules/ssrf-validator");
    const validator = new SsrfValidator();
    const result = await validator.validate({
      targetUrl: context.target,
      parameterName: step.config.parameter || "url",
      parameterLocation: step.config.parameterLocation || "url_param",
      originalValue: step.config.value || "http://example.com",
      httpMethod: step.config.method || "GET",
      headers: step.config.headers,
    });
    
    return {
      stepId: step.id,
      stepName: step.name,
      status: result.vulnerable ? "success" : "failed",
      verdict: result.verdict,
      confidence: result.confidence,
      evidence: [{
        type: "ssrf_validation",
        data: result.evidence,
        capturedAt: new Date(),
      }],
      startedAt: new Date(),
      completedAt: new Date(),
      durationMs: 0,
      retryCount: 0,
    };
  }
}

class SsrfPivotHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { SsrfPostExploitModule } = await import("./post-exploitation/ssrf-post-exploit");
      const module = new SsrfPostExploitModule();

      // Extract lateral pivot paths as custom probe targets
      const customUrls: string[] = [];
      if (step.config?.lateralPivotPaths && Array.isArray(step.config.lateralPivotPaths)) {
        for (const pivot of step.config.lateralPivotPaths) {
          if (pivot.to && typeof pivot.to === "string") {
            // Normalize to URL: "10.0.0.5:8080" → "http://10.0.0.5:8080"
            const target = pivot.to.startsWith("http") ? pivot.to : `http://${pivot.to}`;
            customUrls.push(target);
          }
        }
      }

      const options: Record<string, any> = { maxProbes: 10 };
      if (customUrls.length > 0) {
        options.customUrls = customUrls;
      }

      const result = await module.runFullExploitation({
        targetUrl: context.target,
        parameterName: step.config.parameter || "url",
        parameterLocation: (step.config.parameterLocation || "url_param") as any,
        httpMethod: (step.config.method || "GET") as any,
        headers: step.config.headers,
      }, options);
      const accessible = result.internalServices.filter((s) => s.accessible).length;
      return {
        stepId: step.id, stepName: step.name,
        status: result.success ? "success" : "failed",
        confidence: result.cloudMetadata?.credentialsExposed ? 95 : (accessible > 0 ? 80 : result.localhostAccess ? 60 : 0),
        evidence: result.proofArtifacts.map((pa) => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

// ============================================================================
// BUSINESS LOGIC STEP HANDLERS
// ============================================================================

class IdorValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { IdorTestModule } = await import("./business-logic/idor-tests");
      const module = new IdorTestModule();
      const result = await module.runFullTest({
        baseUrl: context.target,
        targetUserId: step.config?.targetUserId || "2",
        headers: step.config?.headers,
      });
      const exploitable = result.vulnerabilities.filter(v => v.exploitable);
      return {
        stepId: step.id, stepName: step.name,
        status: exploitable.length > 0 ? "success" : "failed",
        confidence: exploitable.length > 0 ? 80 : 10,
        evidence: result.proofArtifacts.map(pa => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class IdorHorizontalHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { IdorTestModule } = await import("./business-logic/idor-tests");
      const module = new IdorTestModule();
      const endpoint = { path: step.config?.endpointPath || "/api/users/{id}", method: (step.config?.method || "GET") as any, idParam: "id", sensitiveFields: step.config?.sensitiveFields || ["email", "phone"] };
      const result = await module.testIdEnumeration({ baseUrl: context.target, targetUserId: step.config?.targetUserId || "2", headers: step.config?.headers }, endpoint, parseInt(step.config?.startId || "1", 10), 5);
      return {
        stepId: step.id, stepName: step.name,
        status: result?.exploitable ? "success" : "failed",
        confidence: result?.exploitable ? 85 : 10,
        evidence: result ? [{ type: "idor_enumeration", data: result.proof || "", capturedAt: new Date() }] : [],
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class IdorVerticalHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { IdorTestModule } = await import("./business-logic/idor-tests");
      const module = new IdorTestModule();
      const adminEndpoint = step.config?.adminEndpoint || "/api/admin/users";
      const result = await module.testVerticalEscalation({ baseUrl: context.target, headers: step.config?.headers }, adminEndpoint);
      return {
        stepId: step.id, stepName: step.name,
        status: result?.exploitable ? "success" : "failed",
        confidence: result?.exploitable ? 90 : 10,
        evidence: result ? [{ type: "idor_vertical", data: result.proof || "", capturedAt: new Date() }] : [],
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class RaceConditionValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { RaceConditionModule } = await import("./business-logic/race-conditions");
      const module = new RaceConditionModule();
      const result = await module.runFullTest({
        targetUrl: context.target,
        endpoint: step.config?.endpoint,
        method: step.config?.method || "POST",
        concurrentRequests: step.config?.concurrentRequests || 10,
        headers: step.config?.headers,
      });
      const exploitable = result.vulnerabilities.filter(v => v.exploitable);
      return {
        stepId: step.id, stepName: step.name,
        status: exploitable.length > 0 ? "success" : "failed",
        confidence: exploitable.length > 0 ? 80 : 10,
        evidence: result.proofArtifacts.map(pa => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class RaceConditionExploitHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { RaceConditionModule } = await import("./business-logic/race-conditions");
      const module = new RaceConditionModule();
      const result = await module.testDoubleSpend({
        targetUrl: context.target,
        endpoint: step.config?.endpoint || "/api/transactions",
        method: "POST",
        body: step.config?.body || { amount: 100, type: "transfer" },
        concurrentRequests: step.config?.concurrentRequests || 10,
        headers: step.config?.headers,
      });
      return {
        stepId: step.id, stepName: step.name,
        status: result.exploitable ? "success" : "failed",
        confidence: result.exploitable ? 90 : 10,
        evidence: result.exploitable ? [{ type: "race_double_spend", data: JSON.stringify(result.details), capturedAt: new Date() }] : [],
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class WorkflowBypassValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { WorkflowBypassModule } = await import("./business-logic/workflow-bypass");
      const module = new WorkflowBypassModule();
      const result = await module.runFullTest({
        baseUrl: context.target,
        headers: step.config?.headers,
      });
      const exploitable = result.vulnerabilities.filter(v => v.exploitable);
      return {
        stepId: step.id, stepName: step.name,
        status: exploitable.length > 0 ? "success" : "failed",
        confidence: exploitable.length > 0 ? 80 : 10,
        evidence: result.proofArtifacts.map(pa => ({ type: pa.type, data: pa.data, hash: pa.hash, capturedAt: pa.capturedAt })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class WorkflowBypassExploitHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { WorkflowBypassModule } = await import("./business-logic/workflow-bypass");
      const module = new WorkflowBypassModule();
      // Run step-skip test on default workflows
      const result = await module.runFullTest({
        baseUrl: context.target,
        headers: step.config?.headers,
      });
      // Filter to step_skip and state_manipulation specifically
      const exploitable = result.vulnerabilities.filter(v => v.exploitable && (v.type === "step_skip" || v.type === "state_manipulation"));
      return {
        stepId: step.id, stepName: step.name,
        status: exploitable.length > 0 ? "success" : "failed",
        confidence: exploitable.length > 0 ? 85 : 10,
        evidence: exploitable.length > 0
          ? [{ type: "workflow_exploit", data: exploitable.map(v => `${v.type} in ${v.workflowId}: ${v.proof}`).join("; "), capturedAt: new Date() }]
          : [],
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

// ============================================================================
// CLOUD SECURITY HANDLERS
// ============================================================================

class IAMValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const permissions = step.config?.permissions || ["iam:*", "s3:*"];
      const result = await awsPentestService.analyzeIAMPrivilegeEscalation(
        permissions,
        step.config?.userId || "unknown",
        step.config?.userName || "unknown",
        step.config?.accountId
      );
      const hasEscalation = result.escalationPaths.length > 0;
      return {
        stepId: step.id, stepName: step.name,
        status: hasEscalation ? "success" : "failed",
        confidence: hasEscalation ? 85 : 10,
        evidence: result.escalationPaths.map(p => ({ type: "iam_escalation", data: `${p.name}: ${p.description} (${p.mitreId})`, capturedAt: new Date() })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class IAMEscalateHandler implements StepHandler {
  async execute(step: PlaybookStep, context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const permissions = step.config?.permissions || ["iam:CreateAccessKey", "iam:AttachUserPolicy"];
      const result = await awsPentestService.analyzeIAMPrivilegeEscalation(permissions, step.config?.userId || "unknown", step.config?.userName || "unknown");
      const highImpact = result.escalationPaths.filter(p => p.impact === "critical" || p.impact === "high");
      return {
        stepId: step.id, stepName: step.name,
        status: highImpact.length > 0 ? "success" : "failed",
        confidence: highImpact.length > 0 ? 90 : 10,
        evidence: highImpact.map(p => ({ type: "iam_escalation_path", data: `${p.name}: ${p.steps.join(" → ")}`, capturedAt: new Date() })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class IAMImpactHandler implements StepHandler {
  async execute(step: PlaybookStep, _context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const permissions = step.config?.permissions || ["iam:*"];
      const result = await awsPentestService.analyzeIAMPrivilegeEscalation(permissions, step.config?.userId || "unknown", step.config?.userName || "unknown");
      const vulnerable = result.riskScore >= 70;
      return {
        stepId: step.id, stepName: step.name,
        status: vulnerable ? "success" : "failed",
        confidence: vulnerable ? 85 : 10,
        evidence: [{ type: "iam_impact", data: `Risk score: ${result.riskScore}, ${result.dangerousPermissions.length} dangerous permissions, ${result.escalationPaths.length} escalation paths`, capturedAt: new Date() }],
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class CloudStorageValidateHandler implements StepHandler {
  async execute(step: PlaybookStep, _context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const buckets = step.config?.buckets || [{ name: "test-bucket", isPublic: false }];
      const result = await awsPentestService.analyzeS3Buckets(buckets);
      const hasIssues = result.misconfigurations.length > 0 || result.publicBuckets.length > 0;
      return {
        stepId: step.id, stepName: step.name,
        status: hasIssues ? "success" : "failed",
        confidence: result.publicBuckets.length > 0 ? 95 : hasIssues ? 75 : 10,
        evidence: result.misconfigurations.map(m => ({ type: "s3_misconfig", data: `${m.bucketName}: ${m.type} (${m.severity}) - ${m.description}`, capturedAt: new Date() })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class CloudStorageAccessHandler implements StepHandler {
  async execute(step: PlaybookStep, _context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const buckets = step.config?.buckets || [{ name: "test-bucket", isPublic: true }];
      const result = await awsPentestService.analyzeS3Buckets(buckets);
      const publicAccess = result.publicBuckets.length > 0;
      return {
        stepId: step.id, stepName: step.name,
        status: publicAccess ? "success" : "failed",
        confidence: publicAccess ? 95 : 10,
        evidence: result.publicBuckets.map(b => ({ type: "s3_public_access", data: `Public bucket: ${b.name} (region: ${b.region || "unknown"})`, capturedAt: new Date() })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

class CloudStorageExfilHandler implements StepHandler {
  async execute(step: PlaybookStep, _context: ChainExecutionContext, _httpClient: ValidatingHttpClient, _signal: AbortSignal): Promise<StepResult> {
    const startTime = Date.now();
    try {
      const { awsPentestService } = await import("../cloud-pentest/aws-pentest-service");
      const buckets = step.config?.buckets || [{ name: "test-bucket", isPublic: true }];
      const result = await awsPentestService.analyzeS3Buckets(buckets);
      const hasExposure = result.sensitiveDataExposures.length > 0;
      return {
        stepId: step.id, stepName: step.name,
        status: hasExposure ? "success" : "failed",
        confidence: hasExposure ? 90 : 10,
        evidence: result.sensitiveDataExposures.map(e => ({ type: "s3_data_exposure", data: `${e.bucketName}/${e.objectKey}: ${e.dataType} (${e.sensitivityLevel})`, capturedAt: new Date() })),
        startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0,
      };
    } catch (error: any) {
      return { stepId: step.id, stepName: step.name, status: "failed", confidence: 0, evidence: [], startedAt: new Date(startTime), completedAt: new Date(), durationMs: Date.now() - startTime, retryCount: 0, error: error.message };
    }
  }
}

// ============================================================================
// SINGLETON EXPORT
// ============================================================================

export const chainOrchestrator = new ChainOrchestrator();
