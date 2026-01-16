import { ValidationEngine, type VulnerabilityType, type ValidationTarget, type UnifiedValidationResult } from "./validation/validation-engine";
import type { DiscoveredEndpoint, WebAppReconResult } from "./web-app-recon";
import { judgeFindingsBatch, buildValidationBundle, type ValidationBundle, type JudgeResult, type BatchJudgeResult } from "./validation/llm-judge";

export interface AgentTask {
  id: string;
  endpointId: string;
  endpoint: DiscoveredEndpoint;
  parameter: {
    name: string;
    location: "query" | "body" | "path" | "header" | "cookie";
  };
  vulnerabilityTypes: VulnerabilityType[];
  status: "pending" | "running" | "completed" | "failed";
  startedAt?: Date;
  completedAt?: Date;
  result?: UnifiedValidationResult;
  llmValidation?: JudgeResult;
  error?: string;
}

export interface AgentDispatchResult {
  totalTasks: number;
  completedTasks: number;
  failedTasks: number;
  findings: ValidatedFinding[];
  falsePositivesFiltered: number;
  executionTimeMs: number;
  tasksByVulnerabilityType: Record<VulnerabilityType, number>;
}

export interface ValidatedFinding {
  id: string;
  endpointUrl: string;
  endpointPath: string;
  parameter: string;
  vulnerabilityType: VulnerabilityType;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  verdict: "confirmed" | "likely" | "theoretical" | "needs_review";
  evidence: string[];
  recommendations: string[];
  llmValidation?: {
    verdict: string;
    confidence: number;
    reason: string;
  };
  reproductionSteps: string[];
  cvssEstimate?: string;
  mitreAttackId?: string;
}

export type DispatchProgressCallback = (
  phase: string,
  progress: number,
  message: string,
  stats?: {
    tasksCompleted: number;
    tasksTotal: number;
    findingsFound: number;
  }
) => void;

interface DispatcherConfig {
  maxConcurrentAgents: number;
  timeoutPerTaskMs: number;
  enableLLMValidation: boolean;
  filterBelowConfidence: number;
  vulnerabilityTypes: VulnerabilityType[];
  tenantId?: string;
  organizationId?: string;
}

const DEFAULT_CONFIG: DispatcherConfig = {
  maxConcurrentAgents: 5,
  timeoutPerTaskMs: 30000,
  enableLLMValidation: true,
  filterBelowConfidence: 50,
  vulnerabilityTypes: ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal", "ssrf"],
  tenantId: "default",
  organizationId: "default",
};

function mapVulnTypeToMitre(vulnType: VulnerabilityType): string {
  const mapping: Record<VulnerabilityType, string> = {
    sqli: "T1190",
    xss: "T1059.007",
    auth_bypass: "T1078",
    command_injection: "T1059",
    path_traversal: "T1083",
    ssrf: "T1071",
  };
  return mapping[vulnType] || "T1190";
}

function determineSeverity(vulnType: VulnerabilityType, confidence: number): ValidatedFinding["severity"] {
  const baseSeverity: Record<VulnerabilityType, number> = {
    sqli: 9,
    command_injection: 9,
    ssrf: 8,
    auth_bypass: 8,
    path_traversal: 7,
    xss: 6,
  };
  
  const base = baseSeverity[vulnType] || 5;
  const adjusted = base * (confidence / 100);
  
  if (adjusted >= 8) return "critical";
  if (adjusted >= 6) return "high";
  if (adjusted >= 4) return "medium";
  return "low";
}

function generateReproductionSteps(
  endpoint: DiscoveredEndpoint,
  parameter: string,
  vulnType: VulnerabilityType,
  result: UnifiedValidationResult
): string[] {
  const steps: string[] = [];
  
  steps.push(`1. Navigate to: ${endpoint.url}`);
  steps.push(`2. Identify the '${parameter}' parameter (location: ${endpoint.parameters.find(p => p.name === parameter)?.location || "query"})`);
  
  const payloadExamples: Record<VulnerabilityType, string> = {
    sqli: "' OR '1'='1",
    xss: "<script>alert(1)</script>",
    command_injection: "; id",
    path_traversal: "../../../etc/passwd",
    ssrf: "http://169.254.169.254/latest/meta-data/",
    auth_bypass: "admin' --",
  };
  
  steps.push(`3. Inject test payload: ${payloadExamples[vulnType]}`);
  steps.push(`4. Observe the application response for vulnerability indicators`);
  
  if (result.evidence && result.evidence.length > 0) {
    steps.push(`5. Evidence observed: ${result.evidence[0].substring(0, 200)}...`);
  }
  
  return steps;
}

function estimateCVSS(vulnType: VulnerabilityType, confidence: number): string {
  const baseScores: Record<VulnerabilityType, number> = {
    sqli: 9.8,
    command_injection: 9.8,
    ssrf: 8.6,
    auth_bypass: 8.1,
    path_traversal: 7.5,
    xss: 6.1,
  };
  
  const base = baseScores[vulnType] || 5.0;
  const adjusted = Math.min(10, base * (0.7 + (confidence / 100) * 0.3));
  
  return adjusted.toFixed(1);
}

function createTasksFromReconResult(
  reconResult: WebAppReconResult,
  config: DispatcherConfig
): AgentTask[] {
  const tasks: AgentTask[] = [];
  let taskId = 0;
  
  // Sort endpoints by priority
  const sortedEndpoints = [...reconResult.endpoints].sort((a, b) => {
    const priorityOrder = { high: 0, medium: 1, low: 2 };
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });
  
  for (const endpoint of sortedEndpoints) {
    // For each parameter, create tasks for relevant vulnerability types
    for (const param of endpoint.parameters) {
      // Determine which vulnerability types to test based on parameter characteristics
      let vulnTypesToTest = param.vulnerabilityPotential.length > 0 
        ? param.vulnerabilityPotential 
        : config.vulnerabilityTypes;
      
      // Filter to only configured vulnerability types
      vulnTypesToTest = vulnTypesToTest.filter(v => config.vulnerabilityTypes.includes(v));
      
      if (vulnTypesToTest.length > 0) {
        tasks.push({
          id: `task-${++taskId}`,
          endpointId: `${endpoint.method}-${endpoint.path}`,
          endpoint,
          parameter: {
            name: param.name,
            location: param.location,
          },
          vulnerabilityTypes: vulnTypesToTest as VulnerabilityType[],
          status: "pending",
        });
      }
    }
    
    // If endpoint has no parameters but is high priority, still test it
    if (endpoint.parameters.length === 0 && endpoint.priority === "high") {
      tasks.push({
        id: `task-${++taskId}`,
        endpointId: `${endpoint.method}-${endpoint.path}`,
        endpoint,
        parameter: {
          name: "_implicit_",
          location: "query",
        },
        vulnerabilityTypes: ["auth_bypass"], // Test for auth issues on parameterless endpoints
        status: "pending",
      });
    }
  }
  
  return tasks;
}

async function runAgentTask(
  task: AgentTask,
  config: DispatcherConfig
): Promise<AgentTask> {
  const updatedTask = { ...task };
  updatedTask.status = "running";
  updatedTask.startedAt = new Date();
  
  try {
    const engine = new ValidationEngine({
      maxPayloadsPerTest: 5,
      timeoutMs: config.timeoutPerTaskMs,
      captureEvidence: true,
      safeMode: false,
      executionMode: "simulation",
      tenantId: config.tenantId,
    });
    
    const target: ValidationTarget = {
      url: task.endpoint.url,
      method: task.endpoint.method,
      parameterName: task.parameter.name,
      parameterLocation: task.parameter.location === "query" ? "url_param" : 
                         task.parameter.location === "body" ? "body_param" :
                         task.parameter.location,
      vulnerabilityTypes: task.vulnerabilityTypes,
    };
    
    const result = await engine.validateTarget(target);
    updatedTask.result = result;
    updatedTask.status = "completed";
    
  } catch (error) {
    console.error(`[AgentDispatcher] Task ${task.id} failed:`, error);
    updatedTask.status = "failed";
    updatedTask.error = error instanceof Error ? error.message : "Unknown error";
  }
  
  updatedTask.completedAt = new Date();
  return updatedTask;
}

async function runTasksInParallel(
  tasks: AgentTask[],
  config: DispatcherConfig,
  onProgress?: DispatchProgressCallback
): Promise<AgentTask[]> {
  const results: AgentTask[] = [];
  const pending = [...tasks];
  const running: Promise<AgentTask>[] = [];
  let completed = 0;
  let findingsFound = 0;
  
  while (pending.length > 0 || running.length > 0) {
    // Start new tasks up to max concurrency
    while (pending.length > 0 && running.length < config.maxConcurrentAgents) {
      const task = pending.shift()!;
      const taskPromise = runAgentTask(task, config).then(result => {
        completed++;
        if (result.result?.vulnerable) {
          findingsFound += result.result.vulnerabilities.filter(v => v.result.vulnerable).length;
        }
        
        const progress = Math.round((completed / tasks.length) * 100);
        onProgress?.("validation", progress, `Validating endpoints... (${completed}/${tasks.length})`, {
          tasksCompleted: completed,
          tasksTotal: tasks.length,
          findingsFound,
        });
        
        return result;
      });
      running.push(taskPromise);
    }
    
    // Wait for at least one task to complete
    if (running.length > 0) {
      const completedTask = await Promise.race(running);
      results.push(completedTask);
      running.splice(running.indexOf(running.find(p => p === Promise.resolve(completedTask))!), 1);
    }
  }
  
  // Wait for any remaining tasks
  const remaining = await Promise.all(running);
  results.push(...remaining);
  
  return results;
}

async function validateFindingsWithLLM(
  findings: ValidatedFinding[],
  onProgress?: DispatchProgressCallback
): Promise<{ validated: ValidatedFinding[]; filtered: number }> {
  if (findings.length === 0) {
    return { validated: [], filtered: 0 };
  }
  
  onProgress?.("llm_validation", 0, `Validating ${findings.length} findings with LLM...`);
  
  // Build validation bundles with proper findingId
  const validationBundles: ValidationBundle[] = findings.map(f => 
    buildValidationBundle(
      {
        id: f.id,
        findingType: f.vulnerabilityType,
        severity: f.severity,
        title: `${f.vulnerabilityType.toUpperCase()} vulnerability in ${f.parameter} parameter`,
        description: `Potential ${f.vulnerabilityType} vulnerability detected at ${f.endpointPath}`,
        affectedComponent: f.endpointUrl,
      },
      {
        attackEvidence: f.evidence.join("\n"),
        context: {
          confidence: f.confidence,
          mitreId: f.mitreAttackId,
          cvss: f.cvssEstimate,
        },
      }
    )
  );
  
  const batchResults = await judgeFindingsBatch(validationBundles);
  
  const validated: ValidatedFinding[] = [];
  let filtered = 0;
  
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    const judgeResult: BatchJudgeResult | undefined = batchResults.find((r: BatchJudgeResult) => r.findingId === finding.id);
    
    if (judgeResult) {
      const updatedFinding = { ...finding };
      updatedFinding.llmValidation = {
        verdict: judgeResult.result.verdict,
        confidence: judgeResult.result.confidence,
        reason: judgeResult.result.reason,
      };
      
      // Filter out noise
      if (judgeResult.result.verdict === "noise") {
        filtered++;
        continue;
      }
      
      // Adjust confidence based on LLM validation
      if (judgeResult.result.verdict === "confirmed") {
        updatedFinding.confidence = Math.max(updatedFinding.confidence, judgeResult.result.confidence);
        updatedFinding.verdict = "confirmed";
      } else if (judgeResult.result.verdict === "needs_review") {
        updatedFinding.verdict = "likely";
      }
      
      validated.push(updatedFinding);
    } else {
      validated.push(finding);
    }
  }
  
  onProgress?.("llm_validation", 100, `LLM validation complete: ${validated.length} confirmed, ${filtered} filtered`);
  
  return { validated, filtered };
}

export async function dispatchParallelAgents(
  reconResult: WebAppReconResult,
  config: Partial<DispatcherConfig> = {},
  onProgress?: DispatchProgressCallback
): Promise<AgentDispatchResult> {
  const startTime = Date.now();
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };
  
  onProgress?.("initialization", 5, "Preparing agent tasks...");
  
  // Create tasks from recon result
  const tasks = createTasksFromReconResult(reconResult, mergedConfig);
  
  if (tasks.length === 0) {
    return {
      totalTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      findings: [],
      falsePositivesFiltered: 0,
      executionTimeMs: Date.now() - startTime,
      tasksByVulnerabilityType: {} as Record<VulnerabilityType, number>,
    };
  }
  
  onProgress?.("dispatch", 10, `Dispatching ${tasks.length} validation agents across ${mergedConfig.maxConcurrentAgents} parallel workers...`);
  
  // Run tasks in parallel
  const completedTasks = await runTasksInParallel(tasks, mergedConfig, onProgress);
  
  onProgress?.("aggregation", 80, "Aggregating findings...");
  
  // Aggregate findings from completed tasks
  const rawFindings: ValidatedFinding[] = [];
  const tasksByType: Record<VulnerabilityType, number> = {
    sqli: 0,
    xss: 0,
    auth_bypass: 0,
    command_injection: 0,
    path_traversal: 0,
    ssrf: 0,
  };
  
  for (const task of completedTasks) {
    for (const vulnType of task.vulnerabilityTypes) {
      tasksByType[vulnType]++;
    }
    
    if (task.status === "completed" && task.result?.vulnerable) {
      for (const vuln of task.result.vulnerabilities) {
        if (vuln.result.vulnerable && vuln.result.confidence >= mergedConfig.filterBelowConfidence) {
          rawFindings.push({
            id: `finding-${task.id}-${vuln.type}`,
            endpointUrl: task.endpoint.url,
            endpointPath: task.endpoint.path,
            parameter: task.parameter.name,
            vulnerabilityType: vuln.type,
            severity: determineSeverity(vuln.type, vuln.result.confidence),
            confidence: vuln.result.confidence,
            verdict: task.result.overallVerdict === "confirmed" ? "confirmed" :
                     task.result.overallVerdict === "likely" ? "likely" : "theoretical",
            evidence: task.result.evidence,
            recommendations: task.result.recommendations,
            reproductionSteps: generateReproductionSteps(task.endpoint, task.parameter.name, vuln.type, task.result),
            cvssEstimate: estimateCVSS(vuln.type, vuln.result.confidence),
            mitreAttackId: mapVulnTypeToMitre(vuln.type),
          });
        }
      }
    }
  }
  
  // LLM validation if enabled
  let finalFindings = rawFindings;
  let falsePositivesFiltered = 0;
  
  if (mergedConfig.enableLLMValidation && rawFindings.length > 0) {
    const validationResult = await validateFindingsWithLLM(rawFindings, onProgress);
    finalFindings = validationResult.validated;
    falsePositivesFiltered = validationResult.filtered;
  }
  
  onProgress?.("complete", 100, `Completed: ${finalFindings.length} validated findings from ${tasks.length} tasks`);
  
  return {
    totalTasks: tasks.length,
    completedTasks: completedTasks.filter(t => t.status === "completed").length,
    failedTasks: completedTasks.filter(t => t.status === "failed").length,
    findings: finalFindings,
    falsePositivesFiltered,
    executionTimeMs: Date.now() - startTime,
    tasksByVulnerabilityType: tasksByType,
  };
}

export function summarizeDispatchResult(result: AgentDispatchResult): string {
  const severityCounts = {
    critical: result.findings.filter(f => f.severity === "critical").length,
    high: result.findings.filter(f => f.severity === "high").length,
    medium: result.findings.filter(f => f.severity === "medium").length,
    low: result.findings.filter(f => f.severity === "low").length,
  };
  
  return `Parallel Agent Dispatch Summary:
Execution Time: ${(result.executionTimeMs / 1000).toFixed(1)}s

Tasks:
- Total: ${result.totalTasks}
- Completed: ${result.completedTasks}
- Failed: ${result.failedTasks}

Findings:
- Total: ${result.findings.length}
- Critical: ${severityCounts.critical}
- High: ${severityCounts.high}
- Medium: ${severityCounts.medium}
- Low: ${severityCounts.low}
- False Positives Filtered: ${result.falsePositivesFiltered}

Tasks by Vulnerability Type:
${Object.entries(result.tasksByVulnerabilityType)
  .filter(([_, count]) => count > 0)
  .map(([type, count]) => `- ${type.toUpperCase()}: ${count}`)
  .join("\n")}`;
}
