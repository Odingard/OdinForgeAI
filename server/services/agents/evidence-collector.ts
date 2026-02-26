import type {
  EvidenceArtifact,
  EvidencePacket,
  AttackPathStep,
  BusinessLogicFinding,
  MultiVectorFinding,
} from "@shared/schema";

export interface EvidenceContext {
  evaluationId: string;
  assetId: string;
  exposureType: string;
  attackPath?: AttackPathStep[];
  businessLogicFindings?: BusinessLogicFinding[];
  multiVectorFindings?: MultiVectorFinding[];
}

export class EvidenceCollector {
  private artifacts: EvidenceArtifact[] = [];
  private timeline: Array<{ timestamp: string; event: string; artifactId?: string }> = [];

  constructor(private context: EvidenceContext) {}

  captureRequestResponse(
    title: string,
    description: string,
    request: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: string;
    },
    response: {
      statusCode: number;
      headers?: Record<string, string>;
      body?: string;
      timing?: number;
    },
    attackStepId?: number
  ): EvidenceArtifact {
    const artifact: EvidenceArtifact = {
      id: `artifact-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: "request_response",
      timestamp: new Date().toISOString(),
      title,
      description,
      data: {
        request: this.sanitizeRequest(request),
        response: this.sanitizeResponse(response),
      },
      attackStepId,
      isSanitized: true,
    };

    this.artifacts.push(artifact);
    this.addTimelineEvent(`Captured request/response: ${title}`, artifact.id);
    return artifact;
  }

  captureExecutionTrace(
    title: string,
    description: string,
    steps: Array<{
      step: number;
      action: string;
      result: string;
      duration?: number;
    }>,
    attackStepId?: number
  ): EvidenceArtifact {
    const artifact: EvidenceArtifact = {
      id: `artifact-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: "execution_trace",
      timestamp: new Date().toISOString(),
      title,
      description,
      data: {
        trace: steps,
      },
      attackStepId,
      isSanitized: true,
    };

    this.artifacts.push(artifact);
    this.addTimelineEvent(`Captured execution trace: ${title}`, artifact.id);
    return artifact;
  }

  captureLogEntries(
    title: string,
    description: string,
    logs: Array<{
      timestamp: string;
      level: "debug" | "info" | "warn" | "error";
      message: string;
      source?: string;
    }>,
    findingId?: string
  ): EvidenceArtifact {
    const artifact: EvidenceArtifact = {
      id: `artifact-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: "log_capture",
      timestamp: new Date().toISOString(),
      title,
      description,
      data: {
        logs: logs.map((log) => ({
          ...log,
          message: this.sanitizeLogMessage(log.message),
        })),
      },
      findingId,
      isSanitized: true,
    };

    this.artifacts.push(artifact);
    this.addTimelineEvent(`Captured logs: ${title}`, artifact.id);
    return artifact;
  }

  captureTimelineEvent(
    event: string,
    details?: string
  ): void {
    const artifact: EvidenceArtifact = {
      id: `artifact-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: "timeline_event",
      timestamp: new Date().toISOString(),
      title: event,
      description: details || event,
      data: {},
      isSanitized: true,
    };

    this.artifacts.push(artifact);
    this.addTimelineEvent(event, artifact.id);
  }

  private addTimelineEvent(event: string, artifactId?: string): void {
    this.timeline.push({
      timestamp: new Date().toISOString(),
      event,
      artifactId,
    });
  }

  private sanitizeRequest(request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  }): typeof request {
    const sanitized = { ...request };
    
    if (sanitized.headers) {
      const sensitiveHeaders = ["authorization", "cookie", "x-api-key", "x-auth-token"];
      sanitized.headers = { ...sanitized.headers };
      for (const header of sensitiveHeaders) {
        if (sanitized.headers[header]) {
          sanitized.headers[header] = "[REDACTED]";
        }
      }
    }

    if (sanitized.body) {
      sanitized.body = this.sanitizeBody(sanitized.body);
    }

    return sanitized;
  }

  private sanitizeResponse(response: {
    statusCode: number;
    headers?: Record<string, string>;
    body?: string;
    timing?: number;
  }): typeof response {
    const sanitized = { ...response };
    
    if (sanitized.headers) {
      const sensitiveHeaders = ["set-cookie", "x-amz-security-token"];
      sanitized.headers = { ...sanitized.headers };
      for (const header of sensitiveHeaders) {
        if (sanitized.headers[header]) {
          sanitized.headers[header] = "[REDACTED]";
        }
      }
    }

    if (sanitized.body) {
      sanitized.body = this.sanitizeBody(sanitized.body);
    }

    return sanitized;
  }

  private sanitizeBody(body: string): string {
    const sensitivePatterns = [
      /password['":\s]*['"]?[^'"}\s,]+/gi,
      /api[_-]?key['":\s]*['"]?[^'"}\s,]+/gi,
      /secret['":\s]*['"]?[^'"}\s,]+/gi,
      /token['":\s]*['"]?[^'"}\s,]+/gi,
      /\b[A-Za-z0-9+/]{40,}\b/g,
    ];

    let sanitized = body;
    for (const pattern of sensitivePatterns) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
    return sanitized;
  }

  private sanitizeLogMessage(message: string): string {
    return this.sanitizeBody(message);
  }

  /**
   * Convert tool call log entries from the exploit agent into evidence artifacts.
   */
  captureFromToolCallLog(
    toolCallLog: Array<{
      turn: number;
      toolName: string;
      arguments: Record<string, unknown>;
      resultSummary: string;
      vulnerable: boolean;
      confidence: number;
      executionTimeMs: number;
    }>
  ): EvidenceArtifact[] {
    const captured: EvidenceArtifact[] = [];
    for (const tc of toolCallLog) {
      const artifact: EvidenceArtifact = {
        id: `artifact-tc-${tc.turn}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        type: "request_response",
        timestamp: new Date().toISOString(),
        title: `Tool Call: ${tc.toolName} (turn ${tc.turn})`,
        description: tc.resultSummary,
        data: {
          request: this.sanitizeRequest({
            method: "TOOL_CALL",
            url: String(tc.arguments.url || tc.arguments.target || ""),
            body: JSON.stringify(tc.arguments),
          }),
          response: {
            statusCode: tc.vulnerable ? 200 : 0,
            body: `[${tc.toolName}] ${tc.vulnerable ? "VULNERABLE" : "clean"} (confidence: ${tc.confidence}%) — ${tc.resultSummary}`,
            timing: tc.executionTimeMs,
          },
        },
        isSanitized: true,
      };
      this.artifacts.push(artifact);
      captured.push(artifact);
      this.addTimelineEvent(`Tool ${tc.toolName}: ${tc.vulnerable ? "VULNERABLE" : "clean"} (${tc.confidence}%)`, artifact.id);
    }
    return captured;
  }

  getArtifacts(): EvidenceArtifact[] {
    return this.artifacts;
  }

  generatePacket(): EvidencePacket {
    const criticalFindings = [
      ...(this.context.attackPath?.filter((s) => s.severity === "critical") || []),
      ...(this.context.businessLogicFindings?.filter((f) => f.severity === "critical") || []),
      ...(this.context.multiVectorFindings?.filter((f) => f.severity === "critical") || []),
    ].length;

    return {
      id: `packet-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      evaluationId: this.context.evaluationId,
      createdAt: new Date().toISOString(),
      title: `Evidence Packet: ${this.context.assetId}`,
      summary: this.generateSummary(),
      artifacts: this.artifacts,
      timeline: this.timeline,
      executiveSummary: this.generateExecutiveSummary(),
      replayInstructions: this.generateReplayInstructions(),
      metadata: {
        evaluationType: this.context.exposureType,
        assetId: this.context.assetId,
        totalArtifacts: this.artifacts.length,
        criticalFindings,
      },
    };
  }

  private generateSummary(): string {
    const artifactCounts = this.artifacts.reduce(
      (acc, a) => {
        acc[a.type] = (acc[a.type] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const parts = Object.entries(artifactCounts)
      .map(([type, count]) => `${count} ${type.replace("_", " ")}(s)`)
      .join(", ");

    return `Evidence collection for ${this.context.assetId} (${this.context.exposureType}): ${parts || "No artifacts captured"}`;
  }

  private generateExecutiveSummary(): string {
    const attackSteps = this.context.attackPath?.length || 0;
    const businessFindings = this.context.businessLogicFindings?.length || 0;
    const multiVectorFindings = this.context.multiVectorFindings?.length || 0;

    return `Security validation completed for asset ${this.context.assetId}. ` +
      `Analysis identified ${attackSteps} attack path steps, ` +
      `${businessFindings} business logic findings, and ` +
      `${multiVectorFindings} multi-vector findings. ` +
      `${this.artifacts.length} evidence artifacts were captured to support these findings.`;
  }

  private generateReplayInstructions(): string {
    const requestArtifacts = this.artifacts.filter((a) => a.type === "request_response");
    
    if (requestArtifacts.length === 0) {
      return "No replay instructions available - execution traces can be reviewed in the timeline.";
    }

    return `To replay the attack path:\n` +
      requestArtifacts
        .map((a, i) => `${i + 1}. ${a.title}: Review the captured request/response pair`)
        .join("\n") +
      `\n\nNote: All sensitive data has been sanitized. Actual credentials and tokens were redacted for security.`;
  }
}

export function generateEvidenceFromAnalysis(
  context: EvidenceContext,
  aiAnalysisSteps?: Array<{ action: string; observation: string; duration?: number }>,
  toolCallLog?: Array<{
    turn: number;
    toolName: string;
    arguments: Record<string, unknown>;
    resultSummary: string;
    vulnerable: boolean;
    confidence: number;
    executionTimeMs: number;
  }>
): EvidenceArtifact[] {
  const collector = new EvidenceCollector(context);

  collector.captureTimelineEvent("Evaluation started", `Beginning analysis of ${context.assetId}`);

  // Capture tool call evidence from the exploit agent
  if (toolCallLog && toolCallLog.length > 0) {
    collector.captureFromToolCallLog(toolCallLog);
  }

  if (aiAnalysisSteps) {
    collector.captureExecutionTrace(
      "AI Analysis Execution",
      "Step-by-step AI reasoning and observations",
      aiAnalysisSteps.map((step, i) => ({
        step: i + 1,
        action: step.action,
        result: step.observation,
        duration: step.duration,
      }))
    );
  }

  if (context.attackPath) {
    for (const step of context.attackPath) {
      collector.captureTimelineEvent(
        `Attack Step ${step.id}: ${step.title}`,
        step.description
      );

      if (step.technique) {
        collector.captureExecutionTrace(
          `Technique: ${step.technique}`,
          step.description,
          [
            {
              step: 1,
              action: `Execute ${step.technique}`,
              result: `Severity: ${step.severity}`,
            },
          ],
          step.id
        );
      }
    }
  }

  if (context.businessLogicFindings) {
    for (const finding of context.businessLogicFindings) {
      collector.captureExecutionTrace(
        `Business Logic: ${finding.title}`,
        finding.description,
        finding.exploitSteps.map((step, i) => ({
          step: i + 1,
          action: step,
          result: i === finding.exploitSteps.length - 1 ? finding.impact : "Step completed",
        })),
        undefined
      );

      if (finding.proofOfConcept) {
        collector.captureLogEntries(
          `Proof of Concept: ${finding.title}`,
          "Captured proof of concept evidence",
          [
            {
              timestamp: new Date().toISOString(),
              level: "info",
              message: finding.proofOfConcept,
              source: "business-logic-engine",
            },
          ],
          finding.id
        );
      }
    }
  }

  collector.captureTimelineEvent("Evaluation completed", "All analysis steps finished");

  return collector.getArtifacts();
}
