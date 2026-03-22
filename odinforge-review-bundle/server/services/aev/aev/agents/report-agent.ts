/**
 * OdinForge AEV — ReportAgent
 *
 * Subscribes to ALL events on the bus from chain start.
 * Writes the Engagement Package continuously as confirmed findings arrive.
 * By the time chain.complete fires, the package is ~80% written.
 * Seals and exports the full package on chain.complete.
 *
 * LLM: narrate confirmed findings only (CISO executive summary generation).
 * NEVER: generate findings, fill missing evidence, describe theoretical paths.
 *
 * Publishes:
 *   package.sealed — Engagement Package is complete and exported
 */

import type { AgentEvent, AgentEventBus } from "../agent-event-bus";
import type { RealHttpEvidence } from "../../../lib/real-evidence";

interface EngagementPackageState {
  chainId: string;
  findings: unknown[];
  cisoNarrative: string;
  engineerDetails: string;
  sigmaRules: unknown[];
  replayFrames: unknown[];
  evidenceContracts: RealHttpEvidence[];
  sealedAt?: string;
}

export class ReportAgent {
  private packageState: EngagementPackageState;
  private eventFrames: Array<{ event: AgentEvent; frameIndex: number }> = [];

  constructor(
    private bus: AgentEventBus,
    private chainId: string,
    private engagementId: string,
  ) {
    this.packageState = {
      chainId,
      findings: [],
      cisoNarrative: "",
      engineerDetails: "",
      sigmaRules: [],
      replayFrames: [],
      evidenceContracts: [],
    };

    bus.subscribe("*", this.onAnyEvent.bind(this));
  }

  private onAnyEvent(event: AgentEvent): void {
    if (event.chainId !== this.chainId) return;

    this.eventFrames.push({
      event,
      frameIndex: this.eventFrames.length,
    });

    switch (event.type) {
      case "breach.confirmed":
        this.writeBreachFinding(event);
        break;
      case "credential.extracted":
        this.writeCredentialExtraction(event);
        break;
      case "chain.complete":
        this.sealPackage();
        break;
    }
  }

  private writeBreachFinding(event: AgentEvent): void {
    const payload = event.payload as { phase: number; description: string };

    this.packageState.findings.push({
      phase: payload.phase,
      description: payload.description,
      evidence: event.evidence,
      timestamp: event.timestamp,
    });

    if (event.evidence) {
      this.packageState.evidenceContracts.push(...event.evidence);
    }

    const sigmaRule = this.generateSigmaRule(event);
    this.packageState.sigmaRules.push(sigmaRule);

    this.appendCISONarrative(payload.description, event.evidence ?? []);

    console.info(
      `[ReportAgent] Wrote Phase ${payload.phase} breach finding. Total: ${this.packageState.findings.length}`,
    );
  }

  private writeCredentialExtraction(event: AgentEvent): void {
    this.appendCISONarrative(
      `Credential extracted: ${(event.payload as { source: string }).source}`,
      event.evidence ?? [],
    );
  }

  private generateSigmaRule(event: AgentEvent): unknown {
    const payload = event.payload as { phase: number; description: string };
    const evidence = event.evidence?.[0];

    return {
      title: `OdinForge: ${payload.description}`,
      status: "experimental",
      description: `Sigma rule generated from confirmed Phase ${payload.phase} finding`,
      logsource: { category: "webserver", product: "odinforge" },
      detection: {
        selection: {
          "cs-uri-query|contains": evidence?.requestPayload ?? "",
          "sc-status": evidence?.statusCode ?? 200,
        },
        condition: "selection",
      },
      level: "high",
      tags: ["attack.initial_access"],
      odinforge: {
        findingPhase: payload.phase,
        evidenceTimestamp: evidence?.capturedAt,
        engagementId: this.engagementId,
      },
    };
  }

  private appendCISONarrative(description: string, evidence: RealHttpEvidence[]): void {
    this.packageState.cisoNarrative += `\n• ${description} [Evidence: HTTP ${evidence[0]?.statusCode ?? "N/A"}]`;
  }

  private sealPackage(): void {
    console.info(
      `[ReportAgent] Sealing Engagement Package — ${this.packageState.findings.length} findings`,
    );

    this.packageState.sealedAt = new Date().toISOString();
    this.packageState.replayFrames = this.eventFrames;

    this.bus.publish({
      type: "package.sealed",
      publishedBy: "report",
      chainId: this.chainId,
      payload: {
        engagementId: this.engagementId,
        findingCount: this.packageState.findings.length,
        sigmaRuleCount: this.packageState.sigmaRules.length,
        replayFrameCount: this.eventFrames.length,
        sealedAt: this.packageState.sealedAt,
      },
      evidence: null,
    });

    console.info(
      `[ReportAgent] Package sealed. Sigma rules: ${this.packageState.sigmaRules.length}. ` +
        `Replay frames: ${this.eventFrames.length}`,
    );
  }

  getPackageState(): Readonly<EngagementPackageState> {
    return { ...this.packageState };
  }
}
