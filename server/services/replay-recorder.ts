/**
 * Breach Chain Replay Recorder
 *
 * Captures every event during an engagement for step-by-step playback.
 * Use cases: training exercises, tabletop simulations, board-level demos,
 * incident response preparation.
 *
 * The engagement phase progress markers already produced by the engine
 * are the natural spine of the replay system.
 */

import { randomUUID } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export type ReplayEventType =
  | "exploit_attempt" | "exploit_success" | "exploit_failure"
  | "credential_extracted" | "credential_inferred"
  | "cloud_iam_probe" | "cloud_iam_escalation"
  | "k8s_probe" | "k8s_breakout"
  | "pivot_attempt" | "pivot_success" | "pivot_failure"
  | "impact_finding"
  | "phase_start" | "phase_complete"
  | "defenders_mirror_rule" | "evidence_gate_verdict";

export interface ReplayEvent {
  id: string;
  sequenceIndex: number;
  timestamp: string;
  relativeTimestampMs: number;
  phase: number;
  phaseName: string;
  phaseProgress: number;
  eventType: ReplayEventType;
  techniqueName: string;
  techniqueCategory: string;
  mitreAttackId: string;
  target: string;
  outcome: "success" | "failure" | "partial" | "skipped";
  evidenceSummary: string;
  evidenceDetail?: Record<string, any>;
  defendersMirrorRef?: string;
  credentialsHarvested?: string[];
  hostsDiscovered?: string[];
  evidenceQuality?: string;
}

export interface ReplaySummary {
  totalTechniquesAttempted: number;
  totalTechniquesSucceeded: number;
  phasesCompleted: number[];
  credentialsHarvested: number;
  uniqueHostsReached: number;
  evidenceQualityBreakdown: {
    proven: number;
    corroborated: number;
    inferred: number;
    unverifiable: number;
  };
  timelineMs: number;
}

export interface EngagementReplayManifest {
  engagementId: string;
  targetScope: string;
  startedAt: string;
  completedAt: string;
  totalDurationMs: number;
  events: ReplayEvent[];
  summary: ReplaySummary;
}

export interface ReplayFilter {
  phase?: number;
  outcome?: "success" | "failure" | "partial" | "skipped";
  eventType?: ReplayEventType;
  techniqueCategory?: string;
  limit?: number;
  offset?: number;
}

// ─── Phase Number Mapping ─────────────────────────────────────────────────────

const PHASE_NAME_TO_NUMBER: Record<string, number> = {
  application_compromise: 1,
  credential_extraction: 2,
  cloud_iam_escalation: 3,
  container_k8s_breakout: 4,
  lateral_movement: 5,
  impact_assessment: 6,
};

// ─── Replay Recorder ─────────────────────────────────────────────────────────

export class ReplayRecorder {
  private events: ReplayEvent[] = [];
  private startedAt: number;
  private engagementId: string;

  constructor(engagementId: string) {
    this.engagementId = engagementId;
    this.startedAt = Date.now();
  }

  /**
   * Record a replay event. Auto-fills id, sequenceIndex, and timestamps.
   */
  record(event: Partial<ReplayEvent> & { eventType: ReplayEventType; target: string }): ReplayEvent {
    const fullEvent: ReplayEvent = {
      id: `re-${randomUUID().slice(0, 12)}`,
      sequenceIndex: this.events.length,
      timestamp: new Date().toISOString(),
      relativeTimestampMs: Date.now() - this.startedAt,
      phase: event.phase ?? 0,
      phaseName: event.phaseName ?? "unknown",
      phaseProgress: event.phaseProgress ?? 0,
      eventType: event.eventType,
      techniqueName: event.techniqueName ?? "",
      techniqueCategory: event.techniqueCategory ?? "",
      mitreAttackId: event.mitreAttackId ?? "",
      target: event.target,
      outcome: event.outcome ?? "partial",
      evidenceSummary: event.evidenceSummary ?? "",
      evidenceDetail: event.evidenceDetail,
      defendersMirrorRef: event.defendersMirrorRef,
      credentialsHarvested: event.credentialsHarvested,
      hostsDiscovered: event.hostsDiscovered,
      evidenceQuality: event.evidenceQuality,
    };

    this.events.push(fullEvent);
    return fullEvent;
  }

  // ── Convenience Methods ─────────────────────────────────────────────────

  recordPhaseStart(phaseName: string, target: string): ReplayEvent {
    return this.record({
      eventType: "phase_start",
      phase: PHASE_NAME_TO_NUMBER[phaseName] || 0,
      phaseName,
      target,
      outcome: "partial",
      evidenceSummary: `Phase started: ${phaseName}`,
    });
  }

  recordPhaseComplete(phaseName: string, target: string, findingCount: number): ReplayEvent {
    return this.record({
      eventType: "phase_complete",
      phase: PHASE_NAME_TO_NUMBER[phaseName] || 0,
      phaseName,
      target,
      outcome: findingCount > 0 ? "success" : "partial",
      evidenceSummary: `Phase complete: ${phaseName} — ${findingCount} findings`,
    });
  }

  recordExploitAttempt(params: {
    target: string;
    technique: string;
    category: string;
    mitreId: string;
    success: boolean;
    evidence: string;
    statusCode?: number;
    payload?: string;
    defendersMirrorRef?: string;
    evidenceQuality?: string;
  }): ReplayEvent {
    return this.record({
      eventType: params.success ? "exploit_success" : "exploit_attempt",
      phase: 1,
      phaseName: "application_compromise",
      target: params.target,
      techniqueName: params.technique,
      techniqueCategory: params.category,
      mitreAttackId: params.mitreId,
      outcome: params.success ? "success" : "failure",
      evidenceSummary: params.evidence,
      evidenceDetail: {
        statusCode: params.statusCode,
        payload: params.payload,
      },
      defendersMirrorRef: params.defendersMirrorRef,
      evidenceQuality: params.evidenceQuality,
    });
  }

  recordCredentialExtracted(params: {
    target: string;
    credentialType: string;
    credentialId: string;
    source: string;
    isInferred: boolean;
    evidenceQuality?: string;
  }): ReplayEvent {
    return this.record({
      eventType: params.isInferred ? "credential_inferred" : "credential_extracted",
      phase: 2,
      phaseName: "credential_extraction",
      target: params.target,
      techniqueName: `${params.credentialType} extraction`,
      techniqueCategory: "credential_extraction",
      mitreAttackId: "T1552",
      outcome: "success",
      evidenceSummary: `${params.credentialType} credential ${params.isInferred ? "inferred" : "extracted"} from ${params.source}`,
      credentialsHarvested: [params.credentialId],
      evidenceQuality: params.evidenceQuality,
    });
  }

  recordPivotAttempt(params: {
    target: string;
    technique: string;
    protocol: string;
    mitreId: string;
    success: boolean;
    accessLevel: string;
    credentialUsed?: string;
    hostsDiscovered?: string[];
    defendersMirrorRef?: string;
    evidenceQuality?: string;
  }): ReplayEvent {
    return this.record({
      eventType: params.success ? "pivot_success" : "pivot_failure",
      phase: 5,
      phaseName: "lateral_movement",
      target: params.target,
      techniqueName: params.technique,
      techniqueCategory: params.protocol,
      mitreAttackId: params.mitreId,
      outcome: params.success ? "success" : "failure",
      evidenceSummary: params.success
        ? `Pivot to ${params.target} via ${params.protocol} — ${params.accessLevel} access`
        : `Pivot to ${params.target} via ${params.protocol} failed`,
      hostsDiscovered: params.hostsDiscovered,
      defendersMirrorRef: params.defendersMirrorRef,
      evidenceQuality: params.evidenceQuality,
    });
  }

  recordImpactFinding(params: {
    target: string;
    title: string;
    severity: string;
    description: string;
    evidenceQuality?: string;
  }): ReplayEvent {
    return this.record({
      eventType: "impact_finding",
      phase: 6,
      phaseName: "impact_assessment",
      target: params.target,
      techniqueName: params.title,
      outcome: "success",
      evidenceSummary: params.description,
      evidenceDetail: { severity: params.severity },
      evidenceQuality: params.evidenceQuality,
    });
  }

  // ── Query Methods ───────────────────────────────────────────────────────

  /**
   * Get filtered events.
   */
  getEvents(filter?: ReplayFilter): ReplayEvent[] {
    let results = [...this.events];

    if (filter?.phase !== undefined) {
      results = results.filter(e => e.phase === filter.phase);
    }
    if (filter?.outcome) {
      results = results.filter(e => e.outcome === filter.outcome);
    }
    if (filter?.eventType) {
      results = results.filter(e => e.eventType === filter.eventType);
    }
    if (filter?.techniqueCategory) {
      results = results.filter(e => e.techniqueCategory === filter.techniqueCategory);
    }

    const offset = filter?.offset ?? 0;
    const limit = filter?.limit ?? results.length;
    return results.slice(offset, offset + limit);
  }

  /**
   * Get engagement state at a specific point in time (by sequence index).
   */
  getSnapshotAt(sequenceIndex: number): {
    events: ReplayEvent[];
    credentialCount: number;
    hostsReached: string[];
    phasesActive: number[];
  } {
    const events = this.events.filter(e => e.sequenceIndex <= sequenceIndex);
    const allCreds = new Set<string>();
    const allHosts = new Set<string>();
    const phases = new Set<number>();

    for (const e of events) {
      if (e.credentialsHarvested) {
        for (const c of e.credentialsHarvested) allCreds.add(c);
      }
      if (e.outcome === "success") allHosts.add(e.target);
      phases.add(e.phase);
    }

    return {
      events,
      credentialCount: allCreds.size,
      hostsReached: Array.from(allHosts),
      phasesActive: Array.from(phases).sort(),
    };
  }

  /**
   * Get total event count.
   */
  getEventCount(): number {
    return this.events.length;
  }

  // ── Finalize ────────────────────────────────────────────────────────────

  /**
   * Build the complete replay manifest with summary statistics.
   */
  finalize(): EngagementReplayManifest {
    const completedAt = new Date().toISOString();
    const totalDurationMs = Date.now() - this.startedAt;

    return {
      engagementId: this.engagementId,
      targetScope: this.events[0]?.target || "unknown",
      startedAt: new Date(this.startedAt).toISOString(),
      completedAt,
      totalDurationMs,
      events: this.events,
      summary: this.buildSummary(totalDurationMs),
    };
  }

  private buildSummary(timelineMs: number): ReplaySummary {
    const succeeded = this.events.filter(e => e.outcome === "success");
    const techniqueEvents = this.events.filter(e =>
      !["phase_start", "phase_complete", "defenders_mirror_rule", "evidence_gate_verdict"].includes(e.eventType)
    );

    // Unique credentials
    const allCreds = new Set<string>();
    for (const e of this.events) {
      if (e.credentialsHarvested) {
        for (const c of e.credentialsHarvested) allCreds.add(c);
      }
    }

    // Unique hosts reached (from successful events)
    const hostsReached = new Set(succeeded.map(e => e.target));

    // Phases completed
    const phasesCompleted = Array.from(
      new Set(
        this.events
          .filter(e => e.eventType === "phase_complete")
          .map(e => e.phase)
      )
    ).sort();

    // Evidence quality breakdown
    const qualityBreakdown = { proven: 0, corroborated: 0, inferred: 0, unverifiable: 0 };
    for (const e of this.events) {
      if (e.evidenceQuality === "proven") qualityBreakdown.proven++;
      else if (e.evidenceQuality === "corroborated") qualityBreakdown.corroborated++;
      else if (e.evidenceQuality === "inferred") qualityBreakdown.inferred++;
      else if (e.evidenceQuality === "unverifiable") qualityBreakdown.unverifiable++;
    }

    return {
      totalTechniquesAttempted: techniqueEvents.length,
      totalTechniquesSucceeded: succeeded.length,
      phasesCompleted,
      credentialsHarvested: allCreds.size,
      uniqueHostsReached: hostsReached.size,
      evidenceQualityBreakdown: qualityBreakdown,
      timelineMs,
    };
  }
}
