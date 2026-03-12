/**
 * OdinForge Prometheus Metrics
 *
 * Exposes engagement performance metrics via /metrics endpoint.
 * Integrates with Prometheus + Grafana for production monitoring.
 */

import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from "prom-client";

export const metricsRegistry = new Registry();

// Collect default Node.js metrics (event loop, memory, GC)
collectDefaultMetrics({ register: metricsRegistry });

// ── Engagement Metrics ──────────────────────────────────────────────────────

export const engagementDuration = new Histogram({
  name: "odinforge_engagement_duration_seconds",
  help: "Total breach chain engagement duration in seconds",
  buckets: [60, 120, 300, 600, 900, 1800, 3600],
  registers: [metricsRegistry],
});

export const phaseDuration = new Histogram({
  name: "odinforge_phase_duration_seconds",
  help: "Per-phase execution duration in seconds",
  labelNames: ["phase"],
  buckets: [10, 30, 60, 120, 300, 600],
  registers: [metricsRegistry],
});

export const phaseSuccess = new Counter({
  name: "odinforge_phase_success_total",
  help: "Count of successful phase completions",
  labelNames: ["phase"],
  registers: [metricsRegistry],
});

export const phaseFailure = new Counter({
  name: "odinforge_phase_failure_total",
  help: "Count of phase failures or timeouts",
  labelNames: ["phase"],
  registers: [metricsRegistry],
});

export const credentialsHarvested = new Counter({
  name: "odinforge_credentials_harvested_total",
  help: "Total credentials extracted across all engagements",
  registers: [metricsRegistry],
});

export const findingsByQuality = new Counter({
  name: "odinforge_findings_by_quality_total",
  help: "Findings classified by evidence quality level",
  labelNames: ["quality"],
  registers: [metricsRegistry],
});

export const detectionRulesGenerated = new Counter({
  name: "odinforge_detection_rules_generated_total",
  help: "Total Defender's Mirror detection rule sets generated",
  registers: [metricsRegistry],
});

export const pivotDepthMax = new Gauge({
  name: "odinforge_pivot_depth_max",
  help: "Maximum lateral movement depth achieved in most recent engagement",
  registers: [metricsRegistry],
});

export const evidenceQualityRatio = new Gauge({
  name: "odinforge_evidence_quality_ratio",
  help: "Ratio of PROVEN findings to total findings (0-1)",
  registers: [metricsRegistry],
});

export const activeEngagements = new Gauge({
  name: "odinforge_active_engagements",
  help: "Number of currently running breach chain engagements",
  registers: [metricsRegistry],
});

// ── Convenience functions for the orchestrator ──────────────────────────────

export function recordEngagementComplete(durationMs: number) {
  engagementDuration.observe(durationMs / 1000);
  activeEngagements.dec();
}

export function recordEngagementStart() {
  activeEngagements.inc();
}

export function recordPhaseComplete(phase: string, durationMs: number, success: boolean) {
  phaseDuration.observe({ phase }, durationMs / 1000);
  if (success) {
    phaseSuccess.inc({ phase });
  } else {
    phaseFailure.inc({ phase });
  }
}

export function recordCredentialHarvested(count: number = 1) {
  credentialsHarvested.inc(count);
}

export function recordFindingQuality(quality: string) {
  findingsByQuality.inc({ quality });
}

export function recordDetectionRules(count: number = 1) {
  detectionRulesGenerated.inc(count);
}
