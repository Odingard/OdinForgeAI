/**
 * OdinForge v3.0 — Continuous Exposure Engine
 *
 * Drives always-on breach chain re-validation:
 *   - Scheduled re-runs (daily / weekly / monthly)
 *   - Risk snapshot append after each completed run
 *   - SLA deadline tracking + breach detection
 *   - Alert event generation (in-app, Slack webhook)
 */

import { randomUUID } from "crypto";
import { storage } from "../../storage";
import { db } from "../../db";
import { breachChainAlerts, breachChains } from "@shared/schema";
import type { BreachChain, BreachChainAlert } from "@shared/schema";
import { eq, and, isNull, lte } from "drizzle-orm";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RiskSnapshot {
  score: number;
  nodeCount: number;
  criticalPathLength: number;
  completedAt: string;
  runId?: string;
}

export interface ExposureSummary {
  organizationId: string;
  totalChains: number;
  activeChains: number;
  scheduledChains: number;
  slaBreached: number;
  slaDue: number; // due within 7 days
  avgRiskScore: number;
  riskTrend: "improving" | "worsening" | "stable";
  criticalChains: BreachChain[];
  overdueSlaChains: BreachChain[];
  recentAlerts: BreachChainAlert[];
  exposureByDay: Array<{ date: string; avgScore: number; chainCount: number }>;
}

// ---------------------------------------------------------------------------
// Risk Snapshot — appended after every completed chain run
// ---------------------------------------------------------------------------

export async function appendRiskSnapshot(
  chainId: string,
  snapshot: RiskSnapshot,
): Promise<void> {
  try {
    const chain = await storage.getBreachChain(chainId);
    if (!chain) return;

    const history = Array.isArray(chain.riskHistory) ? chain.riskHistory : [];

    // Keep last 90 snapshots
    const updated = [...history, snapshot].slice(-90);

    await storage.updateBreachChain(chainId, {
      riskHistory: updated,
      updatedAt: new Date(),
    } as any);

    // Fire alert if risk worsened by 10+ points vs previous run
    if (history.length > 0) {
      const prev = history[history.length - 1];
      const delta = snapshot.score - prev.score;
      if (delta >= 10) {
        await createAlert(chain, "risk_worsened", {
          title: `Risk score increased on "${chain.name}"`,
          message: `Breach chain risk score worsened from ${prev.score} → ${snapshot.score} (+${delta} points). ${snapshot.nodeCount} attack nodes active.`,
          previousScore: prev.score,
          currentScore: snapshot.score,
          deltaScore: delta,
          severity: delta >= 20 ? "critical" : "high",
        });
      } else if (delta <= -10) {
        await createAlert(chain, "risk_improved", {
          title: `Risk reduced on "${chain.name}"`,
          message: `Breach chain risk improved from ${prev.score} → ${snapshot.score} (${delta} points). Remediation progress detected.`,
          previousScore: prev.score,
          currentScore: snapshot.score,
          deltaScore: delta,
          severity: "low",
        });
      }
    } else if (snapshot.score >= 70) {
      // First run and already high risk — alert
      await createAlert(chain, "new_breach_path", {
        title: `Critical breach path discovered in "${chain.name}"`,
        message: `Initial breach chain analysis found a critical attack path with risk score ${snapshot.score}. ${snapshot.nodeCount} attack nodes, critical path depth ${snapshot.criticalPathLength}.`,
        previousScore: undefined,
        currentScore: snapshot.score,
        deltaScore: undefined,
        severity: snapshot.score >= 85 ? "critical" : "high",
      });
    }
  } catch (err) {
    console.error("[ContinuousExposure] appendRiskSnapshot failed:", err);
  }
}

// ---------------------------------------------------------------------------
// SLA Tracking
// ---------------------------------------------------------------------------

/**
 * Set initial SLA deadline when a chain first identifies a critical path.
 * Called after the first run that produces a risk score.
 */
export async function initializeSla(
  chainId: string,
  riskScore: number,
): Promise<void> {
  const chain = await storage.getBreachChain(chainId);
  if (!chain || chain.slaDeadline) return; // already set

  // SLA window based on risk score
  const slaDays = riskScore >= 85 ? 7 : riskScore >= 70 ? 14 : riskScore >= 50 ? 30 : 60;
  const deadline = new Date();
  deadline.setDate(deadline.getDate() + slaDays);

  await storage.updateBreachChain(chainId, {
    slaDeadline: deadline,
    remediationDueAt: deadline,
    slaDays,
  } as any);
}

/**
 * Check all chains in an org for SLA breaches. Call this daily.
 */
export async function checkSlaBreaches(organizationId: string): Promise<number> {
  const chains = await storage.getBreachChains(organizationId);
  const now = new Date();
  let breachCount = 0;

  for (const chain of chains) {
    if (!chain.slaDeadline || chain.slaBreachedAt) continue;
    if (chain.status === "completed" && (chain.overallRiskScore ?? 0) === 0) continue;

    const deadline = new Date(chain.slaDeadline);
    if (deadline <= now) {
      // Mark as SLA breached
      await storage.updateBreachChain(chain.id, {
        slaBreachedAt: now,
      } as any);

      await createAlert(chain, "sla_breach", {
        title: `SLA breached: "${chain.name}" overdue for remediation`,
        message: `Breach chain "${chain.name}" exceeded its ${chain.slaDays ?? 30}-day remediation SLA. Current risk score: ${chain.overallRiskScore ?? "unknown"}. Immediate action required.`,
        previousScore: chain.overallRiskScore ?? undefined,
        currentScore: chain.overallRiskScore ?? undefined,
        deltaScore: 0,
        severity: "critical",
      });

      breachCount++;
    }
  }

  return breachCount;
}

// ---------------------------------------------------------------------------
// Schedule Management
// ---------------------------------------------------------------------------

export interface ChainScheduleConfig {
  enabled: boolean;
  frequency: "daily" | "weekly" | "monthly" | "manual";
  timeOfDay?: string;
  dayOfWeek?: number;
}

export function computeNextRunAt(config: ChainScheduleConfig): Date {
  const now = new Date();
  const [hours, minutes] = (config.timeOfDay || "02:00").split(":").map(Number);
  const next = new Date(now);
  next.setHours(hours, minutes, 0, 0);

  switch (config.frequency) {
    case "daily":
      if (next <= now) next.setDate(next.getDate() + 1);
      break;
    case "weekly": {
      const target = config.dayOfWeek ?? 1; // Monday default
      let days = target - now.getDay();
      if (days < 0 || (days === 0 && next <= now)) days += 7;
      next.setDate(now.getDate() + days);
      break;
    }
    case "monthly":
      next.setDate(1);
      if (next <= now) next.setMonth(next.getMonth() + 1);
      break;
    case "manual":
      return new Date(9999, 0, 1); // far future
  }

  return next;
}

/**
 * Return all chains with schedules due for re-run.
 */
export async function getDueChains(organizationId?: string): Promise<BreachChain[]> {
  const chains = await storage.getBreachChains(organizationId);
  const now = new Date();

  return chains.filter((chain) => {
    const sc = chain.scheduleConfig as any;
    if (!sc?.enabled) return false;
    if (!sc.nextRunAt) return false;
    return new Date(sc.nextRunAt) <= now;
  });
}

/**
 * Update the schedule config on a chain after a run completes.
 */
export async function advanceSchedule(chain: BreachChain): Promise<void> {
  const sc = chain.scheduleConfig as any;
  if (!sc?.enabled) return;

  const nextRunAt = computeNextRunAt(sc);
  await storage.updateBreachChain(chain.id, {
    scheduleConfig: {
      ...sc,
      lastRunAt: new Date().toISOString(),
      nextRunAt: nextRunAt.toISOString(),
    },
  } as any);
}

// ---------------------------------------------------------------------------
// Exposure Summary — aggregate view across all chains
// ---------------------------------------------------------------------------

export async function buildExposureSummary(
  organizationId: string,
): Promise<ExposureSummary> {
  const [chains, alerts] = await Promise.all([
    storage.getBreachChains(organizationId),
    storage.getBreachChainAlerts(organizationId),
  ]);

  const now = new Date();
  const sevenDaysOut = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const activeChains = chains.filter((c) => c.status === "completed" && (c.overallRiskScore ?? 0) > 0);
  const scheduledChains = chains.filter((c) => (c.scheduleConfig as any)?.enabled);
  const slaBreached = chains.filter((c) => !!c.slaBreachedAt);
  const slaDue = chains.filter((c) => {
    if (!c.slaDeadline || c.slaBreachedAt) return false;
    const dl = new Date(c.slaDeadline);
    return dl > now && dl <= sevenDaysOut;
  });

  const scores = activeChains.map((c) => c.overallRiskScore ?? 0).filter((s) => s > 0);
  const avgRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

  // Trend: compare last 2 snapshots across all chains
  let trendDelta = 0;
  let trendSamples = 0;
  for (const chain of activeChains) {
    const hist = Array.isArray(chain.riskHistory) ? chain.riskHistory : [];
    if (hist.length >= 2) {
      trendDelta += hist[hist.length - 1].score - hist[hist.length - 2].score;
      trendSamples++;
    }
  }
  const riskTrend: ExposureSummary["riskTrend"] =
    trendSamples === 0 ? "stable"
    : trendDelta / trendSamples > 3 ? "worsening"
    : trendDelta / trendSamples < -3 ? "improving"
    : "stable";

  // Exposure by day — aggregate historical snapshots from all chains
  const dayMap = new Map<string, { totalScore: number; count: number }>();
  for (const chain of activeChains) {
    const hist = Array.isArray(chain.riskHistory) ? chain.riskHistory : [];
    for (const snap of hist) {
      const day = snap.completedAt.slice(0, 10); // YYYY-MM-DD
      const existing = dayMap.get(day) ?? { totalScore: 0, count: 0 };
      dayMap.set(day, { totalScore: existing.totalScore + snap.score, count: existing.count + 1 });
    }
  }
  const exposureByDay = Array.from(dayMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-30) // last 30 days
    .map(([date, { totalScore, count }]) => ({
      date,
      avgScore: Math.round(totalScore / count),
      chainCount: count,
    }));

  return {
    organizationId,
    totalChains: chains.length,
    activeChains: activeChains.length,
    scheduledChains: scheduledChains.length,
    slaBreached: slaBreached.length,
    slaDue: slaDue.length,
    avgRiskScore,
    riskTrend,
    criticalChains: activeChains.filter((c) => (c.overallRiskScore ?? 0) >= 70).slice(0, 5),
    overdueSlaChains: slaBreached.slice(0, 5),
    recentAlerts: alerts.slice(0, 10),
    exposureByDay,
  };
}

// ---------------------------------------------------------------------------
// Alert Creation
// ---------------------------------------------------------------------------

async function createAlert(
  chain: BreachChain,
  alertType: string,
  opts: {
    title: string;
    message: string;
    previousScore?: number;
    currentScore?: number;
    deltaScore?: number;
    severity: string;
  },
): Promise<void> {
  try {
    await storage.createBreachChainAlert({
      id: randomUUID(),
      organizationId: chain.organizationId,
      chainId: chain.id,
      chainName: chain.name,
      alertType,
      severity: opts.severity,
      title: opts.title,
      message: opts.message,
      previousScore: opts.previousScore ?? null,
      currentScore: opts.currentScore ?? null,
      deltaScore: opts.deltaScore ?? null,
      delivered: false,
      dismissed: false,
    });

    // If Slack webhook is configured, fire it
    const slackUrl = process.env.SLACK_ALERT_WEBHOOK;
    if (slackUrl && opts.severity !== "low") {
      const emoji = opts.severity === "critical" ? "🔴" : opts.severity === "high" ? "🟠" : "🟡";
      await fetch(slackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: `${emoji} *OdinForge Alert* — ${opts.title}`,
          attachments: [{
            color: opts.severity === "critical" ? "danger" : "warning",
            text: opts.message,
            footer: `OdinForge AEV • ${new Date().toUTCString()}`,
          }],
        }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => { /* non-blocking */ });
    }
  } catch (err) {
    console.error("[ContinuousExposure] createAlert failed:", err);
  }
}
