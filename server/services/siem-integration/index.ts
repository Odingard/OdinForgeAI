/**
 * SIEM Integration Orchestrator
 *
 * After an evaluation completes, queries connected SIEMs for matching alerts
 * and records whether each attack technique was detected or missed.
 */

import { storage } from "../../storage";
import type { SiemProviderAdapter, SiemConnectionConfig } from "./types";
import { ElasticAdapter } from "./elastic-adapter";
import { SplunkAdapter } from "./splunk-adapter";
import { SentinelAdapter } from "./sentinel-adapter";
import { randomUUID } from "crypto";

function createAdapter(config: SiemConnectionConfig): SiemProviderAdapter {
  switch (config.provider) {
    case "elastic":
      return new ElasticAdapter(config);
    case "splunk":
      return new SplunkAdapter(config);
    case "sentinel":
      return new SentinelAdapter(config);
    default:
      throw new Error(`Unsupported SIEM provider: ${config.provider}`);
  }
}

/**
 * Test a SIEM connection's credentials and connectivity.
 */
export async function testSiemConnection(connectionId: string): Promise<{ success: boolean; message: string }> {
  const conn = await storage.getSiemConnection(connectionId);
  if (!conn) throw new Error(`SIEM connection not found: ${connectionId}`);

  const adapter = createAdapter(conn as SiemConnectionConfig);
  const result = await adapter.testConnection();

  await storage.updateSiemConnection(connectionId, {
    status: result.success ? "connected" : "error",
    lastError: result.success ? null : result.message,
    lastSyncAt: result.success ? new Date() : undefined,
  });

  return result;
}

/**
 * Run post-evaluation defensive validation.
 *
 * For each SIEM connection in the org, queries for alerts that match
 * the attack techniques used in the evaluation, then records detection results.
 */
export async function runPostEvaluationValidation(
  evaluationId: string,
  organizationId: string,
  attackTechniques: Array<{
    mitreAttackId: string;
    mitreTactic: string;
    startedAt?: Date;
    completedAt?: Date;
  }>,
  targetHost?: string
): Promise<{ validationsCreated: number }> {
  const connections = await storage.getSiemConnections(organizationId);
  const activeConnections = connections.filter(c => c.syncEnabled && c.status === "connected");

  if (activeConnections.length === 0 || attackTechniques.length === 0) {
    return { validationsCreated: 0 };
  }

  let validationsCreated = 0;

  for (const conn of activeConnections) {
    const adapter = createAdapter(conn as SiemConnectionConfig);
    const queryWindow = (conn.alertQueryWindow || 300) * 1000; // convert to ms

    for (const technique of attackTechniques) {
      const validationId = `dv-${randomUUID().slice(0, 8)}`;
      const attackStart = technique.startedAt || new Date();
      const attackEnd = technique.completedAt || new Date();
      const queryEnd = new Date(attackEnd.getTime() + queryWindow);

      // Create pending validation record
      await storage.createDefensiveValidation({
        id: validationId,
        organizationId,
        evaluationId,
        siemConnectionId: conn.id,
        attackStartedAt: attackStart,
        attackCompletedAt: attackEnd,
        mitreAttackId: technique.mitreAttackId,
        mitreTactic: technique.mitreTactic,
        status: "querying",
      });

      try {
        const result = await adapter.queryAlerts({
          from: attackStart,
          to: queryEnd,
          mitreAttackId: technique.mitreAttackId,
          mitreTactic: technique.mitreTactic,
          targetHost,
          limit: 50,
        });

        const detected = result.alerts.length > 0;
        const firstAlert = detected ? result.alerts[0] : null;
        const mttdSeconds = detected && firstAlert?.timestamp
          ? Math.round((new Date(firstAlert.timestamp).getTime() - attackStart.getTime()) / 1000)
          : null;

        await storage.updateDefensiveValidation(validationId, {
          detected,
          status: detected ? "detected" : "missed",
          alertCount: result.alerts.length,
          alertIds: result.alerts.map(a => a.id),
          alertDetails: result.alerts.slice(0, 10).map(a => ({
            id: a.id,
            timestamp: a.timestamp,
            ruleName: a.ruleName,
            severity: a.severity,
          })),
          firstAlertAt: firstAlert?.timestamp ? new Date(firstAlert.timestamp) : null,
          mttdSeconds: mttdSeconds !== null && mttdSeconds >= 0 ? mttdSeconds : null,
        });
      } catch (err: any) {
        console.error(`[SIEM] Query failed for ${conn.name}/${technique.mitreAttackId}:`, err.message);
        await storage.updateDefensiveValidation(validationId, {
          status: "error",
          errorMessage: err.message,
        });
      }

      validationsCreated++;
    }
  }

  return { validationsCreated };
}

/**
 * Get detection summary for an evaluation.
 */
export async function getDetectionSummary(evaluationId: string): Promise<{
  total: number;
  detected: number;
  missed: number;
  pending: number;
  detectionRate: number;
  avgMttdSeconds: number | null;
}> {
  const validations = await storage.getDefensiveValidationsByEvaluation(evaluationId);

  const detected = validations.filter(v => v.status === "detected").length;
  const missed = validations.filter(v => v.status === "missed").length;
  const pending = validations.filter(v => v.status === "pending" || v.status === "querying").length;
  const total = validations.length;

  const mttdValues = validations
    .filter(v => v.mttdSeconds !== null && v.mttdSeconds !== undefined)
    .map(v => v.mttdSeconds!);

  const avgMttd = mttdValues.length > 0
    ? Math.round(mttdValues.reduce((a, b) => a + b, 0) / mttdValues.length)
    : null;

  return {
    total,
    detected,
    missed,
    pending,
    detectionRate: total > 0 ? Math.round((detected / (detected + missed)) * 100) : 0,
    avgMttdSeconds: avgMttd,
  };
}
