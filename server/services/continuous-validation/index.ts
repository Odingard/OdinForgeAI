/**
 * Continuous Validation Service
 *
 * Handles:
 * - Marking assets as evaluated after evaluations complete
 * - Creating revalidation scans when findings are resolved
 * - Flagging assets for re-evaluation when telemetry shows changes
 * - Managing validation campaigns
 */

import { storage } from "../../storage";
import { randomUUID } from "crypto";

/**
 * Mark an asset as recently evaluated after an evaluation completes.
 */
export async function markAssetEvaluated(assetId: string): Promise<void> {
  try {
    await storage.updateAssetLastEvaluated(assetId, new Date());
  } catch (err) {
    console.error(`[ContinuousValidation] Failed to mark asset ${assetId} as evaluated:`, err);
  }
}

/**
 * When a finding is resolved, create a revalidation scan for the same asset/technique.
 */
export async function onFindingResolved(
  findingId: string,
  assetId: string,
  organizationId: string,
  mitreAttackId?: string
): Promise<string | null> {
  try {
    const scan = await storage.createScheduledScan({
      organizationId,
      name: `Revalidation: ${mitreAttackId || "Finding"} on ${assetId}`,
      description: `Auto-created revalidation after finding ${findingId} was resolved`,
      assets: [{
        assetId,
        exposureType: "vulnerability",
        priority: "high",
        description: `Revalidation of resolved finding ${findingId}`,
      }],
      frequency: "once",
      enabled: true,
      scanType: "revalidation",
      techniqueSet: mitreAttackId ? [mitreAttackId] : null,
      triggerCondition: "finding_resolved",
      sourceEvaluationId: findingId,
    });

    console.log(`[ContinuousValidation] Created revalidation scan ${scan.id} for resolved finding ${findingId}`);
    return scan.id;
  } catch (err) {
    console.error(`[ContinuousValidation] Failed to create revalidation scan:`, err);
    return null;
  }
}

/**
 * When agent telemetry shows a changed port/service, flag the asset for re-evaluation.
 */
export async function onAssetChange(
  assetId: string,
  organizationId: string,
  changeType: "new_port" | "new_service" | "config_change"
): Promise<string | null> {
  try {
    const scan = await storage.createScheduledScan({
      organizationId,
      name: `Change-triggered: ${changeType} on ${assetId}`,
      description: `Auto-created evaluation after ${changeType} detected on asset ${assetId}`,
      assets: [{
        assetId,
        exposureType: "change_detection",
        priority: "medium",
        description: `Triggered by ${changeType}`,
      }],
      frequency: "once",
      enabled: true,
      scanType: "revalidation",
      triggerCondition: "asset_changed",
    });

    console.log(`[ContinuousValidation] Created change-triggered scan ${scan.id} for asset ${assetId}`);
    return scan.id;
  } catch (err) {
    console.error(`[ContinuousValidation] Failed to create change-triggered scan:`, err);
    return null;
  }
}

/**
 * Create a validation campaign — a recurring set of scans targeting specific assets and techniques.
 */
export async function createValidationCampaign(params: {
  organizationId: string;
  name: string;
  description?: string;
  assetIds: string[];
  techniqueIds: string[];
  frequency: string; // daily, weekly, monthly
  timeOfDay?: string;
  dayOfWeek?: number;
}): Promise<string> {
  const scan = await storage.createScheduledScan({
    organizationId: params.organizationId,
    name: params.name,
    description: params.description || `Validation campaign: ${params.techniqueIds.length} techniques across ${params.assetIds.length} assets`,
    assets: params.assetIds.map(assetId => ({
      assetId,
      exposureType: "validation_campaign",
      priority: "high",
      description: `Campaign: ${params.name}`,
    })),
    frequency: params.frequency,
    timeOfDay: params.timeOfDay || "06:00",
    dayOfWeek: params.dayOfWeek,
    enabled: true,
    scanType: "validation_campaign",
    techniqueSet: params.techniqueIds,
    triggerCondition: "manual",
  });

  console.log(`[ContinuousValidation] Created campaign ${scan.id}: ${params.name}`);
  return scan.id;
}

/**
 * Get stale assets that haven't been evaluated within the threshold.
 */
export async function getStaleAssets(organizationId: string, thresholdDays = 30) {
  return storage.getStaleAssets(organizationId, thresholdDays);
}

/**
 * Get validation campaigns (scheduled scans with scanType = validation_campaign).
 */
export async function getValidationCampaigns(organizationId: string) {
  const scans = await storage.getScheduledScans(organizationId);
  return scans.filter(s => s.scanType === "validation_campaign");
}
