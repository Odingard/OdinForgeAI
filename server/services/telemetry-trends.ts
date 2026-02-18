/**
 * Telemetry Trends — Time-series aggregation for agent metrics
 *
 * Provides time-bucketed resource metrics (CPU, memory, disk) and
 * security finding counts over configurable time ranges.
 */

import { db } from "../db";
import { agentTelemetry, aevResults, aevEvaluations } from "@shared/schema";
import { eq, and, gte, lte, desc } from "drizzle-orm";

export interface TelemetryDataPoint {
  timestamp: string;
  cpuUsage: number | null;
  memoryPercent: number | null;
  diskPercent: number | null;
  serviceCount: number;
  openPortCount: number;
  findingCount: number;
}

export interface TelemetryTrendResult {
  agentId: string;
  dataPoints: TelemetryDataPoint[];
  timeRange: { from: string; to: string };
  totalDataPoints: number;
}

export interface AssetSecurityTrendPoint {
  timestamp: string;
  score: number | null;
  exploitable: boolean;
  findingCount: number;
}

export async function getAgentTelemetryTrends(
  agentId: string,
  organizationId: string,
  from: Date,
  to: Date,
  maxPoints: number = 50
): Promise<TelemetryTrendResult> {
  const records = await db
    .select()
    .from(agentTelemetry)
    .where(and(
      eq(agentTelemetry.agentId, agentId),
      eq(agentTelemetry.organizationId, organizationId),
      gte(agentTelemetry.collectedAt, from),
      lte(agentTelemetry.collectedAt, to)
    ))
    .orderBy(agentTelemetry.collectedAt)
    .limit(maxPoints * 3); // Fetch more for bucketing

  // Bucket by dividing the time range
  const rangeMs = to.getTime() - from.getTime();
  const bucketMs = Math.max(rangeMs / maxPoints, 60_000); // Min 1 minute buckets
  const buckets = new Map<number, typeof records>();

  for (const record of records) {
    const t = new Date(record.collectedAt).getTime();
    const bucketKey = Math.floor((t - from.getTime()) / bucketMs);
    if (!buckets.has(bucketKey)) buckets.set(bucketKey, []);
    buckets.get(bucketKey)!.push(record);
  }

  const dataPoints: TelemetryDataPoint[] = [];

  for (const [bucketKey, bucketRecords] of Array.from(buckets.entries()).sort((a, b) => a[0] - b[0])) {
    const timestamp = new Date(from.getTime() + bucketKey * bucketMs).toISOString();

    // Average metrics across bucket
    let cpuSum = 0, cpuCount = 0;
    let memSum = 0, memCount = 0;
    let diskSum = 0, diskCount = 0;
    let serviceSum = 0, portSum = 0, findingSum = 0;

    for (const r of bucketRecords) {
      const metrics = r.resourceMetrics as any;
      if (metrics?.cpuUsage != null) { cpuSum += metrics.cpuUsage; cpuCount++; }
      if (metrics?.memoryPercent != null) { memSum += metrics.memoryPercent; memCount++; }
      if (metrics?.diskPercent != null) { diskSum += metrics.diskPercent; diskCount++; }
      serviceSum += (r.services as any[])?.length || 0;
      portSum += (r.openPorts as any[])?.length || 0;
      findingSum += (r.securityFindings as any[])?.length || 0;
    }

    const n = bucketRecords.length;
    dataPoints.push({
      timestamp,
      cpuUsage: cpuCount > 0 ? cpuSum / cpuCount : null,
      memoryPercent: memCount > 0 ? memSum / memCount : null,
      diskPercent: diskCount > 0 ? diskSum / diskCount : null,
      serviceCount: Math.round(serviceSum / n),
      openPortCount: Math.round(portSum / n),
      findingCount: Math.round(findingSum / n),
    });
  }

  return {
    agentId,
    dataPoints,
    timeRange: { from: from.toISOString(), to: to.toISOString() },
    totalDataPoints: records.length,
  };
}

export async function getOrganizationTelemetryTrends(
  organizationId: string,
  from: Date,
  to: Date
): Promise<{
  agentCount: number;
  avgCpu: number | null;
  avgMemory: number | null;
  avgDisk: number | null;
  totalFindings: number;
  totalServices: number;
}> {
  // Get the most recent telemetry for each agent in the org
  const recentTelemetry = await db
    .select()
    .from(agentTelemetry)
    .where(and(
      eq(agentTelemetry.organizationId, organizationId),
      gte(agentTelemetry.collectedAt, from),
      lte(agentTelemetry.collectedAt, to)
    ))
    .orderBy(desc(agentTelemetry.collectedAt))
    .limit(500);

  // Deduplicate by agentId (keep latest)
  const byAgent = new Map<string, typeof recentTelemetry[0]>();
  for (const record of recentTelemetry) {
    if (!byAgent.has(record.agentId)) {
      byAgent.set(record.agentId, record);
    }
  }

  const agents = Array.from(byAgent.values());
  if (agents.length === 0) {
    return { agentCount: 0, avgCpu: null, avgMemory: null, avgDisk: null, totalFindings: 0, totalServices: 0 };
  }

  let cpuSum = 0, cpuCount = 0;
  let memSum = 0, memCount = 0;
  let diskSum = 0, diskCount = 0;
  let totalFindings = 0, totalServices = 0;

  for (const a of agents) {
    const metrics = a.resourceMetrics as any;
    if (metrics?.cpuUsage != null) { cpuSum += metrics.cpuUsage; cpuCount++; }
    if (metrics?.memoryPercent != null) { memSum += metrics.memoryPercent; memCount++; }
    if (metrics?.diskPercent != null) { diskSum += metrics.diskPercent; diskCount++; }
    totalFindings += (a.securityFindings as any[])?.length || 0;
    totalServices += (a.services as any[])?.length || 0;
  }

  return {
    agentCount: agents.length,
    avgCpu: cpuCount > 0 ? cpuSum / cpuCount : null,
    avgMemory: memCount > 0 ? memSum / memCount : null,
    avgDisk: diskCount > 0 ? diskSum / diskCount : null,
    totalFindings,
    totalServices,
  };
}

export async function getAssetSecurityTrend(
  assetId: string,
  organizationId: string,
  from: Date,
  to: Date,
  maxPoints: number = 30
): Promise<AssetSecurityTrendPoint[]> {
  // aevResults doesn't have assetId/organizationId — join through aevEvaluations
  const results = await db
    .select({
      completedAt: aevResults.completedAt,
      score: aevResults.score,
      exploitable: aevResults.exploitable,
      attackPath: aevResults.attackPath,
      businessLogicFindings: aevResults.businessLogicFindings,
      multiVectorFindings: aevResults.multiVectorFindings,
    })
    .from(aevResults)
    .innerJoin(aevEvaluations, eq(aevResults.evaluationId, aevEvaluations.id))
    .where(and(
      eq(aevEvaluations.assetId, assetId),
      eq(aevEvaluations.organizationId, organizationId),
      gte(aevResults.completedAt, from),
      lte(aevResults.completedAt, to)
    ))
    .orderBy(aevResults.completedAt)
    .limit(maxPoints);

  return results.map(r => ({
    timestamp: r.completedAt?.toISOString() || new Date().toISOString(),
    score: r.score,
    exploitable: r.exploitable || false,
    findingCount: ((r.attackPath as any[])?.length || 0) +
      ((r.businessLogicFindings as any[])?.length || 0) +
      ((r.multiVectorFindings as any[])?.length || 0),
  }));
}
