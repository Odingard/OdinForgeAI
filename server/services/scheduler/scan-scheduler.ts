import cron from "node-cron";
import { storage } from "../../storage";
import { queueService } from "../queue/queue-service";
import type { ScheduledScan } from "@shared/schema";

let schedulerTask: ReturnType<typeof cron.schedule> | null = null;
let threatIntelTask: ReturnType<typeof cron.schedule> | null = null;

function calculateNextRunAt(scan: ScheduledScan): Date {
  const now = new Date();
  let nextRun = new Date(now);

  const [hours, minutes] = (scan.timeOfDay || "00:00").split(":").map(Number);
  nextRun.setHours(hours, minutes, 0, 0);

  switch (scan.frequency) {
    case "once":
      return nextRun > now ? nextRun : new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

    case "daily":
      if (nextRun <= now) {
        nextRun.setDate(nextRun.getDate() + 1);
      }
      break;

    case "weekly":
      const targetDay = scan.dayOfWeek ?? 0;
      const currentDay = now.getDay();
      let daysUntilTarget = targetDay - currentDay;
      if (daysUntilTarget < 0 || (daysUntilTarget === 0 && nextRun <= now)) {
        daysUntilTarget += 7;
      }
      nextRun.setDate(now.getDate() + daysUntilTarget);
      break;

    case "monthly":
      const targetDayOfMonth = scan.dayOfMonth ?? 1;
      nextRun.setDate(targetDayOfMonth);
      if (nextRun <= now) {
        nextRun.setMonth(nextRun.getMonth() + 1);
      }
      break;

    case "quarterly":
      const currentQuarter = Math.floor(now.getMonth() / 3);
      const nextQuarterStart = new Date(now.getFullYear(), (currentQuarter + 1) * 3, scan.dayOfMonth ?? 1);
      nextQuarterStart.setHours(hours, minutes, 0, 0);
      if (nextQuarterStart <= now) {
        nextQuarterStart.setMonth(nextQuarterStart.getMonth() + 3);
      }
      nextRun = nextQuarterStart;
      break;

    default:
      nextRun.setDate(nextRun.getDate() + 1);
  }

  return nextRun;
}

async function processDueScans(): Promise<void> {
  try {
    const allScans = await storage.getScheduledScans();
    const now = new Date();

    const dueScans = allScans.filter((scan) => {
      if (!scan.enabled) return false;
      if (!scan.nextRunAt) {
        return false;
      }
      return new Date(scan.nextRunAt) <= now;
    });

    if (dueScans.length === 0) {
      return;
    }

    console.log(`[Scheduler] Found ${dueScans.length} due scheduled scan(s)`);

    for (const scan of dueScans) {
      try {
        console.log(`[Scheduler] Processing scheduled scan: ${scan.name} (${scan.id})`);

        const evaluationIds: string[] = [];

        for (const asset of scan.assets) {
          const evaluation = await storage.createEvaluation({
            assetId: asset.assetId,
            exposureType: asset.exposureType,
            priority: asset.priority,
            description: asset.description,
            organizationId: scan.organizationId,
          });

          evaluationIds.push(evaluation.id);

          const tenantId = (scan as any).tenantId || "default";
          await queueService.addJob(
            "evaluation",
            {
              type: "evaluation",
              evaluationId: evaluation.id,
              executionMode: "safe",
              assetId: asset.assetId,
              tenantId,
              organizationId: scan.organizationId,
              exposureData: {
                exposureType: asset.exposureType,
                priority: asset.priority,
                description: asset.description,
                scheduledScanId: scan.id,
              },
            },
            {
              priority: asset.priority === "critical" ? "critical" : asset.priority === "high" ? "high" : "normal",
            }
          );
        }

        const nextRunAt = calculateNextRunAt(scan);
        await storage.updateScheduledScan(scan.id, {
          lastRunAt: now,
          nextRunAt: nextRunAt,
        });

        console.log(`[Scheduler] Queued ${evaluationIds.length} evaluations for scan ${scan.id}`);
        console.log(`[Scheduler] Scheduled scan ${scan.id} next run: ${nextRunAt.toISOString()}`);

        if (scan.frequency === "once") {
          await storage.updateScheduledScan(scan.id, { enabled: false });
          console.log(`[Scheduler] Disabled one-time scan ${scan.id}`);
        }

      } catch (scanError) {
        console.error(`[Scheduler] Error processing scan ${scan.id}:`, scanError);
      }
    }

  } catch (error) {
    console.error("[Scheduler] Error checking for due scans:", error);
  }
}

async function syncDueThreatIntelFeeds(): Promise<void> {
  try {
    const { syncFeed } = await import("../threat-intel/index");
    // Check all orgs - get feeds that are enabled and due for sync
    const feeds = await storage.getThreatIntelFeeds("default");
    const now = new Date();

    for (const feed of feeds) {
      if (!feed.enabled) continue;
      const interval = (feed.checkInterval || 86400) * 1000;
      const lastChecked = feed.lastCheckedAt ? new Date(feed.lastCheckedAt).getTime() : 0;
      if (now.getTime() - lastChecked < interval) continue;

      try {
        console.log(`[ThreatIntel] Auto-syncing feed: ${feed.name}`);
        const result = await syncFeed(feed.id);
        console.log(`[ThreatIntel] Synced ${feed.name}: ${result.newIndicators} new, ${result.updatedIndicators} updated`);
      } catch (err) {
        console.error(`[ThreatIntel] Failed to sync feed ${feed.id}:`, err);
      }
    }
  } catch (error) {
    console.error("[ThreatIntel] Scheduler error:", error);
  }
}

export function initScheduler(): void {
  if (schedulerTask) {
    console.log("[Scheduler] Scheduler already running");
    return;
  }

  schedulerTask = cron.schedule("* * * * *", async () => {
    await processDueScans();
  });

  // Threat intel feed sync - check every hour, feeds control their own interval
  threatIntelTask = cron.schedule("0 * * * *", async () => {
    await syncDueThreatIntelFeeds();
  });

  console.log("[Scheduler] Scan scheduler initialized (checking every minute)");
  console.log("[Scheduler] Threat intel sync scheduled (checking every hour)");

  setTimeout(() => {
    processDueScans().catch((err) => {
      console.error("[Scheduler] Initial scan check failed:", err);
    });
  }, 5000);
}

export function stopScheduler(): void {
  if (schedulerTask) {
    schedulerTask.stop();
    schedulerTask = null;
  }
  if (threatIntelTask) {
    threatIntelTask.stop();
    threatIntelTask = null;
  }
  console.log("[Scheduler] All schedulers stopped");
}

export async function triggerImmediateScan(scanId: string): Promise<{ evaluationIds: string[] } | null> {
  const scan = await storage.getScheduledScan(scanId);
  if (!scan) {
    console.error(`[Scheduler] Scan ${scanId} not found`);
    return null;
  }

  console.log(`[Scheduler] Triggering immediate run for scan: ${scan.name}`);

  const evaluationIds: string[] = [];

  for (const asset of scan.assets) {
    const evaluation = await storage.createEvaluation({
      assetId: asset.assetId,
      exposureType: asset.exposureType,
      priority: asset.priority,
      description: asset.description,
      organizationId: scan.organizationId,
    });

    evaluationIds.push(evaluation.id);

    const tenantId = (scan as any).tenantId || "default";
    await queueService.addJob(
      "evaluation",
      {
        type: "evaluation",
        evaluationId: evaluation.id,
        executionMode: "safe",
        assetId: asset.assetId,
        tenantId,
        organizationId: scan.organizationId,
        exposureData: {
          exposureType: asset.exposureType,
          priority: asset.priority,
          description: asset.description,
          scheduledScanId: scan.id,
        },
      },
      {
        priority: asset.priority === "critical" ? "critical" : asset.priority === "high" ? "high" : "normal",
      }
    );
  }

  await storage.updateScheduledScan(scan.id, {
    lastRunAt: new Date(),
  });

  return { evaluationIds };
}
