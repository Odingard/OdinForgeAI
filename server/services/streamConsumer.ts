// =============================================================================
// Task 03 — Redis Stream Consumer (OdinForge side)
//
// Reads MimirAssessmentComplete events from Redis Stream and enqueues
// mimir_triggered_evaluation BullMQ jobs via the existing queueService.
//
// Uses XREADGROUP for durable, exactly-once delivery with consumer groups.
//
// Start at server startup:
//   import { streamConsumer } from "./services/streamConsumer";
//   await streamConsumer.start();
//   process.on("SIGTERM", () => streamConsumer.stop());
// =============================================================================

import Redis from "ioredis";
import { randomUUID } from "crypto";
import { queueService } from "./queue/queue-service";
import type { MimirTriggeredEvaluationJobData } from "./queue/job-types";

// Stream config — must match stream_publisher.py
const STREAM_NAME = "sixsense:events:mimir_assessment_complete";
const CONSUMER_GROUP = "odinforge-consumers";
const CONSUMER_NAME = `odinforge-${process.env.POD_NAME ?? randomUUID().slice(0, 8)}`;
const BLOCK_MS = 5_000;
const BATCH_SIZE = 10;
const ACK_TIMEOUT_MS = 30_000;
const RECLAIM_INTERVAL = 60_000;


// =============================================================================
// EVENT SHAPE — mirrors MimirAssessmentCompleteEvent in stream_publisher.py
// =============================================================================

interface MimirFinding {
  finding_id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  risk_score: number | null;
  cve_id: string | null;
  is_kev_listed: boolean;
  entity_id: string | null;
}

interface MimirAssessmentCompleteEvent {
  event_version: string;
  event_id: string;
  published_at: string;
  assessment_id: string;
  organization_id: string;
  target_domain: string;
  entity_id: string;
  risk_grade: string;
  risk_score: number;
  kev_count: number;
  critical_count: number;
  high_count: number;
  total_findings: number;
  top_risk_findings: MimirFinding[];
  industry: string | null;
  company_name: string | null;
  mimir_assessment_id: string;
}


// =============================================================================
// STREAM CONSUMER
// =============================================================================

export class StreamConsumer {
  private redis: Redis | null = null;
  private redisUrl: string;
  private running: boolean = false;
  private reclaimTimer?: NodeJS.Timeout;

  constructor(redisUrl: string) {
    this.redisUrl = redisUrl;
  }

  async start(): Promise<void> {
    if (!this.redisUrl) {
      console.warn("[StreamConsumer] No REDIS_URL configured — stream consumer disabled");
      return;
    }

    try {
      this.redis = new Redis(this.redisUrl, {
        enableReadyCheck: true,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
      });

      await this.redis.connect();
      await this.ensureConsumerGroup();

      this.running = true;
      console.log(`[StreamConsumer] Started as consumer "${CONSUMER_NAME}" on stream "${STREAM_NAME}"`);

      this.reclaimTimer = setInterval(
        () => this.reclaimPendingMessages(),
        RECLAIM_INTERVAL,
      );

      // Main read loop — runs until stop() is called
      this.readLoop().catch(err => {
        console.error("[StreamConsumer] Read loop crashed:", err);
      });
    } catch (err) {
      console.warn("[StreamConsumer] Failed to start:", (err as Error).message);
      console.warn("[StreamConsumer] Cross-product stream consumer disabled");
    }
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.reclaimTimer) clearInterval(this.reclaimTimer);
    if (this.redis) {
      await this.redis.quit().catch(() => {});
      this.redis = null;
    }
    console.log("[StreamConsumer] Stopped");
  }

  private async ensureConsumerGroup(): Promise<void> {
    if (!this.redis) return;
    try {
      await this.redis.xgroup("CREATE", STREAM_NAME, CONSUMER_GROUP, "$", "MKSTREAM");
      console.log(`[StreamConsumer] Consumer group "${CONSUMER_GROUP}" created`);
    } catch (err: any) {
      if (err.message?.includes("BUSYGROUP")) {
        // Already exists — expected on restarts
      } else {
        throw err;
      }
    }
  }

  private async readLoop(): Promise<void> {
    while (this.running && this.redis) {
      try {
        const results = await this.redis.xreadgroup(
          "GROUP", CONSUMER_GROUP, CONSUMER_NAME,
          "COUNT", BATCH_SIZE,
          "BLOCK", BLOCK_MS,
          "STREAMS", STREAM_NAME, ">",
        ) as Array<[string, Array<[string, string[]]>]> | null;

        if (!results || results.length === 0) {
          continue;
        }

        const [, messages] = results[0];

        for (const [entryId, fields] of messages) {
          await this.processMessage(entryId, fields);
        }
      } catch (err: any) {
        if (!this.running) break;
        console.error("[StreamConsumer] Read error:", err.message);
        await sleep(2_000);
      }
    }
  }

  private async processMessage(entryId: string, fields: string[]): Promise<void> {
    const fieldMap = parseStreamFields(fields);
    const rawEvent = fieldMap["event"];

    if (!rawEvent) {
      console.warn(`[StreamConsumer] Message ${entryId} has no "event" field — acking and skipping`);
      await this.ack(entryId);
      return;
    }

    let event: MimirAssessmentCompleteEvent;
    try {
      event = JSON.parse(rawEvent);
    } catch {
      console.error(`[StreamConsumer] Failed to parse event in ${entryId}`);
      await this.ack(entryId);
      return;
    }

    console.log(
      `[StreamConsumer] Processing event ${event.event_id} — `
      + `domain=${event.target_domain} grade=${event.risk_grade}`,
    );

    try {
      await this.enqueueJob(entryId, event);
      await this.ack(entryId);
    } catch (err) {
      // Do NOT ack — message will be redelivered after ACK_TIMEOUT_MS
      console.error(
        `[StreamConsumer] Failed to enqueue job for ${entryId}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  private async enqueueJob(
    entryId: string,
    event: MimirAssessmentCompleteEvent,
  ): Promise<void> {
    const executionMode =
      event.risk_grade === "F" || (event.risk_grade === "D" && event.kev_count > 0)
        ? "aggressive"
        : "safe";

    const tenantId = event.organization_id;

    const jobData: MimirTriggeredEvaluationJobData = {
      type: "mimir_triggered_evaluation",
      tenantId,
      organizationId: event.organization_id,
      userId: undefined,
      correlationId: event.event_id,
      stream_event_id: entryId,
      mimir_event_id: event.event_id,
      mimir_assessment_id: event.mimir_assessment_id,
      target_domain: event.target_domain,
      entity_id: event.entity_id,
      risk_grade: event.risk_grade as "A" | "B" | "C" | "D" | "F",
      risk_score: event.risk_score,
      kev_count: event.kev_count,
      critical_count: event.critical_count,
      top_risk_findings: event.top_risk_findings,
      industry: event.industry,
      company_name: event.company_name,
      execution_mode: executionMode,
    };

    await queueService.addJob("mimir_triggered_evaluation", jobData, {
      jobId: `mimir-triggered-${event.event_id}`,
    });

    console.log(
      `[StreamConsumer] Enqueued mimir_triggered_evaluation for `
      + `${event.target_domain} (mode=${executionMode})`,
    );
  }

  private async ack(entryId: string): Promise<void> {
    if (!this.redis) return;
    await this.redis.xack(STREAM_NAME, CONSUMER_GROUP, entryId);
  }

  private async reclaimPendingMessages(): Promise<void> {
    if (!this.redis) return;
    try {
      const result = await this.redis.xautoclaim(
        STREAM_NAME,
        CONSUMER_GROUP,
        CONSUMER_NAME,
        ACK_TIMEOUT_MS,
        "0-0",
        "COUNT", 10,
      ) as [string, Array<[string, string[]]>, string[]];

      const [, messages] = result;
      if (messages.length > 0) {
        console.log(`[StreamConsumer] Reclaimed ${messages.length} pending message(s)`);
        for (const [entryId, fields] of messages) {
          await this.processMessage(entryId, fields);
        }
      }
    } catch (err: any) {
      if (!err.message?.includes("unknown command")) {
        console.warn("[StreamConsumer] Reclaim error:", err.message);
      }
    }
  }
}


// =============================================================================
// HELPERS
// =============================================================================

function parseStreamFields(fields: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (let i = 0; i < fields.length; i += 2) {
    map[fields[i]] = fields[i + 1];
  }
  return map;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}


// =============================================================================
// SINGLETON — import in server startup to start the consumer
// =============================================================================
export const streamConsumer = new StreamConsumer(
  process.env.REDIS_URL ?? "",
);
