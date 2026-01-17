import { Queue, Worker, Job, QueueEvents } from "bullmq";
import { getBullMQConnection, testRedisConnection, markRedisUnavailable, type BullMQConnectionOptions } from "./redis-connection";
import { 
  JobType, 
  JobStatus, 
  JobPriority, 
  jobPriorities,
  AnyJobData,
  JobResult,
  JobProgress,
} from "./job-types";
import { randomUUID } from "crypto";
import { EventEmitter } from "events";

const QUEUE_NAME = "odinforge-jobs";

interface QueuedJob {
  id: string;
  type: JobType;
  data: AnyJobData;
  priority: JobPriority;
  status: JobStatus;
  progress: number;
  progressStage?: string;
  result?: JobResult;
  error?: string;
  attempts: number;
  maxAttempts: number;
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  tenantId: string;
  organizationId: string;
}

export type JobHandler = (job: Job<AnyJobData>) => Promise<JobResult>;

class QueueService extends EventEmitter {
  private queue: Queue<AnyJobData> | null = null;
  private sharedWorker: Worker<AnyJobData, JobResult> | null = null;
  private queueEvents: QueueEvents | null = null;
  private handlers: Map<JobType, JobHandler> = new Map();
  private inMemoryJobs: Map<string, QueuedJob> = new Map();
  private useRedis: boolean = false;
  private redisConnectionOptions: BullMQConnectionOptions | null = null;

  async initialize(): Promise<void> {
    try {
      const connOptions = getBullMQConnection();
      if (!connOptions) {
        console.warn("[Queue] Redis not configured, using in-memory queue fallback");
        this.useRedis = false;
        return;
      }
      
      const connectionWorks = await testRedisConnection();
      if (!connectionWorks) {
        console.warn("[Queue] Redis connection test failed, using in-memory queue fallback");
        this.useRedis = false;
        return;
      }
      
      this.redisConnectionOptions = connOptions;
      this.useRedis = true;
      
      this.queue = new Queue<AnyJobData>(QUEUE_NAME, {
        connection: connOptions,
        defaultJobOptions: {
          attempts: 3,
          backoff: {
            type: "exponential",
            delay: 1000,
          },
          removeOnComplete: {
            age: 3600 * 24,
            count: 1000,
          },
          removeOnFail: {
            age: 3600 * 24 * 7,
          },
        },
      });

      this.queueEvents = new QueueEvents(QUEUE_NAME, {
        connection: connOptions,
      });

      this.setupQueueEvents();
      console.log("[Queue] Initialized with Redis backend");
    } catch (error: any) {
      console.warn("[Queue] Redis initialization error:", error.message);
      console.warn("[Queue] Using in-memory queue fallback");
      markRedisUnavailable();
      this.useRedis = false;
    }
  }

  private setupQueueEvents(): void {
    if (!this.queueEvents) return;

    this.queueEvents.on("completed", ({ jobId, returnvalue }) => {
      this.emit("job:completed", { jobId, result: returnvalue });
    });

    this.queueEvents.on("failed", ({ jobId, failedReason }) => {
      this.emit("job:failed", { jobId, error: failedReason });
    });

    this.queueEvents.on("progress", ({ jobId, data }) => {
      this.emit("job:progress", { jobId, progress: data });
    });

    this.queueEvents.on("stalled", ({ jobId }) => {
      this.emit("job:stalled", { jobId });
    });
  }

  registerHandler(jobType: JobType, handler: JobHandler): void {
    this.handlers.set(jobType, handler);
  }

  // Start the shared worker after all handlers are registered
  startWorker(): void {
    if (!this.useRedis || !this.queue || !this.redisConnectionOptions || this.sharedWorker) {
      return;
    }

    this.sharedWorker = new Worker<AnyJobData, JobResult>(
      QUEUE_NAME,
      async (job) => {
        // Use job.name (the type passed to queue.add) to route to the correct handler
        const jobType = job.name as JobType;
        const handler = this.handlers.get(jobType);
        
        if (!handler) {
          throw new Error(`No handler registered for job type: ${jobType}`);
        }
        
        return handler(job);
      },
      {
        connection: this.redisConnectionOptions,
        concurrency: 5,
      }
    );

    this.sharedWorker.on("completed", (job, result) => {
      console.log(`Job ${job.id} (${job.name}) completed:`, result.success ? "success" : "failed");
    });

    this.sharedWorker.on("failed", (job, error) => {
      console.error(`Job ${job?.id} (${job?.name}) failed:`, error.message);
    });

    this.sharedWorker.on("progress", (job, progress) => {
      console.log(`Job ${job.id} progress:`, progress);
    });

    console.log("[Queue] Shared worker started");
  }

  async addJob(
    type: JobType,
    data: AnyJobData,
    options?: {
      priority?: JobPriority;
      delay?: number;
      jobId?: string;
    }
  ): Promise<string> {
    const jobId = options?.jobId || `${type}-${randomUUID().slice(0, 8)}`;
    const priority = options?.priority || "normal";

    if (this.useRedis && this.queue) {
      const job = await this.queue.add(type, data, {
        jobId,
        priority: jobPriorities[priority],
        delay: options?.delay,
      });
      return job.id!;
    }

    const queuedJob: QueuedJob = {
      id: jobId,
      type,
      data,
      priority,
      status: "pending",
      progress: 0,
      attempts: 0,
      maxAttempts: 3,
      createdAt: new Date(),
      tenantId: data.tenantId,
      organizationId: data.organizationId,
    };

    this.inMemoryJobs.set(jobId, queuedJob);
    this.processInMemoryJob(jobId);

    return jobId;
  }

  private async processInMemoryJob(jobId: string): Promise<void> {
    const queuedJob = this.inMemoryJobs.get(jobId);
    if (!queuedJob) return;

    const handler = this.handlers.get(queuedJob.type);
    if (!handler) {
      queuedJob.status = "failed";
      queuedJob.error = `No handler registered for job type: ${queuedJob.type}`;
      return;
    }

    queuedJob.status = "processing";
    queuedJob.startedAt = new Date();
    queuedJob.attempts++;

    try {
      const mockJob = {
        id: jobId,
        data: queuedJob.data,
        progress: (value: number) => {
          queuedJob.progress = typeof value === "number" ? value : 0;
        },
        updateProgress: async (progress: JobProgress | number) => {
          if (typeof progress === "number") {
            queuedJob.progress = progress;
          } else {
            queuedJob.progress = progress.percent;
            queuedJob.progressStage = progress.stage;
          }
          this.emit("job:progress", { jobId, progress });
        },
        attemptsMade: queuedJob.attempts,
        opts: { attempts: queuedJob.maxAttempts },
      } as unknown as Job<AnyJobData>;

      const result = await handler(mockJob);
      
      queuedJob.status = result.success ? "completed" : "failed";
      queuedJob.result = result;
      queuedJob.completedAt = new Date();
      queuedJob.progress = 100;

      this.emit("job:completed", { jobId, result });
    } catch (error: any) {
      if (queuedJob.attempts < queuedJob.maxAttempts) {
        queuedJob.status = "retrying";
        setTimeout(() => this.processInMemoryJob(jobId), 1000 * queuedJob.attempts);
      } else {
        queuedJob.status = "failed";
        queuedJob.error = error.message;
        queuedJob.completedAt = new Date();
        this.emit("job:failed", { jobId, error: error.message });
      }
    }
  }

  async getJob(jobId: string): Promise<QueuedJob | null> {
    if (this.useRedis && this.queue) {
      const job = await this.queue.getJob(jobId);
      if (!job) return null;

      const state = await job.getState();
      return {
        id: job.id!,
        type: job.data.type as JobType,
        data: job.data,
        priority: "normal",
        status: this.mapBullMQState(state),
        progress: typeof job.progress === "number" ? job.progress : 0,
        attempts: job.attemptsMade,
        maxAttempts: job.opts.attempts || 3,
        createdAt: new Date(job.timestamp),
        startedAt: job.processedOn ? new Date(job.processedOn) : undefined,
        completedAt: job.finishedOn ? new Date(job.finishedOn) : undefined,
        tenantId: job.data.tenantId,
        organizationId: job.data.organizationId,
      };
    }

    return this.inMemoryJobs.get(jobId) || null;
  }

  private mapBullMQState(state: string): JobStatus {
    const stateMap: Record<string, JobStatus> = {
      waiting: "queued",
      active: "processing",
      completed: "completed",
      failed: "failed",
      delayed: "pending",
      prioritized: "queued",
    };
    return stateMap[state] || "pending";
  }

  async getJobsByTenant(tenantId: string, options?: {
    status?: JobStatus;
    type?: JobType;
    limit?: number;
    offset?: number;
  }): Promise<QueuedJob[]> {
    const jobs: QueuedJob[] = [];

    if (this.useRedis && this.queue) {
      const allJobs = await this.queue.getJobs(
        ["waiting", "active", "completed", "failed", "delayed"],
        0,
        options?.limit || 100
      );

      for (const job of allJobs) {
        if (job.data.tenantId === tenantId) {
          const state = await job.getState();
          const mappedStatus = this.mapBullMQState(state);
          
          if (options?.status && mappedStatus !== options.status) continue;
          if (options?.type && job.data.type !== options.type) continue;

          jobs.push({
            id: job.id!,
            type: job.data.type as JobType,
            data: job.data,
            priority: "normal",
            status: mappedStatus,
            progress: typeof job.progress === "number" ? job.progress : 0,
            attempts: job.attemptsMade,
            maxAttempts: job.opts.attempts || 3,
            createdAt: new Date(job.timestamp),
            startedAt: job.processedOn ? new Date(job.processedOn) : undefined,
            completedAt: job.finishedOn ? new Date(job.finishedOn) : undefined,
            tenantId: job.data.tenantId,
            organizationId: job.data.organizationId,
          });
        }
      }
    } else {
      const allInMemoryJobs = Array.from(this.inMemoryJobs.values());
      for (const job of allInMemoryJobs) {
        if (job.tenantId !== tenantId) continue;
        if (options?.status && job.status !== options.status) continue;
        if (options?.type && job.type !== options.type) continue;
        jobs.push(job);
      }
    }

    return jobs.slice(options?.offset || 0, (options?.offset || 0) + (options?.limit || 100));
  }

  async cancelJob(jobId: string): Promise<boolean> {
    if (this.useRedis && this.queue) {
      const job = await this.queue.getJob(jobId);
      if (job) {
        await job.remove();
        return true;
      }
      return false;
    }

    const job = this.inMemoryJobs.get(jobId);
    if (job && job.status !== "completed" && job.status !== "failed") {
      job.status = "cancelled";
      job.completedAt = new Date();
      return true;
    }
    return false;
  }

  async retryJob(jobId: string): Promise<boolean> {
    if (this.useRedis && this.queue) {
      const job = await this.queue.getJob(jobId);
      if (job) {
        await job.retry();
        return true;
      }
      return false;
    }

    const job = this.inMemoryJobs.get(jobId);
    if (job && job.status === "failed") {
      job.status = "pending";
      job.attempts = 0;
      this.processInMemoryJob(jobId);
      return true;
    }
    return false;
  }

  async getQueueStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    if (this.useRedis && this.queue) {
      return {
        waiting: await this.queue.getWaitingCount(),
        active: await this.queue.getActiveCount(),
        completed: await this.queue.getCompletedCount(),
        failed: await this.queue.getFailedCount(),
        delayed: await this.queue.getDelayedCount(),
      };
    }

    let waiting = 0, active = 0, completed = 0, failed = 0, delayed = 0;
    const allStatsJobs = Array.from(this.inMemoryJobs.values());
    for (const job of allStatsJobs) {
      switch (job.status) {
        case "pending":
        case "queued":
          waiting++;
          break;
        case "processing":
          active++;
          break;
        case "completed":
          completed++;
          break;
        case "failed":
          failed++;
          break;
      }
    }

    return { waiting, active, completed, failed, delayed };
  }

  async shutdown(): Promise<void> {
    if (this.sharedWorker) {
      await this.sharedWorker.close();
      this.sharedWorker = null;
    }

    if (this.queueEvents) {
      await this.queueEvents.close();
    }

    if (this.queue) {
      await this.queue.close();
    }
  }

  isUsingRedis(): boolean {
    return this.useRedis;
  }
}

export const queueService = new QueueService();
