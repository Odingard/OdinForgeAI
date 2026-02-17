/**
 * Worker Entry Point — runs BullMQ job handlers in a separate process.
 *
 * This is the entry point for the worker container. It initializes only
 * what's needed for job processing: database, RLS, queue, handlers,
 * and the ws-bridge (in worker mode, publishing via Redis pub/sub).
 *
 * It does NOT start Express, HTTP server, WebSocket, static files,
 * Vite, scheduler, or data reconciliation.
 */

import { queueService } from "./services/queue";
import { registerJobHandlers } from "./services/queue/handlers";
import { initializeRLS } from "./services/rls-setup";
import { initWsBridge, shutdownWsBridge } from "./services/ws-bridge";

async function startWorker() {
  console.log("[Worker] Starting OdinForge worker process...");

  // Initialize Row-Level Security (handlers use withTenantContext)
  try {
    await initializeRLS();
    console.log("[Worker] RLS initialized");
  } catch (error) {
    console.warn("[Worker] RLS initialization skipped:", error instanceof Error ? error.message : error);
  }

  // Initialize WebSocket bridge in worker mode (publish via Redis pub/sub)
  try {
    await initWsBridge("worker");
  } catch (error) {
    console.warn("[Worker] WS bridge initialization skipped:", error instanceof Error ? error.message : error);
  }

  // Initialize job queue and register handlers
  try {
    await queueService.initialize();
    registerJobHandlers();
    console.log(`[Worker] Queue initialized (Redis: ${queueService.isUsingRedis()})`);
    console.log("[Worker] Ready — waiting for jobs...");
  } catch (error) {
    console.error("[Worker] Queue initialization failed:", error instanceof Error ? error.message : error);
    process.exit(1);
  }

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`[Worker] Received ${signal}, shutting down gracefully...`);
    try {
      await queueService.shutdown();
      await shutdownWsBridge();
    } catch (error) {
      console.error("[Worker] Error during shutdown:", error);
    }
    process.exit(0);
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

startWorker().catch((error) => {
  console.error("[Worker] Fatal error:", error);
  process.exit(1);
});
