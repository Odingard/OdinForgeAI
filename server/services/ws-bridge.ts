/**
 * WebSocket Bridge — enables real-time WebSocket event delivery from both
 * the app container (direct) and worker containers (via Redis Pub/Sub).
 *
 * App mode:  Subscribes to Redis pub/sub and forwards events to wsService.
 *            Also handles direct local broadcastToChannel calls.
 * Worker mode: Publishes events to Redis pub/sub for the app to relay.
 *
 * Falls back silently if Redis is unavailable (same best-effort pattern
 * as the original direct WebSocket calls in handlers).
 */

import Redis from "ioredis";

const PUBSUB_CHANNEL = "odinforge:ws-events";

type BridgeMode = "app" | "worker" | "standalone";

let bridgeMode: BridgeMode = "standalone";
let publisher: Redis | null = null;
let subscriber: Redis | null = null;
let initialized = false;

function createRedisClient(): Redis | null {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) return null;

  try {
    const client = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      connectTimeout: 5000,
      lazyConnect: true,
    });
    return client;
  } catch {
    return null;
  }
}

/**
 * Initialize the bridge. Call once at startup.
 * - "app" mode: subscribes to Redis pub/sub and relays to wsService
 * - "worker" mode: publishes to Redis pub/sub
 * - "standalone" mode: direct wsService calls only (no pub/sub)
 */
export async function initWsBridge(mode: BridgeMode): Promise<void> {
  if (initialized) return;
  bridgeMode = mode;

  if (mode === "app") {
    // App container: subscribe to Redis pub/sub for worker events
    subscriber = createRedisClient();
    if (subscriber) {
      try {
        await subscriber.connect();
        await subscriber.subscribe(PUBSUB_CHANNEL);
        subscriber.on("message", (_channel: string, message: string) => {
          try {
            const parsed = JSON.parse(message);
            const { wsService } = require("./websocket");
            if (!wsService) return;

            if (parsed.type === "broadcast") {
              wsService.broadcast(parsed.event);
            } else {
              wsService.broadcastToChannel(parsed.channel, parsed.event);
            }
          } catch {
            // Best-effort: silently ignore parse/delivery errors
          }
        });
        console.log("[WS-Bridge] App mode: subscribed to Redis pub/sub");
      } catch (err: any) {
        console.warn("[WS-Bridge] Redis subscribe failed:", err.message);
        subscriber = null;
      }
    }
    // Also create publisher for local app use (not strictly needed but keeps API consistent)
    publisher = createRedisClient();
    if (publisher) {
      try {
        await publisher.connect();
      } catch {
        publisher = null;
      }
    }
  } else if (mode === "worker") {
    // Worker container: publish events to Redis pub/sub
    publisher = createRedisClient();
    if (publisher) {
      try {
        await publisher.connect();
        console.log("[WS-Bridge] Worker mode: connected to Redis pub/sub");
      } catch (err: any) {
        console.warn("[WS-Bridge] Redis publish connect failed:", err.message);
        publisher = null;
      }
    }
  }

  initialized = true;
}

/**
 * Broadcast an event to a WebSocket channel.
 * - In app/standalone mode: calls wsService.broadcastToChannel() directly
 * - In worker mode: publishes via Redis pub/sub for the app to relay
 */
export function broadcastToChannel(channel: string, event: Record<string, any>): void {
  if (bridgeMode === "worker") {
    if (publisher) {
      publisher.publish(PUBSUB_CHANNEL, JSON.stringify({ type: "channel", channel, event })).catch(() => {});
    }
    return;
  }

  // App or standalone: deliver directly via wsService
  try {
    const { wsService } = require("./websocket");
    if (wsService) {
      wsService.broadcastToChannel(channel, event);
    }
  } catch {
    // wsService not available — silently ignore
  }
}

/**
 * Broadcast an event to ALL connected WebSocket clients (no channel filter).
 * - In app/standalone mode: calls wsService.broadcast() directly
 * - In worker mode: publishes via Redis pub/sub for the app to relay
 */
export function broadcast(event: Record<string, any>): void {
  if (bridgeMode === "worker") {
    if (publisher) {
      publisher.publish(PUBSUB_CHANNEL, JSON.stringify({ type: "broadcast", event })).catch(() => {});
    }
    return;
  }

  try {
    const { wsService } = require("./websocket");
    if (wsService) {
      wsService.broadcast(event);
    }
  } catch {
    // wsService not available — silently ignore
  }
}

/**
 * Graceful shutdown — close Redis connections.
 */
export async function shutdownWsBridge(): Promise<void> {
  if (subscriber) {
    await subscriber.unsubscribe(PUBSUB_CHANNEL).catch(() => {});
    await subscriber.quit().catch(() => {});
    subscriber = null;
  }
  if (publisher) {
    await publisher.quit().catch(() => {});
    publisher = null;
  }
  initialized = false;
}
