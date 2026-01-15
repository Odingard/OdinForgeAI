import Redis from "ioredis";

let redisConnection: Redis | null = null;
let connectionFailed = false;
let reconnectAttempts = 0;

const REDIS_CONFIG = {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT || "5000", 10),
  commandTimeout: parseInt(process.env.REDIS_COMMAND_TIMEOUT || "5000", 10),
  lazyConnect: true,
  keepAlive: 10000,
  family: 4,
  maxRetriesOnStartup: parseInt(process.env.REDIS_MAX_RETRIES || "3", 10),
};

export function getRedisConnection(): Redis {
  if (connectionFailed) {
    throw new Error("Redis connection previously failed");
  }
  
  if (!redisConnection) {
    let redisUrl = process.env.REDIS_URL || "redis://localhost:6379";
    const maxRetries = REDIS_CONFIG.maxRetriesOnStartup;
    
    // Validate URL format - Upstash REST API URLs (https://) won't work with ioredis
    if (redisUrl.startsWith("https://")) {
      console.error("[Redis] Invalid REDIS_URL: REST API URL (https://) provided. Need Redis protocol URL (rediss://)");
      console.error("[Redis] Go to Upstash dashboard → your database → 'Connect to your database' → look for rediss:// URL");
      connectionFailed = true;
      throw new Error("Invalid REDIS_URL: Use rediss:// protocol URL, not https:// REST API URL");
    }
    
    // Log connection attempt (without exposing full credentials)
    const urlParts = new URL(redisUrl);
    console.log(`[Redis] Connecting to ${urlParts.hostname}:${urlParts.port} (TLS: ${redisUrl.startsWith("rediss://")})`);
    
    redisConnection = new Redis(redisUrl, {
      ...REDIS_CONFIG,
      // Upstash requires TLS - ioredis handles this automatically with rediss:// URLs
      tls: redisUrl.startsWith("rediss://") ? {} : undefined,
      retryStrategy(times) {
        reconnectAttempts = times;
        if (times > maxRetries) {
          connectionFailed = true;
          console.warn(`[Redis] Max reconnection attempts (${maxRetries}) reached, giving up`);
          return null;
        }
        const delay = Math.min(times * 200, 2000);
        console.log(`[Redis] Reconnection attempt ${times}/${maxRetries} in ${delay}ms`);
        return delay;
      },
      reconnectOnError(err) {
        const targetErrors = ["READONLY", "ECONNRESET", "ETIMEDOUT"];
        return targetErrors.some(e => err.message.includes(e));
      },
    });

    redisConnection.on("error", (err) => {
      if (!connectionFailed) {
        console.warn("Redis connection error:", err.message);
      }
    });

    redisConnection.on("connect", () => {
      reconnectAttempts = 0;
      console.log("[Redis] Connected successfully");
    });

    redisConnection.on("ready", () => {
      console.log("[Redis] Ready to accept commands");
    });

    redisConnection.on("close", () => {
      if (!connectionFailed) {
        console.log("[Redis] Connection closed");
      }
    });
  }

  return redisConnection;
}

export async function closeRedisConnection(): Promise<void> {
  if (redisConnection) {
    await redisConnection.quit();
    redisConnection = null;
  }
}

export function isRedisAvailable(): boolean {
  return redisConnection !== null && redisConnection.status === "ready";
}
