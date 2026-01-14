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
    const redisUrl = process.env.REDIS_URL || "redis://localhost:6379";
    const maxRetries = REDIS_CONFIG.maxRetriesOnStartup;
    
    redisConnection = new Redis(redisUrl, {
      ...REDIS_CONFIG,
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
