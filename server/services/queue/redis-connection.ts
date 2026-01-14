import Redis from "ioredis";

let redisConnection: Redis | null = null;
let connectionFailed = false;

export function getRedisConnection(): Redis {
  if (connectionFailed) {
    throw new Error("Redis connection previously failed");
  }
  
  if (!redisConnection) {
    const redisUrl = process.env.REDIS_URL || "redis://localhost:6379";
    
    redisConnection = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: false,
      connectTimeout: 5000,
      lazyConnect: true,
      retryStrategy(times) {
        if (times > 3) {
          connectionFailed = true;
          return null;
        }
        return Math.min(times * 100, 1000);
      },
    });

    redisConnection.on("error", (err) => {
      if (!connectionFailed) {
        console.warn("Redis connection error:", err.message);
      }
    });

    redisConnection.on("connect", () => {
      console.log("Redis connected successfully");
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
