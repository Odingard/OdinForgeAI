import Redis from "ioredis";
import type { RedisOptions } from "ioredis";

let connectionFailed = false;

export interface BullMQConnectionOptions {
  host: string;
  port: number;
  password?: string;
  username?: string;
  tls?: {};
  maxRetriesPerRequest: null;
}

function validateAndParseRedisUrl(): { valid: boolean; options?: BullMQConnectionOptions; error?: string } {
  const redisUrl = process.env.REDIS_URL;
  
  if (!redisUrl) {
    return { valid: false, error: "REDIS_URL not set" };
  }
  
  if (redisUrl.startsWith("https://")) {
    console.error("[Redis] Invalid REDIS_URL: REST API URL (https://) provided. Need Redis protocol URL (rediss://)");
    console.error("[Redis] Go to Upstash dashboard → your database → 'Connect to your database' → look for rediss:// URL");
    return { valid: false, error: "Invalid REDIS_URL: Use rediss:// protocol URL, not https:// REST API URL" };
  }
  
  try {
    const urlParts = new URL(redisUrl);
    const useTls = redisUrl.startsWith("rediss://");
    
    console.log(`[Redis] Parsing connection for ${urlParts.hostname}:${urlParts.port || 6379} (TLS: ${useTls})`);
    
    const options: BullMQConnectionOptions = {
      host: urlParts.hostname,
      port: parseInt(urlParts.port || "6379", 10),
      maxRetriesPerRequest: null,
    };
    
    if (urlParts.password) {
      options.password = urlParts.password;
    }
    if (urlParts.username && urlParts.username !== "default") {
      options.username = urlParts.username;
    }
    if (useTls) {
      options.tls = {};
    }
    
    return { valid: true, options };
  } catch (err) {
    return { valid: false, error: `Failed to parse REDIS_URL: ${err}` };
  }
}

export function getBullMQConnection(): BullMQConnectionOptions | null {
  if (connectionFailed) {
    return null;
  }
  
  const result = validateAndParseRedisUrl();
  if (!result.valid) {
    connectionFailed = true;
    return null;
  }
  
  return result.options!;
}

export async function testRedisConnection(): Promise<boolean> {
  const connOptions = getBullMQConnection();
  if (!connOptions) {
    return false;
  }
  
  const testRedis = new Redis({
    host: connOptions.host,
    port: connOptions.port,
    password: connOptions.password,
    username: connOptions.username,
    tls: connOptions.tls,
    maxRetriesPerRequest: 3,
    connectTimeout: 5000,
    lazyConnect: true,
  });
  
  try {
    await testRedis.connect();
    await Promise.race([
      testRedis.ping(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Redis ping timeout")), 3000))
    ]);
    console.log("[Redis] Connection test successful");
    await testRedis.quit();
    return true;
  } catch (err: any) {
    console.error("[Redis] Connection test failed:", err.message);
    await testRedis.quit().catch(() => {});
    connectionFailed = true;
    return false;
  }
}

export function isRedisConfigured(): boolean {
  return getBullMQConnection() !== null;
}

export function markRedisUnavailable(): void {
  connectionFailed = true;
}
