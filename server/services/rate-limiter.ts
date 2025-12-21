import { Request, Response, NextFunction } from "express";
import { storage } from "../storage";

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: Request) => string;
  skipFailedRequests?: boolean;
  message?: string;
}

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

const cleanupInterval = setInterval(() => {
  const now = Date.now();
  const keysToDelete: string[] = [];
  rateLimitStore.forEach((entry, key) => {
    if (now - entry.windowStart > 60000 * 5) {
      keysToDelete.push(key);
    }
  });
  keysToDelete.forEach(key => rateLimitStore.delete(key));
}, 60000);

if (cleanupInterval.unref) {
  cleanupInterval.unref();
}

export const rateLimitConfigs = {
  auth: {
    windowMs: 15 * 60 * 1000,
    maxRequests: 10,
    message: "Too many authentication attempts. Please try again in 15 minutes.",
  },
  agentTelemetry: {
    windowMs: 60 * 1000,
    maxRequests: 120,
    message: "Agent telemetry rate limit exceeded. Reduce reporting frequency.",
  },
  apiGeneral: {
    windowMs: 60 * 1000,
    maxRequests: 100,
    message: "API rate limit exceeded. Please slow down your requests.",
  },
  batchOperations: {
    windowMs: 60 * 1000,
    maxRequests: 10,
    message: "Batch operation rate limit exceeded. Please wait before submitting more batches.",
  },
  evaluationCreate: {
    windowMs: 60 * 1000,
    maxRequests: 30,
    message: "Evaluation creation rate limit exceeded.",
  },
  reportGenerate: {
    windowMs: 60 * 1000,
    maxRequests: 5,
    message: "Report generation rate limit exceeded. Reports are resource-intensive.",
  },
  simulation: {
    windowMs: 5 * 60 * 1000,
    maxRequests: 3,
    message: "Simulation rate limit exceeded. AI simulations are resource-intensive.",
  },
} as const;

function getDefaultKey(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = forwarded 
    ? (Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0])
    : req.ip || req.socket.remoteAddress || "unknown";
  return ip;
}

function checkRateLimit(key: string, config: RateLimitConfig): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  
  if (!entry || now - entry.windowStart >= config.windowMs) {
    rateLimitStore.set(key, { count: 1, windowStart: now });
    return { 
      allowed: true, 
      remaining: config.maxRequests - 1,
      resetTime: now + config.windowMs
    };
  }
  
  if (entry.count >= config.maxRequests) {
    return { 
      allowed: false, 
      remaining: 0,
      resetTime: entry.windowStart + config.windowMs
    };
  }
  
  entry.count++;
  return { 
    allowed: true, 
    remaining: config.maxRequests - entry.count,
    resetTime: entry.windowStart + config.windowMs
  };
}

export function createRateLimiter(config: RateLimitConfig, configName?: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const keyGenerator = config.keyGenerator || getDefaultKey;
    // Use configName prefix for proper aggregation by getAllRateLimitStatuses
    const prefix = configName || req.path;
    const key = `[${prefix}]:${keyGenerator(req)}`;
    
    const result = checkRateLimit(key, config);
    
    res.setHeader("X-RateLimit-Limit", config.maxRequests);
    res.setHeader("X-RateLimit-Remaining", result.remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(result.resetTime / 1000));
    
    if (!result.allowed) {
      const retryAfter = Math.ceil((result.resetTime - Date.now()) / 1000);
      res.setHeader("Retry-After", retryAfter);
      
      logRateLimitEvent(req, key, config);
      
      return res.status(429).json({
        error: "Too Many Requests",
        message: config.message || "Rate limit exceeded",
        retryAfter,
      });
    }
    
    next();
  };
}

async function logRateLimitEvent(req: Request, key: string, config: RateLimitConfig) {
  try {
    const forwarded = req.headers["x-forwarded-for"];
    const ip = forwarded 
      ? (Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0])
      : req.ip || "unknown";
      
    console.warn(`[RATE_LIMIT] Blocked: ${req.method} ${req.path} from ${ip}`);
  } catch (error) {
    console.error("Failed to log rate limit event:", error);
  }
}

export const authRateLimiter = createRateLimiter(rateLimitConfigs.auth, "auth");
export const agentTelemetryRateLimiter = createRateLimiter(rateLimitConfigs.agentTelemetry, "agentTelemetry");
export const apiRateLimiter = createRateLimiter(rateLimitConfigs.apiGeneral, "apiGeneral");
export const batchRateLimiter = createRateLimiter(rateLimitConfigs.batchOperations, "batchOperations");
export const evaluationRateLimiter = createRateLimiter(rateLimitConfigs.evaluationCreate, "evaluationCreate");
export const reportRateLimiter = createRateLimiter(rateLimitConfigs.reportGenerate, "reportGenerate");
export const simulationRateLimiter = createRateLimiter(rateLimitConfigs.simulation, "simulation");

export function getRateLimitStatus(key: string, configName: keyof typeof rateLimitConfigs): { 
  count: number; 
  remaining: number; 
  resetIn: number 
} | null {
  const config = rateLimitConfigs[configName];
  const entry = rateLimitStore.get(key);
  
  if (!entry) {
    return { count: 0, remaining: config.maxRequests, resetIn: 0 };
  }
  
  const now = Date.now();
  if (now - entry.windowStart >= config.windowMs) {
    return { count: 0, remaining: config.maxRequests, resetIn: 0 };
  }
  
  return {
    count: entry.count,
    remaining: Math.max(0, config.maxRequests - entry.count),
    resetIn: Math.ceil((entry.windowStart + config.windowMs - now) / 1000)
  };
}

export function clearRateLimitStore(): void {
  rateLimitStore.clear();
}

export function getAllRateLimitStatuses(): Array<{
  name: string;
  displayName: string;
  windowMs: number;
  maxRequests: number;
  currentUsage: number;
  remaining: number;
  resetInSeconds: number;
}> {
  const statuses: Array<{
    name: string;
    displayName: string;
    windowMs: number;
    maxRequests: number;
    currentUsage: number;
    remaining: number;
    resetInSeconds: number;
  }> = [];

  const displayNames: Record<string, string> = {
    auth: "Authentication",
    agentTelemetry: "Agent Telemetry",
    apiGeneral: "General API",
    batchOperations: "Batch Operations",
    evaluationCreate: "Evaluation Creation",
    reportGenerate: "Report Generation",
    simulation: "AI Simulations",
  };

  for (const [name, config] of Object.entries(rateLimitConfigs)) {
    let totalCount = 0;
    let oldestReset = 0;
    const now = Date.now();

    rateLimitStore.forEach((entry, key) => {
      // Keys are formatted as [configName]:ip
      if (key.startsWith(`[${name}]:`)) {
        if (now - entry.windowStart < config.windowMs) {
          totalCount += entry.count;
          const resetTime = entry.windowStart + config.windowMs - now;
          if (resetTime > oldestReset) {
            oldestReset = resetTime;
          }
        }
      }
    });

    statuses.push({
      name,
      displayName: displayNames[name] || name,
      windowMs: config.windowMs,
      maxRequests: config.maxRequests,
      currentUsage: totalCount,
      remaining: Math.max(0, config.maxRequests - totalCount),
      resetInSeconds: Math.ceil(oldestReset / 1000),
    });
  }

  return statuses;
}
