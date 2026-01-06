import { wsService } from "../websocket";

interface AgentHeartbeat {
  evaluationId: string;
  agentName: string;
  stage: string;
  progress: number;
  message: string;
  lastUpdate: number;
  startTime: number;
  isStalled: boolean;
  stallCount: number;
  maxStallAttempts: number;
}

const activeHeartbeats = new Map<string, AgentHeartbeat>();
const STALL_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes without progress = stalled
const HEARTBEAT_CHECK_INTERVAL_MS = 30 * 1000; // Check every 30 seconds

let heartbeatIntervalId: NodeJS.Timeout | null = null;

export function startHeartbeatMonitor(): void {
  if (heartbeatIntervalId) return;
  
  heartbeatIntervalId = setInterval(() => {
    const now = Date.now();
    
    for (const [key, heartbeat] of Array.from(activeHeartbeats.entries())) {
      const timeSinceUpdate = now - heartbeat.lastUpdate;
      
      if (timeSinceUpdate > STALL_THRESHOLD_MS && !heartbeat.isStalled) {
        heartbeat.isStalled = true;
        heartbeat.stallCount++;
        
        console.warn(`[HeartbeatTracker] Agent stalled: ${heartbeat.agentName} for evaluation ${heartbeat.evaluationId}`);
        console.warn(`[HeartbeatTracker] Last activity: ${Math.round(timeSinceUpdate / 1000)}s ago`);
        
        wsService.broadcast({
          type: "agent_stall_detected",
          evaluationId: heartbeat.evaluationId,
          agentName: heartbeat.agentName,
          stage: heartbeat.stage,
          lastProgress: heartbeat.progress,
          stalledDuration: timeSinceUpdate,
          stallCount: heartbeat.stallCount,
          message: `${heartbeat.agentName} has not reported progress for ${Math.round(timeSinceUpdate / 60000)} minutes`,
        } as any);
      }
    }
  }, HEARTBEAT_CHECK_INTERVAL_MS);
}

export function stopHeartbeatMonitor(): void {
  if (heartbeatIntervalId) {
    clearInterval(heartbeatIntervalId);
    heartbeatIntervalId = null;
  }
}

export function registerAgentStart(evaluationId: string, agentName: string): string {
  const key = `${evaluationId}:${agentName}`;
  const now = Date.now();
  
  activeHeartbeats.set(key, {
    evaluationId,
    agentName,
    stage: "initializing",
    progress: 0,
    message: "Starting agent...",
    lastUpdate: now,
    startTime: now,
    isStalled: false,
    stallCount: 0,
    maxStallAttempts: 3,
  });
  
  return key;
}

export function updateAgentHeartbeat(
  evaluationId: string,
  agentName: string,
  stage: string,
  progress: number,
  message: string
): void {
  const key = `${evaluationId}:${agentName}`;
  const heartbeat = activeHeartbeats.get(key);
  
  if (heartbeat) {
    heartbeat.stage = stage;
    heartbeat.progress = progress;
    heartbeat.message = message;
    heartbeat.lastUpdate = Date.now();
    heartbeat.isStalled = false;
  }
}

export function unregisterAgent(evaluationId: string, agentName: string): void {
  const key = `${evaluationId}:${agentName}`;
  activeHeartbeats.delete(key);
}

export function getAgentStatus(evaluationId: string, agentName: string): AgentHeartbeat | undefined {
  const key = `${evaluationId}:${agentName}`;
  return activeHeartbeats.get(key);
}

export function getActiveAgents(): AgentHeartbeat[] {
  return Array.from(activeHeartbeats.values());
}

export function getStalledAgents(): AgentHeartbeat[] {
  return Array.from(activeHeartbeats.values()).filter(h => h.isStalled);
}

export interface RunWithHeartbeatOptions {
  maxRetries?: number;
  retryDelayMs?: number;
  stallTimeoutMs?: number; // Timeout for detecting stall (triggers retry)
  onStallDetected?: (agentName: string, stallCount: number) => void;
  onRetry?: (agentName: string, attempt: number, maxAttempts: number) => void;
}

class StallTimeoutError extends Error {
  constructor(agentName: string, timeoutMs: number) {
    super(`${agentName} timed out after ${Math.round(timeoutMs / 1000)}s without progress`);
    this.name = "StallTimeoutError";
  }
}

export async function runWithHeartbeat<T>(
  evaluationId: string,
  agentName: string,
  agentFn: () => Promise<T>,
  onProgress?: (stage: string, progress: number, message: string) => void,
  options?: RunWithHeartbeatOptions
): Promise<T> {
  const maxRetries = options?.maxRetries ?? 2;
  const retryDelayMs = options?.retryDelayMs ?? 5000;
  const stallTimeoutMs = options?.stallTimeoutMs ?? STALL_THRESHOLD_MS; // Default to 5 minutes
  
  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const key = registerAgentStart(evaluationId, agentName);
    
    const wrappedProgress = (stage: string, progress: number, message: string) => {
      updateAgentHeartbeat(evaluationId, agentName, stage, progress, message);
      onProgress?.(stage, progress, message);
    };
    
    try {
      if (attempt > 0) {
        console.log(`[HeartbeatTracker] Retrying ${agentName} (attempt ${attempt + 1}/${maxRetries + 1})`);
        options?.onRetry?.(agentName, attempt + 1, maxRetries + 1);
        wrappedProgress("retrying", 0, `${agentName} retrying (attempt ${attempt + 1}/${maxRetries + 1})...`);
        
        // Brief delay before retry
        await new Promise(resolve => setTimeout(resolve, retryDelayMs));
      } else {
        wrappedProgress("starting", 0, `${agentName} initializing...`);
      }
      
      // Run agent with stall timeout - race the agent against a stall detection timer
      const result = await runWithStallTimeout(
        evaluationId,
        agentName,
        agentFn(),
        stallTimeoutMs,
        key
      );
      
      wrappedProgress("complete", 100, `${agentName} completed`);
      return result;
      
    } catch (error) {
      const heartbeat = activeHeartbeats.get(key);
      const elapsed = heartbeat ? Math.round((Date.now() - heartbeat.startTime) / 1000) : 0;
      const wasStalled = heartbeat?.isStalled || error instanceof StallTimeoutError;
      
      lastError = error instanceof Error ? error : new Error(String(error));
      
      console.error(`[HeartbeatTracker] Agent ${agentName} failed after ${elapsed}s (attempt ${attempt + 1}/${maxRetries + 1})${wasStalled ? " - was stalled/timed out" : ""}`);
      
      // If stalled/timed out and we have retries left, notify and continue to retry
      if (wasStalled && attempt < maxRetries) {
        if (heartbeat) {
          heartbeat.stallCount++;
          options?.onStallDetected?.(agentName, heartbeat.stallCount);
        }
        wsService.broadcast({
          type: "agent_recovery_attempt",
          evaluationId,
          agentName,
          attempt: attempt + 1,
          maxAttempts: maxRetries + 1,
          message: `${agentName} stalled/timed out, attempting recovery...`,
        } as any);
        
        // Continue to next retry attempt
        unregisterAgent(evaluationId, agentName);
        continue;
      }
      
      // Non-stall error or exhausted retries - break out
      break;
      
    } finally {
      unregisterAgent(evaluationId, agentName);
    }
  }
  
  // All attempts exhausted
  console.error(`[HeartbeatTracker] Agent ${agentName} failed after ${maxRetries + 1} attempts`);
  wsService.broadcast({
    type: "agent_recovery_failed",
    evaluationId,
    agentName,
    attempts: maxRetries + 1,
    message: `${agentName} failed after ${maxRetries + 1} attempts`,
  } as any);
  
  throw lastError || new Error(`${agentName} failed after ${maxRetries + 1} attempts`);
}

// Helper that races the agent promise against a stall-detection timer
async function runWithStallTimeout<T>(
  evaluationId: string,
  agentName: string,
  agentPromise: Promise<T>,
  timeoutMs: number,
  heartbeatKey: string
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let completed = false;
    let checkInterval: NodeJS.Timeout | null = null;
    
    // Periodic check for stall based on heartbeat updates
    const startTime = Date.now();
    checkInterval = setInterval(() => {
      if (completed) {
        if (checkInterval) clearInterval(checkInterval);
        return;
      }
      
      const heartbeat = activeHeartbeats.get(heartbeatKey);
      if (!heartbeat) {
        if (checkInterval) clearInterval(checkInterval);
        return;
      }
      
      const timeSinceUpdate = Date.now() - heartbeat.lastUpdate;
      const totalElapsed = Date.now() - startTime;
      
      // If no progress for stallTimeout, trigger stall timeout error
      if (timeSinceUpdate > timeoutMs) {
        completed = true;
        if (checkInterval) clearInterval(checkInterval);
        heartbeat.isStalled = true;
        
        console.warn(`[HeartbeatTracker] ${agentName} stall timeout after ${Math.round(totalElapsed / 1000)}s ` +
          `(no progress for ${Math.round(timeSinceUpdate / 1000)}s)`);
        
        wsService.broadcast({
          type: "agent_stall_detected",
          evaluationId,
          agentName,
          stage: heartbeat.stage,
          lastProgress: heartbeat.progress,
          stalledDuration: timeSinceUpdate,
          message: `${agentName} timed out - no progress for ${Math.round(timeSinceUpdate / 60000)} minutes`,
        } as any);
        
        reject(new StallTimeoutError(agentName, timeSinceUpdate));
      }
    }, 30000); // Check every 30 seconds
    
    // Race the actual agent
    agentPromise
      .then(result => {
        if (!completed) {
          completed = true;
          if (checkInterval) clearInterval(checkInterval);
          resolve(result);
        }
      })
      .catch(error => {
        if (!completed) {
          completed = true;
          if (checkInterval) clearInterval(checkInterval);
          reject(error);
        }
      });
  });
}

// Check if a specific agent is currently stalled
export function isAgentStalled(evaluationId: string, agentName: string): boolean {
  const key = `${evaluationId}:${agentName}`;
  const heartbeat = activeHeartbeats.get(key);
  return heartbeat?.isStalled ?? false;
}

// Force reset an agent's stall state (useful for manual intervention)
export function resetAgentStall(evaluationId: string, agentName: string): void {
  const key = `${evaluationId}:${agentName}`;
  const heartbeat = activeHeartbeats.get(key);
  if (heartbeat) {
    heartbeat.isStalled = false;
    heartbeat.lastUpdate = Date.now();
  }
}

startHeartbeatMonitor();
