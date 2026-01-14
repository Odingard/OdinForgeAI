import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";
import type { IncomingMessage } from "http";
import { jwtAuthService, type TokenValidationResult } from "./jwt-auth";

interface AEVProgressEvent {
  type: "aev_progress";
  evaluationId: string;
  agentName: string;
  stage: string;
  progress: number;
  message: string;
}

interface AEVCompleteEvent {
  type: "aev_complete";
  evaluationId: string;
  success: boolean;
  error?: string;
}

interface SimulationProgressEvent {
  type: "simulation_progress";
  simulationId: string;
  round: number;
  phase: "attack" | "defense" | "analysis";
  message: string;
}

interface ReconProgressEvent {
  type: "recon_progress";
  scanId: string;
  phase: "dns" | "ports" | "ssl" | "http" | "complete" | "error";
  progress: number;
  message: string;
  portsFound?: number;
  vulnerabilitiesFound?: number;
}

interface HeartbeatEvent {
  type: "heartbeat";
  timestamp: number;
}

type WebSocketEvent = AEVProgressEvent | AEVCompleteEvent | SimulationProgressEvent | ReconProgressEvent | HeartbeatEvent;

interface ClientInfo {
  ws: WebSocket;
  lastPing: number;
  lastPong: number;
  messageQueue: string[];
  subscriptions: Set<string>;
  ip: string;
  authenticated: boolean;
  userId?: string;
  organizationId?: string;
  tenantId?: string;
}

interface WebSocketConfig {
  maxConnections: number;
  maxConnectionsPerIp: number;
  heartbeatIntervalMs: number;
  clientTimeoutMs: number;
  maxMessageQueueSize: number;
  maxMessageSize: number;
  requireAuth: boolean;
}

const DEFAULT_CONFIG: WebSocketConfig = {
  maxConnections: 1000,
  maxConnectionsPerIp: 50,
  heartbeatIntervalMs: 30000,
  clientTimeoutMs: 60000,
  maxMessageQueueSize: 100,
  maxMessageSize: 64 * 1024,
  // Enable auth by default in production; disable only if explicitly set to "false" for demo/testing
  requireAuth: process.env.NODE_ENV === "production" && process.env.WS_REQUIRE_AUTH !== "false",
};

class WebSocketService {
  private wss: WebSocketServer | null = null;
  private clients: Map<WebSocket, ClientInfo> = new Map();
  private ipConnectionCount: Map<string, number> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private config: WebSocketConfig = DEFAULT_CONFIG;
  private stats = {
    totalConnections: 0,
    totalMessages: 0,
    totalDisconnections: 0,
    rejectedConnections: 0,
  };

  initialize(server: Server, config?: Partial<WebSocketConfig>): void {
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    this.wss = new WebSocketServer({ 
      server, 
      path: "/ws",
      maxPayload: this.config.maxMessageSize,
    });

    this.wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
      this.handleConnection(ws, req);
    });

    this.startHeartbeat();
    this.startCleanup();

    console.log(`WebSocket server initialized on /ws (max: ${this.config.maxConnections} connections)`);
  }

  private getClientIp(req: IncomingMessage): string {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
      const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0];
      return ips.trim();
    }
    return req.socket.remoteAddress || "unknown";
  }

  private async handleConnection(ws: WebSocket, req: IncomingMessage): Promise<void> {
    const ip = this.getClientIp(req);
    
    if (this.clients.size >= this.config.maxConnections) {
      console.warn(`[WS] Connection rejected: max connections reached (${this.config.maxConnections})`);
      ws.close(1013, "Max connections reached");
      this.stats.rejectedConnections++;
      return;
    }
    
    const ipCount = this.ipConnectionCount.get(ip) || 0;
    if (ipCount >= this.config.maxConnectionsPerIp) {
      console.warn(`[WS] Connection rejected: max connections per IP reached for ${ip}`);
      ws.close(1013, "Max connections per IP reached");
      this.stats.rejectedConnections++;
      return;
    }
    
    // Extract token from URL query string for authentication
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");
    
    // In production with requireAuth=true, reject unauthenticated connections
    let authenticated = !this.config.requireAuth;
    let userId: string | undefined;
    let organizationId: string | undefined;
    let tenantId: string | undefined;
    
    if (this.config.requireAuth && !token) {
      console.warn(`[WS] Connection rejected: authentication required from ${ip}`);
      ws.close(1008, "Authentication required");
      this.stats.rejectedConnections++;
      return;
    }
    
    // Validate JWT token if provided
    if (token) {
      try {
        const validation: TokenValidationResult = await jwtAuthService.validateToken(token);
        if (validation.valid && validation.payload) {
          authenticated = true;
          userId = validation.payload.sub;
          organizationId = validation.payload.organizationId;
          tenantId = validation.payload.tenantId;
          console.log(`[WS] Token validated for user ${userId}, tenant ${tenantId}, org ${organizationId}`);
        } else if (this.config.requireAuth) {
          console.warn(`[WS] Connection rejected: invalid token from ${ip} - ${validation.error}`);
          ws.close(1008, "Invalid token");
          this.stats.rejectedConnections++;
          return;
        }
      } catch (error) {
        console.error(`[WS] Token validation error from ${ip}:`, error);
        if (this.config.requireAuth) {
          ws.close(1008, "Token validation failed");
          this.stats.rejectedConnections++;
          return;
        }
      }
    }
    
    const clientInfo: ClientInfo = {
      ws,
      lastPing: Date.now(),
      lastPong: Date.now(),
      messageQueue: [],
      subscriptions: new Set(),
      ip,
      authenticated,
      userId: userId || undefined,
      organizationId: organizationId || undefined,
      tenantId: tenantId || undefined,
    };
    
    this.clients.set(ws, clientInfo);
    this.ipConnectionCount.set(ip, ipCount + 1);
    this.stats.totalConnections++;
    
    console.log(`[WS] Client connected from ${ip} (auth: ${authenticated}, total: ${this.clients.size})`);
    
    ws.on("pong", () => {
      const client = this.clients.get(ws);
      if (client) {
        client.lastPong = Date.now();
      }
    });
    
    ws.on("message", (data: Buffer) => {
      this.handleMessage(ws, data);
    });

    ws.on("close", (code: number, reason: Buffer) => {
      this.handleDisconnection(ws, code, reason.toString());
    });

    ws.on("error", (error: Error) => {
      console.error(`[WS] Client error from ${ip}:`, error.message);
      this.handleDisconnection(ws, 1011, "Internal error");
    });
    
    this.sendToClient(ws, { type: "heartbeat", timestamp: Date.now() });
  }

  private handleMessage(ws: WebSocket, data: Buffer): void {
    const client = this.clients.get(ws);
    if (!client) return;
    
    try {
      const message = JSON.parse(data.toString());
      
      if (message.type === "subscribe" && typeof message.channel === "string") {
        const channel = message.channel;
        
        // Validate tenant-scoped channel subscriptions
        if (channel.startsWith("network-scan:") || channel.startsWith("scan:")) {
          // Format: network-scan:{tenantId}:{organizationId}:{scanId} or scan:{tenantId}:{organizationId}:{scanId}
          const parts = channel.split(":");
          if (parts.length >= 3) {
            const [, channelTenantId, channelOrgId] = parts;
            
            // Reject if client's tenant/org doesn't match channel's tenant/org
            if (!client.tenantId || !client.organizationId ||
                client.tenantId !== channelTenantId || 
                client.organizationId !== channelOrgId) {
              console.warn(`[WS] Subscription denied: client tenant/org mismatch for channel ${channel}`);
              this.sendToClient(ws, { type: "heartbeat", timestamp: Date.now() }); // Ack without subscribing
              return;
            }
          } else {
            // Legacy format without tenant scope - deny for security
            console.warn(`[WS] Subscription denied: insecure channel format ${channel}`);
            return;
          }
        }
        
        client.subscriptions.add(channel);
        console.log(`[WS] Client subscribed to: ${channel}`);
      }
      
      if (message.type === "unsubscribe" && typeof message.channel === "string") {
        client.subscriptions.delete(message.channel);
      }
      
      if (message.type === "ping") {
        this.sendToClient(ws, { type: "heartbeat", timestamp: Date.now() });
      }
    } catch (error) {
      console.warn(`[WS] Invalid message from client`);
    }
  }

  private handleDisconnection(ws: WebSocket, code: number, reason: string): void {
    const client = this.clients.get(ws);
    if (!client) return;
    
    const ipCount = this.ipConnectionCount.get(client.ip) || 0;
    if (ipCount > 1) {
      this.ipConnectionCount.set(client.ip, ipCount - 1);
    } else {
      this.ipConnectionCount.delete(client.ip);
    }
    
    this.clients.delete(ws);
    this.stats.totalDisconnections++;
    
    console.log(`[WS] Client disconnected from ${client.ip} (code: ${code}, total: ${this.clients.size})`);
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();
      
      this.clients.forEach((client, ws) => {
        if (now - client.lastPong > this.config.clientTimeoutMs) {
          console.log(`[WS] Client timeout, terminating connection from ${client.ip}`);
          ws.terminate();
          return;
        }
        
        if (ws.readyState === WebSocket.OPEN) {
          client.lastPing = now;
          ws.ping();
        }
      });
    }, this.config.heartbeatIntervalMs);
    
    if (this.heartbeatInterval.unref) {
      this.heartbeatInterval.unref();
    }
  }

  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      this.clients.forEach((client, ws) => {
        if (ws.readyState !== WebSocket.OPEN) {
          this.handleDisconnection(ws, 1006, "Connection lost");
        }
        
        if (client.messageQueue.length > 0 && ws.readyState === WebSocket.OPEN) {
          const messages = client.messageQueue.splice(0, 10);
          messages.forEach(msg => ws.send(msg));
        }
      });
    }, 5000);
    
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  private sendToClient(ws: WebSocket, event: WebSocketEvent): boolean {
    const client = this.clients.get(ws);
    if (!client) return false;
    
    const message = JSON.stringify(event);
    
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(message);
        this.stats.totalMessages++;
        return true;
      } catch (error) {
        if (client.messageQueue.length < this.config.maxMessageQueueSize) {
          client.messageQueue.push(message);
        }
        return false;
      }
    } else if (client.messageQueue.length < this.config.maxMessageQueueSize) {
      client.messageQueue.push(message);
    }
    
    return false;
  }

  broadcast(event: WebSocketEvent): void {
    this.clients.forEach((client, ws) => {
      this.sendToClient(ws, event);
    });
  }

  broadcastToChannel(channel: string, event: WebSocketEvent | Record<string, any>): void {
    this.clients.forEach((client, ws) => {
      if (client.subscriptions.has(channel)) {
        this.sendToClient(ws, event as WebSocketEvent);
      }
    });
  }

  sendProgress(evaluationId: string, agentName: string, stage: string, progress: number, message: string): void {
    const event: AEVProgressEvent = {
      type: "aev_progress",
      evaluationId,
      agentName,
      stage,
      progress,
      message,
    };
    
    this.broadcast(event);
    this.broadcastToChannel(`evaluation:${evaluationId}`, event);
  }

  sendComplete(evaluationId: string, success: boolean, error?: string): void {
    const event: AEVCompleteEvent = {
      type: "aev_complete",
      evaluationId,
      success,
      error,
    };
    
    this.broadcast(event);
    this.broadcastToChannel(`evaluation:${evaluationId}`, event);
  }

  sendSimulationProgress(simulationId: string, round: number, phase: "attack" | "defense" | "analysis", message: string): void {
    const event: SimulationProgressEvent = {
      type: "simulation_progress",
      simulationId,
      round,
      phase,
      message,
    };
    
    this.broadcast(event);
    this.broadcastToChannel(`simulation:${simulationId}`, event);
  }

  sendReconProgress(scanId: string, phase: "dns" | "ports" | "ssl" | "http" | "complete", progress: number, message: string, portsFound?: number, vulnerabilitiesFound?: number): void {
    const event: ReconProgressEvent = {
      type: "recon_progress",
      scanId,
      phase,
      progress,
      message,
      portsFound,
      vulnerabilitiesFound,
    };
    
    this.broadcast(event);
    this.broadcastToChannel(`recon:${scanId}`, event);
  }

  sendNetworkScanProgress(
    tenantId: string,
    organizationId: string,
    scanId: string,
    phase: "ports" | "vulnerabilities" | "complete" | "error",
    progress: number,
    message: string,
    portsFound?: number,
    vulnerabilitiesFound?: number
  ): void {
    // Map input phases to ReconProgressEvent phases (error is preserved as-is)
    const mappedPhase: ReconProgressEvent["phase"] = 
      phase === "vulnerabilities" ? "http" : phase;
    
    const event: ReconProgressEvent = {
      type: "recon_progress",
      scanId,
      phase: mappedPhase,
      progress,
      message,
      portsFound,
      vulnerabilitiesFound,
    };
    
    // Broadcast only to tenant-scoped channel for security
    const channel = `network-scan:${tenantId}:${organizationId}:${scanId}`;
    this.broadcastToChannel(channel, event);
  }

  getStats(): {
    activeConnections: number;
    totalConnections: number;
    totalMessages: number;
    totalDisconnections: number;
    rejectedConnections: number;
    uniqueIps: number;
  } {
    return {
      activeConnections: this.clients.size,
      totalConnections: this.stats.totalConnections,
      totalMessages: this.stats.totalMessages,
      totalDisconnections: this.stats.totalDisconnections,
      rejectedConnections: this.stats.rejectedConnections,
      uniqueIps: this.ipConnectionCount.size,
    };
  }

  shutdown(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    this.clients.forEach((client, ws) => {
      ws.close(1001, "Server shutting down");
    });
    
    this.clients.clear();
    this.ipConnectionCount.clear();
    
    if (this.wss) {
      this.wss.close();
    }
    
    console.log("[WS] WebSocket server shutdown complete");
  }
}

export const wsService = new WebSocketService();
