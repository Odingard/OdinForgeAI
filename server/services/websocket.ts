import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";

interface AEVProgressEvent {
  type: "aev_progress";
  evaluationId: string;
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

type WebSocketEvent = AEVProgressEvent | AEVCompleteEvent;

class WebSocketService {
  private wss: WebSocketServer | null = null;
  private clients: Set<WebSocket> = new Set();

  initialize(server: Server): void {
    this.wss = new WebSocketServer({ server, path: "/ws" });

    this.wss.on("connection", (ws) => {
      console.log("WebSocket client connected");
      this.clients.add(ws);

      ws.on("close", () => {
        console.log("WebSocket client disconnected");
        this.clients.delete(ws);
      });

      ws.on("error", (error) => {
        console.error("WebSocket error:", error);
        this.clients.delete(ws);
      });
    });

    console.log("WebSocket server initialized on /ws");
  }

  broadcast(event: WebSocketEvent): void {
    const message = JSON.stringify(event);
    this.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  sendProgress(evaluationId: string, stage: string, progress: number, message: string): void {
    this.broadcast({
      type: "aev_progress",
      evaluationId,
      stage,
      progress,
      message,
    });
  }

  sendComplete(evaluationId: string, success: boolean, error?: string): void {
    this.broadcast({
      type: "aev_complete",
      evaluationId,
      success,
      error,
    });
  }
}

export const wsService = new WebSocketService();
