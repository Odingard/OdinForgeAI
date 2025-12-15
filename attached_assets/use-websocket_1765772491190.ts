import { useEffect, useRef, useState, useCallback } from "react";

export interface WSMessage {
  type: 
    | "alert" 
    | "threat" 
    | "aev_progress" 
    | "aev_complete"
    | "endpoint_status"
    | "audit_event"
    | "system_status"
    | "user_event"
    | "apikey_event"
    | "error"
    | "ping"
    | "pong"
    | "subscribed"
    | "unsubscribed";
  data: any;
  organizationId?: string;
  timestamp: number;
}

export type ConnectionState = "connecting" | "connected" | "disconnected" | "error";

interface UseWebSocketOptions {
  token: string | null;
  onMessage?: (message: WSMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

interface UseWebSocketReturn {
  connectionState: ConnectionState;
  lastMessage: WSMessage | null;
  subscribe: (channel: string) => void;
  unsubscribe: (channel: string) => void;
  sendPing: () => void;
}

export function useWebSocket({
  token,
  onMessage,
  onConnect,
  onDisconnect,
  onError,
  autoReconnect = true,
  reconnectInterval = 3000,
  maxReconnectAttempts = 5,
}: UseWebSocketOptions): UseWebSocketReturn {
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimeout = useRef<NodeJS.Timeout | null>(null);
  const subscribedChannels = useRef<Set<string>>(new Set());

  const connect = useCallback(() => {
    if (!token) {
      setConnectionState("disconnected");
      return;
    }

    // Don't connect if already connecting or connected
    if (wsRef.current && wsRef.current.readyState === WebSocket.CONNECTING) {
      return;
    }
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    // Build WebSocket URL
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws?token=${encodeURIComponent(token)}`;

    setConnectionState("connecting");

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      const handleOpen = () => {
        setConnectionState("connected");
        reconnectAttempts.current = 0;
        onConnect?.();

        // Resubscribe to previously subscribed channels
        subscribedChannels.current.forEach((channel) => {
          ws.send(JSON.stringify({ type: "subscribe", channel }));
        });
      };

      const handleMessage = (event: MessageEvent) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          setLastMessage(message);
          onMessage?.(message);
        } catch (error) {
          console.error("Failed to parse WebSocket message:", error);
        }
      };

      const handleClose = () => {
        // Remove event listeners to prevent memory leaks
        ws.removeEventListener("open", handleOpen);
        ws.removeEventListener("message", handleMessage);
        ws.removeEventListener("close", handleClose);
        ws.removeEventListener("error", handleError);
        
        setConnectionState("disconnected");
        wsRef.current = null;
        onDisconnect?.();

        // Auto-reconnect logic with exponential backoff
        if (autoReconnect && reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current++;
          const delay = reconnectInterval * Math.pow(2, reconnectAttempts.current - 1);
          reconnectTimeout.current = setTimeout(() => {
            connect();
          }, Math.min(delay, 30000)); // Cap at 30 seconds
        }
      };

      const handleError = (error: Event) => {
        setConnectionState("error");
        onError?.(error);
      };

      ws.addEventListener("open", handleOpen);
      ws.addEventListener("message", handleMessage);
      ws.addEventListener("close", handleClose);
      ws.addEventListener("error", handleError);
    } catch (error) {
      setConnectionState("error");
      console.error("Failed to create WebSocket connection:", error);
    }
  }, [token, onMessage, onConnect, onDisconnect, onError, autoReconnect, reconnectInterval, maxReconnectAttempts]);

  const disconnect = useCallback(() => {
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const subscribe = useCallback((channel: string) => {
    subscribedChannels.current.add(channel);
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "subscribe", channel }));
    }
  }, []);

  const unsubscribe = useCallback((channel: string) => {
    subscribedChannels.current.delete(channel);
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "unsubscribe", channel }));
    }
  }, []);

  const sendPing = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "ping" }));
    }
  }, []);

  // Connect when token changes
  useEffect(() => {
    if (token) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [token, connect, disconnect]);

  return {
    connectionState,
    lastMessage,
    subscribe,
    unsubscribe,
    sendPing,
  };
}

// Specialized hooks for specific event types

export function useAlerts(token: string | null) {
  const [alerts, setAlerts] = useState<WSMessage[]>([]);
  
  const handleMessage = useCallback((message: WSMessage) => {
    if (message.type === "alert") {
      setAlerts((prev) => [message, ...prev].slice(0, 100)); // Keep last 100 alerts
    }
  }, []);

  const { connectionState, subscribe, unsubscribe } = useWebSocket({
    token,
    onMessage: handleMessage,
    onConnect: () => subscribe("alerts"),
  });

  return { alerts, connectionState, clearAlerts: () => setAlerts([]) };
}

export function useThreats(token: string | null) {
  const [threats, setThreats] = useState<WSMessage[]>([]);
  
  const handleMessage = useCallback((message: WSMessage) => {
    if (message.type === "threat") {
      setThreats((prev) => [message, ...prev].slice(0, 100));
    }
  }, []);

  const { connectionState, subscribe, unsubscribe } = useWebSocket({
    token,
    onMessage: handleMessage,
    onConnect: () => subscribe("threats"),
  });

  return { threats, connectionState, clearThreats: () => setThreats([]), unsubscribe };
}

export function useAEVProgress(token: string | null) {
  const [evaluations, setEvaluations] = useState<Map<string, WSMessage>>(new Map());
  
  const handleMessage = useCallback((message: WSMessage) => {
    if (message.type === "aev_progress" || message.type === "aev_complete") {
      setEvaluations((prev) => {
        const next = new Map(prev);
        next.set(message.data.evaluationId, message);
        return next;
      });
    }
  }, []);

  const { connectionState, subscribe } = useWebSocket({
    token,
    onMessage: handleMessage,
    onConnect: () => subscribe("aev"),
  });

  return { 
    evaluations: Array.from(evaluations.values()), 
    connectionState,
    clearEvaluations: () => setEvaluations(new Map()),
  };
}

export function useSystemStatus(token: string | null) {
  const [status, setStatus] = useState<WSMessage | null>(null);
  
  const handleMessage = useCallback((message: WSMessage) => {
    if (message.type === "system_status") {
      setStatus(message);
    }
  }, []);

  const { connectionState } = useWebSocket({
    token,
    onMessage: handleMessage,
  });

  return { status, connectionState };
}
