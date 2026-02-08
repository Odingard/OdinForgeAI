import { useEffect, useRef, useState, useCallback } from "react";

export interface WebSocketMessage {
  type: string;
  [key: string]: any;
}

export interface UseWebSocketOptions {
  url?: string;
  enabled?: boolean;
  reconnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
  onMessage?: (data: WebSocketMessage) => void;
}

export interface UseWebSocketReturn {
  isConnected: boolean;
  isConnecting: boolean;
  send: (data: any) => void;
  subscribe: (channel: string) => void;
  unsubscribe: (channel: string) => void;
  reconnect: () => void;
}

export function useWebSocket({
  url,
  enabled = true,
  reconnect = true,
  reconnectInterval = 1000,
  maxReconnectAttempts = 10,
  onOpen,
  onClose,
  onError,
  onMessage,
}: UseWebSocketOptions = {}): UseWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Generate WebSocket URL from window location if not provided
  const wsUrl = url || (() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws`;
  })();

  const connect = useCallback(() => {
    if (!enabled || isConnecting || isConnected) {
      return;
    }

    setIsConnecting(true);

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setIsConnecting(false);
        reconnectAttemptsRef.current = 0;
        onOpen?.();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage?.(data);
        } catch (error) {
          console.error("[WebSocket] Failed to parse message:", error);
        }
      };

      ws.onerror = (error) => {
        console.error("[WebSocket] Connection error:", error);
        onError?.(error);
      };

      ws.onclose = () => {
        setIsConnected(false);
        setIsConnecting(false);
        wsRef.current = null;
        onClose?.();

        // Attempt reconnection with exponential backoff
        if (reconnect && reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          const delay = Math.min(
            reconnectInterval * Math.pow(2, reconnectAttemptsRef.current - 1),
            30000 // Max 30 seconds
          );

          console.log(
            `[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts})`
          );

          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, delay);
        }
      };
    } catch (error) {
      console.error("[WebSocket] Failed to create connection:", error);
      setIsConnecting(false);
    }
  }, [enabled, isConnecting, isConnected, wsUrl, reconnect, maxReconnectAttempts, reconnectInterval, onOpen, onMessage, onError, onClose]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  const send = useCallback((data: any) => {
    if (wsRef.current && isConnected) {
      wsRef.current.send(JSON.stringify(data));
    } else {
      console.warn("[WebSocket] Cannot send message: not connected");
    }
  }, [isConnected]);

  const subscribe = useCallback((channel: string) => {
    send({ type: "subscribe", channel });
  }, [send]);

  const unsubscribe = useCallback((channel: string) => {
    send({ type: "unsubscribe", channel });
  }, [send]);

  const manualReconnect = useCallback(() => {
    disconnect();
    reconnectAttemptsRef.current = 0;
    connect();
  }, [disconnect, connect]);

  // Connect on mount if enabled
  useEffect(() => {
    if (enabled) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [enabled]); // Only depend on enabled

  return {
    isConnected,
    isConnecting,
    send,
    subscribe,
    unsubscribe,
    reconnect: manualReconnect,
  };
}
