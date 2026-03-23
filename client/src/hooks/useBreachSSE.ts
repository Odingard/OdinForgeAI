import { useState, useEffect, useRef } from "react";

export interface SSEEvent {
  id: string;
  type: string;
  chainId: string;
  cognitiveType?: string;
  summary?: string;
  target?: string;
  detail?: string;
  timestamp: string;
  // Node/edge events
  nodeId?: string;
  kind?: string;
  phase?: string;
  label?: string;
  severity?: string;
  technique?: string;
  statusCode?: number;
  curlCommand?: string;
  // Reasoning events
  decision?: string;
  rationale?: string;
  outcome?: string;
}

export function useBreachSSE(chainId: string | undefined, enabled: boolean) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const counterRef = useRef(0);

  useEffect(() => {
    if (!enabled || !chainId) return;

    const token = localStorage.getItem("accessToken");
    if (!token) return;

    // EventSource doesn't support custom headers, so pass token as query param
    const url = `/api/breach-chains/${chainId}/events?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === "connected") return;

        const event: SSEEvent = {
          id: `sse-${counterRef.current++}`,
          ...data,
        };
        setEvents((prev) => {
          const next = [...prev, event];
          return next.length > 200 ? next.slice(-200) : next;
        });
      } catch {
        // ignore parse errors
      }
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
      setConnected(false);
    };
  }, [chainId, enabled]);

  return { events, connected };
}
