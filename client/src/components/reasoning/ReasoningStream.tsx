import { useEffect, useRef } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

interface ReasoningStreamProps {
  events: any[];
}

type ReasoningIntent =
  | "explore"
  | "exploit"
  | "validate"
  | "pivot"
  | "escalate"
  | "replay"
  | "summarize";

const INTENT_COLORS: Record<ReasoningIntent, string> = {
  explore: "text-blue-400",
  exploit: "text-orange-400",
  validate: "text-green-400",
  pivot: "text-purple-400",
  replay: "text-cyan-400",
  escalate: "text-red-400",
  summarize: "text-white",
};

const INTENT_BG: Record<ReasoningIntent, string> = {
  explore: "bg-blue-400/20",
  exploit: "bg-orange-400/20",
  validate: "bg-green-400/20",
  pivot: "bg-purple-400/20",
  replay: "bg-cyan-400/20",
  escalate: "bg-red-400/20",
  summarize: "bg-white/10",
};

const MAX_VISIBLE = 20;

// ── Component ────────────────────────────────────────────────────────────────

export function ReasoningStream({ events }: ReasoningStreamProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    const el = scrollRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [events.length]);

  const visible = events.slice(-MAX_VISIBLE);

  return (
    <div
      ref={scrollRef}
      className="h-full overflow-y-auto font-mono text-xs leading-relaxed px-3 py-2 bg-[hsl(var(--card))] rounded-lg border border-[hsl(var(--border))]"
    >
      {visible.length === 0 && (
        <div className="text-gray-500 py-4 text-center">
          Waiting for reasoning events...
        </div>
      )}

      {visible.map((evt, i) => {
        const intent: ReasoningIntent =
          (evt.reasoningIntent || evt.intent || "summarize") as ReasoningIntent;
        const colorClass = INTENT_COLORS[intent] || "text-white";
        const bgClass = INTENT_BG[intent] || "bg-white/10";
        const timestamp = formatTimestamp(evt.timestamp);
        const message: string = evt.message || evt.detail || "";
        const target: string = evt.target || "";

        return (
          <div key={`${evt.timestamp}-${i}`} className="flex items-start gap-2 py-0.5">
            <span className="text-gray-500 shrink-0">{timestamp}</span>
            <span
              className={`${colorClass} ${bgClass} px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase shrink-0`}
            >
              {intent}
            </span>
            <span className="text-gray-300 break-all">
              {message}
              {target ? (
                <span className="text-gray-500">
                  {" "}
                  &rarr; <span className="text-gray-400">{target}</span>
                </span>
              ) : null}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTimestamp(ts: string | undefined): string {
  if (!ts) return "--:--:--";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "--:--:--";
  }
}
