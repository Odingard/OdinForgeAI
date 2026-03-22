import { useEffect, useRef } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

interface ActionFeedProps {
  events: any[];
  currentPhase?: string | null;
}

interface FeedRow {
  timestamp: string;
  agent: string;
  agentClass: string;
  message: string;
  messageClass: string;
}

// ── Intent → agent badge mapping ─────────────────────────────────────────────
// Maps reasoning intent types to the prototype's agent badges and CSS classes.

const INTENT_TO_AGENT: Record<string, { label: string; cls: string }> = {
  explore:   { label: "RECON",    cls: "ar" },
  exploit:   { label: "EXPLOIT",  cls: "ae" },
  validate:  { label: "CONFIRM",  cls: "av" },
  pivot:     { label: "PIVOT",    cls: "ap" },
  escalate:  { label: "CLOUD",    cls: "ac" },
  replay:    { label: "LATERAL",  cls: "al" },
  summarize: { label: "SYS",      cls: "as" },
};

// ── Severity → message color class ───────────────────────────────────────────

function messageClassForEvent(evt: any): string {
  const msg: string = evt.message || evt.detail || "";
  const sev: string = (evt.severity || "").toLowerCase();
  if (sev === "critical" || msg.includes("CRITICAL"))  return "crit";
  if (sev === "high" || msg.includes("confirmed"))     return "warn";
  if (sev === "info" || evt.reasoningIntent === "summarize") return "dim";
  if (msg.includes("OK") || msg.includes("success"))   return "ok";
  return "";
}

// ── Format timestamp ─────────────────────────────────────────────────────────

function fmtTs(ts: string | undefined): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    const mm = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    return `${mm}:${ss}`;
  } catch {
    return "";
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function ActionFeed({ events, currentPhase }: ActionFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events.length]);

  const rows: FeedRow[] = events.map((evt) => {
    const intent: string = evt.reasoningIntent || evt.intent || "summarize";
    const agentInfo = INTENT_TO_AGENT[intent] || INTENT_TO_AGENT.summarize;
    return {
      timestamp: fmtTs(evt.timestamp),
      agent: agentInfo.label,
      agentClass: agentInfo.cls,
      message: evt.message || evt.detail || evt.decision || "",
      messageClass: messageClassForEvent(evt),
    };
  });

  return (
    <div className="cv-tf">
      <div className="cv-th">
        <span className="cv-th-t">live action feed</span>
        {currentPhase && (
          <span className="cv-tph">{currentPhase}</span>
        )}
      </div>
      <div className="cv-tb" ref={scrollRef}>
        {rows.length === 0 && (
          <div className="cv-row">
            <span className="cv-rt" />
            <span className="cv-ra as">SYS</span>
            <span className="cv-rm dim">awaiting engagement start...</span>
          </div>
        )}

        {rows.map((row, i) => (
          <div className="cv-row" key={i}>
            <span className="cv-rt">{row.timestamp}</span>
            <span className={`cv-ra ${row.agentClass}`}>{row.agent}</span>
            <span className={`cv-rm ${row.messageClass}`}>{row.message}</span>
          </div>
        ))}

        {/* Blinking cursor */}
        <div className="cv-row">
          <span className="cv-rt" />
          <span className="cv-rm dim">
            <span className="cv-cur" />
          </span>
        </div>
      </div>
    </div>
  );
}
