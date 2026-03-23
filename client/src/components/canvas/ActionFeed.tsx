import { useEffect, useRef } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

interface ActionFeedProps {
  events: any[];
  currentPhase?: string | null;
  startedAt?: string | null;
}

interface FeedRow {
  timestamp: string;
  agent: string;
  agentClass: string;
  message: string;
  messageClass: string;
  technique?: string;
  credentialType?: string;
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
  const msg: string = evt.detail || evt.message || "";
  const sev: string = (evt.severity || "").toLowerCase();
  if (sev === "critical" || msg.includes("CRITICAL"))  return "crit";
  if (sev === "high" || msg.includes("confirmed") || msg.includes("CONFIRMED") || msg.includes("ACCEPTED"))  return "warn";
  if (sev === "info" || evt.reasoningIntent === "summarize") return "dim";
  if (msg.includes("OK") || msg.includes("success"))   return "ok";
  if (msg.includes("REJECTED") || msg.includes("failed")) return "dim";
  return "";
}

// ── Format timestamp as elapsed mm:ss from start ────────────────────────────

function fmtTs(ts: string | undefined, startIso?: string | null): string {
  if (!ts) return "";
  try {
    const d = new Date(ts).getTime();
    const s = startIso ? new Date(startIso).getTime() : d;
    const diffSec = Math.max(0, Math.floor((d - s) / 1000));
    const mm = Math.floor(diffSec / 60);
    const ss = diffSec % 60;
    return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
  } catch {
    return "";
  }
}

// ── Clean debug prefixes from messages ───────────────────────────────────────

function stripDebugPrefixes(msg: string): string {
  let out = msg;
  out = out.replace(/\[HEADLESS:[^\]]*\]\s*/g, "");
  out = out.replace(/\[PROBE\]\s*/g, "");
  out = out.replace(/\[FRONTIER:[^\]]*\]\s*/g, "");
  out = out.replace(/\[JS_EXTRACT[^\]]*\]\s*/g, "");
  out = out.replace(/\[endpoint\]\s*/g, "");
  // "GET /path — HTTP 200" → "Found /path (HTTP 200)"
  const httpMatch = out.match(/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s*—?\s*HTTP\s+(\d+)/i);
  if (httpMatch) return `Found ${httpMatch[1]} (HTTP ${httpMatch[2]})`;
  // "200 — /path" → "Found /path (HTTP 200)"
  const probeMatch = out.match(/^(\d{3})\s*—?\s*(\S+)/);
  if (probeMatch) return `Found ${probeMatch[2]} (HTTP ${probeMatch[1]})`;
  // Progress messages cleanup
  const progressMatch = out.match(/^(\d+)\/(\d+)\s+endpoints?\s+tested,?\s*(\d+)\s+validated/i);
  if (progressMatch) return `Testing: ${progressMatch[1]}/${progressMatch[2]}, ${progressMatch[3]} validated`;
  if (out.length > 60) out = out.slice(0, 57) + "...";
  return out;
}

// ── Build display message ────────────────────────────────────────────────────
// Prefer the enriched `detail` field, fall back to `message`, then `decision`.

function buildDisplayMessage(evt: any): string {
  let raw = "";
  // The enriched detail field carries technique + target + what was found
  if (evt.detail && evt.detail.length > 0) raw = evt.detail;
  // Fall back to the existing message field
  else if (evt.message && evt.message.length > 0) raw = evt.message;
  // BreachReasoningEvent uses `decision` + `rationale`
  else if (evt.decision) {
    const suffix = evt.rationale ? ` \u2014 ${evt.rationale}` : "";
    raw = `${evt.decision}${suffix}`;
  }
  return stripDebugPrefixes(raw);
}

// ── Component ────────────────────────────────────────────────────────────────

export function ActionFeed({ events, currentPhase, startedAt }: ActionFeedProps) {
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
      timestamp: fmtTs(evt.timestamp, startedAt),
      agent: agentInfo.label,
      agentClass: agentInfo.cls,
      message: buildDisplayMessage(evt),
      messageClass: messageClassForEvent(evt),
      technique: evt.technique || evt.techniqueTried || undefined,
      credentialType: evt.credentialType || undefined,
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
            <span className={`cv-rm ${row.messageClass}`}>
              {row.technique && (
                <span className="cv-tech-badge">{row.technique}</span>
              )}
              {row.credentialType && (
                <span className="cv-cred-badge">{row.credentialType}</span>
              )}
              {row.message}
            </span>
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
