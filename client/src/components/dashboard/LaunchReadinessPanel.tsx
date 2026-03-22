/**
 * LaunchReadinessPanel — read-only Go/No-Go verdict panel.
 *
 * Displays:
 *  - Verdict badge (GO=green, HOLD=amber, NO_GO=red)
 *  - Summary counters (pass/risk/fail)
 *  - Section cards with check rows and evidence
 *
 * Uses the project's dark theme CSS variables.
 */

import { useLaunchReadiness } from "@/hooks/useLaunchReadiness";
import type { CheckStatus, SectionResult, LaunchCheck } from "@/types/launch-readiness";

// ── Color maps ────────────────────────────────────────────────────────────────

const VERDICT_STYLE: Record<string, { bg: string; border: string; color: string; label: string }> = {
  GO:    { bg: "rgba(34,197,94,.08)",  border: "var(--green-border, rgba(34,197,94,.3))",  color: "var(--green, #22c55e)",  label: "GO" },
  HOLD:  { bg: "rgba(245,158,11,.08)", border: "var(--amber-border, rgba(245,158,11,.3))", color: "var(--amber, #f59e0b)",  label: "HOLD" },
  NO_GO: { bg: "rgba(232,56,79,.08)",  border: "var(--red-border, rgba(232,56,79,.3))",    color: "var(--red, #e8384f)",    label: "NO GO" },
};

const STATUS_DOT: Record<CheckStatus, string> = {
  PASS: "var(--green, #22c55e)",
  RISK: "var(--amber, #f59e0b)",
  FAIL: "var(--red, #e8384f)",
};

// ── Sub-components ────────────────────────────────────────────────────────────

function CheckRow({ c }: { c: LaunchCheck }) {
  return (
    <div className="flex items-start gap-2 py-[5px]" style={{ borderBottom: "1px solid var(--border, rgba(255,255,255,.06))" }}>
      <span
        className="flex-shrink-0 mt-[3px]"
        style={{ width: 7, height: 7, borderRadius: "50%", background: STATUS_DOT[c.status] }}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9px] tracking-[.1em]" style={{ color: "var(--t3, #888)", minWidth: 22 }}>
            {c.id}
          </span>
          <span className="font-mono text-[10px]" style={{ color: "var(--t1, #eee)" }}>
            {c.description}
          </span>
        </div>
        {c.evidence && (
          <div className="font-mono text-[9px] mt-[2px] pl-[30px]" style={{ color: "var(--t3, #888)", lineHeight: 1.5 }}>
            {c.evidence}
          </div>
        )}
      </div>
      <span
        className="font-mono text-[8px] tracking-[.1em] uppercase flex-shrink-0 px-[6px] py-[1px]"
        style={{
          color: STATUS_DOT[c.status],
          border: `1px solid ${STATUS_DOT[c.status]}33`,
          background: `${STATUS_DOT[c.status]}0d`,
        }}
      >
        {c.status}
      </span>
    </div>
  );
}

function SectionCard({ section }: { section: SectionResult }) {
  const dotColor = STATUS_DOT[section.status];
  return (
    <div style={{
      background: "var(--panel, #1a1a1a)",
      border: "1px solid var(--border, rgba(255,255,255,.06))",
      marginBottom: 8,
    }}>
      <div
        className="flex items-center gap-2 px-3 py-[7px]"
        style={{ borderBottom: "1px solid var(--border, rgba(255,255,255,.06))", background: "var(--panel2, #141414)" }}
      >
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: dotColor }} />
        <span className="font-mono text-[10px] tracking-[.08em] uppercase font-semibold" style={{ color: "var(--t1, #eee)" }}>
          {section.section}
        </span>
        <span className="font-mono text-[8px] ml-auto" style={{ color: "var(--t3, #888)" }}>
          {section.checks.filter((c) => c.status === "PASS").length}/{section.checks.length} passed
        </span>
      </div>
      <div className="px-3 py-1">
        {section.checks.map((c) => (
          <CheckRow key={c.id} c={c} />
        ))}
      </div>
    </div>
  );
}

// ── Main Panel ────────────────────────────────────────────────────────────────

interface LaunchReadinessPanelProps {
  chainId: string;
}

export function LaunchReadinessPanel({ chainId }: LaunchReadinessPanelProps) {
  const { report, isLoading, error } = useLaunchReadiness(chainId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-6">
        <div className="h-4 w-4 border-2 border-t-transparent rounded-full animate-spin"
          style={{ borderColor: "var(--t3, #888)", borderTopColor: "transparent" }} />
        <span className="font-mono text-[9px] ml-2" style={{ color: "var(--t4, #666)" }}>Evaluating readiness...</span>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="p-4 font-mono text-[10px]" style={{ color: "var(--t3, #888)" }}>
        {error ? `Failed to load readiness report: ${(error as Error).message}` : "No readiness data available."}
      </div>
    );
  }

  const vs = VERDICT_STYLE[report.finalVerdict] ?? VERDICT_STYLE.HOLD;

  return (
    <div className="flex flex-col h-full overflow-hidden" style={{ background: "var(--bg, #0f0f0f)" }}>
      {/* Header with verdict badge */}
      <div className="flex items-center gap-4 px-4 py-3 flex-shrink-0"
        style={{ borderBottom: "1px solid var(--border, rgba(255,255,255,.06))", background: "var(--panel, #1a1a1a)" }}>
        {/* Verdict badge */}
        <div
          className="flex items-center gap-2 px-3 py-[6px]"
          style={{ background: vs.bg, border: `1px solid ${vs.border}` }}
        >
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: vs.color }} />
          <span className="font-mono text-[13px] font-bold tracking-[.1em]" style={{ color: vs.color }}>
            {vs.label}
          </span>
        </div>

        {/* Summary counters */}
        <div className="flex items-center gap-4 ml-auto">
          {[
            { val: report.summary.pass, label: "PASS", color: "var(--green, #22c55e)" },
            { val: report.summary.risk, label: "RISK", color: "var(--amber, #f59e0b)" },
            { val: report.summary.fail, label: "FAIL", color: "var(--red, #e8384f)" },
          ].map(({ val, label, color }) => (
            <div key={label} className="flex flex-col items-center" style={{ minWidth: 36 }}>
              <div className="font-mono text-[14px] font-semibold leading-none" style={{ color: val > 0 ? color : "var(--t4, #666)" }}>
                {val}
              </div>
              <div className="font-mono text-[7px] tracking-[.12em] uppercase mt-[2px]" style={{ color: "var(--t3, #888)" }}>
                {label}
              </div>
            </div>
          ))}
        </div>

        <div className="font-mono text-[9px] tracking-[.1em] uppercase" style={{ color: "var(--t3, #888)" }}>
          launch readiness
        </div>
      </div>

      {/* Section cards */}
      <div className="flex-1 overflow-y-auto p-3">
        {report.sections.map((s) => (
          <SectionCard key={s.section} section={s} />
        ))}
      </div>
    </div>
  );
}
