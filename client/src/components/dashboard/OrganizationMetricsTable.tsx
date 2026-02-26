import { useMemo, memo } from "react";
import { buildOrgMetrics } from "@/lib/dashboard-transforms";

export const OrganizationMetricsTable = memo(function OrganizationMetricsTable({ assets = [], evaluations = [] }: { assets: any[]; evaluations: any[] }) {
  const rows = useMemo(() => buildOrgMetrics(assets, evaluations), [assets, evaluations]);

  return (
    <div className="falcon-panel">
      <div className="falcon-panel-head">
        <span className="font-mono text-[9px] font-normal tracking-[0.18em] uppercase" style={{ color: "var(--falcon-t3)" }}>
          Org Metrics
        </span>
      </div>

      {rows.length === 0 ? (
        <p className="text-[10px] text-center py-4 tracking-wider uppercase" style={{ color: "var(--falcon-t4)" }}>
          No data
        </p>
      ) : (
        <div className="p-3">
          {/* Column headers */}
          <div className="grid grid-cols-4 gap-1 pb-2 mb-1" style={{ borderBottom: "1px solid var(--falcon-border)" }}>
            {["Type", "Assets", "Crit", "Open"].map((h, i) => (
              <span
                key={h}
                className={`font-mono text-[9px] font-normal tracking-[0.18em] uppercase ${i > 0 ? "text-right" : ""}`}
                style={{ color: "var(--falcon-t3)" }}
              >
                {h}
              </span>
            ))}
          </div>

          {/* Rows */}
          {rows.map((row) => (
            <div
              key={row.type}
              className="grid grid-cols-4 gap-1 py-[5px]"
              style={{ borderBottom: "1px solid rgba(30,45,69,0.4)" }}
            >
              <span className="text-[11px] font-medium" style={{ color: "var(--falcon-t2)" }}>
                {row.name}
              </span>
              <span className="font-mono text-[10px] text-right tabular-nums" style={{ color: "var(--falcon-t3)" }}>
                {row.total}
              </span>
              <span
                className="font-mono text-[10px] text-right tabular-nums font-medium"
                style={{ color: row.critical > 0 ? "var(--falcon-red)" : "var(--falcon-t4)" }}
              >
                {row.critical}
              </span>
              <span
                className="font-mono text-[10px] text-right tabular-nums font-medium"
                style={{ color: row.open > 0 ? "var(--falcon-orange)" : "var(--falcon-t4)" }}
              >
                {row.open}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
});
