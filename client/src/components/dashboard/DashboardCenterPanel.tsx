import { AssetFlowSankey } from "./AssetFlowSankey";

export function DashboardCenterPanel() {
  return (
    <div
      className="rounded-lg overflow-hidden h-full min-h-[400px]"
      style={{
        background: "#06090f",
        border: "1px solid rgba(56,189,248,0.08)",
      }}
    >
      {/* Header bar */}
      <div
        className="px-4 py-2.5 flex items-center justify-between"
        style={{
          background: "rgba(6,9,15,0.95)",
          borderBottom: "1px solid rgba(56,189,248,0.08)",
        }}
      >
        <div className="flex items-center gap-3">
          <span
            style={{
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#94a3b8",
              letterSpacing: 1.5,
              textTransform: "uppercase",
              fontWeight: 600,
            }}
          >
            Exposure Map
          </span>
          <span
            style={{
              fontSize: 8,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#22c55e",
              background: "rgba(34,197,94,0.08)",
              padding: "2px 8px",
              borderRadius: 100,
              border: "1px solid rgba(34,197,94,0.15)",
              letterSpacing: 1.5,
              textTransform: "uppercase",
              fontWeight: 600,
            }}
          >
            Live
          </span>
        </div>
        <span
          style={{
            fontSize: 8,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#334155",
            letterSpacing: 1,
          }}
        >
          ASSET → FINDING FLOW
        </span>
      </div>
      <AssetFlowSankey />
    </div>
  );
}
