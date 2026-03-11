import { useQuery } from "@tanstack/react-query";

interface ComparisonNode {
  id: string;
  label: string;
  tactic?: string;
  compromiseLevel?: string;
}

interface ComparisonData {
  verdict: "IMPROVED" | "REGRESSED" | "UNCHANGED";
  summary: string;
  attackSurfaceDelta: number;
  criticalPathDelta: number;
  riskScoreDelta: number;
  nodesRemoved: ComparisonNode[];
  nodesAdded: ComparisonNode[];
  nodesWorsened: ComparisonNode[];
  nodesImproved: ComparisonNode[];
  tacticsClosed: string[];
  tacticsAdded: string[];
}

interface ApiResponse {
  comparison: ComparisonData;
}

interface ChainComparisonProps {
  chainA: { id: string; name: string };
  chainB: { id: string; name: string };
  onClose: () => void;
}

function verdictColor(verdict: string): string {
  if (verdict === "IMPROVED") return "var(--falcon-green)";
  if (verdict === "REGRESSED") return "var(--falcon-red)";
  return "var(--falcon-t3)";
}

function verdictBg(verdict: string): string {
  if (verdict === "IMPROVED") return "rgba(16,185,129,0.15)";
  if (verdict === "REGRESSED") return "rgba(239,68,68,0.15)";
  return "var(--falcon-panel-2)";
}

function deltaStr(val: number, suffix = ""): string {
  if (val === 0) return `0${suffix}`;
  return val > 0 ? `+${val}${suffix}` : `${val}${suffix}`;
}

function deltaColor(val: number, invertGood = false): string {
  if (val === 0) return "var(--falcon-t3)";
  const isGood = invertGood ? val > 0 : val < 0;
  return isGood ? "var(--falcon-green)" : "var(--falcon-red)";
}

function NodeCard({ node, variant }: { node: ComparisonNode; variant: "added" | "removed" }) {
  const isRemoved = variant === "removed";
  return (
    <div style={{
      padding: "10px 12px",
      borderRadius: 6,
      border: `1px solid ${isRemoved ? "rgba(16,185,129,0.3)" : "rgba(239,68,68,0.3)"}`,
      background: isRemoved ? "rgba(16,185,129,0.05)" : "rgba(239,68,68,0.05)",
      display: "flex",
      flexDirection: "column",
      gap: 4,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", flex: 1 }}>{node.label}</span>
        {node.tactic && (
          <span className="f-chip" style={{
            fontSize: 10,
            background: "var(--falcon-panel-2)",
            color: "var(--falcon-t2)",
          }}>{node.tactic}</span>
        )}
        {node.compromiseLevel && (
          <span className={`f-chip ${
            node.compromiseLevel === "critical" ? "f-chip-crit" :
            node.compromiseLevel === "high" ? "f-chip-high" :
            node.compromiseLevel === "medium" ? "f-chip-med" : "f-chip-low"
          }`} style={{ fontSize: 10 }}>{node.compromiseLevel}</span>
        )}
      </div>
      <p style={{ fontSize: 10, color: isRemoved ? "var(--falcon-green)" : "var(--falcon-red)", margin: 0 }}>
        {isRemoved ? "This attack vector no longer exists" : "New attack path identified"}
      </p>
    </div>
  );
}

function CompactNode({ node, color }: { node: ComparisonNode; color: string }) {
  return (
    <div style={{
      padding: "8px 12px",
      borderLeft: `3px solid ${color}`,
      background: "var(--falcon-panel-2)",
      borderRadius: "0 4px 4px 0",
      display: "flex",
      alignItems: "center",
      gap: 8,
    }}>
      <span style={{ fontSize: 12, color: "var(--falcon-t1)", flex: 1 }}>{node.label}</span>
      {node.compromiseLevel && (
        <span style={{ fontSize: 10, color, fontWeight: 600 }}>{node.compromiseLevel}</span>
      )}
    </div>
  );
}

export function ChainComparison({ chainA, chainB, onClose }: ChainComparisonProps) {
  const { data, isLoading } = useQuery<ApiResponse>({
    queryKey: [`/api/breach-chains/compare`, chainA.id, chainB.id],
    queryFn: () =>
      fetch(`/api/breach-chains/compare?a=${chainA.id}&b=${chainB.id}`).then((r) => r.json()),
  });

  const comparison = data?.comparison;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.75)",
        zIndex: 1000,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        padding: "24px 16px",
        overflowY: "auto",
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--falcon-panel)",
          border: "1px solid var(--falcon-border)",
          borderRadius: 10,
          width: "100%",
          maxWidth: 900,
          display: "flex",
          flexDirection: "column",
          gap: 0,
          overflow: "hidden",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{
          padding: "16px 20px",
          borderBottom: "1px solid var(--falcon-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
        }}>
          <div>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>
              Chain Comparison
            </h2>
            <p style={{ fontSize: 11, color: "var(--falcon-t3)", margin: "2px 0 0 0", fontFamily: "var(--font-mono)" }}>
              {chainA.name} vs {chainB.name}
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {comparison && (
              <span style={{
                fontSize: 11,
                fontWeight: 700,
                padding: "3px 10px",
                borderRadius: 4,
                color: verdictColor(comparison.verdict),
                background: verdictBg(comparison.verdict),
                letterSpacing: "0.05em",
              }}>
                {comparison.verdict}
              </span>
            )}
            <button
              style={{
                background: "transparent",
                border: "1px solid var(--falcon-border)",
                borderRadius: 4,
                color: "var(--falcon-t2)",
                cursor: "pointer",
                fontSize: 16,
                lineHeight: 1,
                padding: "4px 8px",
              }}
              onClick={onClose}
            >
              ✕
            </button>
          </div>
        </div>

        {isLoading && (
          <div style={{ padding: "48px 0", textAlign: "center", color: "var(--falcon-t3)", fontSize: 13 }}>
            Loading comparison data...
          </div>
        )}

        {!isLoading && !comparison && (
          <div style={{ padding: "48px 0", textAlign: "center", color: "var(--falcon-t3)", fontSize: 13 }}>
            No comparison data available.
          </div>
        )}

        {comparison && (
          <div style={{ padding: "20px", display: "flex", flexDirection: "column", gap: 20 }}>
            {/* Summary bar */}
            <div style={{
              padding: "14px 16px",
              borderRadius: 6,
              background: verdictBg(comparison.verdict),
              border: `1px solid ${verdictColor(comparison.verdict)}33`,
            }}>
              <p style={{ fontSize: 12, color: "var(--falcon-t1)", margin: "0 0 10px 0" }}>
                {comparison.summary}
              </p>
              <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: deltaColor(comparison.attackSurfaceDelta),
                  }}>
                    {deltaStr(comparison.attackSurfaceDelta, "%")}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Attack Surface</span>
                </div>
                <div style={{ width: 1, background: "var(--falcon-border)" }} />
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: deltaColor(comparison.criticalPathDelta),
                  }}>
                    {deltaStr(comparison.criticalPathDelta, " steps")}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Critical Path</span>
                </div>
                <div style={{ width: 1, background: "var(--falcon-border)" }} />
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{
                    fontSize: 14,
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: deltaColor(comparison.riskScoreDelta),
                  }}>
                    {deltaStr(comparison.riskScoreDelta)}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Risk Score</span>
                </div>
              </div>
            </div>

            {/* Two-column: closed vs new */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Closed */}
              <div>
                <h3 style={{
                  fontSize: 12,
                  fontWeight: 700,
                  color: "var(--falcon-green)",
                  margin: "0 0 10px 0",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}>
                  ✓ {comparison.nodesRemoved.length} Attack Paths Closed
                </h3>
                {comparison.nodesRemoved.length === 0 ? (
                  <p style={{ fontSize: 11, color: "var(--falcon-t4)", margin: 0 }}>No paths closed</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {comparison.nodesRemoved.map((n, i) => (
                      <NodeCard key={n.id ?? i} node={n} variant="removed" />
                    ))}
                  </div>
                )}
              </div>

              {/* New threats */}
              <div>
                <h3 style={{
                  fontSize: 12,
                  fontWeight: 700,
                  color: "var(--falcon-red)",
                  margin: "0 0 10px 0",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}>
                  ⚠ {comparison.nodesAdded.length} New Vectors Discovered
                </h3>
                {comparison.nodesAdded.length === 0 ? (
                  <p style={{ fontSize: 11, color: "var(--falcon-t4)", margin: 0 }}>No new threats</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {comparison.nodesAdded.map((n, i) => (
                      <NodeCard key={n.id ?? i} node={n} variant="added" />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Worsened */}
            {comparison.nodesWorsened.length > 0 && (
              <div>
                <h3 style={{
                  fontSize: 12,
                  fontWeight: 700,
                  color: "var(--falcon-orange)",
                  margin: "0 0 10px 0",
                }}>
                  ↑ {comparison.nodesWorsened.length} Worsened
                </h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {comparison.nodesWorsened.map((n, i) => (
                    <CompactNode key={n.id ?? i} node={n} color="var(--falcon-orange)" />
                  ))}
                </div>
              </div>
            )}

            {/* Improved */}
            {comparison.nodesImproved.length > 0 && (
              <div>
                <h3 style={{
                  fontSize: 12,
                  fontWeight: 700,
                  color: "var(--falcon-green)",
                  margin: "0 0 10px 0",
                }}>
                  ↓ {comparison.nodesImproved.length} Improved
                </h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {comparison.nodesImproved.map((n, i) => (
                    <CompactNode key={n.id ?? i} node={n} color="var(--falcon-green)" />
                  ))}
                </div>
              </div>
            )}

            {/* Tactics diff */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, paddingTop: 4 }}>
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t2)", margin: "0 0 8px 0" }}>
                  Tactics Eliminated
                </h4>
                {comparison.tacticsClosed.length === 0 ? (
                  <p style={{ fontSize: 11, color: "var(--falcon-t4)", margin: 0 }}>None</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {comparison.tacticsClosed.map((t, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--falcon-t1)" }}>
                        <span style={{ color: "var(--falcon-green)", fontWeight: 700 }}>✓</span>
                        {t}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t2)", margin: "0 0 8px 0" }}>
                  New Tactics
                </h4>
                {comparison.tacticsAdded.length === 0 ? (
                  <p style={{ fontSize: 11, color: "var(--falcon-t4)", margin: 0 }}>None</p>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {comparison.tacticsAdded.map((t, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--falcon-t1)" }}>
                        <span style={{ color: "var(--falcon-red)", fontWeight: 700 }}>⚠</span>
                        {t}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
