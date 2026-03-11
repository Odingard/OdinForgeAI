import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Network, Shield, AlertTriangle, ChevronDown, ChevronRight,
  Globe, Server, Cloud, Database, Cpu, Search, RefreshCw,
  ExternalLink, CheckSquare, Square, Zap, X, Target,
  Eye, Clock, Activity, Lock, Unlock, TriangleAlert,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface VulnSummary {
  id: string;
  title: string;
  severity: string;
  cveId: string | null;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  isKevListed: boolean;
  affectedPort: number | null;
  affectedService: string | null;
  status: string;
  solution: string | null;
}

interface AssetRecon {
  portScan: Array<{ port: number; state: string; service?: string; banner?: string }>;
  httpFingerprint: any;
  sslCheck: any;
  dnsEnum: any;
  attackReadiness: any;
  networkExposure: any;
}

interface SurfaceAsset {
  id: string;
  assetIdentifier: string;
  displayName: string;
  assetType: string;
  status: string;
  criticality: string;
  ipAddresses: string[];
  hostname: string;
  fqdn: string | null;
  operatingSystem: string | null;
  osVersion: string | null;
  cloudProvider: string | null;
  cloudRegion: string | null;
  environment: string | null;
  discoverySource: string;
  lastSeen: string | null;
  firstDiscovered: string | null;
  openPorts: Array<{ port: number; protocol: string; service?: string; version?: string }>;
  installedSoftware: Array<{ name: string; version: string; vendor?: string }>;
  vulns: VulnSummary[];
  topVulns: VulnSummary[];
  riskScore: number;
  kevCount: number;
  criticalCount: number;
  evaluationCount: number;
  lastEvaluatedAt: string | null;
  hasRecon: boolean;
  recon: AssetRecon | null;
  subnetGroup: string;
  source: string;
}

interface SubnetGroup {
  subnet: string;
  label: string;
  assetCount: number;
  highestRisk: number;
  criticalCount: number;
  kevCount: number;
  assets: SurfaceAsset[];
}

interface AttackSurfaceData {
  groups: SubnetGroup[];
  summary: {
    totalAssets: number;
    internetFacing: number;
    criticalFindings: number;
    kevListedCount: number;
    highRiskAssets: number;
    totalVulns: number;
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const RISK_COLOR = (score: number) => {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-emerald-400";
};

const RISK_BAR = (score: number) => {
  if (score >= 75) return "bg-red-500";
  if (score >= 50) return "bg-orange-500";
  if (score >= 25) return "bg-yellow-500";
  return "bg-emerald-500";
};

const assetIcon = (type: string) => {
  if (type.includes("cloud") || type.includes("Cloud")) return Cloud;
  if (type.includes("database") || type.includes("db")) return Database;
  if (type.includes("container") || type.includes("k8s")) return Cpu;
  if (type.includes("web") || type.includes("application")) return Globe;
  return Server;
};

const fmtDate = (d: string | null) => d
  ? new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
  : "—";

const fmtTime = (d: string | null) => d
  ? new Date(d).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
  : "—";

// ─── Asset Detail Drawer ───────────────────────────────────────────────────────

function AssetDetailDrawer({ asset, onClose, onSelect, selected }: {
  asset: SurfaceAsset;
  onClose: () => void;
  onSelect: (id: string) => void;
  selected: boolean;
}) {
  const [activeTab, setActiveTab] = useState<"overview" | "vulns" | "ports" | "recon" | "software">("overview");
  const Icon = assetIcon(asset.assetType);

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "vulns",    label: `Vulnerabilities (${asset.vulns.length})` },
    { id: "ports",    label: `Ports (${asset.openPorts.length + (asset.recon?.portScan?.length || 0)})` },
    { id: "recon",    label: "Recon Data" },
    { id: "software", label: `Software (${asset.installedSoftware.length})` },
  ] as const;

  const allPorts = useMemo(() => {
    const map = new Map<number, any>();
    for (const p of asset.openPorts) map.set(p.port, { ...p, state: "open" });
    for (const p of (asset.recon?.portScan || [])) {
      if (!map.has(p.port)) map.set(p.port, p);
    }
    return Array.from(map.values()).sort((a, b) => a.port - b.port);
  }, [asset]);

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1" />
      <div
        className="w-[640px] h-full bg-[#0d1117] border-l border-white/10 flex flex-col overflow-hidden shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-white/10">
          <div className="flex items-start gap-3 min-w-0">
            <div className="w-10 h-10 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center flex-shrink-0 mt-0.5">
              <Icon className="w-5 h-5 text-[#00FF94]" />
            </div>
            <div className="min-w-0">
              <div className="font-semibold text-white text-lg truncate">{asset.displayName}</div>
              <div className="text-sm text-white/50 truncate">{asset.assetIdentifier}</div>
              <div className="flex items-center gap-2 mt-1.5">
                <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SEVERITY_COLOR[asset.criticality] || "text-white/40 bg-white/5 border-white/10"}`}>
                  {asset.criticality.toUpperCase()}
                </span>
                {asset.kevCount > 0 && (
                  <span className="text-xs px-2 py-0.5 rounded border font-bold text-red-400 bg-red-500/10 border-red-500/30">
                    {asset.kevCount} KEV
                  </span>
                )}
                <span className="text-xs text-white/40">{asset.discoverySource}</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0 ml-4">
            <button
              onClick={() => onSelect(asset.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-all ${
                selected
                  ? "bg-[#00FF94]/10 text-[#00FF94] border-[#00FF94]/30"
                  : "text-white/60 border-white/10 hover:border-white/20 hover:text-white"
              }`}
            >
              {selected ? <CheckSquare className="w-3.5 h-3.5" /> : <Square className="w-3.5 h-3.5" />}
              {selected ? "Selected" : "Select"}
            </button>
            <button onClick={onClose} className="text-white/40 hover:text-white transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Risk score bar */}
        <div className="px-5 py-3 border-b border-white/10 bg-white/[0.02]">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs text-white/50">Risk Score</span>
            <span className={`text-sm font-bold ${RISK_COLOR(asset.riskScore)}`}>{asset.riskScore}/100</span>
          </div>
          <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${RISK_BAR(asset.riskScore)}`}
              style={{ width: `${asset.riskScore}%` }}
            />
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-white/10 overflow-x-auto flex-shrink-0">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`px-4 py-2.5 text-xs font-medium whitespace-nowrap border-b-2 transition-colors ${
                activeTab === t.id
                  ? "border-[#00FF94] text-[#00FF94]"
                  : "border-transparent text-white/40 hover:text-white/70"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">

          {/* OVERVIEW */}
          {activeTab === "overview" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "IP Addresses", value: asset.ipAddresses.join(", ") || "—" },
                  { label: "Hostname",     value: asset.hostname || "—" },
                  { label: "FQDN",         value: asset.fqdn || "—" },
                  { label: "OS",           value: asset.osVersion ? `${asset.operatingSystem} ${asset.osVersion}` : asset.operatingSystem || "—" },
                  { label: "Environment",  value: asset.environment || "—" },
                  { label: "Cloud",        value: asset.cloudProvider ? `${asset.cloudProvider}${asset.cloudRegion ? ` / ${asset.cloudRegion}` : ""}` : "—" },
                  { label: "Last Seen",    value: fmtTime(asset.lastSeen) },
                  { label: "First Found",  value: fmtDate(asset.firstDiscovered) },
                  { label: "Evaluations",  value: `${asset.evaluationCount}` },
                  { label: "Last Evaluated", value: fmtTime(asset.lastEvaluatedAt) },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-white/[0.03] rounded-lg p-3 border border-white/5">
                    <div className="text-[10px] text-white/40 uppercase tracking-wider mb-1">{label}</div>
                    <div className="text-sm text-white/80 break-all">{value}</div>
                  </div>
                ))}
              </div>

              {/* Top vulns preview */}
              {asset.topVulns.length > 0 && (
                <div>
                  <div className="text-xs text-white/40 uppercase tracking-wider mb-2">Top Findings</div>
                  <div className="space-y-2">
                    {asset.topVulns.map(v => (
                      <div key={v.id} className="flex items-start gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold flex-shrink-0 mt-0.5 ${SEVERITY_COLOR[v.severity] || "text-white/40 bg-white/5 border-white/10"}`}>
                          {v.severity.toUpperCase()}
                        </span>
                        <div className="min-w-0">
                          <div className="text-sm text-white/80 leading-snug">{v.title}</div>
                          <div className="flex items-center gap-2 mt-1">
                            {v.cveId && <span className="text-[10px] text-white/40 font-mono">{v.cveId}</span>}
                            {v.epssScore != null && (
                              <span className="text-[10px] text-purple-400">EPSS {(v.epssScore * 100).toFixed(1)}%</span>
                            )}
                            {v.isKevListed && (
                              <span className="text-[10px] text-red-400 font-bold">KEV</span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* VULNERABILITIES */}
          {activeTab === "vulns" && (
            <div className="space-y-2">
              {asset.vulns.length === 0 && (
                <div className="text-center text-white/30 py-12 text-sm">No vulnerabilities recorded for this asset</div>
              )}
              {asset.vulns.map(v => (
                <div key={v.id} className="p-3 bg-white/[0.03] rounded-lg border border-white/5 hover:border-white/10 transition-colors">
                  <div className="flex items-start gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold flex-shrink-0 mt-0.5 ${SEVERITY_COLOR[v.severity] || "text-white/40 bg-white/5 border-white/10"}`}>
                      {v.severity.toUpperCase()}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-white/80">{v.title}</div>
                      <div className="flex flex-wrap items-center gap-2 mt-1.5">
                        {v.cveId && <span className="text-[10px] font-mono text-white/40 bg-white/5 px-1.5 py-0.5 rounded">{v.cveId}</span>}
                        {v.cvssScore != null && <span className="text-[10px] text-white/40">CVSS {v.cvssScore}</span>}
                        {v.epssScore != null && (
                          <span className="text-[10px] text-purple-400">
                            EPSS {(v.epssScore * 100).toFixed(1)}%
                            {v.epssPercentile != null ? ` (P${Math.round(v.epssPercentile * 100)})` : ""}
                          </span>
                        )}
                        {v.isKevListed && <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/30">CISA KEV</span>}
                        {v.affectedPort && <span className="text-[10px] text-white/40">Port {v.affectedPort}</span>}
                        {v.affectedService && <span className="text-[10px] text-white/40">{v.affectedService}</span>}
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${v.status === "open" ? "text-red-400" : "text-emerald-400"}`}>
                          {v.status}
                        </span>
                      </div>
                      {v.solution && (
                        <div className="mt-2 text-[11px] text-white/40 leading-relaxed">{v.solution}</div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* PORTS */}
          {activeTab === "ports" && (
            <div className="space-y-1.5">
              {allPorts.length === 0 && (
                <div className="text-center text-white/30 py-12 text-sm">No port data available</div>
              )}
              {allPorts.map((p, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
                  <div className="w-2 h-2 rounded-full flex-shrink-0 bg-emerald-500" />
                  <span className="font-mono text-sm text-white/80 w-16">{p.port}/{p.protocol || "tcp"}</span>
                  <span className="text-sm text-white/50 flex-1">{p.service || p.service || "unknown"}</span>
                  {(p.version || p.banner) && (
                    <span className="text-xs text-white/30 truncate max-w-[200px]">{p.version || p.banner}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* RECON */}
          {activeTab === "recon" && (
            <>
              {!asset.recon ? (
                <div className="text-center text-white/30 py-12 text-sm">No recon data available — run a scan to populate</div>
              ) : (
                <div className="space-y-4">
                  {asset.recon.httpFingerprint && (
                    <div>
                      <div className="text-xs text-white/40 uppercase tracking-wider mb-2">HTTP Fingerprint</div>
                      <div className="bg-white/[0.03] rounded-lg p-3 border border-white/5 space-y-2">
                        {Object.entries(asset.recon.httpFingerprint).filter(([, v]) => v).map(([k, v]) => (
                          <div key={k} className="flex gap-3">
                            <span className="text-xs text-white/40 w-36 flex-shrink-0 capitalize">{k.replace(/_/g, " ")}</span>
                            <span className="text-xs text-white/70 break-all">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {asset.recon.attackReadiness && (
                    <div>
                      <div className="text-xs text-white/40 uppercase tracking-wider mb-2">Attack Readiness</div>
                      <div className="bg-white/[0.03] rounded-lg p-3 border border-white/5">
                        <pre className="text-xs text-white/60 whitespace-pre-wrap break-all">
                          {JSON.stringify(asset.recon.attackReadiness, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                  {asset.recon.sslCheck && (
                    <div>
                      <div className="text-xs text-white/40 uppercase tracking-wider mb-2">SSL / TLS</div>
                      <div className="bg-white/[0.03] rounded-lg p-3 border border-white/5">
                        <pre className="text-xs text-white/60 whitespace-pre-wrap break-all">
                          {JSON.stringify(asset.recon.sslCheck, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* SOFTWARE */}
          {activeTab === "software" && (
            <div className="space-y-1.5">
              {asset.installedSoftware.length === 0 && (
                <div className="text-center text-white/30 py-12 text-sm">No software inventory available</div>
              )}
              {asset.installedSoftware.map((s, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
                  <div className="flex-1 min-w-0">
                    <span className="text-sm text-white/80">{s.name}</span>
                    {s.vendor && <span className="text-xs text-white/30 ml-2">{s.vendor}</span>}
                  </div>
                  <span className="text-xs font-mono text-white/40">{s.version}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer CTA */}
        <div className="p-4 border-t border-white/10 bg-white/[0.02] flex gap-2">
          <button
            onClick={() => onSelect(asset.id)}
            className={`flex-1 py-2 rounded text-sm font-medium transition-all border ${
              selected
                ? "bg-[#00FF94]/10 text-[#00FF94] border-[#00FF94]/30 hover:bg-[#00FF94]/20"
                : "bg-white/5 text-white/70 border-white/10 hover:bg-white/10 hover:text-white"
            }`}
          >
            {selected ? "Remove from Engagement" : "Add to Engagement"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Asset Card ────────────────────────────────────────────────────────────────

function AssetCard({ asset, selected, onToggleSelect, onDeepDive }: {
  asset: SurfaceAsset;
  selected: boolean;
  onToggleSelect: (id: string) => void;
  onDeepDive: (asset: SurfaceAsset) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const Icon = assetIcon(asset.assetType);

  return (
    <div
      className={`rounded-lg border transition-all ${
        selected ? "border-[#00FF94]/40 bg-[#00FF94]/[0.03]" : "border-white/5 bg-white/[0.02] hover:border-white/10"
      }`}
    >
      {/* Main row */}
      <div className="flex items-center gap-3 p-3">
        {/* Select checkbox */}
        <button
          onClick={() => onToggleSelect(asset.id)}
          className="flex-shrink-0 text-white/30 hover:text-[#00FF94] transition-colors"
        >
          {selected ? <CheckSquare className="w-4 h-4 text-[#00FF94]" /> : <Square className="w-4 h-4" />}
        </button>

        {/* Icon */}
        <div className="w-8 h-8 rounded bg-white/5 border border-white/10 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-white/50" />
        </div>

        {/* Identity */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-white/90 truncate">{asset.displayName}</span>
            {asset.kevCount > 0 && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 flex-shrink-0">
                {asset.kevCount} KEV
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-xs text-white/30 font-mono truncate">
              {asset.ipAddresses[0] || asset.hostname || asset.assetIdentifier}
            </span>
            {asset.operatingSystem && (
              <span className="text-xs text-white/20">· {asset.operatingSystem}</span>
            )}
          </div>
        </div>

        {/* Risk score */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="text-right">
            <div className={`text-sm font-bold ${RISK_COLOR(asset.riskScore)}`}>{asset.riskScore}</div>
            <div className="text-[10px] text-white/30">risk</div>
          </div>

          {/* Mini port pills */}
          <div className="hidden sm:flex gap-1">
            {asset.openPorts.slice(0, 4).map(p => (
              <span key={p.port} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-white/40 border border-white/5">
                {p.port}
              </span>
            ))}
            {asset.openPorts.length > 4 && (
              <span className="text-[9px] text-white/20">+{asset.openPorts.length - 4}</span>
            )}
          </div>

          {/* Severity counts */}
          <div className="flex gap-1">
            {asset.criticalCount > 0 && (
              <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{asset.criticalCount}C</span>
            )}
            {asset.vulns.filter(v => v.severity === "high").length > 0 && (
              <span className="text-[10px] font-bold text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">
                {asset.vulns.filter(v => v.severity === "high").length}H
              </span>
            )}
          </div>

          {/* Actions */}
          <button
            onClick={() => setExpanded(e => !e)}
            className="text-white/20 hover:text-white/60 transition-colors"
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
          <button
            onClick={() => onDeepDive(asset)}
            className="text-white/20 hover:text-[#00FF94] transition-colors"
            title="Deep dive"
          >
            <Eye className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Expanded inline detail */}
      {expanded && (
        <div className="px-3 pb-3 border-t border-white/5 mt-0 pt-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
          {/* Ports */}
          {asset.openPorts.length > 0 && (
            <div>
              <div className="text-[10px] text-white/30 uppercase tracking-wider mb-1.5">Open Ports</div>
              <div className="flex flex-wrap gap-1">
                {asset.openPorts.map(p => (
                  <span key={p.port} className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-white/50 border border-white/5">
                    {p.port} {p.service ? `(${p.service})` : ""}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Top vulns */}
          {asset.topVulns.length > 0 && (
            <div>
              <div className="text-[10px] text-white/30 uppercase tracking-wider mb-1.5">Top Findings</div>
              <div className="space-y-1">
                {asset.topVulns.slice(0, 3).map(v => (
                  <div key={v.id} className="flex items-center gap-2">
                    <span className={`text-[9px] px-1 py-0.5 rounded border font-bold flex-shrink-0 ${SEVERITY_COLOR[v.severity] || "text-white/40 bg-white/5 border-white/10"}`}>
                      {v.severity[0].toUpperCase()}
                    </span>
                    <span className="text-[11px] text-white/50 truncate">{v.title}</span>
                    {v.isKevListed && <span className="text-[9px] text-red-400 font-bold flex-shrink-0">KEV</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="sm:col-span-2 pt-1 flex justify-end">
            <button
              onClick={() => onDeepDive(asset)}
              className="text-xs text-[#00FF94]/60 hover:text-[#00FF94] flex items-center gap-1 transition-colors"
            >
              <Eye className="w-3 h-3" /> Full Detail
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Subnet Group ──────────────────────────────────────────────────────────────

function SubnetGroupRow({ group, selectedIds, onToggleSelect, onDeepDive, search }: {
  group: SubnetGroup;
  selectedIds: Set<string>;
  onToggleSelect: (id: string) => void;
  onDeepDive: (asset: SurfaceAsset) => void;
  search: string;
}) {
  const [open, setOpen] = useState(true);

  const filtered = useMemo(() =>
    search
      ? group.assets.filter(a =>
          a.displayName.toLowerCase().includes(search) ||
          a.hostname.toLowerCase().includes(search) ||
          a.ipAddresses.some(ip => ip.includes(search)) ||
          a.assetIdentifier.toLowerCase().includes(search)
        )
      : group.assets,
    [group.assets, search]
  );

  if (filtered.length === 0) return null;

  const isExternal = group.subnet.startsWith("External");
  const isCloud = group.subnet.startsWith("Cloud");

  return (
    <div className="mb-4">
      {/* Group header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 py-2 px-1 hover:bg-white/[0.02] rounded transition-colors group"
      >
        {open ? <ChevronDown className="w-3.5 h-3.5 text-white/30" /> : <ChevronRight className="w-3.5 h-3.5 text-white/30" />}
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {isExternal && <Globe className="w-3.5 h-3.5 text-orange-400 flex-shrink-0" />}
          {isCloud   && <Cloud  className="w-3.5 h-3.5 text-blue-400  flex-shrink-0" />}
          {!isExternal && !isCloud && <Network className="w-3.5 h-3.5 text-white/30 flex-shrink-0" />}
          <span className="text-sm font-mono text-white/70 truncate">{group.label}</span>
          <span className="text-xs text-white/30">{filtered.length} asset{filtered.length !== 1 ? "s" : ""}</span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {group.criticalCount > 0 && (
            <span className="text-xs text-red-400 font-medium">{group.criticalCount} critical</span>
          )}
          {group.kevCount > 0 && (
            <span className="text-xs text-red-400 font-bold bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
              {group.kevCount} KEV
            </span>
          )}
          <div className="flex items-center gap-1.5">
            <div className="w-24 h-1 bg-white/5 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${RISK_BAR(group.highestRisk)}`}
                style={{ width: `${group.highestRisk}%` }}
              />
            </div>
            <span className={`text-xs font-medium ${RISK_COLOR(group.highestRisk)}`}>{group.highestRisk}</span>
          </div>
        </div>
      </button>

      {open && (
        <div className="ml-5 space-y-1.5 mt-1">
          {filtered.map(asset => (
            <AssetCard
              key={asset.id}
              asset={asset}
              selected={selectedIds.has(asset.id)}
              onToggleSelect={onToggleSelect}
              onDeepDive={onDeepDive}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Engagement Builder Bar ────────────────────────────────────────────────────

function EngagementBar({ selectedIds, assets, onClear }: {
  selectedIds: Set<string>;
  assets: SurfaceAsset[];
  onClear: () => void;
}) {
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const count = selectedIds.size;

  const createChain = useMutation({
    mutationFn: async () => {
      const selected = assets.filter(a => selectedIds.has(a.id));
      const targets = selected.map(a => a.assetIdentifier || a.ipAddresses[0] || a.hostname).filter(Boolean);

      const res = await fetch("/api/breach-chains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `Attack Surface Engagement — ${new Date().toLocaleDateString()}`,
          description: `Scoped from Attack Surface Map. Targets: ${targets.slice(0, 5).join(", ")}${targets.length > 5 ? ` +${targets.length - 5} more` : ""}`,
          assetIds: targets,
          config: {
            executionMode: "live",
            enabledPhases: ["application_compromise", "credential_extraction", "cloud_iam_escalation", "container_k8s_breakout", "lateral_movement", "impact_assessment"],
            adversaryProfile: "opportunistic",
            phaseTimeoutMs: 300000,
            totalTimeoutMs: 1800000,
          },
        }),
      });
      if (!res.ok) throw new Error("Failed to create breach chain");
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      setLocation(`/breach-chains`);
    },
  });

  if (count === 0) return null;

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-4 px-5 py-3 rounded-xl border border-[#00FF94]/30 bg-[#0d1117]/95 backdrop-blur shadow-2xl shadow-[#00FF94]/5">
      <div className="flex items-center gap-2">
        <Target className="w-4 h-4 text-[#00FF94]" />
        <span className="text-sm font-medium text-white">
          <span className="text-[#00FF94] font-bold">{count}</span> asset{count !== 1 ? "s" : ""} selected
        </span>
      </div>
      <div className="h-4 w-px bg-white/10" />
      <button
        onClick={() => createChain.mutate()}
        disabled={createChain.isPending}
        className="flex items-center gap-2 px-4 py-1.5 bg-[#00FF94] text-black text-sm font-bold rounded hover:bg-[#00FF94]/90 disabled:opacity-50 transition-all"
      >
        <Zap className="w-3.5 h-3.5" />
        {createChain.isPending ? "Creating…" : "Build Engagement"}
      </button>
      <button onClick={onClear} className="text-white/30 hover:text-white/70 transition-colors">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function AttackSurface() {
  const [search, setSearch] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [drawerAsset, setDrawerAsset] = useState<SurfaceAsset | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  const { data, isLoading, isFetching, refetch } = useQuery<AttackSurfaceData>({
    queryKey: ["/api/attack-surface"],
    refetchInterval: 60000,
  });

  const allAssets = useMemo(() =>
    (data?.groups || []).flatMap(g => g.assets),
    [data]
  );

  const filteredGroups = useMemo(() => {
    if (!data) return [];
    const q = search.toLowerCase().trim();
    return data.groups.map(g => ({
      ...g,
      assets: g.assets.filter(a => {
        const matchSearch = !q ||
          a.displayName.toLowerCase().includes(q) ||
          a.hostname.toLowerCase().includes(q) ||
          a.ipAddresses.some(ip => ip.includes(q)) ||
          a.assetIdentifier.toLowerCase().includes(q);
        const matchSeverity = filterSeverity === "all" ||
          (filterSeverity === "kev" && a.kevCount > 0) ||
          (filterSeverity === "critical" && a.criticalCount > 0) ||
          (filterSeverity === "high-risk" && a.riskScore >= 50);
        return matchSearch && matchSeverity;
      }),
    })).filter(g => g.assets.length > 0);
  }, [data, search, filterSeverity]);

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const summary = data?.summary;

  return (
    <div className="min-h-screen bg-[#080b10] text-white">
      {/* Header */}
      <div className="border-b border-white/5 bg-[#0a0d14]/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#00FF94]/10 border border-[#00FF94]/20 flex items-center justify-center">
                <Network className="w-4 h-4 text-[#00FF94]" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-white">Attack Surface</h1>
                <p className="text-xs text-white/40">Your network as an attacker sees it</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => refetch()}
                disabled={isFetching}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-white/50 border border-white/10 rounded hover:text-white hover:border-white/20 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
                Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6">
        {/* Summary KPIs */}
        {summary && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
            {[
              { label: "Total Assets",     value: summary.totalAssets,     icon: Server,        color: "text-white/70" },
              { label: "Internet-Facing",  value: summary.internetFacing,  icon: Globe,         color: "text-orange-400" },
              { label: "High-Risk",        value: summary.highRiskAssets,  icon: AlertTriangle, color: "text-yellow-400" },
              { label: "Critical Findings",value: summary.criticalFindings, icon: Shield,        color: "text-red-400" },
              { label: "KEV Listed",       value: summary.kevListedCount,  icon: TriangleAlert, color: "text-red-400" },
              { label: "Total Vulns",      value: summary.totalVulns,      icon: Activity,      color: "text-white/50" },
            ].map(({ label, value, icon: Icon, color }) => (
              <div key={label} className="bg-white/[0.03] border border-white/5 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`w-3.5 h-3.5 ${color}`} />
                  <span className="text-xs text-white/40">{label}</span>
                </div>
                <div className={`text-2xl font-bold ${color}`}>{value}</div>
              </div>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center gap-3 mb-5">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
            <input
              type="text"
              placeholder="Search assets, IPs, hostnames…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-white/[0.03] border border-white/10 rounded-lg text-sm text-white placeholder-white/30 focus:outline-none focus:border-white/20"
            />
          </div>
          <div className="flex gap-1.5">
            {[
              { id: "all",       label: "All" },
              { id: "kev",       label: "KEV" },
              { id: "critical",  label: "Critical" },
              { id: "high-risk", label: "High Risk" },
            ].map(f => (
              <button
                key={f.id}
                onClick={() => setFilterSeverity(f.id)}
                className={`px-3 py-1.5 text-xs rounded border transition-all ${
                  filterSeverity === f.id
                    ? "bg-[#00FF94]/10 text-[#00FF94] border-[#00FF94]/30"
                    : "text-white/40 border-white/10 hover:text-white/70 hover:border-white/20"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          {selectedIds.size > 0 && (
            <button
              onClick={() => setSelectedIds(new Set())}
              className="text-xs text-white/30 hover:text-white/60 transition-colors"
            >
              Clear selection
            </button>
          )}
        </div>

        {/* Asset groups */}
        {isLoading ? (
          <div className="flex items-center justify-center py-24 text-white/30">
            <RefreshCw className="w-5 h-5 animate-spin mr-2" />
            Loading attack surface…
          </div>
        ) : filteredGroups.length === 0 ? (
          <div className="text-center py-24">
            <Network className="w-10 h-10 text-white/10 mx-auto mb-3" />
            <div className="text-white/30 text-sm">
              {search || filterSeverity !== "all" ? "No assets match your filters" : "No assets discovered yet — run a recon scan to populate"}
            </div>
          </div>
        ) : (
          <div className="pb-24">
            {filteredGroups.map(group => (
              <SubnetGroupRow
                key={group.subnet}
                group={group}
                selectedIds={selectedIds}
                onToggleSelect={toggleSelect}
                onDeepDive={setDrawerAsset}
                search={search.toLowerCase()}
              />
            ))}
          </div>
        )}
      </div>

      {/* Detail drawer */}
      {drawerAsset && (
        <AssetDetailDrawer
          asset={drawerAsset}
          onClose={() => setDrawerAsset(null)}
          onSelect={toggleSelect}
          selected={selectedIds.has(drawerAsset.id)}
        />
      )}

      {/* Floating engagement bar */}
      <EngagementBar
        selectedIds={selectedIds}
        assets={allAssets}
        onClear={() => setSelectedIds(new Set())}
      />
    </div>
  );
}
