import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  Target,
  Loader2,
  TrendingUp,
  Shield,
  Clock,
  Crosshair,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface PortfolioSummary {
  activeRuns: number;
  completedRuns: number;
  totalFindings: number;
  mostExposedTarget: string | null;
  mostExposedScore: number | null;
}

interface PortfolioRun {
  chainId: string;
  target: string;
  status: string;
  findings: number;
  paths: number;
  primaryPath: string | null;
  lastUpdate: string;
}

interface RankedTarget {
  target: string;
  score: number;
  reason: string;
}

interface PortfolioPanelProps {
  onSelectRun: (chainId: string) => void;
}

// ── Status badge colours ───────────────────────────────────────────────────────

const STATUS_BADGE: Record<string, { text: string; bg: string; ring: string }> = {
  queued:      { text: "text-gray-400",  bg: "bg-gray-700/50",    ring: "ring-gray-600" },
  pending:     { text: "text-gray-400",  bg: "bg-gray-700/50",    ring: "ring-gray-600" },
  discovering: { text: "text-blue-400",  bg: "bg-blue-900/40",    ring: "ring-blue-700" },
  running:     { text: "text-blue-400",  bg: "bg-blue-900/40",    ring: "ring-blue-700" },
  exploiting:  { text: "text-orange-400",bg: "bg-orange-900/40",  ring: "ring-orange-700" },
  validating:  { text: "text-emerald-400",bg: "bg-emerald-900/40",ring: "ring-emerald-700" },
  replaying:   { text: "text-cyan-400",  bg: "bg-cyan-900/40",    ring: "ring-cyan-700" },
  completed:   { text: "text-emerald-400",bg: "bg-emerald-900/40",ring: "ring-emerald-700" },
  failed:      { text: "text-red-400",   bg: "bg-red-900/40",     ring: "ring-red-700" },
  paused:      { text: "text-yellow-400",bg: "bg-yellow-900/40",  ring: "ring-yellow-700" },
  aborted:     { text: "text-gray-400",  bg: "bg-gray-700/50",    ring: "ring-gray-600" },
};

function statusBadge(status: string) {
  const s = STATUS_BADGE[status] || STATUS_BADGE.queued;
  return s;
}

function isActiveStatus(status: string): boolean {
  return ["queued", "pending", "discovering", "running", "exploiting", "validating", "replaying", "paused"].includes(status);
}

// ── Rank medal helpers ─────────────────────────────────────────────────────────

const RANK_COLORS = [
  "text-yellow-400 border-yellow-500/50 bg-yellow-900/20",
  "text-gray-300 border-gray-500/50 bg-gray-800/40",
  "text-orange-400 border-orange-500/50 bg-orange-900/20",
];

// ── Component ──────────────────────────────────────────────────────────────────

export function PortfolioPanel({ onSelectRun }: PortfolioPanelProps) {
  const {
    data: summary,
    isLoading: summaryLoading,
  } = useQuery<PortfolioSummary>({
    queryKey: ["/api/portfolio/summary"],
    refetchInterval: (query) => {
      const d = query.state.data as PortfolioSummary | undefined;
      return d && d.activeRuns > 0 ? 5000 : false;
    },
  });

  const {
    data: runs = [],
    isLoading: runsLoading,
  } = useQuery<PortfolioRun[]>({
    queryKey: ["/api/portfolio/runs"],
    refetchInterval: (query) => {
      const d = query.state.data as PortfolioRun[] | undefined;
      const hasActive = d?.some((r) => isActiveStatus(r.status));
      return hasActive ? 5000 : false;
    },
  });

  const {
    data: ranking = [],
    isLoading: rankingLoading,
  } = useQuery<RankedTarget[]>({
    queryKey: ["/api/portfolio/ranking"],
    refetchInterval: (query) => {
      const d = query.state.data as RankedTarget[] | undefined;
      // refresh while we have no data or active runs
      return !d || d.length === 0 ? 15000 : false;
    },
  });

  const isLoading = summaryLoading || runsLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-7 h-7 text-gray-500 animate-spin" />
      </div>
    );
  }

  const safeSummary: PortfolioSummary = summary ?? {
    activeRuns: 0,
    completedRuns: 0,
    totalFindings: 0,
    mostExposedTarget: null,
    mostExposedScore: null,
  };

  return (
    <div className="flex flex-col gap-5">
      {/* ── Summary cards ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <SummaryCard
          icon={<Activity className="w-4 h-4 text-blue-400" />}
          label="Active Runs"
          value={safeSummary.activeRuns}
          accent="text-blue-400"
        />
        <SummaryCard
          icon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />}
          label="Completed"
          value={safeSummary.completedRuns}
          accent="text-emerald-400"
        />
        <SummaryCard
          icon={<AlertTriangle className="w-4 h-4 text-orange-400" />}
          label="Total Findings"
          value={safeSummary.totalFindings}
          accent="text-orange-400"
        />
        <SummaryCard
          icon={<Target className="w-4 h-4 text-red-400" />}
          label="Most Exposed"
          value={safeSummary.mostExposedTarget ?? "\u2014"}
          sub={safeSummary.mostExposedScore != null ? `Score ${safeSummary.mostExposedScore}` : undefined}
          accent="text-red-400"
        />
      </div>

      {/* ── Target ranking ────────────────────────────────────────────── */}
      {!rankingLoading && ranking.length > 0 && (
        <div className="rounded-lg border border-gray-700/60 bg-gray-900/80 p-4">
          <h3 className="text-xs font-semibold text-gray-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <TrendingUp className="w-3.5 h-3.5 text-yellow-400" />
            Top Exposed Targets
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {ranking.slice(0, 3).map((t, i) => (
              <div
                key={t.target}
                className={`flex items-start gap-3 rounded-md border p-3 ${RANK_COLORS[i] ?? "text-gray-400 border-gray-700 bg-gray-800/30"}`}
              >
                <span className="text-lg font-bold tabular-nums leading-none mt-0.5">
                  #{i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold truncate text-gray-100">
                    {t.target}
                  </div>
                  <div className="text-xs mt-0.5 font-mono tabular-nums">
                    Score {t.score}
                  </div>
                  <div className="text-[10px] mt-1 text-gray-400 leading-tight line-clamp-2">
                    {t.reason}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Run list table ────────────────────────────────────────────── */}
      <div className="rounded-lg border border-gray-700/60 bg-gray-900/80 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-700/60 flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-gray-400" />
          <h3 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            Breach Chain Runs
          </h3>
          <span className="ml-auto text-[10px] font-mono text-gray-500">
            {runs.length} total
          </span>
        </div>

        {runs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <Crosshair className="w-8 h-8 mb-3 opacity-40" />
            <p className="text-sm">No breach chain runs yet</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-gray-700/60 text-[10px] uppercase tracking-wider text-gray-500">
                  <th className="px-4 py-2.5 font-semibold">Target</th>
                  <th className="px-4 py-2.5 font-semibold">Status</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Findings</th>
                  <th className="px-4 py-2.5 font-semibold text-right">Paths</th>
                  <th className="px-4 py-2.5 font-semibold">Primary Path</th>
                  <th className="px-4 py-2.5 font-semibold">Last Update</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => {
                  const badge = statusBadge(run.status);
                  return (
                    <tr
                      key={run.chainId}
                      onClick={() => onSelectRun(run.chainId)}
                      className="border-b border-gray-800/60 hover:bg-gray-800/50 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-2.5 font-medium text-gray-100 truncate max-w-[200px]">
                        {run.target}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[10px] font-semibold ring-1 ring-inset ${badge.text} ${badge.bg} ${badge.ring}`}
                        >
                          {isActiveStatus(run.status) && (
                            <Loader2 className="w-2.5 h-2.5 animate-spin" />
                          )}
                          {run.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums text-gray-300">
                        {run.findings}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono tabular-nums text-gray-300">
                        {run.paths}
                      </td>
                      <td className="px-4 py-2.5 text-gray-400 truncate max-w-[180px]">
                        {run.primaryPath ?? "\u2014"}
                      </td>
                      <td className="px-4 py-2.5 text-gray-500 font-mono whitespace-nowrap">
                        <span className="inline-flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatRelative(run.lastUpdate)}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function SummaryCard({
  icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
}) {
  return (
    <div className="rounded-lg border border-gray-700/60 bg-gray-900/80 p-4 flex flex-col gap-1">
      <div className="flex items-center gap-2 text-gray-500 text-[10px] uppercase tracking-wider font-semibold">
        {icon}
        {label}
      </div>
      <div className={`text-xl font-bold font-mono tabular-nums ${accent} truncate`}>
        {value}
      </div>
      {sub && (
        <div className="text-[10px] text-gray-500 font-mono">{sub}</div>
      )}
    </div>
  );
}

function formatRelative(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  if (isNaN(then)) return iso;

  const diffMs = now - then;
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
