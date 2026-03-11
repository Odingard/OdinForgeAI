/**
 * OdinForge v3.0 — Continuous Exposure Dashboard
 *
 * Shows org-wide exposure trend, SLA status, schedule controls,
 * and alert feed across all breach chains.
 */

import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import {
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  Clock,
  CheckCircle2,
  Calendar,
  Bell,
  BellOff,
  RefreshCw,
  Shield,
  XCircle,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ExposureSummary {
  organizationId: string;
  totalChains: number;
  activeChains: number;
  scheduledChains: number;
  slaBreached: number;
  slaDue: number;
  avgRiskScore: number;
  riskTrend: "improving" | "worsening" | "stable";
  criticalChains: any[];
  overdueSlaChains: any[];
  recentAlerts: any[];
  exposureByDay: Array<{ date: string; avgScore: number; chainCount: number }>;
}

interface ChainAlert {
  id: string;
  chainId: string;
  chainName: string;
  alertType: string;
  severity: string;
  title: string;
  message: string;
  previousScore?: number;
  currentScore?: number;
  deltaScore?: number;
  dismissed: boolean;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Sparkline chart — exposure over time
// ---------------------------------------------------------------------------

function ExposureChart({ data }: { data: Array<{ date: string; avgScore: number }> }) {
  if (!data || data.length < 2) {
    return (
      <div className="flex items-center justify-center h-[80px]" style={{ color: "var(--falcon-t4)", fontSize: 11 }}>
        No trend data yet — runs will populate this chart
      </div>
    );
  }

  const W = 100; // percentage-based SVG viewport
  const H = 60;
  const PAD = 4;

  const scores = data.map((d) => d.avgScore);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1;

  const coords = data.map((d, i) => ({
    x: PAD + (i / (data.length - 1)) * (W - PAD * 2),
    y: PAD + ((max - d.avgScore) / range) * (H - PAD * 2),
  }));

  const linePath = coords.reduce((p, pt, i) => {
    if (i === 0) return `M ${pt.x} ${pt.y}`;
    const prev = coords[i - 1];
    const cpx = (prev.x + pt.x) / 2;
    return `${p} C ${cpx} ${prev.y} ${cpx} ${pt.y} ${pt.x} ${pt.y}`;
  }, "");

  const areaPath = `${linePath} L ${coords[coords.length - 1].x} ${H} L ${coords[0].x} ${H} Z`;

  const last = scores[scores.length - 1];
  const first = scores[0];
  const lineColor = last < first ? "var(--falcon-green)" : last > first ? "var(--falcon-red)" : "var(--falcon-t3)";

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: 80 }}>
      <defs>
        <linearGradient id="exp-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={lineColor} stopOpacity={0.25} />
          <stop offset="100%" stopColor={lineColor} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={areaPath} fill="url(#exp-grad)" />
      <path d={linePath} fill="none" stroke={lineColor} strokeWidth={1.5} strokeLinecap="round" />
      <circle cx={coords[coords.length - 1].x} cy={coords[coords.length - 1].y} r={2.5} fill={lineColor} />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// SLA Badge
// ---------------------------------------------------------------------------

export function SlaBadge({ chain }: { chain: any }) {
  if (!chain.slaDeadline) return null;

  const deadline = new Date(chain.slaDeadline);
  const now = new Date();
  const daysLeft = Math.ceil((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  const breached = !!chain.slaBreachedAt || daysLeft < 0;

  if (breached) {
    return (
      <span
        className="font-mono text-[9px] tracking-[0.06em] px-[5px] py-[2px] rounded"
        style={{ background: "rgba(239,68,68,0.15)", color: "var(--falcon-red)", border: "1px solid rgba(239,68,68,0.3)" }}
      >
        SLA BREACHED
      </span>
    );
  }

  if (daysLeft <= 7) {
    return (
      <span
        className="font-mono text-[9px] tracking-[0.06em] px-[5px] py-[2px] rounded"
        style={{ background: "rgba(251,191,36,0.15)", color: "var(--falcon-yellow)", border: "1px solid rgba(251,191,36,0.3)" }}
      >
        SLA {daysLeft}d
      </span>
    );
  }

  return (
    <span
      className="font-mono text-[9px] tracking-[0.06em] px-[5px] py-[2px] rounded"
      style={{ background: "rgba(34,197,94,0.1)", color: "var(--falcon-green)", border: "1px solid rgba(34,197,94,0.2)" }}
    >
      SLA {daysLeft}d
    </span>
  );
}

// ---------------------------------------------------------------------------
// Schedule Badge
// ---------------------------------------------------------------------------

export function ScheduleBadge({ chain }: { chain: any }) {
  const sc = chain.scheduleConfig;
  if (!sc?.enabled) return null;

  const nextRun = sc.nextRunAt ? new Date(sc.nextRunAt) : null;
  const label = nextRun
    ? `Next: ${nextRun.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
    : sc.frequency;

  return (
    <span
      className="font-mono text-[9px] tracking-[0.06em] px-[5px] py-[2px] rounded flex items-center gap-1"
      style={{ background: "rgba(96,165,250,0.1)", color: "var(--falcon-blue-hi)", border: "1px solid rgba(96,165,250,0.2)" }}
    >
      <Calendar style={{ width: 8, height: 8 }} />
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Schedule Controls Panel
// ---------------------------------------------------------------------------

export function SchedulePanel({ chain, onClose }: { chain: any; onClose: () => void }) {
  const { toast } = { toast: (x: any) => console.log(x) }; // minimal — no import needed

  const setScheduleMutation = useMutation({
    mutationFn: (body: any) =>
      apiRequest("POST", `/api/breach-chains/${chain.id}/schedule`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      onClose();
    },
  });

  const disableMutation = useMutation({
    mutationFn: () =>
      fetch(`/api/breach-chains/${chain.id}/schedule`, { method: "DELETE" }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      onClose();
    },
  });

  const [freq, setFreq] = useState<string>("weekly");
  const [timeOfDay, setTimeOfDay] = useState("02:00");
  const [dayOfWeek, setDayOfWeek] = useState(1);

  const sc = chain.scheduleConfig;
  const isEnabled = sc?.enabled;

  return (
    <div
      className="p-4 rounded-lg space-y-4"
      style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
    >
      <div className="flex items-center justify-between">
        <div className="text-[13px] font-semibold" style={{ color: "var(--falcon-t1)" }}>
          <Calendar style={{ width: 13, height: 13, display: "inline", marginRight: 6 }} />
          Schedule Re-run
        </div>
        <button onClick={onClose} style={{ color: "var(--falcon-t3)" }}>
          <XCircle style={{ width: 14, height: 14 }} />
        </button>
      </div>

      {isEnabled && sc?.nextRunAt && (
        <div className="text-[11px]" style={{ color: "var(--falcon-t3)" }}>
          Currently scheduled: <span style={{ color: "var(--falcon-t1)" }}>{sc.frequency}</span>, next run {new Date(sc.nextRunAt).toLocaleString()}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="font-mono text-[9px] tracking-[0.1em] uppercase block mb-1" style={{ color: "var(--falcon-t4)" }}>Frequency</label>
          <select
            value={freq}
            onChange={(e) => setFreq(e.target.value)}
            className="w-full text-[12px] rounded px-2 py-1.5"
            style={{ background: "var(--falcon-bg)", border: "1px solid var(--falcon-border)", color: "var(--falcon-t1)" }}
          >
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>
        <div>
          <label className="font-mono text-[9px] tracking-[0.1em] uppercase block mb-1" style={{ color: "var(--falcon-t4)" }}>Time (UTC)</label>
          <input
            type="time"
            value={timeOfDay}
            onChange={(e) => setTimeOfDay(e.target.value)}
            className="w-full text-[12px] rounded px-2 py-1.5"
            style={{ background: "var(--falcon-bg)", border: "1px solid var(--falcon-border)", color: "var(--falcon-t1)" }}
          />
        </div>
        {freq === "weekly" && (
          <div className="col-span-2">
            <label className="font-mono text-[9px] tracking-[0.1em] uppercase block mb-1" style={{ color: "var(--falcon-t4)" }}>Day of Week</label>
            <select
              value={dayOfWeek}
              onChange={(e) => setDayOfWeek(Number(e.target.value))}
              className="w-full text-[12px] rounded px-2 py-1.5"
              style={{ background: "var(--falcon-bg)", border: "1px solid var(--falcon-border)", color: "var(--falcon-t1)" }}
            >
              {["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"].map((d, i) => (
                <option key={d} value={i}>{d}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="flex gap-2">
        <button
          onClick={() => setScheduleMutation.mutate({ enabled: true, frequency: freq, timeOfDay, dayOfWeek })}
          disabled={setScheduleMutation.isPending}
          className="flex-1 py-1.5 rounded text-[12px] font-medium"
          style={{ background: "var(--falcon-red)", color: "#fff" }}
        >
          {setScheduleMutation.isPending ? "Saving…" : isEnabled ? "Update Schedule" : "Enable Schedule"}
        </button>
        {isEnabled && (
          <button
            onClick={() => disableMutation.mutate()}
            disabled={disableMutation.isPending}
            className="px-3 py-1.5 rounded text-[12px]"
            style={{ border: "1px solid var(--falcon-border)", color: "var(--falcon-t3)" }}
          >
            Disable
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert Feed
// ---------------------------------------------------------------------------

function AlertCard({ alert, onDismiss }: { alert: ChainAlert; onDismiss: () => void }) {
  const colors: Record<string, string> = {
    critical: "var(--falcon-red)",
    high: "var(--falcon-yellow)",
    medium: "var(--falcon-blue-hi)",
    low: "var(--falcon-green)",
  };
  const color = colors[alert.severity] ?? "var(--falcon-t3)";

  const typeIcon: Record<string, string> = {
    new_breach_path: "🔴",
    sla_breach: "⏰",
    risk_worsened: "📈",
    risk_improved: "📉",
    schedule_failed: "⚠️",
  };

  const age = (() => {
    const ms = Date.now() - new Date(alert.createdAt).getTime();
    const h = Math.floor(ms / 3600000);
    if (h < 1) return "Just now";
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  })();

  return (
    <div
      className="p-3 rounded-lg"
      style={{ background: "var(--falcon-panel)", border: `1px solid ${color}33` }}
    >
      <div className="flex items-start gap-2">
        <span style={{ fontSize: 14, lineHeight: 1 }}>{typeIcon[alert.alertType] ?? "🔔"}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-[12px] font-medium" style={{ color: "var(--falcon-t1)" }}>{alert.title}</span>
            <span className="font-mono text-[9px]" style={{ color: "var(--falcon-t4)" }}>{age}</span>
          </div>
          <div className="text-[11px]" style={{ color: "var(--falcon-t3)" }}>{alert.message}</div>
          {alert.deltaScore !== null && alert.deltaScore !== undefined && (
            <div className="mt-1 font-mono text-[10px]" style={{ color }}>
              {alert.deltaScore > 0 ? `+${alert.deltaScore}` : alert.deltaScore} pts
              {alert.previousScore !== null && alert.previousScore !== undefined && ` (${alert.previousScore} → ${alert.currentScore})`}
            </div>
          )}
        </div>
        <button onClick={onDismiss} style={{ color: "var(--falcon-t4)", flexShrink: 0 }}>
          <BellOff style={{ width: 12, height: 12 }} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ExposureDashboard
// ---------------------------------------------------------------------------

import { useState } from "react";

export function ExposureDashboard() {
  const { data: summary, isLoading } = useQuery<ExposureSummary>({
    queryKey: ["/api/breach-chains/exposure-summary"],
    queryFn: () => fetch("/api/breach-chains/exposure-summary").then((r) => r.json()),
    refetchInterval: 60_000,
  });

  const { data: alertData } = useQuery<{ total: number; unread: number; alerts: ChainAlert[] }>({
    queryKey: ["/api/breach-chain-alerts"],
    queryFn: () => fetch("/api/breach-chain-alerts").then((r) => r.json()),
    refetchInterval: 30_000,
  });

  const dismissMutation = useMutation({
    mutationFn: (alertId: string) =>
      fetch(`/api/breach-chain-alerts/${alertId}/dismiss`, { method: "POST" }).then((r) => r.json()),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/breach-chain-alerts"] }),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-5 w-5 border-2 border-falcon-red border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const s = summary;
  const alerts = alertData?.alerts ?? [];

  const trendIcon = s?.riskTrend === "improving"
    ? <TrendingDown style={{ width: 14, height: 14, color: "var(--falcon-green)" }} />
    : s?.riskTrend === "worsening"
    ? <TrendingUp style={{ width: 14, height: 14, color: "var(--falcon-red)" }} />
    : <Minus style={{ width: 14, height: 14, color: "var(--falcon-t3)" }} />;

  const trendLabel = s?.riskTrend === "improving" ? "Improving" : s?.riskTrend === "worsening" ? "Worsening" : "Stable";
  const trendColor = s?.riskTrend === "improving" ? "var(--falcon-green)" : s?.riskTrend === "worsening" ? "var(--falcon-red)" : "var(--falcon-t3)";

  return (
    <div className="space-y-5">

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          {
            label: "Avg Risk Score",
            value: s?.avgRiskScore ?? "—",
            sub: <span style={{ color: trendColor }} className="flex items-center gap-1">{trendIcon} {trendLabel}</span>,
            color: (s?.avgRiskScore ?? 0) >= 70 ? "var(--falcon-red)" : (s?.avgRiskScore ?? 0) >= 50 ? "var(--falcon-yellow)" : "var(--falcon-green)",
          },
          {
            label: "SLA Breached",
            value: s?.slaBreached ?? 0,
            sub: <span style={{ color: "var(--falcon-t4)" }}>{s?.slaDue ?? 0} due soon</span>,
            color: (s?.slaBreached ?? 0) > 0 ? "var(--falcon-red)" : "var(--falcon-t1)",
          },
          {
            label: "Active Chains",
            value: s?.activeChains ?? 0,
            sub: <span style={{ color: "var(--falcon-t4)" }}>{s?.totalChains ?? 0} total</span>,
            color: "var(--falcon-t1)",
          },
          {
            label: "Scheduled",
            value: s?.scheduledChains ?? 0,
            sub: <span style={{ color: "var(--falcon-t4)" }}>auto re-runs</span>,
            color: "var(--falcon-blue-hi)",
          },
        ].map((kpi) => (
          <div
            key={kpi.label}
            className="p-4 rounded-lg"
            style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
          >
            <div className="font-mono text-[9px] tracking-[0.16em] uppercase mb-1" style={{ color: "var(--falcon-t4)" }}>
              {kpi.label}
            </div>
            <div className="text-[28px] font-bold leading-none mb-1" style={{ color: kpi.color }}>
              {kpi.value}
            </div>
            <div className="text-[11px] flex items-center gap-1">{kpi.sub}</div>
          </div>
        ))}
      </div>

      {/* Exposure over time chart */}
      <div
        className="p-4 rounded-lg"
        style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
      >
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-[13px] font-semibold" style={{ color: "var(--falcon-t1)" }}>
              Exposure Over Time
            </div>
            <div className="text-[11px]" style={{ color: "var(--falcon-t3)" }}>
              Average breach chain risk score — last 30 days
            </div>
          </div>
          {s?.riskTrend && (
            <div className="flex items-center gap-1.5 font-mono text-[10px]" style={{ color: trendColor }}>
              {trendIcon}
              {trendLabel}
            </div>
          )}
        </div>
        <ExposureChart data={s?.exposureByDay ?? []} />
        <div className="flex justify-between mt-1">
          <span className="font-mono text-[9px]" style={{ color: "var(--falcon-t4)" }}>
            {s?.exposureByDay?.[0]?.date ?? "—"}
          </span>
          <span className="font-mono text-[9px]" style={{ color: "var(--falcon-t4)" }}>
            {s?.exposureByDay?.[s.exposureByDay.length - 1]?.date ?? "today"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Critical chains */}
        <div
          className="p-4 rounded-lg"
          style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
        >
          <div className="text-[13px] font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--falcon-t1)" }}>
            <Shield style={{ width: 13, height: 13, color: "var(--falcon-red)" }} />
            Critical Chains
          </div>
          {(s?.criticalChains ?? []).length === 0 ? (
            <div className="text-[11px]" style={{ color: "var(--falcon-t4)" }}>No critical breach chains</div>
          ) : (
            <div className="space-y-2">
              {(s?.criticalChains ?? []).map((chain: any) => (
                <div key={chain.id} className="flex items-center justify-between">
                  <div className="text-[12px]" style={{ color: "var(--falcon-t1)" }}>{chain.name}</div>
                  <div className="flex items-center gap-2">
                    <SlaBadge chain={chain} />
                    <span
                      className="font-mono text-[12px] font-bold"
                      style={{ color: (chain.overallRiskScore ?? 0) >= 85 ? "var(--falcon-red)" : "var(--falcon-yellow)" }}
                    >
                      {chain.overallRiskScore ?? 0}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Alert feed */}
        <div
          className="p-4 rounded-lg"
          style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
        >
          <div className="text-[13px] font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--falcon-t1)" }}>
            <Bell style={{ width: 13, height: 13, color: "var(--falcon-yellow)" }} />
            Alerts
            {alerts.length > 0 && (
              <span
                className="font-mono text-[9px] px-1.5 py-0.5 rounded-full"
                style={{ background: "var(--falcon-red)", color: "#fff" }}
              >
                {alerts.length}
              </span>
            )}
          </div>
          {alerts.length === 0 ? (
            <div className="text-[11px] flex items-center gap-2" style={{ color: "var(--falcon-t4)" }}>
              <CheckCircle2 style={{ width: 13, height: 13, color: "var(--falcon-green)" }} />
              No active alerts
            </div>
          ) : (
            <div className="space-y-2 max-h-[200px] overflow-y-auto">
              {alerts.map((alert) => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  onDismiss={() => dismissMutation.mutate(alert.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* SLA-breached chains */}
      {(s?.overdueSlaChains ?? []).length > 0 && (
        <div
          className="p-4 rounded-lg"
          style={{ background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.3)" }}
        >
          <div className="text-[13px] font-semibold mb-3 flex items-center gap-2" style={{ color: "var(--falcon-red)" }}>
            <AlertTriangle style={{ width: 13, height: 13 }} />
            SLA Breached — Immediate Action Required
          </div>
          <div className="space-y-2">
            {(s?.overdueSlaChains ?? []).map((chain: any) => (
              <div key={chain.id} className="flex items-center justify-between">
                <div className="text-[12px]" style={{ color: "var(--falcon-t1)" }}>{chain.name}</div>
                <div className="flex items-center gap-3">
                  <span className="text-[11px]" style={{ color: "var(--falcon-t3)" }}>
                    SLA: {chain.slaDays ?? 30} days
                  </span>
                  <span className="font-mono text-[12px] font-bold" style={{ color: "var(--falcon-red)" }}>
                    {chain.overallRiskScore ?? 0}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
