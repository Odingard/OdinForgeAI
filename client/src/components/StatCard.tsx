import { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: { value: number; isPositive: boolean };
  colorClass?: string;
  critical?: boolean;
}

export function StatCard({ label, value, icon: Icon, trend, colorClass = "text-foreground", critical = false }: StatCardProps) {
  // Determine glow color based on colorClass
  const getGlowConfig = () => {
    if (critical) return { glow: "glow-red-sm", iconGlow: "glow-red-sm", textGlow: "text-neon-red" };
    if (colorClass.includes("cyan")) return { glow: "glow-cyan-sm", iconGlow: "", textGlow: "" };
    if (colorClass.includes("emerald") || colorClass.includes("green")) return { glow: "glow-green-sm", iconGlow: "", textGlow: "" };
    if (colorClass.includes("red")) return { glow: "glow-red-sm", iconGlow: "glow-red-sm", textGlow: "" };
    if (colorClass.includes("purple")) return { glow: "glow-purple-sm", iconGlow: "", textGlow: "" };
    return { glow: "", iconGlow: "", textGlow: "" };
  };

  const { glow, iconGlow, textGlow } = getGlowConfig();

  return (
    <div
      className={`glass border border-border/50 rounded-lg p-4 hover-elevate transition-all duration-300 ${glow} ${critical ? 'pulse-glow' : ''}`}
      data-testid={`stat-${label.toLowerCase().replace(/\s+/g, '-')}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-xs uppercase tracking-wider text-muted-foreground/80 truncate font-medium">
            {label}
          </p>
          <p className={`text-3xl font-bold mt-2 tabular-nums ${critical ? textGlow : colorClass} transition-all`}>
            {value}
          </p>
          {trend && (
            <div className="flex items-center gap-1 mt-2">
              <span className={`text-xs font-medium ${trend.isPositive ? "text-emerald-400" : "text-red-400"}`}>
                {trend.isPositive ? "↗" : "↘"} {trend.isPositive ? "+" : ""}{trend.value}%
              </span>
              <span className="text-xs text-muted-foreground/60">vs last week</span>
            </div>
          )}
        </div>
        <div className={`p-3 rounded-lg bg-gradient-to-br relative overflow-hidden ${iconGlow} ${
          colorClass.includes("cyan") ? "from-cyan-500/10 to-blue-500/10 border border-cyan-500/20" :
          colorClass.includes("emerald") || colorClass.includes("green") ? "from-emerald-500/10 to-green-500/10 border border-emerald-500/20" :
          colorClass.includes("red") ? "from-red-500/10 to-orange-500/10 border border-red-500/20" :
          colorClass.includes("amber") ? "from-amber-500/10 to-yellow-500/10 border border-amber-500/20" :
          colorClass.includes("purple") ? "from-purple-500/10 to-pink-500/10 border border-purple-500/20" :
          "from-primary/10 to-blue-500/10 border border-primary/20"
        }`}>
          {/* Animated background gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent animate-pulse opacity-0 hover:opacity-100 transition-opacity duration-500" />
          <Icon className={`h-6 w-6 ${colorClass} relative z-10`} />
        </div>
      </div>
    </div>
  );
}
