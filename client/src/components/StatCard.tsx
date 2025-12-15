import { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: { value: number; isPositive: boolean };
  colorClass?: string;
}

export function StatCard({ label, value, icon: Icon, trend, colorClass = "text-foreground" }: StatCardProps) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 hover-elevate" data-testid={`stat-${label.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-xs uppercase tracking-wider text-muted-foreground truncate">{label}</p>
          <p className={`text-2xl font-bold mt-1 tabular-nums ${colorClass}`}>{value}</p>
          {trend && (
            <p className={`text-xs mt-1 ${trend.isPositive ? "text-emerald-400" : "text-red-400"}`}>
              {trend.isPositive ? "+" : ""}{trend.value}% from last week
            </p>
          )}
        </div>
        <div className={`p-2 rounded-lg bg-gradient-to-br ${
          colorClass.includes("cyan") ? "from-cyan-500/20 to-blue-500/20" :
          colorClass.includes("emerald") ? "from-emerald-500/20 to-green-500/20" :
          colorClass.includes("red") ? "from-red-500/20 to-orange-500/20" :
          colorClass.includes("amber") ? "from-amber-500/20 to-yellow-500/20" :
          "from-primary/20 to-blue-500/20"
        }`}>
          <Icon className={`h-5 w-5 ${colorClass}`} />
        </div>
      </div>
    </div>
  );
}
