import { cn } from "@/lib/utils";
import { ReactNode } from "react";

interface GlowChartContainerProps {
  children: ReactNode;
  title?: string;
  description?: string;
  glowColor?: "red" | "cyan" | "green" | "purple" | "none";
  className?: string;
  actions?: ReactNode;
}

export function GlowChartContainer({
  children,
  title,
  description,
  glowColor = "cyan",
  className,
  actions
}: GlowChartContainerProps) {
  const glowClass = glowColor !== "none" ? `glow-${glowColor}-sm` : "";

  return (
    <div className={cn(
      "glass border border-border/50 rounded-lg p-6",
      glowClass,
      "transition-all duration-300 hover:border-border",
      className
    )}>
      {(title || actions) && (
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1">
            {title && (
              <h3 className="text-lg font-semibold text-foreground">{title}</h3>
            )}
            {description && (
              <p className="text-sm text-muted-foreground/80 mt-1">{description}</p>
            )}
          </div>
          {actions && (
            <div className="ml-4">{actions}</div>
          )}
        </div>
      )}

      <div className="relative">
        {/* Subtle scan line effect on hover */}
        <div className="absolute inset-0 pointer-events-none opacity-0 hover:opacity-100 transition-opacity">
          <div className="scan-line" />
        </div>

        {children}
      </div>
    </div>
  );
}

interface MetricBadgeProps {
  label: string;
  value: string | number;
  trend?: "up" | "down" | "neutral";
  glowColor?: "red" | "cyan" | "green" | "purple";
  className?: string;
}

export function MetricBadge({
  label,
  value,
  trend,
  glowColor = "cyan",
  className
}: MetricBadgeProps) {
  const trendIcon = trend === "up" ? "↗" : trend === "down" ? "↘" : "→";
  const trendColor =
    trend === "up" ? "text-green-400" :
    trend === "down" ? "text-red-400" :
    "text-muted-foreground";

  return (
    <div className={cn(
      "glass border border-border/50 rounded-lg px-4 py-3",
      `glow-${glowColor}-sm`,
      className
    )}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-xs text-muted-foreground/80 uppercase tracking-wider font-medium truncate">
            {label}
          </p>
          <p className={cn(
            "text-2xl font-bold mt-1 tabular-nums",
            `text-${glowColor === "red" ? "red" : glowColor === "green" ? "emerald" : glowColor}-400`
          )}>
            {value}
          </p>
        </div>
        {trend && (
          <div className={cn("text-lg font-bold", trendColor)}>
            {trendIcon}
          </div>
        )}
      </div>
    </div>
  );
}

interface ChartLegendProps {
  items: Array<{
    label: string;
    color: string;
    value?: string | number;
  }>;
  className?: string;
}

export function ChartLegend({ items, className }: ChartLegendProps) {
  return (
    <div className={cn("flex flex-wrap gap-4", className)}>
      {items.map((item, index) => (
        <div key={index} className="flex items-center gap-2">
          <div
            className="h-3 w-3 rounded-full"
            style={{
              backgroundColor: item.color,
              boxShadow: `0 0 8px ${item.color}40`
            }}
          />
          <span className="text-sm text-muted-foreground">
            {item.label}
            {item.value !== undefined && (
              <span className="ml-1 font-semibold text-foreground">
                {item.value}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
