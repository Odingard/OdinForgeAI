import { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { LucideIcon } from "lucide-react";

export interface Metric {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  iconColor?: string;
  valueColor?: string;
  trend?: {
    value: number;
    label: string;
    direction: "up" | "down" | "neutral";
  };
  "data-testid"?: string;
}

export interface MetricsGridProps {
  metrics: Metric[];
  columns?: 2 | 3 | 4 | 5 | 6;
  isLoading?: boolean;
  "data-testid"?: string;
}

export function MetricsGrid({
  metrics,
  columns = 4,
  isLoading = false,
  "data-testid": testId = "metrics-grid",
}: MetricsGridProps) {
  const gridColsClass = {
    2: "grid-cols-1 md:grid-cols-2",
    3: "grid-cols-1 md:grid-cols-3",
    4: "grid-cols-1 md:grid-cols-2 lg:grid-cols-4",
    5: "grid-cols-2 md:grid-cols-3 lg:grid-cols-5",
    6: "grid-cols-2 md:grid-cols-3 lg:grid-cols-6",
  }[columns];

  if (isLoading) {
    return (
      <div className={`grid ${gridColsClass} gap-4`} data-testid={`${testId}-loading`}>
        {Array.from({ length: columns }).map((_, index) => (
          <Card key={index}>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-4 rounded-full" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className={`grid ${gridColsClass} gap-4`} data-testid={testId}>
      {metrics.map((metric, index) => {
        const Icon = metric.icon;

        return (
          <Card key={index} data-testid={metric["data-testid"] || `${testId}-metric-${index}`}>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {metric.label}
              </CardTitle>
              {Icon && (
                <Icon
                  className={`h-4 w-4 ${metric.iconColor || "text-muted-foreground"}`}
                />
              )}
            </CardHeader>
            <CardContent>
              <div
                className={`text-3xl font-bold ${metric.valueColor || ""}`}
                data-testid={`${metric["data-testid"] || `${testId}-metric-${index}`}-value`}
              >
                {metric.value}
              </div>
              {metric.trend && (
                <div className="flex items-center gap-1 mt-2 text-xs">
                  <span
                    className={`font-medium ${
                      metric.trend.direction === "up"
                        ? "text-green-500"
                        : metric.trend.direction === "down"
                        ? "text-red-500"
                        : "text-muted-foreground"
                    }`}
                  >
                    {metric.trend.direction === "up" && "↑"}
                    {metric.trend.direction === "down" && "↓"}
                    {metric.trend.direction === "neutral" && "→"}
                    {" "}{metric.trend.value}
                  </span>
                  <span className="text-muted-foreground">{metric.trend.label}</span>
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
