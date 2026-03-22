import { ReactNode } from "react";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export interface TimeSeriesDataPoint {
  timestamp: string | number;
  [key: string]: string | number;
}

export interface TimeSeriesMetric {
  key: string;
  label: string;
  color: string;
}

export interface TimeSeriesChartProps {
  data: TimeSeriesDataPoint[];
  metrics: TimeSeriesMetric[];
  type?: "line" | "area" | "bar";
  title?: string;
  description?: string;
  timestampKey?: string;
  height?: number;
  showGrid?: boolean;
  showLegend?: boolean;
  isLoading?: boolean;
  emptyMessage?: string;
  "data-testid"?: string;
}

export function TimeSeriesChart({
  data,
  metrics,
  type = "line",
  title,
  description,
  timestampKey = "timestamp",
  height = 300,
  showGrid = true,
  showLegend = true,
  isLoading = false,
  emptyMessage = "No data available",
  "data-testid": testId = "timeseries-chart",
}: TimeSeriesChartProps) {
  const chartConfig = metrics.reduce((acc, metric) => {
    acc[metric.key] = {
      label: metric.label,
      color: metric.color,
    };
    return acc;
  }, {} as Record<string, { label: string; color: string }>);

  const renderChart = () => {
    const commonProps = {
      data,
      margin: { top: 5, right: 5, left: 5, bottom: 5 },
    };

    switch (type) {
      case "area":
        return (
          <AreaChart {...commonProps}>
            {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
            <XAxis
              dataKey={timestampKey}
              className="text-xs"
              tick={{ fontSize: 12 }}
              tickLine={false}
            />
            <YAxis className="text-xs" tick={{ fontSize: 12 }} tickLine={false} />
            <ChartTooltip content={<ChartTooltipContent />} />
            {showLegend && <Legend wrapperStyle={{ fontSize: "12px" }} />}
            {metrics.map((metric) => (
              <Area
                key={metric.key}
                type="monotone"
                dataKey={metric.key}
                stroke={metric.color}
                fill={metric.color}
                fillOpacity={0.2}
                strokeWidth={2}
                name={metric.label}
              />
            ))}
          </AreaChart>
        );

      case "bar":
        return (
          <BarChart {...commonProps}>
            {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
            <XAxis
              dataKey={timestampKey}
              className="text-xs"
              tick={{ fontSize: 12 }}
              tickLine={false}
            />
            <YAxis className="text-xs" tick={{ fontSize: 12 }} tickLine={false} />
            <ChartTooltip content={<ChartTooltipContent />} />
            {showLegend && <Legend wrapperStyle={{ fontSize: "12px" }} />}
            {metrics.map((metric) => (
              <Bar
                key={metric.key}
                dataKey={metric.key}
                fill={metric.color}
                name={metric.label}
                radius={[4, 4, 0, 0]}
              />
            ))}
          </BarChart>
        );

      case "line":
      default:
        return (
          <LineChart {...commonProps}>
            {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
            <XAxis
              dataKey={timestampKey}
              className="text-xs"
              tick={{ fontSize: 12 }}
              tickLine={false}
            />
            <YAxis className="text-xs" tick={{ fontSize: 12 }} tickLine={false} />
            <ChartTooltip content={<ChartTooltipContent />} />
            {showLegend && <Legend wrapperStyle={{ fontSize: "12px" }} />}
            {metrics.map((metric) => (
              <Line
                key={metric.key}
                type="monotone"
                dataKey={metric.key}
                stroke={metric.color}
                strokeWidth={2}
                name={metric.label}
                dot={false}
              />
            ))}
          </LineChart>
        );
    }
  };

  const content = (
    <div style={{ height }} data-testid={testId}>
      {isLoading ? (
        <div className="flex items-center justify-center h-full">
          <p className="text-sm text-muted-foreground">Loading chart data...</p>
        </div>
      ) : data.length === 0 ? (
        <div className="flex items-center justify-center h-full">
          <p className="text-sm text-muted-foreground">{emptyMessage}</p>
        </div>
      ) : (
        <ChartContainer config={chartConfig}>
          <ResponsiveContainer width="100%" height="100%">
            {renderChart()}
          </ResponsiveContainer>
        </ChartContainer>
      )}
    </div>
  );

  // If title provided, wrap in Card
  if (title || description) {
    return (
      <Card>
        <CardHeader>
          {title && <CardTitle>{title}</CardTitle>}
          {description && <CardDescription>{description}</CardDescription>}
        </CardHeader>
        <CardContent>{content}</CardContent>
      </Card>
    );
  }

  return content;
}
