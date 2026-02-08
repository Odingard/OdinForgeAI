import { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { formatDistanceToNow } from "date-fns";
import { LucideIcon, Circle, CheckCircle2, XCircle, Clock, AlertTriangle } from "lucide-react";

export interface TimelineEvent {
  id: string;
  title: string;
  description?: string;
  timestamp: string | Date;
  status?: "success" | "error" | "warning" | "info" | "pending";
  icon?: LucideIcon;
  metadata?: Record<string, any>;
}

export interface StatusTimelineProps {
  events: TimelineEvent[];
  isLoading?: boolean;
  emptyMessage?: string;
  showRelativeTime?: boolean;
  "data-testid"?: string;
}

const getStatusIcon = (status?: string): LucideIcon => {
  switch (status) {
    case "success":
      return CheckCircle2;
    case "error":
      return XCircle;
    case "warning":
      return AlertTriangle;
    case "pending":
      return Clock;
    case "info":
    default:
      return Circle;
  }
};

const getStatusColor = (status?: string): string => {
  switch (status) {
    case "success":
      return "text-green-500";
    case "error":
      return "text-red-500";
    case "warning":
      return "text-amber-500";
    case "pending":
      return "text-blue-500";
    case "info":
    default:
      return "text-muted-foreground";
  }
};

const getStatusBadgeVariant = (status?: string): "default" | "destructive" | "outline" | "secondary" => {
  switch (status) {
    case "success":
      return "outline";
    case "error":
      return "destructive";
    case "warning":
      return "secondary";
    default:
      return "outline";
  }
};

export function StatusTimeline({
  events,
  isLoading = false,
  emptyMessage = "No events to display",
  showRelativeTime = true,
  "data-testid": testId = "status-timeline",
}: StatusTimelineProps) {
  if (isLoading) {
    return (
      <div className="py-8 text-center text-sm text-muted-foreground" data-testid={`${testId}-loading`}>
        Loading timeline...
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="py-8 text-center" data-testid={`${testId}-empty`}>
        <Clock className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
        <p className="text-sm text-muted-foreground">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className="space-y-0" data-testid={testId}>
      {events.map((event, index) => {
        const Icon = event.icon || getStatusIcon(event.status);
        const iconColor = getStatusColor(event.status);
        const isLast = index === events.length - 1;
        const timestamp = typeof event.timestamp === "string" ? new Date(event.timestamp) : event.timestamp;

        return (
          <div
            key={event.id}
            className="relative pb-8 last:pb-0"
            data-testid={`${testId}-event-${index}`}
          >
            {/* Timeline line */}
            {!isLast && (
              <div className="absolute left-4 top-8 bottom-0 w-px bg-border" />
            )}

            <div className="flex gap-4">
              {/* Icon */}
              <div className={`flex-shrink-0 mt-0.5 ${iconColor}`}>
                <Icon className="h-8 w-8" />
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-4 mb-1">
                  <h4 className="font-medium text-sm" data-testid={`${testId}-event-${index}-title`}>
                    {event.title}
                  </h4>
                  {event.status && (
                    <Badge variant={getStatusBadgeVariant(event.status)} className="capitalize">
                      {event.status}
                    </Badge>
                  )}
                </div>

                {event.description && (
                  <p className="text-sm text-muted-foreground mb-2" data-testid={`${testId}-event-${index}-description`}>
                    {event.description}
                  </p>
                )}

                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <time dateTime={timestamp.toISOString()} data-testid={`${testId}-event-${index}-time`}>
                    {showRelativeTime
                      ? formatDistanceToNow(timestamp, { addSuffix: true })
                      : timestamp.toLocaleString()}
                  </time>
                </div>

                {event.metadata && Object.keys(event.metadata).length > 0 && (
                  <div className="mt-2 p-2 rounded bg-muted/50 text-xs space-y-1">
                    {Object.entries(event.metadata).map(([key, value]) => (
                      <div key={key} className="flex gap-2">
                        <span className="font-medium text-muted-foreground capitalize">
                          {key.replace(/_/g, " ")}:
                        </span>
                        <span className="text-foreground">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
