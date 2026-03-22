import { formatDTG, formatLocalDateTime, isValidDate } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Clock } from "lucide-react";

interface DTGDisplayProps {
  date: Date | string | number | null | undefined;
  showIcon?: boolean;
  className?: string;
  compact?: boolean;
  showLocalInline?: boolean;
}

export function DTGDisplay({ date, showIcon = false, className = "", compact = false, showLocalInline = false }: DTGDisplayProps) {
  if (!isValidDate(date)) {
    return <span className={`text-muted-foreground ${className}`}>—</span>;
  }

  const dtg = formatDTG(date!);
  const localTime = formatLocalDateTime(date!);

  if (showLocalInline) {
    return (
      <span className={`font-mono ${compact ? 'text-xs' : 'text-sm'} inline-flex items-center gap-1 ${className}`}>
        {showIcon && <Clock className={`${compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} text-muted-foreground`} />}
        {dtg}
        <span className="text-muted-foreground font-sans">({localTime})</span>
      </span>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`font-mono ${compact ? 'text-xs' : 'text-sm'} cursor-help inline-flex items-center gap-1 ${className}`}>
          {showIcon && <Clock className={`${compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} text-muted-foreground`} />}
          {dtg}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="font-sans">
        <p className="text-xs text-muted-foreground">Local time</p>
        <p className="font-medium">{localTime}</p>
      </TooltipContent>
    </Tooltip>
  );
}

interface DTGRangeDisplayProps {
  startDate: Date | string | number | null | undefined;
  endDate: Date | string | number | null | undefined;
  className?: string;
  compact?: boolean;
  showLocalInline?: boolean;
}

export function DTGRangeDisplay({ startDate, endDate, className = "", compact = false, showLocalInline = false }: DTGRangeDisplayProps) {
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return <span className={`text-muted-foreground ${className}`}>—</span>;
  }

  const startDtg = formatDTG(startDate!);
  const endDtg = formatDTG(endDate!);
  const startLocal = formatLocalDateTime(startDate!);
  const endLocal = formatLocalDateTime(endDate!);

  if (showLocalInline) {
    return (
      <span className={`font-mono ${compact ? 'text-xs' : 'text-sm'} inline-flex items-center gap-1 flex-wrap ${className}`}>
        <Clock className={`${compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} text-muted-foreground`} />
        {startDtg} — {endDtg}
        <span className="text-muted-foreground font-sans text-xs">({startLocal} to {endLocal})</span>
      </span>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`font-mono ${compact ? 'text-xs' : 'text-sm'} cursor-help inline-flex items-center gap-1 ${className}`}>
          <Clock className={`${compact ? 'h-2.5 w-2.5' : 'h-3 w-3'} text-muted-foreground`} />
          {startDtg} — {endDtg}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="font-sans">
        <p className="text-xs text-muted-foreground mb-1">Local time range</p>
        <p className="font-medium text-sm">{startLocal}</p>
        <p className="text-xs text-muted-foreground">to</p>
        <p className="font-medium text-sm">{endLocal}</p>
      </TooltipContent>
    </Tooltip>
  );
}
