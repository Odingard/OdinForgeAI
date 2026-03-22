import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  className?: string;
  message?: string;
  variant?: "default" | "cyber" | "pulse";
}

export function LoadingSpinner({
  size = "md",
  className,
  message,
  variant = "default"
}: LoadingSpinnerProps) {
  const sizeConfig = {
    sm: "h-4 w-4",
    md: "h-8 w-8",
    lg: "h-12 w-12",
  };

  if (variant === "cyber") {
    return (
      <div className={cn("flex flex-col items-center justify-center gap-4", className)}>
        <div className="relative">
          {/* Outer glow */}
          <div className="absolute inset-0 glow-cyan-sm rounded-full animate-pulse" />

          {/* Rotating border */}
          <div className={cn(
            "relative rounded-full border-2 border-cyan-500/30 animate-spin",
            sizeConfig[size]
          )}>
            <div className="absolute inset-0 rounded-full border-t-2 border-cyan-500" />
          </div>

          {/* Center dot */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="h-2 w-2 rounded-full bg-cyan-500 glow-cyan-sm animate-pulse" />
          </div>
        </div>

        {message && (
          <p className="text-sm text-cyan-400 font-medium animate-pulse">
            {message}
          </p>
        )}
      </div>
    );
  }

  if (variant === "pulse") {
    return (
      <div className={cn("flex flex-col items-center justify-center gap-4", className)}>
        <div className="flex gap-2">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-3 w-3 rounded-full bg-gradient-to-br from-red-500 to-cyan-500 glow-red-sm"
              style={{
                animation: `pulse 1.5s ease-in-out ${i * 0.15}s infinite`
              }}
            />
          ))}
        </div>

        {message && (
          <p className="text-sm text-muted-foreground font-medium">
            {message}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col items-center justify-center gap-3", className)}>
      <Loader2 className={cn(sizeConfig[size], "animate-spin text-primary glow-red-sm")} />
      {message && (
        <p className="text-sm text-muted-foreground">{message}</p>
      )}
    </div>
  );
}

interface LoadingCardProps {
  className?: string;
  scanLine?: boolean;
}

export function LoadingCard({ className, scanLine = true }: LoadingCardProps) {
  return (
    <div className={cn(
      "glass border border-border/50 rounded-lg p-6",
      scanLine && "scan-line",
      className
    )}>
      <div className="space-y-4">
        <div className="h-4 bg-gradient-to-r from-muted/50 via-muted to-muted/50 rounded animate-pulse" />
        <div className="h-4 bg-gradient-to-r from-muted/50 via-muted to-muted/50 rounded animate-pulse w-3/4" />
        <div className="h-4 bg-gradient-to-r from-muted/50 via-muted to-muted/50 rounded animate-pulse w-1/2" />
      </div>
    </div>
  );
}

interface LoadingOverlayProps {
  message?: string;
  progress?: number;
}

export function LoadingOverlay({ message, progress }: LoadingOverlayProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="glass-strong border border-border/50 rounded-lg p-8 min-w-[300px] glow-cyan-sm">
        <LoadingSpinner variant="cyber" size="lg" message={message} />

        {progress !== undefined && (
          <div className="mt-6">
            <div className="h-2 bg-muted/30 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 glow-cyan-sm transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-xs text-center text-muted-foreground mt-2">{progress}%</p>
          </div>
        )}
      </div>
    </div>
  );
}
