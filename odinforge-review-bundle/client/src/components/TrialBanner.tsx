import { useUIAuth } from "@/contexts/UIAuthContext";
import { Clock, ArrowRight } from "lucide-react";

export function TrialBanner() {
  const { trial } = useUIAuth();

  // Don't show banner if no trial info or not on trial
  if (!trial || trial.status !== "trial") return null;

  const isExpired = trial.isExpired;
  const days = trial.daysRemaining ?? 0;

  if (isExpired) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-sm text-destructive">
          <Clock className="h-4 w-4 shrink-0" />
          <span className="font-medium">
            Your free trial has ended. Upgrade to continue using OdinForge.
          </span>
        </div>
        <a
          href="mailto:sales@odinforgeai.com?subject=OdinForge%20Upgrade"
          className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shrink-0"
        >
          Upgrade Now <ArrowRight className="h-3 w-3" />
        </a>
      </div>
    );
  }

  // Show warning when 3 days or less remain
  const isUrgent = days <= 3;

  return (
    <div
      className={`rounded-lg border px-4 py-2.5 flex items-center justify-between gap-4 ${
        isUrgent
          ? "border-amber-500/50 bg-amber-500/10"
          : "border-blue-500/30 bg-blue-500/5"
      }`}
    >
      <div
        className={`flex items-center gap-2 text-sm ${
          isUrgent ? "text-amber-400" : "text-blue-400"
        }`}
      >
        <Clock className="h-4 w-4 shrink-0" />
        <span>
          <span className="font-medium">Free Trial</span>
          {" — "}
          {days === 0
            ? "expires today"
            : days === 1
              ? "1 day remaining"
              : `${days} days remaining`}
        </span>
      </div>
      <a
        href="mailto:sales@odinforgeai.com?subject=OdinForge%20Upgrade"
        className="inline-flex items-center gap-1 rounded-md bg-primary/10 border border-primary/20 px-3 py-1 text-xs font-medium text-primary hover:bg-primary/20 transition-colors shrink-0"
      >
        Upgrade <ArrowRight className="h-3 w-3" />
      </a>
    </div>
  );
}
