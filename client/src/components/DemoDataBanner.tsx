import { useDemoDataStatus, useClearDemoData } from "@/hooks/useDemoData";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { FlaskConical, X } from "lucide-react";
import { useState } from "react";

/**
 * Banner that shows when demo data is loaded
 * Allows users to clear the demo data
 */
export function DemoDataBanner() {
  const { data: status } = useDemoDataStatus();
  const clearDemoData = useClearDemoData();
  const [dismissed, setDismissed] = useState(false);

  // Don't show if no demo data or dismissed
  if (!status?.hasDemoData || dismissed) {
    return null;
  }

  return (
    <Alert className="relative border-purple-500/50 bg-purple-500/10">
      <FlaskConical className="h-4 w-4 text-purple-400" />
      <AlertDescription className="flex items-center justify-between gap-4 pr-8">
        <div className="flex items-center gap-2 text-sm">
          <span className="font-medium text-purple-400">Demo Mode Active</span>
          <span className="text-muted-foreground">
            You're viewing sample data. {status.counts.agents} agents and {status.counts.evaluations} evaluations loaded.
          </span>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => clearDemoData.mutate()}
          disabled={clearDemoData.isPending}
          className="shrink-0"
        >
          Clear Demo Data
        </Button>
      </AlertDescription>
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-2 top-2 h-6 w-6"
        onClick={() => setDismissed(true)}
      >
        <X className="h-3 w-3" />
      </Button>
    </Alert>
  );
}
