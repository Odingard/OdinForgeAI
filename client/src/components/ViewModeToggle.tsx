import { Button } from "@/components/ui/button";
import { Briefcase, Wrench } from "lucide-react";

interface ViewModeToggleProps {
  mode: "executive" | "engineer";
  onChange: (mode: "executive" | "engineer") => void;
}

export function ViewModeToggle({ mode, onChange }: ViewModeToggleProps) {
  return (
    <div className="inline-flex items-center gap-1 bg-muted/50 rounded-lg p-1" data-testid="view-mode-toggle">
      <Button
        variant={mode === "executive" ? "default" : "ghost"}
        size="sm"
        onClick={() => onChange("executive")}
        className="gap-1.5"
        data-testid="btn-executive-view"
      >
        <Briefcase className="h-3.5 w-3.5" />
        Executive
      </Button>
      <Button
        variant={mode === "engineer" ? "default" : "ghost"}
        size="sm"
        onClick={() => onChange("engineer")}
        className="gap-1.5"
        data-testid="btn-engineer-view"
      >
        <Wrench className="h-3.5 w-3.5" />
        Engineer
      </Button>
    </div>
  );
}
