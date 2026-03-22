import { CircleDot, Circle, CheckCircle, AlertCircle, ArrowRight, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { WorkflowStateMachine } from "@shared/schema";

interface WorkflowStateMachineVisualizerProps {
  workflow: WorkflowStateMachine;
}

const stateTypeIcons = {
  initial: CircleDot,
  intermediate: Circle,
  terminal: CheckCircle,
  error: AlertCircle,
};

const stateTypeColors = {
  initial: "text-cyan-400 bg-cyan-500/10",
  intermediate: "text-blue-400 bg-blue-500/10",
  terminal: "text-emerald-400 bg-emerald-500/10",
  error: "text-red-400 bg-red-500/10",
};

const authColors = {
  none: "",
  user: "border-blue-500/30",
  admin: "border-orange-500/30",
  system: "border-red-500/30",
};

export function WorkflowStateMachineVisualizer({ workflow }: WorkflowStateMachineVisualizerProps) {
  const stateMap = new Map(workflow.states.map(s => [s.id, s]));

  return (
    <div className="space-y-6" data-testid="workflow-state-machine">
      <div className="flex items-center gap-2 mb-4">
        <h4 className="font-semibold text-foreground">{workflow.name}</h4>
        <Badge variant="outline" className="text-xs">
          {workflow.states.length} states
        </Badge>
        <Badge variant="outline" className="text-xs">
          {workflow.transitions.length} transitions
        </Badge>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        {workflow.states.map((state) => {
          const Icon = stateTypeIcons[state.type];
          const colorClass = stateTypeColors[state.type];
          const authBorder = state.requiredAuth ? authColors[state.requiredAuth] : "";
          
          return (
            <div
              key={state.id}
              className={`p-3 rounded-lg border ${authBorder || "border-border"} bg-card`}
              data-testid={`state-${state.id}`}
            >
              <div className="flex items-center gap-2 mb-1">
                <div className={`p-1 rounded ${colorClass}`}>
                  <Icon className="h-4 w-4" />
                </div>
                <span className="font-medium text-sm text-foreground truncate">{state.name}</span>
              </div>
              <div className="flex items-center gap-1 mt-2">
                <Badge variant="outline" className="text-xs">
                  {state.type}
                </Badge>
                {state.requiredAuth && state.requiredAuth !== "none" && (
                  <Badge variant="outline" className="text-xs gap-1">
                    <Lock className="h-3 w-3" />
                    {state.requiredAuth}
                  </Badge>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div>
        <label className="text-xs uppercase tracking-wider text-muted-foreground mb-3 block">
          Transitions
        </label>
        <div className="space-y-2">
          {workflow.transitions.map((transition) => {
            const fromState = stateMap.get(transition.from);
            const toState = stateMap.get(transition.to);
            
            return (
              <div
                key={transition.id}
                className={`flex items-center gap-3 p-3 rounded-lg border ${
                  transition.isSecurityCritical 
                    ? "border-red-500/30 bg-red-500/5" 
                    : "border-border bg-muted/30"
                }`}
                data-testid={`transition-${transition.id}`}
              >
                <Badge variant="outline" className="font-mono text-xs">
                  {fromState?.name || transition.from}
                </Badge>
                <div className="flex items-center gap-2 flex-1">
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  <div className="flex-1">
                    <span className="text-sm text-foreground">{transition.trigger}</span>
                    {transition.guard && (
                      <span className="text-xs text-muted-foreground ml-2">
                        [guard: {transition.guard}]
                      </span>
                    )}
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                </div>
                <Badge variant="outline" className="font-mono text-xs">
                  {toState?.name || transition.to}
                </Badge>
                {transition.isSecurityCritical && (
                  <Badge className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                    Security Critical
                  </Badge>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {workflow.securityBoundaries && workflow.securityBoundaries.length > 0 && (
        <div>
          <label className="text-xs uppercase tracking-wider text-muted-foreground mb-3 block">
            Security Boundaries
          </label>
          <div className="space-y-2">
            {workflow.securityBoundaries.map((boundary, i) => (
              <div
                key={i}
                className="p-3 rounded-lg border border-purple-500/30 bg-purple-500/5"
              >
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="h-4 w-4 text-purple-400" />
                  <span className="font-medium text-foreground">{boundary.name}</span>
                  <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs">
                    {boundary.requiredPrivilege}
                  </Badge>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {boundary.statesWithin.map((stateId, j) => {
                    const state = stateMap.get(stateId);
                    return (
                      <Badge key={j} variant="outline" className="text-xs font-mono">
                        {state?.name || stateId}
                      </Badge>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
