import { useState } from "react";
import { ShieldAlert, ShieldCheck, ShieldX, ChevronDown, ChevronRight, Clock, FileText, AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface SafetyDecision {
  id: string;
  evaluationId: string;
  organizationId?: string;
  agentName: string;
  originalAction: string;
  decision: "ALLOW" | "DENY" | "MODIFY";
  modifiedAction?: string;
  reasoning: string;
  policyReferences?: string[];
  executionMode?: "safe" | "simulation" | "live";
  timestamp?: Date | string;
}

interface SafetyDecisionsPanelProps {
  decisions: SafetyDecision[];
  showTitle?: boolean;
}

export function SafetyDecisionsPanel({ decisions, showTitle = true }: SafetyDecisionsPanelProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const toggleExpanded = (id: string) => {
    const newSet = new Set(expandedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setExpandedIds(newSet);
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case "ALLOW":
        return <ShieldCheck className="h-4 w-4 text-emerald-400" />;
      case "DENY":
        return <ShieldX className="h-4 w-4 text-red-400" />;
      case "MODIFY":
        return <ShieldAlert className="h-4 w-4 text-amber-400" />;
      default:
        return <ShieldAlert className="h-4 w-4 text-gray-400" />;
    }
  };

  const getDecisionBadge = (decision: string) => {
    const config: Record<string, { label: string; className: string }> = {
      ALLOW: { label: "Allowed", className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
      DENY: { label: "Blocked", className: "bg-red-500/10 text-red-400 border-red-500/30" },
      MODIFY: { label: "Modified", className: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
    };
    const badgeConfig = config[decision] || { label: decision, className: "bg-gray-500/10 text-gray-400 border-gray-500/30" };
    return <Badge className={badgeConfig.className}>{badgeConfig.label}</Badge>;
  };

  const getAgentBadge = (agentName: string) => {
    const agentConfig: Record<string, { className: string }> = {
      ExploitAgent: { className: "bg-purple-500/10 text-purple-400 border-purple-500/30" },
      LateralAgent: { className: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
    };
    const config = agentConfig[agentName] || { className: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" };
    return <Badge className={config.className}>{agentName}</Badge>;
  };

  const getExecutionModeBadge = (mode: string) => {
    const modeConfig: Record<string, { label: string; className: string }> = {
      safe: { label: "Safe Mode", className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
      simulation: { label: "Simulation", className: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
      live: { label: "Live", className: "bg-red-500/10 text-red-400 border-red-500/30" },
    };
    const config = modeConfig[mode] || { label: mode, className: "bg-gray-500/10 text-gray-400 border-gray-500/30" };
    return <Badge className={config.className}>{config.label}</Badge>;
  };

  const stats = {
    total: decisions.length,
    allowed: decisions.filter(d => d.decision === "ALLOW").length,
    denied: decisions.filter(d => d.decision === "DENY").length,
    modified: decisions.filter(d => d.decision === "MODIFY").length,
  };

  if (decisions.length === 0) {
    return (
      <Card className="border-border">
        <CardContent className="flex flex-col items-center justify-center p-8 text-center">
          <ShieldCheck className="h-10 w-10 text-muted-foreground mb-3" />
          <p className="text-muted-foreground">No policy checks recorded for this evaluation.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border">
      {showTitle && (
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-primary" />
              <CardTitle className="text-lg">PolicyGuardian Decisions</CardTitle>
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground" data-testid="safety-decisions-stats">
              <span className="flex items-center gap-1" data-testid="stat-allowed">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                {stats.allowed}
              </span>
              <span className="flex items-center gap-1" data-testid="stat-denied">
                <ShieldX className="h-3.5 w-3.5 text-red-400" />
                {stats.denied}
              </span>
              <span className="flex items-center gap-1" data-testid="stat-modified">
                <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                {stats.modified}
              </span>
            </div>
          </div>
        </CardHeader>
      )}

      <CardContent className={showTitle ? "pt-0" : ""}>
        <ScrollArea className="max-h-[500px]">
          <div className="space-y-2">
            {decisions.map((decision) => (
              <Collapsible
                key={decision.id}
                open={expandedIds.has(decision.id)}
                onOpenChange={() => toggleExpanded(decision.id)}
              >
                <CollapsibleTrigger className="w-full" data-testid={`safety-decision-${decision.id}`}>
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover-elevate transition-colors">
                    {getDecisionIcon(decision.decision)}
                    <div className="flex-1 text-left min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {getDecisionBadge(decision.decision)}
                        {getAgentBadge(decision.agentName)}
                        {decision.executionMode && getExecutionModeBadge(decision.executionMode)}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1 truncate">
                        {decision.originalAction.substring(0, 100)}
                        {decision.originalAction.length > 100 ? "..." : ""}
                      </p>
                    </div>
                    {expandedIds.has(decision.id) ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
                </CollapsibleTrigger>

                <CollapsibleContent>
                  <div className="mt-2 p-4 rounded-lg bg-muted/20 space-y-4">
                    <div>
                      <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-1">
                        <FileText className="h-3.5 w-3.5" />
                        Original Action
                      </div>
                      <pre className="text-sm bg-muted/50 p-3 rounded-md overflow-x-auto whitespace-pre-wrap break-words" data-testid={`text-original-action-${decision.id}`}>
                        {decision.originalAction}
                      </pre>
                    </div>

                    {decision.modifiedAction && (
                      <div>
                        <div className="flex items-center gap-2 text-sm font-medium text-amber-400 mb-1">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          Modified Action
                        </div>
                        <pre className="text-sm bg-amber-500/10 p-3 rounded-md overflow-x-auto whitespace-pre-wrap break-words border border-amber-500/20" data-testid={`text-modified-action-${decision.id}`}>
                          {decision.modifiedAction}
                        </pre>
                      </div>
                    )}

                    <div>
                      <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-1">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        Policy Reasoning
                      </div>
                      <p className="text-sm text-foreground/80" data-testid={`text-reasoning-${decision.id}`}>{decision.reasoning}</p>
                    </div>

                    {decision.policyReferences && decision.policyReferences.length > 0 && (
                      <div>
                        <div className="text-sm font-medium text-muted-foreground mb-2">
                          Policy References
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {decision.policyReferences.map((ref: string, idx: number) => (
                            <Badge key={idx} variant="outline" className="text-xs">
                              {ref}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {decision.timestamp && (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {new Date(decision.timestamp).toLocaleString()}
                      </div>
                    )}
                  </div>
                </CollapsibleContent>
              </Collapsible>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
