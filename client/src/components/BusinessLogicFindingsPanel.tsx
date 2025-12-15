import { AlertTriangle, ArrowRight, CheckCircle2, DollarSign, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import type { BusinessLogicFinding } from "@shared/schema";

interface BusinessLogicFindingsPanelProps {
  findings: BusinessLogicFinding[];
}

const categoryLabels: Record<string, string> = {
  payment_bypass: "Payment Bypass",
  subscription_abuse: "Subscription Abuse",
  order_manipulation: "Order Manipulation",
  state_transition: "State Transition",
  privilege_escalation: "Privilege Escalation",
  workflow_bypass: "Workflow Bypass",
  race_condition: "Race Condition",
  parameter_tampering: "Parameter Tampering",
  session_abuse: "Session Abuse",
  logic_flaw: "Logic Flaw",
};

const severityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
};

export function BusinessLogicFindingsPanel({ findings }: BusinessLogicFindingsPanelProps) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No business logic findings</p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="business-logic-findings">
      {findings.map((finding, index) => (
        <Collapsible key={finding.id || index}>
          <Card className="overflow-hidden">
            <CollapsibleTrigger className="w-full text-left">
              <div className="p-4 flex items-start gap-4">
                <div className={`p-2 rounded-lg ${finding.validatedExploit ? "bg-red-500/10" : "bg-amber-500/10"}`}>
                  {finding.validatedExploit ? (
                    <XCircle className={`h-5 w-5 ${finding.validatedExploit ? "text-red-400" : "text-amber-400"}`} />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-amber-400" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <h4 className="font-semibold text-foreground">{finding.title}</h4>
                    <Badge className={severityColors[finding.severity]}>
                      {finding.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {categoryLabels[finding.category] || finding.category}
                    </Badge>
                    {finding.validatedExploit && (
                      <Badge className="bg-red-500/10 text-red-400 border-red-500/30">
                        VALIDATED
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground line-clamp-2">{finding.description}</p>
                </div>
              </div>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                      Intended Workflow
                    </label>
                    <div className="flex items-center gap-1 flex-wrap text-xs font-mono">
                      {finding.intendedWorkflow.map((step, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <span className="px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded">
                            {step}
                          </span>
                          {i < finding.intendedWorkflow.length - 1 && (
                            <ArrowRight className="h-3 w-3 text-muted-foreground" />
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                      Actual Workflow
                    </label>
                    <div className="flex items-center gap-1 flex-wrap text-xs font-mono">
                      {finding.actualWorkflow.map((step, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <span className="px-2 py-1 bg-red-500/10 text-red-400 rounded">
                            {step}
                          </span>
                          {i < finding.actualWorkflow.length - 1 && (
                            <ArrowRight className="h-3 w-3 text-muted-foreground" />
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {finding.stateViolations && finding.stateViolations.length > 0 && (
                  <div>
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                      State Violations
                    </label>
                    <div className="space-y-2">
                      {finding.stateViolations.map((violation, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs p-2 bg-muted/30 rounded-lg">
                          <Badge variant="outline">{violation.fromState}</Badge>
                          <ArrowRight className="h-3 w-3 text-red-400" />
                          <Badge variant="outline">{violation.toState}</Badge>
                          <span className="text-muted-foreground">via</span>
                          <Badge className="bg-red-500/10 text-red-400 border-red-500/30">
                            {violation.actualTransition}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                    Exploit Steps
                  </label>
                  <ol className="space-y-1 text-sm text-muted-foreground list-decimal list-inside">
                    {finding.exploitSteps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>

                {finding.businessImpact && (
                  <div className="grid grid-cols-2 gap-4">
                    {finding.businessImpact.financialLoss && (
                      <div className="flex items-center gap-2 p-2 bg-red-500/5 rounded-lg">
                        <DollarSign className="h-4 w-4 text-red-400" />
                        <div>
                          <p className="text-xs text-muted-foreground">Financial Loss</p>
                          <p className="text-sm text-foreground">{finding.businessImpact.financialLoss}</p>
                        </div>
                      </div>
                    )}
                    {finding.businessImpact.reputationalDamage && (
                      <div className="flex items-center gap-2 p-2 bg-orange-500/5 rounded-lg">
                        <AlertTriangle className="h-4 w-4 text-orange-400" />
                        <div>
                          <p className="text-xs text-muted-foreground">Reputation Risk</p>
                          <p className="text-sm text-foreground">{finding.businessImpact.reputationalDamage}</p>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                    Impact
                  </label>
                  <p className="text-sm text-foreground">{finding.impact}</p>
                </div>

                {finding.proofOfConcept && (
                  <div>
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                      Proof of Concept
                    </label>
                    <pre className="p-3 bg-muted/50 rounded-lg text-xs font-mono overflow-x-auto">
                      {finding.proofOfConcept}
                    </pre>
                  </div>
                )}
              </div>
            </CollapsibleContent>
          </Card>
        </Collapsible>
      ))}
    </div>
  );
}
