import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Code,
  Shield,
  Network,
  Bell,
  Layers,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  TrendingDown,
  AlertTriangle,
  FileCode,
  Zap,
} from "lucide-react";
import type { RemediationGuidance } from "@shared/schema";

interface RemediationPanelProps {
  guidance: RemediationGuidance;
  viewMode?: "executive" | "engineer";
}

export function RemediationPanel({ guidance, viewMode = "engineer" }: RemediationPanelProps) {
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const toggleExpanded = (id: string) => {
    setExpandedItems(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getEffortColor = (effort: "low" | "medium" | "high") => {
    switch (effort) {
      case "low": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "medium": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "high": return "bg-red-500/10 text-red-400 border-red-500/30";
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "code_fix": return <Code className="h-4 w-4" />;
      case "waf_rule": return <Shield className="h-4 w-4" />;
      case "iam_policy": return <Layers className="h-4 w-4" />;
      case "network_control": return <Network className="h-4 w-4" />;
      case "detection_rule": return <Bell className="h-4 w-4" />;
      case "compensating": return <AlertTriangle className="h-4 w-4" />;
      default: return <Zap className="h-4 w-4" />;
    }
  };

  if (viewMode === "executive") {
    return (
      <div className="space-y-6" data-testid="remediation-panel-executive">
        <div className="bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 rounded-lg p-6 border border-emerald-500/20">
          <div className="flex items-center justify-between flex-wrap gap-4 mb-4">
            <div>
              <h3 className="text-lg font-semibold text-foreground">Risk Reduction Summary</h3>
              <p className="text-sm text-muted-foreground">Implementation roadmap</p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-emerald-400">{guidance.totalRiskReduction}%</div>
              <div className="text-xs text-muted-foreground">Total Risk Reduction</div>
            </div>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed">{guidance.executiveSummary}</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground mb-2">
              <Clock className="h-4 w-4" />
              <span className="text-sm">Implementation Time</span>
            </div>
            <div className="text-xl font-semibold text-foreground">{guidance.estimatedImplementationTime}</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground mb-2">
              <Zap className="h-4 w-4" />
              <span className="text-sm">Total Actions</span>
            </div>
            <div className="text-xl font-semibold text-foreground">{guidance.prioritizedActions.length}</div>
          </div>
        </div>

        <div className="space-y-3">
          <h4 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Priority Actions</h4>
          {guidance.prioritizedActions.slice(0, 5).map((action) => (
            <div
              key={action.order}
              className="flex items-center gap-4 p-3 bg-card border border-border rounded-lg"
              data-testid={`action-item-${action.order}`}
            >
              <div className="flex items-center justify-center w-8 h-8 rounded-full bg-muted text-foreground font-medium">
                {action.order}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  {getTypeIcon(action.type)}
                  <span className="font-medium text-foreground truncate">{action.action}</span>
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                  <span>{action.timeEstimate}</span>
                  <span className="flex items-center gap-1">
                    <TrendingDown className="h-3 w-3 text-emerald-400" />
                    {action.riskReduction}% reduction
                  </span>
                </div>
              </div>
              <Badge className={getEffortColor(action.effort)}>{action.effort}</Badge>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="remediation-panel-engineer">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h3 className="font-semibold text-foreground">Remediation Guidance</h3>
          <p className="text-xs text-muted-foreground">{guidance.summary}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
            {guidance.totalRiskReduction}% Risk Reduction
          </Badge>
        </div>
      </div>

      <Tabs defaultValue="priority" className="w-full">
        <TabsList className="flex flex-wrap gap-1 h-auto p-1">
          <TabsTrigger value="priority" className="gap-1.5 text-xs" data-testid="tab-priority">
            <Zap className="h-3.5 w-3.5" />
            Priority
          </TabsTrigger>
          {guidance.codeFixes && guidance.codeFixes.length > 0 && (
            <TabsTrigger value="code" className="gap-1.5 text-xs" data-testid="tab-code">
              <Code className="h-3.5 w-3.5" />
              Code ({guidance.codeFixes.length})
            </TabsTrigger>
          )}
          {guidance.wafRules && guidance.wafRules.length > 0 && (
            <TabsTrigger value="waf" className="gap-1.5 text-xs" data-testid="tab-waf">
              <Shield className="h-3.5 w-3.5" />
              WAF ({guidance.wafRules.length})
            </TabsTrigger>
          )}
          {guidance.iamPolicies && guidance.iamPolicies.length > 0 && (
            <TabsTrigger value="iam" className="gap-1.5 text-xs" data-testid="tab-iam">
              <Layers className="h-3.5 w-3.5" />
              IAM ({guidance.iamPolicies.length})
            </TabsTrigger>
          )}
          {guidance.detectionRules && guidance.detectionRules.length > 0 && (
            <TabsTrigger value="detection" className="gap-1.5 text-xs" data-testid="tab-detection">
              <Bell className="h-3.5 w-3.5" />
              Detection ({guidance.detectionRules.length})
            </TabsTrigger>
          )}
          {guidance.compensatingControls && guidance.compensatingControls.length > 0 && (
            <TabsTrigger value="compensating" className="gap-1.5 text-xs" data-testid="tab-compensating">
              <AlertTriangle className="h-3.5 w-3.5" />
              Compensating ({guidance.compensatingControls.length})
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="priority" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-2">
              {guidance.prioritizedActions.map((action) => (
                <div
                  key={action.order}
                  className="flex items-center gap-3 p-3 bg-muted/30 rounded-lg border border-border"
                  data-testid={`priority-action-${action.order}`}
                >
                  <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/10 text-primary text-xs font-medium">
                    {action.order}
                  </div>
                  <div className="flex items-center gap-2 text-muted-foreground">
                    {getTypeIcon(action.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-medium text-foreground">{action.action}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">{action.timeEstimate}</span>
                    <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
                      -{action.riskReduction}%
                    </Badge>
                    <Badge className={`${getEffortColor(action.effort)} text-xs`}>
                      {action.effort}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="code" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {guidance.codeFixes?.map((fix) => (
                <Card key={fix.id} className="overflow-hidden" data-testid={`code-fix-${fix.id}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => toggleExpanded(fix.id)}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <FileCode className="h-5 w-5 text-cyan-400" />
                        <div>
                          <h4 className="font-medium text-foreground">{fix.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30 text-xs">
                              {fix.language}
                            </Badge>
                            <Badge className={getEffortColor(fix.complexity === "trivial" ? "low" : fix.complexity === "low" ? "low" : fix.complexity === "medium" ? "medium" : "high")}>
                              {fix.complexity}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {expandedItems.has(fix.id) ? (
                        <ChevronUp className="h-5 w-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {expandedItems.has(fix.id) && (
                    <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                      {fix.filePath && (
                        <div className="text-xs font-mono text-muted-foreground">{fix.filePath}</div>
                      )}
                      <p className="text-sm text-muted-foreground">{fix.explanation}</p>
                      
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-red-400 uppercase">Before (Vulnerable)</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(fix.beforeCode, `before-${fix.id}`)}
                            data-testid={`copy-before-${fix.id}`}
                          >
                            {copiedId === `before-${fix.id}` ? (
                              <Check className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="bg-red-500/5 border border-red-500/20 rounded-md p-3 text-xs font-mono overflow-x-auto text-foreground">
                          {fix.beforeCode}
                        </pre>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-emerald-400 uppercase">After (Fixed)</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(fix.afterCode, `after-${fix.id}`)}
                            data-testid={`copy-after-${fix.id}`}
                          >
                            {copiedId === `after-${fix.id}` ? (
                              <Check className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="bg-emerald-500/5 border border-emerald-500/20 rounded-md p-3 text-xs font-mono overflow-x-auto text-foreground">
                          {fix.afterCode}
                        </pre>
                      </div>

                      {fix.testingNotes && (
                        <div className="text-xs text-muted-foreground bg-muted/50 rounded-md p-3">
                          <span className="font-medium">Testing Notes:</span> {fix.testingNotes}
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="waf" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {guidance.wafRules?.map((rule) => (
                <Card key={rule.id} className="overflow-hidden" data-testid={`waf-rule-${rule.id}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => toggleExpanded(rule.id)}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <Shield className="h-5 w-5 text-orange-400" />
                        <div>
                          <h4 className="font-medium text-foreground">{rule.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/30 text-xs">
                              {rule.platform}
                            </Badge>
                            <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs">
                              {rule.ruleType}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {expandedItems.has(rule.id) ? (
                        <ChevronUp className="h-5 w-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {expandedItems.has(rule.id) && (
                    <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                      <p className="text-sm text-muted-foreground">{rule.description}</p>
                      
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div>
                          <span className="text-muted-foreground">Priority:</span>
                          <span className="ml-2 text-foreground">{rule.priority}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">False Positive Risk:</span>
                          <Badge className={`ml-2 ${rule.falsePositiveRisk === "low" ? "bg-emerald-500/10 text-emerald-400" : rule.falsePositiveRisk === "medium" ? "bg-amber-500/10 text-amber-400" : "bg-red-500/10 text-red-400"}`}>
                            {rule.falsePositiveRisk}
                          </Badge>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-muted-foreground uppercase">Rule Configuration</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(rule.rawConfig, rule.id)}
                            data-testid={`copy-waf-${rule.id}`}
                          >
                            {copiedId === rule.id ? (
                              <Check className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="bg-muted/50 rounded-md p-3 text-xs font-mono overflow-x-auto text-foreground">
                          {rule.rawConfig}
                        </pre>
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="iam" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {guidance.iamPolicies?.map((policy) => (
                <Card key={policy.id} className="overflow-hidden" data-testid={`iam-policy-${policy.id}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => toggleExpanded(policy.id)}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <Layers className="h-5 w-5 text-purple-400" />
                        <div>
                          <h4 className="font-medium text-foreground">{policy.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs">
                              {policy.platform}
                            </Badge>
                            <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30 text-xs">
                              {policy.policyType}
                            </Badge>
                            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
                              -{policy.riskReduction}% risk
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {expandedItems.has(policy.id) ? (
                        <ChevronUp className="h-5 w-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {expandedItems.has(policy.id) && (
                    <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <span className="text-xs font-medium text-red-400 uppercase block mb-1">Current State</span>
                          <p className="text-sm text-muted-foreground">{policy.currentState}</p>
                        </div>
                        <div>
                          <span className="text-xs font-medium text-emerald-400 uppercase block mb-1">Recommended State</span>
                          <p className="text-sm text-muted-foreground">{policy.recommendedState}</p>
                        </div>
                      </div>

                      <div>
                        <span className="text-xs font-medium text-muted-foreground uppercase block mb-2">Implementation Steps</span>
                        <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                          {policy.implementationSteps.map((step, i) => (
                            <li key={i}>{step}</li>
                          ))}
                        </ol>
                      </div>

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-muted-foreground uppercase">Policy JSON</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(policy.rawPolicy, policy.id)}
                            data-testid={`copy-iam-${policy.id}`}
                          >
                            {copiedId === policy.id ? (
                              <Check className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="bg-muted/50 rounded-md p-3 text-xs font-mono overflow-x-auto text-foreground">
                          {policy.rawPolicy}
                        </pre>
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="detection" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {guidance.detectionRules?.map((rule) => (
                <Card key={rule.id} className="overflow-hidden" data-testid={`detection-rule-${rule.id}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => toggleExpanded(rule.id)}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <Bell className="h-5 w-5 text-yellow-400" />
                        <div>
                          <h4 className="font-medium text-foreground">{rule.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30 text-xs">
                              {rule.platform}
                            </Badge>
                            <Badge className={`text-xs ${
                              rule.severity === "critical" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                              rule.severity === "high" ? "bg-orange-500/10 text-orange-400 border-orange-500/30" :
                              rule.severity === "medium" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                              "bg-blue-500/10 text-blue-400 border-blue-500/30"
                            }`}>
                              {rule.severity}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {expandedItems.has(rule.id) ? (
                        <ChevronUp className="h-5 w-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {expandedItems.has(rule.id) && (
                    <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                      <p className="text-sm text-muted-foreground">{rule.description}</p>
                      
                      <div className="text-xs text-muted-foreground">
                        <span className="font-medium">Logic:</span> {rule.logic}
                      </div>

                      <div className="flex flex-wrap gap-1">
                        <span className="text-xs text-muted-foreground">Data Sources:</span>
                        {rule.dataSource.map((ds, i) => (
                          <Badge key={i} size="sm" className="bg-muted text-muted-foreground text-xs">
                            {ds}
                          </Badge>
                        ))}
                      </div>

                      {rule.mitreTechniques && rule.mitreTechniques.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          <span className="text-xs text-muted-foreground">MITRE:</span>
                          {rule.mitreTechniques.map((tech, i) => (
                            <Badge key={i} size="sm" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                              {tech}
                            </Badge>
                          ))}
                        </div>
                      )}

                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-muted-foreground uppercase">Detection Rule</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(rule.rawRule, rule.id)}
                            data-testid={`copy-detection-${rule.id}`}
                          >
                            {copiedId === rule.id ? (
                              <Check className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                        <pre className="bg-muted/50 rounded-md p-3 text-xs font-mono overflow-x-auto text-foreground">
                          {rule.rawRule}
                        </pre>
                      </div>

                      {rule.responsePlaybook && (
                        <div className="text-xs text-muted-foreground bg-amber-500/5 border border-amber-500/20 rounded-md p-3">
                          <span className="font-medium text-amber-400">Response Playbook:</span> {rule.responsePlaybook}
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="compensating" className="mt-4">
          <ScrollArea className="h-[400px] pr-4">
            <div className="space-y-4">
              {guidance.compensatingControls?.map((control) => (
                <Card key={control.id} className="overflow-hidden" data-testid={`compensating-control-${control.id}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => toggleExpanded(control.id)}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-5 w-5 text-amber-400" />
                        <div>
                          <h4 className="font-medium text-foreground">{control.title}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/30 text-xs">
                              {control.controlType}
                            </Badge>
                            <Badge className={control.duration === "temporary" ? "bg-blue-500/10 text-blue-400 border-blue-500/30 text-xs" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs"}>
                              {control.duration}
                            </Badge>
                            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
                              {control.effectiveness}% effective
                            </Badge>
                          </div>
                        </div>
                      </div>
                      {expandedItems.has(control.id) ? (
                        <ChevronUp className="h-5 w-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                  {expandedItems.has(control.id) && (
                    <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                      <p className="text-sm text-muted-foreground">{control.description}</p>
                      
                      <div className="text-sm text-muted-foreground bg-muted/50 rounded-md p-3">
                        <span className="font-medium text-foreground">Rationale:</span> {control.rationale}
                      </div>

                      <div>
                        <span className="text-xs font-medium text-muted-foreground uppercase block mb-2">Implementation Guide</span>
                        <p className="text-sm text-muted-foreground whitespace-pre-line">{control.implementationGuide}</p>
                      </div>

                      {control.reviewDate && (
                        <div className="text-xs text-muted-foreground">
                          <span className="font-medium">Review Date:</span> {control.reviewDate}
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </div>
  );
}
