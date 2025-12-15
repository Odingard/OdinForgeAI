import { Cloud, Key, Users, Globe, Server, ArrowRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import type { MultiVectorFinding } from "@shared/schema";

interface MultiVectorFindingsPanelProps {
  findings: MultiVectorFinding[];
}

const vectorIcons: Record<string, typeof Cloud> = {
  cloud_misconfiguration: Cloud,
  iam_abuse: Key,
  saas_permission: Users,
  shadow_admin: Users,
};

const vectorLabels: Record<string, string> = {
  cve: "CVE",
  misconfiguration: "Misconfiguration",
  behavioral_anomaly: "Behavioral Anomaly",
  network_vulnerability: "Network",
  cloud_misconfiguration: "Cloud Misconfiguration",
  iam_abuse: "IAM Abuse",
  saas_permission: "SaaS Permission",
  shadow_admin: "Shadow Admin",
  api_sequence_abuse: "API Abuse",
  payment_flow: "Payment Flow",
  subscription_bypass: "Subscription Bypass",
  state_machine: "State Machine",
  privilege_boundary: "Privilege Boundary",
  workflow_desync: "Workflow Desync",
  order_lifecycle: "Order Lifecycle",
};

const cloudVectorLabels: Record<string, string> = {
  s3_public_bucket: "S3 Public Bucket",
  iam_role_chaining: "IAM Role Chaining",
  cross_account_access: "Cross Account Access",
  metadata_service_abuse: "Metadata Service",
  lambda_privilege_escalation: "Lambda Priv Esc",
  storage_account_exposure: "Storage Account",
  service_account_abuse: "Service Account",
  federation_bypass: "Federation Bypass",
  permission_boundary_bypass: "Permission Boundary",
  resource_policy_abuse: "Resource Policy",
};

const severityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
};

const providerColors: Record<string, string> = {
  aws: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  gcp: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  azure: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  "multi-cloud": "bg-purple-500/10 text-purple-400 border-purple-500/30",
};

export function MultiVectorFindingsPanel({ findings }: MultiVectorFindingsPanelProps) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Cloud className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No multi-vector findings</p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="multi-vector-findings">
      {findings.map((finding, index) => {
        const Icon = vectorIcons[finding.vectorType] || Globe;
        return (
          <Collapsible key={finding.id || index}>
            <Card className="overflow-hidden">
              <CollapsibleTrigger className="w-full text-left">
                <div className="p-4 flex items-start gap-4">
                  <div className="p-2 rounded-lg bg-cyan-500/10">
                    <Icon className="h-5 w-5 text-cyan-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <h4 className="font-semibold text-foreground">{finding.title}</h4>
                      <Badge className={severityColors[finding.severity]}>
                        {finding.severity.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {vectorLabels[finding.vectorType] || finding.vectorType}
                      </Badge>
                      {finding.cloudVector && (
                        <Badge variant="outline" className="text-xs bg-cyan-500/5">
                          {cloudVectorLabels[finding.cloudVector] || finding.cloudVector}
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground line-clamp-2">{finding.description}</p>
                  </div>
                </div>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="px-4 pb-4 space-y-4 border-t border-border pt-4">
                  <div>
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                      Affected Resources
                    </label>
                    <div className="flex gap-2 flex-wrap">
                      {finding.affectedResources.map((resource, i) => (
                        <Badge key={i} variant="outline" className="font-mono text-xs">
                          <Server className="h-3 w-3 mr-1" />
                          {resource}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {finding.exploitPath && finding.exploitPath.length > 0 && (
                    <div>
                      <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                        Exploit Path
                      </label>
                      <div className="space-y-2">
                        {finding.exploitPath.map((step, i) => (
                          <div key={i} className="flex items-center gap-3 p-2 bg-muted/30 rounded-lg">
                            <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold">
                              {step.step}
                            </span>
                            <div className="flex-1">
                              <p className="text-sm text-foreground">{step.action}</p>
                              <p className="text-xs text-muted-foreground">
                                Target: <span className="font-mono">{step.target}</span>
                                {step.technique && (
                                  <>
                                    {" "}| Technique: <span className="text-cyan-400">{step.technique}</span>
                                  </>
                                )}
                              </p>
                            </div>
                            {i < finding.exploitPath.length - 1 && (
                              <ArrowRight className="h-4 w-4 text-muted-foreground" />
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {finding.iamContext && (
                    <div>
                      <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                        IAM Context
                      </label>
                      <div className="p-3 bg-muted/30 rounded-lg space-y-2 text-sm">
                        {finding.iamContext.principal && (
                          <div className="flex items-center gap-2">
                            <span className="text-muted-foreground">Principal:</span>
                            <span className="font-mono text-foreground">{finding.iamContext.principal}</span>
                          </div>
                        )}
                        {finding.iamContext.assumableRoles && finding.iamContext.assumableRoles.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Assumable Roles:</span>
                            <div className="flex gap-2 flex-wrap mt-1">
                              {finding.iamContext.assumableRoles.map((role, i) => (
                                <Badge key={i} variant="outline" className="font-mono text-xs">
                                  <Key className="h-3 w-3 mr-1" />
                                  {role}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                        {finding.iamContext.privilegeEscalationPath && (
                          <div className="mt-2 p-2 bg-red-500/10 rounded border border-red-500/30">
                            <span className="text-red-400 text-xs uppercase tracking-wider">Priv Esc Path:</span>
                            <p className="text-foreground mt-1">{finding.iamContext.privilegeEscalationPath}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {finding.cloudContext && (
                    <div>
                      <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                        Cloud Context
                      </label>
                      <div className="flex gap-2 flex-wrap">
                        {finding.cloudContext.provider && (
                          <Badge className={providerColors[finding.cloudContext.provider]}>
                            {finding.cloudContext.provider.toUpperCase()}
                          </Badge>
                        )}
                        {finding.cloudContext.service && (
                          <Badge variant="outline">{finding.cloudContext.service}</Badge>
                        )}
                        {finding.cloudContext.region && (
                          <Badge variant="outline" className="font-mono text-xs">
                            {finding.cloudContext.region}
                          </Badge>
                        )}
                      </div>
                      {finding.cloudContext.resourceArn && (
                        <p className="mt-2 text-xs font-mono text-muted-foreground">
                          ARN: {finding.cloudContext.resourceArn}
                        </p>
                      )}
                    </div>
                  )}

                  {finding.saasContext && (
                    <div>
                      <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                        SaaS Context
                      </label>
                      <div className="p-3 bg-muted/30 rounded-lg space-y-2 text-sm">
                        {finding.saasContext.platform && (
                          <div className="flex items-center gap-2">
                            <span className="text-muted-foreground">Platform:</span>
                            <Badge variant="outline">{finding.saasContext.platform}</Badge>
                          </div>
                        )}
                        {finding.saasContext.permissionLevel && (
                          <div className="flex items-center gap-2">
                            <span className="text-muted-foreground">Permission Level:</span>
                            <span className="text-foreground">{finding.saasContext.permissionLevel}</span>
                          </div>
                        )}
                        {finding.saasContext.shadowAdminIndicators && finding.saasContext.shadowAdminIndicators.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Shadow Admin Indicators:</span>
                            <div className="flex gap-2 flex-wrap mt-1">
                              {finding.saasContext.shadowAdminIndicators.map((indicator, i) => (
                                <Badge key={i} className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs">
                                  {indicator}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {finding.chainableWith && finding.chainableWith.length > 0 && (
                    <div>
                      <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                        Chainable With
                      </label>
                      <div className="flex gap-2 flex-wrap">
                        {finding.chainableWith.map((chain, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {chain}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        );
      })}
    </div>
  );
}
