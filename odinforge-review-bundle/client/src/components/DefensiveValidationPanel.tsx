/**
 * DefensiveValidationPanel
 *
 * Shows SIEM detection results for an evaluation:
 * - Detection rate summary (detected vs missed)
 * - Per-technique detection status
 * - Alert details and MTTD metrics
 */

import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, ShieldAlert, ShieldCheck, ShieldX, Clock, AlertTriangle } from "lucide-react";

interface DefensiveValidation {
  id: string;
  evaluationId: string;
  siemConnectionId: string;
  mitreAttackId: string | null;
  mitreTactic: string | null;
  detected: boolean | null;
  status: string | null;
  alertCount: number | null;
  mttdSeconds: number | null;
  firstAlertAt: string | null;
  alertDetails: Array<{ id: string; ruleName: string; severity: string; timestamp: string }> | null;
  errorMessage: string | null;
}

interface DetectionSummary {
  total: number;
  detected: number;
  missed: number;
  pending: number;
  detectionRate: number;
  avgMttdSeconds: number | null;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hrs}h ${mins}m`;
}

export function DefensiveValidationPanel({ evaluationId }: { evaluationId: string }) {
  const { data, isLoading } = useQuery<{ validations: DefensiveValidation[]; summary: DetectionSummary }>({
    queryKey: [`/api/defensive-validations/${evaluationId}`],
    enabled: !!evaluationId,
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="py-6 text-center text-sm text-muted-foreground">
          Loading detection results...
        </CardContent>
      </Card>
    );
  }

  if (!data || data.validations.length === 0) {
    return (
      <Card>
        <CardContent className="py-6 text-center">
          <Shield className="h-8 w-8 mx-auto mb-2 text-muted-foreground opacity-30" />
          <p className="text-sm text-muted-foreground">
            No SIEM validation data. Connect a SIEM on the Infrastructure page to validate detection coverage.
          </p>
        </CardContent>
      </Card>
    );
  }

  const { validations, summary } = data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldAlert className="h-5 w-5 text-blue-400" />
          Defensive Validation
        </CardTitle>
        <CardDescription>
          Did your SIEM detect the attack techniques used in this evaluation?
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary Bar */}
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <div className="flex justify-between text-sm mb-1">
              <span>Detection Rate</span>
              <span className="font-medium">{summary.detectionRate}%</span>
            </div>
            <Progress value={summary.detectionRate} className="h-2" />
          </div>
          <div className="flex gap-3 text-sm">
            <div className="text-center">
              <div className="text-lg font-bold text-emerald-400">{summary.detected}</div>
              <div className="text-xs text-muted-foreground">Detected</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-red-400">{summary.missed}</div>
              <div className="text-xs text-muted-foreground">Missed</div>
            </div>
            {summary.avgMttdSeconds !== null && (
              <div className="text-center">
                <div className="text-lg font-bold text-amber-400">{formatDuration(summary.avgMttdSeconds)}</div>
                <div className="text-xs text-muted-foreground">Avg MTTD</div>
              </div>
            )}
          </div>
        </div>

        {/* Per-technique results */}
        <div className="space-y-2">
          {validations.map((v) => (
            <div key={v.id} className="flex items-center justify-between p-2 rounded-md border bg-card/50 text-sm">
              <div className="flex items-center gap-2">
                {v.status === "detected" ? (
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                ) : v.status === "missed" ? (
                  <ShieldX className="h-4 w-4 text-red-400" />
                ) : v.status === "error" ? (
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                ) : (
                  <Clock className="h-4 w-4 text-muted-foreground animate-pulse" />
                )}
                <span className="font-mono">{v.mitreAttackId || "—"}</span>
                <span className="text-muted-foreground">{v.mitreTactic}</span>
              </div>
              <div className="flex items-center gap-2">
                {v.status === "detected" && (
                  <>
                    <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                      {v.alertCount} alert{v.alertCount !== 1 ? "s" : ""}
                    </Badge>
                    {v.mttdSeconds !== null && (
                      <span className="text-xs text-muted-foreground">
                        MTTD: {formatDuration(v.mttdSeconds)}
                      </span>
                    )}
                  </>
                )}
                {v.status === "missed" && (
                  <Badge className="bg-red-500/10 text-red-400 border-red-500/30">Undetected</Badge>
                )}
                {v.status === "error" && (
                  <span className="text-xs text-red-400">{v.errorMessage}</span>
                )}
                {(v.status === "pending" || v.status === "querying") && (
                  <Badge variant="outline">Querying...</Badge>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
