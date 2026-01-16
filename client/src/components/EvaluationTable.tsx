import { useState } from "react";
import { 
  ChevronDown, 
  ChevronUp, 
  Eye, 
  Play, 
  AlertTriangle, 
  Shield, 
  Activity, 
  Target, 
  Zap,
  CheckCircle,
  Clock,
  XCircle,
  Loader2,
  Swords
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export interface Evaluation {
  id: string;
  assetId: string;
  exposureType: "cve" | "misconfiguration" | "behavior" | "network" | "business_logic" | "api_abuse";
  priority: "critical" | "high" | "medium" | "low";
  status: "pending" | "in_progress" | "completed" | "failed";
  exploitable?: boolean;
  score?: number;
  confidence?: number;
  createdAt: string;
}

interface EvaluationTableProps {
  evaluations: Evaluation[];
  onViewDetails: (evaluation: Evaluation) => void;
  onRunEvaluation: (evaluation: Evaluation) => void;
  onStartSimulation?: (evaluation: Evaluation) => void;
}

type SortField = "createdAt" | "priority" | "status" | "score";

export function EvaluationTable({ evaluations, onViewDetails, onRunEvaluation, onStartSimulation }: EvaluationTableProps) {
  const [sortField, setSortField] = useState<SortField>("createdAt");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const statusOrder = { in_progress: 0, pending: 1, completed: 2, failed: 3 };

  const sortedEvaluations = [...evaluations].sort((a, b) => {
    let comparison = 0;
    if (sortField === "createdAt") {
      comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    } else if (sortField === "priority") {
      comparison = priorityOrder[a.priority] - priorityOrder[b.priority];
    } else if (sortField === "status") {
      comparison = statusOrder[a.status] - statusOrder[b.status];
    } else if (sortField === "score") {
      comparison = (a.score || 0) - (b.score || 0);
    }
    return sortOrder === "asc" ? comparison : -comparison;
  });

  const getExposureIcon = (type: string) => {
    switch (type) {
      case "cve": return <AlertTriangle className="h-4 w-4 text-orange-400" />;
      case "misconfiguration": return <Shield className="h-4 w-4 text-blue-400" />;
      case "behavior": return <Activity className="h-4 w-4 text-purple-400" />;
      case "network": return <Target className="h-4 w-4 text-cyan-400" />;
      case "business_logic": return <Zap className="h-4 w-4 text-amber-400" />;
      case "api_abuse": return <Zap className="h-4 w-4 text-pink-400" />;
      default: return <Zap className="h-4 w-4 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string, exploitable?: boolean) => {
    if (status === "completed" && exploitable === true) {
      return <Badge variant="destructive" className="bg-red-500/10 text-red-400 border-red-500/30">EXPLOITABLE</Badge>;
    }
    if (status === "completed" && exploitable === false) {
      return <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">SAFE</Badge>;
    }
    switch (status) {
      case "in_progress":
        return <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/30"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Running</Badge>;
      case "pending":
        return <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case "failed":
        return <Badge variant="destructive" className="bg-red-500/10 text-red-400 border-red-500/30"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getPriorityBadge = (priority: string) => {
    const classes: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return <Badge className={classes[priority] || ""}>{priority.toUpperCase()}</Badge>;
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-30" />;
    return sortOrder === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />;
  };

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium">
                Asset
              </th>
              <th className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium">
                Type
              </th>
              <th 
                className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium cursor-pointer hover:text-foreground"
                onClick={() => toggleSort("priority")}
              >
                <div className="flex items-center gap-1">
                  Priority <SortIcon field="priority" />
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium cursor-pointer hover:text-foreground"
                onClick={() => toggleSort("status")}
              >
                <div className="flex items-center gap-1">
                  Status <SortIcon field="status" />
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium cursor-pointer hover:text-foreground"
                onClick={() => toggleSort("score")}
              >
                <div className="flex items-center gap-1">
                  Risk Score <SortIcon field="score" />
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground font-medium cursor-pointer hover:text-foreground"
                onClick={() => toggleSort("createdAt")}
              >
                <div className="flex items-center gap-1">
                  Created <SortIcon field="createdAt" />
                </div>
              </th>
              <th className="px-4 py-3 text-right text-xs uppercase tracking-wider text-muted-foreground font-medium">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {sortedEvaluations.map((evaluation) => (
              <tr 
                key={evaluation.id} 
                className="hover:bg-muted/20 transition-colors group"
                data-testid={`row-evaluation-${evaluation.id}`}
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-mono text-foreground">{evaluation.assetId}</code>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    {getExposureIcon(evaluation.exposureType)}
                    <span className="text-sm text-muted-foreground capitalize">
                      {evaluation.exposureType.replace("_", " ")}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">{getPriorityBadge(evaluation.priority)}</td>
                <td className="px-4 py-3">{getStatusBadge(evaluation.status, evaluation.exploitable)}</td>
                <td className="px-4 py-3">
                  {evaluation.score !== undefined ? (
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            evaluation.score >= 80 ? "bg-red-500" :
                            evaluation.score >= 60 ? "bg-orange-500" :
                            evaluation.score >= 40 ? "bg-amber-500" :
                            "bg-emerald-500"
                          }`}
                          style={{ width: `${evaluation.score}%` }}
                        />
                      </div>
                      <span className={`text-sm font-mono ${
                        evaluation.score >= 80 ? "text-red-400" :
                        evaluation.score >= 60 ? "text-orange-400" :
                        evaluation.score >= 40 ? "text-amber-400" :
                        "text-emerald-400"
                      }`}>
                        {evaluation.score}
                      </span>
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-muted-foreground">
                    {new Date(evaluation.createdAt).toLocaleDateString()}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={() => onViewDetails(evaluation)}
                          data-testid={`button-view-${evaluation.id}`}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>View Details</TooltipContent>
                    </Tooltip>
                    {evaluation.status !== "in_progress" && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button 
                            variant="ghost" 
                            size="icon"
                            onClick={() => onRunEvaluation(evaluation)}
                            data-testid={`button-run-${evaluation.id}`}
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Re-run Evaluation</TooltipContent>
                      </Tooltip>
                    )}
                    {evaluation.status === "completed" && onStartSimulation && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button 
                            variant="ghost" 
                            size="icon"
                            onClick={() => onStartSimulation(evaluation)}
                            data-testid={`button-simulate-${evaluation.id}`}
                          >
                            <Swords className="h-4 w-4 text-purple-500" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Start AI Simulation</TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
