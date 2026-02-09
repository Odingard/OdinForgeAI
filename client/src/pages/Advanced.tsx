import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Brain,
  Target,
  Shield,
  Crosshair,
  Users,
  Activity,
  TrendingUp,
  TrendingDown,
  Minus,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Zap,
  Play,
  Loader2,
  Plus,
  ExternalLink,
  Eye,
  EyeOff,
  Skull,
  Building2,
  GraduationCap,
  Gauge,
  BarChart3,
  RefreshCw,
  Info,
  ThumbsUp,
  ThumbsDown,
  HelpCircle,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
} from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { format } from "date-fns";
import type { 
  DefensivePostureScore, 
  AiAdversaryProfile, 
  AiSimulation, 
  PurpleTeamFinding 
} from "@shared/schema";

const ORG_ID = "default";

interface AttackPredictionVector {
  vector: string;
  likelihood: number;
  confidence: number;
  adversaryProfile: string;
  estimatedImpact: string;
  mitreAttackId: string;
  occurrences: number;
}

interface AttackPredictionMetrics {
  id: string;
  organizationId: string;
  predictedAttackVectors: AttackPredictionVector[];
  overallBreachLikelihood: number;
  riskFactors: Array<{ factor: string; contribution: number; trend: string }>;
  recommendedActions: string[];
  dataSource: "computed" | "insufficient_data";
  evaluationsAnalyzed: number;
  timeHorizon: string;
  modelVersion: string;
  calculatedAt: string;
}

const adversaryTypeConfig: Record<string, { label: string; icon: typeof Skull; color: string }> = {
  script_kiddie: { label: "Script Kiddie", icon: GraduationCap, color: "text-emerald-400" },
  opportunistic_criminal: { label: "Opportunistic Criminal", icon: Target, color: "text-amber-400" },
  organized_crime: { label: "Organized Crime", icon: Building2, color: "text-orange-400" },
  insider_threat: { label: "Insider Threat", icon: Users, color: "text-red-400" },
  nation_state: { label: "Nation State", icon: Shield, color: "text-red-500" },
  apt_group: { label: "APT Group", icon: Skull, color: "text-red-600" },
  hacktivist: { label: "Hacktivist", icon: Zap, color: "text-purple-400" },
  competitor: { label: "Competitor", icon: Building2, color: "text-blue-400" },
};

const trendIcons = {
  improving: { icon: TrendingUp, color: "text-emerald-400" },
  stable: { icon: Minus, color: "text-amber-400" },
  degrading: { icon: TrendingDown, color: "text-red-400" },
  new: { icon: Zap, color: "text-cyan-400" },
  increasing: { icon: TrendingUp, color: "text-red-400" },
  decreasing: { icon: TrendingDown, color: "text-emerald-400" },
};

const detectionStatusConfig: Record<string, { label: string; color: string }> = {
  detected: { label: "Detected", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
  partially_detected: { label: "Partial", color: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  missed: { label: "Missed", color: "bg-red-500/10 text-red-400 border-red-500/30" },
};

const feedbackStatusConfig: Record<string, { label: string; color: string }> = {
  pending: { label: "Pending", color: "bg-gray-500/10 text-gray-400 border-gray-500/30" },
  in_progress: { label: "In Progress", color: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
  implemented: { label: "Implemented", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
  wont_fix: { label: "Won't Fix", color: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
};

const priorityConfig: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: "bg-red-500/10 text-red-400 border-red-500/30" },
  high: { label: "High", color: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  medium: { label: "Medium", color: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  low: { label: "Low", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
};

const getConfidenceLevel = (confidence: number): { label: string; color: string; description: string } => {
  if (confidence >= 80) return { label: "High", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", description: "Strong evidence from multiple data sources" };
  if (confidence >= 50) return { label: "Medium", color: "bg-amber-500/10 text-amber-400 border-amber-500/30", description: "Moderate evidence, some uncertainty" };
  return { label: "Low", color: "bg-gray-500/10 text-gray-400 border-gray-500/30", description: "Limited data, requires verification" };
};

interface SecurityStatusResult {
  status: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  icon: typeof ShieldCheck;
  message: string;
  action: string;
}

const getSecurityStatus = (score: number, breachLikelihood: number): SecurityStatusResult => {
  if (score >= 80 && breachLikelihood <= 20) {
    return { status: "Good", textColor: "text-emerald-400", bgColor: "bg-emerald-500/10", borderColor: "border-emerald-500/30", icon: ShieldCheck, message: "Your security posture is strong", action: "Continue monitoring and run periodic simulations" };
  }
  if (score >= 50 && breachLikelihood <= 50) {
    return { status: "Needs Attention", textColor: "text-amber-400", bgColor: "bg-amber-500/10", borderColor: "border-amber-500/30", icon: ShieldAlert, message: "Some security gaps detected", action: "Review predictions below and address high-priority items" };
  }
  return { status: "Critical", textColor: "text-red-400", bgColor: "bg-red-500/10", borderColor: "border-red-500/30", icon: ShieldX, message: "Significant security vulnerabilities found", action: "Immediate action required on critical findings" };
};

const formatTimeAgo = (dateString: string): string => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
};

export default function Advanced() {
  const { toast } = useToast();
  const [timeHorizon, setTimeHorizon] = useState("30d");
  const [isSimulationDialogOpen, setIsSimulationDialogOpen] = useState(false);
  const [dismissedVectors, setDismissedVectors] = useState<Set<string>>(new Set());
  const [verifiedVectors, setVerifiedVectors] = useState<Set<string>>(new Set());
  const [showDismissed, setShowDismissed] = useState(false);
  const [newSimulation, setNewSimulation] = useState({
    name: "",
    description: "",
    attackerProfileId: "",
  });

  const { data: posture, isLoading: postureLoading, error: postureError } = useQuery<DefensivePostureScore>({
    queryKey: ["/api/defensive-posture", ORG_ID],
  });

  const { data: predictions, isLoading: predictionsLoading } = useQuery<AttackPredictionMetrics>({
    queryKey: ["/api/attack-predictions", ORG_ID],
  });

  const { data: adversaryProfiles = [], isLoading: profilesLoading } = useQuery<AiAdversaryProfile[]>({
    queryKey: ["/api/adversary-profiles"],
  });

  const { data: simulations = [], isLoading: simulationsLoading } = useQuery<AiSimulation[]>({
    queryKey: ["/api/ai-simulations", ORG_ID],
  });

  const { data: purpleTeamFindings = [], isLoading: findingsLoading } = useQuery<PurpleTeamFinding[]>({
    queryKey: ["/api/purple-team", ORG_ID],
  });

  const generatePredictionMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/attack-predictions/generate", {
        organizationId: ORG_ID,
        timeHorizon,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/attack-predictions", ORG_ID] });
      toast({
        title: "Prediction Generated",
        description: "New attack prediction analysis complete",
      });
    },
    onError: (error) => {
      toast({
        title: "Generation Failed",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const createSimulationMutation = useMutation({
    mutationFn: async (data: typeof newSimulation) => {
      const response = await apiRequest("POST", "/api/ai-simulations", {
        ...data,
        organizationId: ORG_ID,
        targetEnvironment: {
          assets: ["web-app-01", "db-server-01", "api-gateway"],
          networkTopology: "standard",
          securityControls: ["WAF", "IDS", "EDR"],
        },
        defenderConfig: {
          detectionCapabilities: ["network", "endpoint", "identity"],
          responseAutomation: true,
          honeypots: false,
          deception: false,
        },
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/ai-simulations", ORG_ID] });
      setIsSimulationDialogOpen(false);
      setNewSimulation({ name: "", description: "", attackerProfileId: "" });
      toast({
        title: "Simulation Started",
        description: "AI vs AI simulation is now running",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to Start Simulation",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const updateFindingMutation = useMutation({
    mutationFn: async ({ id, updates }: { id: string; updates: Partial<PurpleTeamFinding> }) => {
      const response = await apiRequest("PATCH", `/api/purple-team/${id}`, updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/purple-team", ORG_ID] });
      toast({
        title: "Finding Updated",
        description: "Purple team finding has been updated",
      });
    },
  });

  const latestPrediction = predictions || null;
  const categoryScores = posture?.categoryScores as Record<string, number> | undefined;

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-emerald-400";
    if (score >= 60) return "text-amber-400";
    if (score >= 40) return "text-orange-400";
    return "text-red-400";
  };

  const getScoreGradient = (score: number) => {
    if (score >= 80) return "from-emerald-500 to-emerald-600";
    if (score >= 60) return "from-amber-500 to-amber-600";
    if (score >= 40) return "from-orange-500 to-orange-600";
    return "from-red-500 to-red-600";
  };

  if (postureLoading) {
    return (
      <div className="space-y-6" data-testid="advanced-loading">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-64 bg-muted rounded" />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-64 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  const isInitialData = simulations.length === 0 && purpleTeamFindings.length === 0 && !predictions;

  return (
    <div className="space-y-6" data-testid="advanced-page">
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2" data-testid="text-advanced-title">
          <Brain className="h-7 w-7 text-cyan-400" />
          Advanced AI Capabilities
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Next-generation threat intelligence and predictive security
        </p>
      </div>

      {postureError && (
        <Alert className="border-red-500/30 bg-red-500/10" data-testid="alert-error">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          <AlertDescription className="text-red-400">
            Failed to load defensive posture: {(postureError as Error).message}
          </AlertDescription>
        </Alert>
      )}

      {isInitialData && !postureError && (
        <Alert className="border-amber-500/30 bg-amber-500/10" data-testid="alert-no-data">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <AlertDescription className="text-amber-400">
            No security data yet. Run evaluations, deploy agents, or use External Recon to gather live findings.
          </AlertDescription>
        </Alert>
      )}

      {!isInitialData && posture && (() => {
        const securityStatus = getSecurityStatus(posture.overallScore || 0, posture.breachLikelihood || 0);
        const StatusIcon = securityStatus.icon;
        return (
          <Card className={`border ${securityStatus.borderColor}`} data-testid="card-security-status">
            <CardContent className="pt-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className={`p-3 rounded-full ${securityStatus.bgColor}`}>
                    <StatusIcon className={`h-8 w-8 ${securityStatus.textColor}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xl font-bold ${securityStatus.textColor}`} data-testid="text-security-status">
                        Security Status: {securityStatus.status}
                      </span>
                      <Tooltip>
                        <TooltipTrigger>
                          <HelpCircle className="h-4 w-4 text-muted-foreground" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">
                          <p>Based on your overall security score ({posture.overallScore}%) and breach likelihood ({posture.breachLikelihood}%)</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                    <p className="text-muted-foreground">{securityStatus.message}</p>
                    <div className="flex items-center gap-2 mt-2 text-sm">
                      <ArrowRight className="h-4 w-4 text-cyan-400" />
                      <span className="text-cyan-400 font-medium">{securityStatus.action}</span>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-3">
                  <div className="text-center px-4 py-2 rounded-lg bg-background/50">
                    <div className="text-2xl font-bold" data-testid="text-quick-score">{posture.overallScore || 0}</div>
                    <div className="text-xs text-muted-foreground">Security Score</div>
                  </div>
                  <div className="text-center px-4 py-2 rounded-lg bg-background/50">
                    <div className="text-2xl font-bold text-orange-400" data-testid="text-quick-breach">{posture.breachLikelihood || 0}%</div>
                    <div className="text-xs text-muted-foreground">Breach Risk</div>
                  </div>
                  {predictions?.calculatedAt && (
                    <div className="text-center px-4 py-2 rounded-lg bg-background/50">
                      <div className="text-sm font-medium flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatTimeAgo(predictions.calculatedAt)}
                      </div>
                      <div className="text-xs text-muted-foreground">Last Updated</div>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })()}

      <Card data-testid="card-defensive-posture">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              <CardTitle className="text-lg">Defensive Posture Score</CardTitle>
            </div>
            {posture?.trendDirection && (
              <Badge variant="outline" className={`${trendIcons[posture.trendDirection as keyof typeof trendIcons]?.color || "text-muted-foreground"}`}>
                {(() => {
                  const TrendIcon = trendIcons[posture.trendDirection as keyof typeof trendIcons]?.icon || Minus;
                  return <TrendIcon className="h-3 w-3 mr-1" />;
                })()}
                {posture.trendDirection.charAt(0).toUpperCase() + posture.trendDirection.slice(1)}
              </Badge>
            )}
          </div>
          <CardDescription>Overall security posture assessment and industry benchmarking</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="flex flex-col items-center justify-center">
              <div className="relative w-40 h-40">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle
                    cx="50"
                    cy="50"
                    r="45"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="8"
                    className="text-muted/30"
                  />
                  <circle
                    cx="50"
                    cy="50"
                    r="45"
                    fill="none"
                    stroke="url(#scoreGradient)"
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={`${(posture?.overallScore || 0) * 2.83} 283`}
                  />
                  <defs>
                    <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" className={`${getScoreGradient(posture?.overallScore || 0).includes("emerald") ? "text-emerald-500" : getScoreGradient(posture?.overallScore || 0).includes("amber") ? "text-amber-500" : getScoreGradient(posture?.overallScore || 0).includes("orange") ? "text-orange-500" : "text-red-500"}`} stopColor="currentColor" />
                      <stop offset="100%" className={`${getScoreGradient(posture?.overallScore || 0).includes("emerald") ? "text-emerald-600" : getScoreGradient(posture?.overallScore || 0).includes("amber") ? "text-amber-600" : getScoreGradient(posture?.overallScore || 0).includes("orange") ? "text-orange-600" : "text-red-600"}`} stopColor="currentColor" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={`text-4xl font-bold ${getScoreColor(posture?.overallScore || 0)}`} data-testid="text-posture-score">
                    {posture?.overallScore || 0}
                  </span>
                  <span className="text-xs text-muted-foreground">/ 100</span>
                </div>
              </div>
              {posture?.benchmarkPercentile && (
                <div className="mt-3 text-center">
                  <Badge variant="outline" className="text-cyan-400 border-cyan-500/30">
                    Top {100 - posture.benchmarkPercentile}% Industry
                  </Badge>
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="p-3 rounded-lg bg-muted/50 cursor-help">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                        Breach Likelihood
                        <HelpCircle className="h-3 w-3" />
                      </div>
                      <div className="text-2xl font-bold text-orange-400" data-testid="text-breach-likelihood">
                        {posture?.breachLikelihood || 0}%
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>Probability of a successful security breach based on current vulnerabilities and threat exposure</p>
                  </TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="p-3 rounded-lg bg-muted/50 cursor-help">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                        Benchmark
                        <HelpCircle className="h-3 w-3" />
                      </div>
                      <div className="text-2xl font-bold text-cyan-400" data-testid="text-benchmark">
                        {posture?.benchmarkPercentile || 0}th %ile
                      </div>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>How your security compares to similar organizations. Higher is better.</p>
                  </TooltipContent>
                </Tooltip>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="p-3 rounded-lg bg-muted/50 cursor-help">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        MTTD
                        <HelpCircle className="h-3 w-3" />
                      </div>
                      <div className="text-2xl font-bold text-foreground" data-testid="text-mttd">
                        {posture?.meanTimeToDetect || 0}h
                      </div>
                      {(posture as any)?.mttdDataSource && (
                        <Badge
                          variant="outline"
                          className={`mt-1 text-[10px] px-1.5 py-0 ${
                            (posture as any).mttdDataSource === "siem_observed"
                              ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
                              : "text-muted-foreground border-muted-foreground/30"
                          }`}
                        >
                          {(posture as any).mttdDataSource === "siem_observed"
                            ? `SIEM (${(posture as any).mttdSampleSize})`
                            : "Estimated"}
                        </Badge>
                      )}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>
                      Mean Time To Detect - Average time to identify a security incident. Lower is better.
                      {(posture as any)?.mttdDataSource === "siem_observed"
                        ? " Based on real SIEM alert data."
                        : " Estimated from evaluation confidence scores. Connect a SIEM for real measurements."}
                    </p>
                  </TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="p-3 rounded-lg bg-muted/50 cursor-help">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                        <Zap className="h-3 w-3" />
                        MTTR
                        <HelpCircle className="h-3 w-3" />
                      </div>
                      <div className="text-2xl font-bold text-foreground" data-testid="text-mttr">
                        {posture?.meanTimeToRespond || 0}h
                      </div>
                      {(posture as any)?.mttrDataSource && (
                        <Badge
                          variant="outline"
                          className={`mt-1 text-[10px] px-1.5 py-0 ${
                            (posture as any).mttrDataSource === "siem_observed"
                              ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
                              : "text-muted-foreground border-muted-foreground/30"
                          }`}
                        >
                          {(posture as any).mttrDataSource === "siem_observed"
                            ? `SIEM (${(posture as any).mttrSampleSize})`
                            : "Estimated"}
                        </Badge>
                      )}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>
                      Mean Time To Respond - Average time to contain a threat after detection. Lower is better.
                      {(posture as any)?.mttrDataSource === "siem_observed"
                        ? " Based on real SIEM resolution data."
                        : " Estimated from evaluation severity data. Connect a SIEM for real measurements."}
                    </p>
                  </TooltipContent>
                </Tooltip>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-sm font-medium text-muted-foreground">Category Breakdown</span>
                <Tooltip>
                  <TooltipTrigger>
                    <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>Scores for each security category. Higher scores indicate stronger defenses in that area.</p>
                  </TooltipContent>
                </Tooltip>
              </div>
              {categoryScores && Object.entries(categoryScores).map(([key, value]) => (
                <div key={key} className="flex items-center gap-2">
                  <div className="w-28 text-xs text-muted-foreground truncate capitalize">
                    {key.replace(/([A-Z])/g, ' $1').trim()}
                  </div>
                  <Progress value={value} className="flex-1 h-2" />
                  <div className={`w-8 text-xs font-mono ${getScoreColor(value)}`}>{value}</div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card data-testid="card-attack-predictions">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Target className="h-5 w-5 text-red-400" />
                <CardTitle className="text-lg">Attack Predictions</CardTitle>
              </div>
              <div className="flex items-center gap-2">
                <Tabs value={timeHorizon} onValueChange={setTimeHorizon}>
                  <TabsList className="h-8">
                    <TabsTrigger value="7d" className="text-xs">7d</TabsTrigger>
                    <TabsTrigger value="30d" className="text-xs">30d</TabsTrigger>
                    <TabsTrigger value="90d" className="text-xs">90d</TabsTrigger>
                  </TabsList>
                </Tabs>
                <Button
                  size="sm"
                  onClick={() => generatePredictionMutation.mutate()}
                  disabled={generatePredictionMutation.isPending}
                  data-testid="btn-generate-prediction"
                >
                  {generatePredictionMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-1" />
                  )}
                  Generate
                </Button>
              </div>
            </div>
            <CardDescription>AI-predicted attack vectors and threat intelligence</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {predictionsLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : latestPrediction ? (
              <>
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                    <span className="text-sm font-medium">Overall Breach Likelihood</span>
                    <Tooltip>
                      <TooltipTrigger>
                        <HelpCircle className="h-3.5 w-3.5 text-red-400/60" />
                      </TooltipTrigger>
                      <TooltipContent className="max-w-xs">
                        <p>Probability of a successful breach within the selected time horizon, based on your current vulnerabilities and threat landscape.</p>
                      </TooltipContent>
                    </Tooltip>
                  </div>
                  <span className="text-2xl font-bold text-red-400" data-testid="text-overall-breach">
                    {latestPrediction.overallBreachLikelihood}%
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-muted-foreground">Predicted Attack Vectors</span>
                      <Tooltip>
                        <TooltipTrigger>
                          <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">
                          <p>AI-predicted attack techniques based on your security posture, known vulnerabilities, and threat intelligence. Verify or dismiss predictions to improve accuracy.</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                    {latestPrediction.calculatedAt && (
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        Updated {formatTimeAgo(latestPrediction.calculatedAt)}
                      </div>
                    )}
                  </div>
                  {(latestPrediction.predictedAttackVectors as any[])?.map((vector, idx) => {
                    const vectorId = vector.mitreAttackId || `vector-${idx}`;
                    const isDismissed = dismissedVectors.has(vectorId);
                    
                    if (isDismissed && !showDismissed) return null;
                    
                    const confidence = getConfidenceLevel(vector.confidence);
                    const isVerified = verifiedVectors.has(vectorId);
                    return (
                      <div 
                        key={vectorId} 
                        className={`p-3 rounded-lg space-y-2 ${isDismissed ? 'opacity-50 border border-dashed border-muted' : isVerified ? 'bg-emerald-500/5 border border-emerald-500/20' : 'bg-muted/50'}`} 
                        data-testid={`card-vector-${vectorId}`}
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{vector.vector}</span>
                            {isVerified && (
                              <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                Verified
                              </Badge>
                            )}
                            {isDismissed && (
                              <Badge variant="outline" className="bg-gray-500/10 text-gray-400 border-gray-500/30 text-xs">
                                Dismissed
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={adversaryTypeConfig[vector.adversaryProfile]?.color || "text-muted-foreground"}>
                              {adversaryTypeConfig[vector.adversaryProfile]?.label || vector.adversaryProfile}
                            </Badge>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Progress value={vector.likelihood} className="flex-1 h-2" />
                          <span className="text-sm font-mono w-12">{vector.likelihood}%</span>
                        </div>
                        <div className="flex items-center justify-between gap-2 text-xs flex-wrap">
                          <div className="flex items-center gap-3">
                            <Tooltip>
                              <TooltipTrigger>
                                <Badge variant="outline" className={confidence.color}>
                                  {confidence.label} Confidence
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent className="max-w-xs">
                                <p>{confidence.description}</p>
                              </TooltipContent>
                            </Tooltip>
                            <a
                              href={`https://attack.mitre.org/techniques/${vector.mitreAttackId}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-cyan-400"
                              data-testid={`link-mitre-${vectorId}`}
                            >
                              {vector.mitreAttackId}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                          <div className="flex items-center gap-1">
                            {isDismissed ? (
                              <Button 
                                size="sm" 
                                variant="ghost" 
                                className="h-7 text-xs text-muted-foreground"
                                onClick={() => {
                                  setDismissedVectors(prev => {
                                    const next = new Set(Array.from(prev));
                                    next.delete(vectorId);
                                    return next;
                                  });
                                  toast({ title: "Prediction Restored", description: "This attack vector has been restored to the list" });
                                }}
                                data-testid={`btn-restore-${vectorId}`}
                              >
                                Restore
                              </Button>
                            ) : (
                              <>
                                {!isVerified && (
                                  <Button 
                                    size="sm" 
                                    variant="ghost" 
                                    className="h-7 text-xs text-emerald-400 hover:text-emerald-300"
                                    onClick={() => {
                                      setVerifiedVectors(prev => new Set([...Array.from(prev), vectorId]));
                                      toast({ title: "Prediction Verified", description: "This attack vector has been confirmed as a valid threat" });
                                    }}
                                    data-testid={`btn-verify-${vectorId}`}
                                  >
                                    <ThumbsUp className="h-3 w-3 mr-1" />
                                    Verify
                                  </Button>
                                )}
                                <Button 
                                  size="sm" 
                                  variant="ghost" 
                                  className="h-7 text-xs text-muted-foreground hover:text-red-400"
                                  onClick={() => {
                                    setDismissedVectors(prev => new Set([...Array.from(prev), vectorId]));
                                    toast({ title: "Prediction Dismissed", description: "This attack vector has been marked as not applicable" });
                                  }}
                                  data-testid={`btn-dismiss-${vectorId}`}
                                >
                                  <ThumbsDown className="h-3 w-3 mr-1" />
                                  Dismiss
                                </Button>
                              </>
                            )}
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">{vector.estimatedImpact}</div>
                      </div>
                    );
                  })}
                  {dismissedVectors.size > 0 && (
                    <Button 
                      variant="ghost" 
                      size="sm" 
                      className="text-xs text-muted-foreground"
                      onClick={() => setShowDismissed(!showDismissed)}
                      data-testid="btn-toggle-dismissed"
                    >
                      {showDismissed ? 'Hide' : 'Show'} {dismissedVectors.size} dismissed prediction{dismissedVectors.size > 1 ? 's' : ''}
                    </Button>
                  )}
                </div>

                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-muted-foreground">Risk Factors</span>
                    <Tooltip>
                      <TooltipTrigger>
                        <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                      </TooltipTrigger>
                      <TooltipContent className="max-w-xs">
                        <p>Key factors contributing to your breach risk. The percentage shows how much each factor impacts your overall risk score. Arrows indicate if the risk is increasing or decreasing.</p>
                      </TooltipContent>
                    </Tooltip>
                  </div>
                  {(latestPrediction.riskFactors as any[])?.map((factor, idx) => {
                    const TrendIcon = trendIcons[factor.trend as keyof typeof trendIcons]?.icon || Minus;
                    const trendColor = trendIcons[factor.trend as keyof typeof trendIcons]?.color || "text-muted-foreground";
                    const trendLabel = factor.trend === "increasing" ? "Getting worse" : factor.trend === "decreasing" ? "Improving" : "Stable";
                    return (
                      <div key={idx} className="flex items-center justify-between gap-2" data-testid={`risk-factor-${idx}`}>
                        <span className="text-sm">{factor.factor}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-mono">{factor.contribution}%</span>
                          <Tooltip>
                            <TooltipTrigger>
                              <TrendIcon className={`h-4 w-4 ${trendColor}`} />
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>{trendLabel}</p>
                            </TooltipContent>
                          </Tooltip>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="space-y-2">
                  <div className="text-sm font-medium text-muted-foreground">Recommended Actions</div>
                  <ul className="space-y-1">
                    {(latestPrediction.recommendedActions as string[])?.map((action, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-sm" data-testid={`action-${idx}`}>
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                        {action}
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Target className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No predictions yet. Click Generate to create one.</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-adversary-profiles">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Skull className="h-5 w-5 text-purple-400" />
              <CardTitle className="text-lg">AI Adversary Profiles</CardTitle>
            </div>
            <CardDescription>Threat actor personas for attack simulation</CardDescription>
          </CardHeader>
          <CardContent>
            {profilesLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : adversaryProfiles.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {adversaryProfiles.map((profile) => {
                  const config = adversaryTypeConfig[profile.profileType] || adversaryTypeConfig.script_kiddie;
                  const ProfileIcon = config.icon;
                  const capabilities = profile.capabilities as any;
                  return (
                    <div
                      key={profile.id}
                      className="p-3 rounded-lg bg-muted/50 space-y-3"
                      data-testid={`card-profile-${profile.id}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <ProfileIcon className={`h-5 w-5 ${config.color}`} />
                          <span className="font-medium">{profile.name}</span>
                        </div>
                        <Badge variant="outline" className={`text-xs ${config.color}`}>
                          {config.label}
                        </Badge>
                      </div>
                      
                      {capabilities && (
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground w-20">Sophistication</span>
                            <Progress value={(capabilities.technicalSophistication || 0) * 10} className="flex-1 h-1.5" />
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground w-20">Resources</span>
                            <Progress value={(capabilities.resources || 0) * 10} className="flex-1 h-1.5" />
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground w-20">Persistence</span>
                            <Progress value={(capabilities.persistence || 0) * 10} className="flex-1 h-1.5" />
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground w-20">Stealth</span>
                            <Progress value={(capabilities.stealth || 0) * 10} className="flex-1 h-1.5" />
                          </div>
                        </div>
                      )}

                      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground flex-wrap">
                        {profile.detectionDifficulty && (
                          <Badge variant="outline" className="text-xs">
                            {profile.detectionDifficulty === "very_high" ? (
                              <EyeOff className="h-3 w-3 mr-1" />
                            ) : (
                              <Eye className="h-3 w-3 mr-1" />
                            )}
                            {profile.detectionDifficulty.replace("_", " ")}
                          </Badge>
                        )}
                        {profile.avgDwellTime && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {profile.avgDwellTime}d dwell
                          </span>
                        )}
                      </div>

                      {(profile.motivations as string[])?.length > 0 && (
                        <div className="flex gap-1 flex-wrap">
                          {(profile.motivations as string[]).slice(0, 3).map((m, i) => (
                            <Badge key={i} variant="secondary" className="text-xs">
                              {m}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Skull className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No adversary profiles configured</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card data-testid="card-ai-simulations">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Crosshair className="h-5 w-5 text-amber-400" />
              <CardTitle className="text-lg">AI vs AI Simulations</CardTitle>
            </div>
            <Dialog open={isSimulationDialogOpen} onOpenChange={setIsSimulationDialogOpen}>
              <DialogTrigger asChild>
                <Button size="sm" data-testid="btn-new-simulation">
                  <Plus className="h-4 w-4 mr-1" />
                  New Simulation
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create AI Simulation</DialogTitle>
                  <DialogDescription>Configure an AI attacker vs AI defender simulation</DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label>Simulation Name</Label>
                    <Input
                      value={newSimulation.name}
                      onChange={(e) => setNewSimulation({ ...newSimulation, name: e.target.value })}
                      placeholder="e.g., Q4 Red Team Exercise"
                      data-testid="input-simulation-name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Description</Label>
                    <Input
                      value={newSimulation.description}
                      onChange={(e) => setNewSimulation({ ...newSimulation, description: e.target.value })}
                      placeholder="Brief description of simulation goals"
                      data-testid="input-simulation-description"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Attacker Profile</Label>
                    <Select
                      value={newSimulation.attackerProfileId}
                      onValueChange={(v) => setNewSimulation({ ...newSimulation, attackerProfileId: v })}
                    >
                      <SelectTrigger data-testid="select-attacker-profile">
                        <SelectValue placeholder="Select attacker profile" />
                      </SelectTrigger>
                      <SelectContent>
                        {adversaryProfiles.map((profile) => (
                          <SelectItem key={profile.id} value={profile.id}>
                            {profile.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setIsSimulationDialogOpen(false)}>
                    Cancel
                  </Button>
                  <Button
                    onClick={() => createSimulationMutation.mutate(newSimulation)}
                    disabled={createSimulationMutation.isPending || !newSimulation.name}
                    data-testid="btn-start-simulation"
                  >
                    {createSimulationMutation.isPending && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
                    Start Simulation
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
          <CardDescription>Run attack simulations with AI-powered offense and defense</CardDescription>
        </CardHeader>
        <CardContent>
          {simulationsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : simulations.length > 0 ? (
            <div className="space-y-4">
              {simulations.map((sim) => {
                const results = sim.simulationResults as any;
                return (
                  <div
                    key={sim.id}
                    className="p-4 rounded-lg bg-muted/50 space-y-3"
                    data-testid={`card-simulation-${sim.id}`}
                  >
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                      <div>
                        <div className="font-medium">{sim.name}</div>
                        {sim.description && (
                          <div className="text-sm text-muted-foreground">{sim.description}</div>
                        )}
                      </div>
                      <Badge
                        variant="outline"
                        className={
                          sim.simulationStatus === "completed"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                            : sim.simulationStatus === "running"
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                            : sim.simulationStatus === "failed"
                            ? "bg-red-500/10 text-red-400 border-red-500/30"
                            : "bg-gray-500/10 text-gray-400 border-gray-500/30"
                        }
                      >
                        {sim.simulationStatus === "running" && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                        {sim.simulationStatus === "completed" && <CheckCircle2 className="h-3 w-3 mr-1" />}
                        {(sim.simulationStatus || "pending").charAt(0).toUpperCase() + (sim.simulationStatus || "pending").slice(1)}
                      </Badge>
                    </div>

                    {sim.simulationStatus === "completed" && results && (
                      <>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="p-2 rounded bg-background text-center">
                            <div className="text-lg font-bold text-red-400">{results.attackerSuccesses}</div>
                            <div className="text-xs text-muted-foreground">Attacker Wins</div>
                          </div>
                          <div className="p-2 rounded bg-background text-center">
                            <div className="text-lg font-bold text-emerald-400">{results.defenderBlocks}</div>
                            <div className="text-xs text-muted-foreground">Defender Blocks</div>
                          </div>
                          <div className="p-2 rounded bg-background text-center">
                            <div className="text-lg font-bold text-cyan-400">{results.timeToDetection}m</div>
                            <div className="text-xs text-muted-foreground">Time to Detect</div>
                          </div>
                          <div className="p-2 rounded bg-background text-center">
                            <div className="text-lg font-bold text-amber-400">{results.timeToContainment}m</div>
                            <div className="text-xs text-muted-foreground">Time to Contain</div>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                          <div>
                            <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Attack Path</div>
                            <ul className="space-y-1">
                              {(results.attackPath as string[])?.slice(0, 3).map((step, i) => (
                                <li key={i} className="flex items-start gap-2">
                                  <span className="text-red-400 font-mono">{i + 1}.</span>
                                  <span className="text-muted-foreground">{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Detection Points</div>
                            <ul className="space-y-1">
                              {(results.detectionPoints as string[])?.map((point, i) => (
                                <li key={i} className="flex items-start gap-2">
                                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                                  <span className="text-muted-foreground">{point}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>

                        {(results.missedAttacks as string[])?.length > 0 && (
                          <div>
                            <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Missed Attacks</div>
                            <ul className="space-y-1">
                              {(results.missedAttacks as string[])?.map((missed, i) => (
                                <li key={i} className="flex items-start gap-2 text-sm">
                                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                                  <span className="text-muted-foreground">{missed}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {(results.recommendations as string[])?.length > 0 && (
                          <div>
                            <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Recommendations</div>
                            <ul className="space-y-1">
                              {(results.recommendations as string[])?.map((rec, i) => (
                                <li key={i} className="flex items-start gap-2 text-sm">
                                  <Zap className="h-4 w-4 text-cyan-400 shrink-0" />
                                  <span>{rec}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </>
                    )}

                    {sim.simulationStatus === "running" && (
                      <div className="flex items-center justify-center py-4">
                        <Loader2 className="h-6 w-6 animate-spin text-amber-400 mr-2" />
                        <span className="text-muted-foreground">Simulation in progress...</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Crosshair className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No simulations yet. Create one to test your defenses.</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card data-testid="card-purple-team">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-purple-400" />
            <CardTitle className="text-lg">Purple Team Feedback Loop</CardTitle>
          </div>
          <CardDescription>Connect offensive findings to defensive improvements</CardDescription>
        </CardHeader>
        <CardContent>
          {findingsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : purpleTeamFindings.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Technique</TableHead>
                    <TableHead>Detection</TableHead>
                    <TableHead>Control %</TableHead>
                    <TableHead>Recommendation</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Assigned</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {purpleTeamFindings.map((finding) => (
                    <TableRow key={finding.id} data-testid={`row-finding-${finding.id}`}>
                      <TableCell className="font-mono text-sm">
                        {finding.offensiveTechnique || "N/A"}
                      </TableCell>
                      <TableCell>
                        {finding.detectionStatus && (
                          <Badge
                            variant="outline"
                            className={`text-xs ${detectionStatusConfig[finding.detectionStatus]?.color}`}
                          >
                            {detectionStatusConfig[finding.detectionStatus]?.label || finding.detectionStatus}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Progress
                            value={finding.controlEffectiveness || 0}
                            className="w-16 h-2"
                          />
                          <span className="text-xs font-mono">{finding.controlEffectiveness || 0}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <span className="text-sm text-muted-foreground line-clamp-2">
                          {finding.defensiveRecommendation || "-"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Select
                          value={finding.feedbackStatus || "pending"}
                          onValueChange={(value) =>
                            updateFindingMutation.mutate({ id: finding.id, updates: { feedbackStatus: value } })
                          }
                        >
                          <SelectTrigger className="h-8 w-28" data-testid={`select-status-${finding.id}`}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {Object.entries(feedbackStatusConfig).map(([key, config]) => (
                              <SelectItem key={key} value={key}>
                                {config.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        {finding.implementationPriority && (
                          <Badge
                            variant="outline"
                            className={`text-xs ${priorityConfig[finding.implementationPriority]?.color}`}
                          >
                            {priorityConfig[finding.implementationPriority]?.label}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">
                          {finding.assignedTo || "-"}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No purple team findings yet</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
