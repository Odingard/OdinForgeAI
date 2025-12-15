import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
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
} from "lucide-react";
import { format } from "date-fns";
import type { 
  DefensivePostureScore, 
  AttackPrediction, 
  AiAdversaryProfile, 
  AiSimulation, 
  PurpleTeamFinding 
} from "@shared/schema";

const ORG_ID = "default";

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

export default function Advanced() {
  const { toast } = useToast();
  const [timeHorizon, setTimeHorizon] = useState("30d");
  const [isSimulationDialogOpen, setIsSimulationDialogOpen] = useState(false);
  const [newSimulation, setNewSimulation] = useState({
    name: "",
    description: "",
    attackerProfileId: "",
  });

  const { data: posture, isLoading: postureLoading } = useQuery<DefensivePostureScore>({
    queryKey: ["/api/defensive-posture", ORG_ID],
  });

  const { data: predictions = [], isLoading: predictionsLoading } = useQuery<AttackPrediction[]>({
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

  const latestPrediction = predictions.length > 0 ? predictions[0] : null;
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
                <div className="p-3 rounded-lg bg-muted/50">
                  <div className="text-xs text-muted-foreground uppercase tracking-wide">Breach Likelihood</div>
                  <div className="text-2xl font-bold text-orange-400" data-testid="text-breach-likelihood">
                    {posture?.breachLikelihood || 0}%
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-muted/50">
                  <div className="text-xs text-muted-foreground uppercase tracking-wide">Benchmark</div>
                  <div className="text-2xl font-bold text-cyan-400" data-testid="text-benchmark">
                    {posture?.benchmarkPercentile || 0}th %ile
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-muted/50">
                  <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    MTTD
                  </div>
                  <div className="text-2xl font-bold text-foreground" data-testid="text-mttd">
                    {posture?.meanTimeToDetect || 0}h
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-muted/50">
                  <div className="text-xs text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                    <Zap className="h-3 w-3" />
                    MTTR
                  </div>
                  <div className="text-2xl font-bold text-foreground" data-testid="text-mttr">
                    {posture?.meanTimeToRespond || 0}h
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium text-muted-foreground mb-3">Category Breakdown</div>
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
                  </div>
                  <span className="text-2xl font-bold text-red-400" data-testid="text-overall-breach">
                    {latestPrediction.overallBreachLikelihood}%
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="text-sm font-medium text-muted-foreground">Predicted Attack Vectors</div>
                  {(latestPrediction.predictedAttackVectors as any[])?.map((vector, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-muted/50 space-y-2" data-testid={`card-vector-${idx}`}>
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="font-medium">{vector.vector}</span>
                        <Badge variant="outline" className={adversaryTypeConfig[vector.adversaryProfile]?.color || "text-muted-foreground"}>
                          {adversaryTypeConfig[vector.adversaryProfile]?.label || vector.adversaryProfile}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        <Progress value={vector.likelihood} className="flex-1 h-2" />
                        <span className="text-sm font-mono w-12">{vector.likelihood}%</span>
                      </div>
                      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground flex-wrap">
                        <span>Confidence: {vector.confidence}%</span>
                        <a
                          href={`https://attack.mitre.org/techniques/${vector.mitreAttackId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-cyan-400"
                          data-testid={`link-mitre-${idx}`}
                        >
                          {vector.mitreAttackId}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                      <div className="text-xs text-muted-foreground">{vector.estimatedImpact}</div>
                    </div>
                  ))}
                </div>

                <div className="space-y-3">
                  <div className="text-sm font-medium text-muted-foreground">Risk Factors</div>
                  {(latestPrediction.riskFactors as any[])?.map((factor, idx) => {
                    const TrendIcon = trendIcons[factor.trend as keyof typeof trendIcons]?.icon || Minus;
                    const trendColor = trendIcons[factor.trend as keyof typeof trendIcons]?.color || "text-muted-foreground";
                    return (
                      <div key={idx} className="flex items-center justify-between gap-2" data-testid={`risk-factor-${idx}`}>
                        <span className="text-sm">{factor.factor}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-mono">{factor.contribution}%</span>
                          <TrendIcon className={`h-4 w-4 ${trendColor}`} />
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
