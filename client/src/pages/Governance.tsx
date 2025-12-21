import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  Shield, 
  AlertTriangle, 
  Power, 
  History, 
  Target, 
  Plus, 
  Trash2,
  Zap,
  Lock,
  CheckCircle2,
  XCircle,
  Clock,
  Activity,
  Gauge,
  ShieldAlert,
  ShieldCheck,
  Play,
  Loader2,
} from "lucide-react";
import { format } from "date-fns";
import type { OrganizationGovernance, ScopeRule, AuthorizationLog } from "@shared/schema";

const ORG_ID = "default";

const executionModeConfig = {
  safe: {
    label: "Safe Mode",
    description: "Dry-run evaluations, no actual exploitation",
    icon: ShieldCheck,
    color: "text-emerald-400",
    bgColor: "bg-emerald-500/10",
    borderColor: "border-emerald-500/30",
  },
  live: {
    label: "Live Mode",
    description: "Real exploitation testing (requires authorization)",
    icon: AlertTriangle,
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/30",
  },
  simulation: {
    label: "Simulation Mode",
    description: "AI vs AI attack simulations",
    icon: Play,
    color: "text-amber-400",
    bgColor: "bg-amber-500/10",
    borderColor: "border-amber-500/30",
  },
};

const targetTypes = [
  { value: "ip", label: "IP Address" },
  { value: "cidr", label: "CIDR Range" },
  { value: "hostname", label: "Hostname" },
  { value: "pattern", label: "Pattern (Regex)" },
];

const ruleTypes = [
  { value: "allow", label: "Allow" },
  { value: "block", label: "Block" },
];

const actionTypes = [
  { value: "all", label: "All Actions" },
  { value: "evaluation_started", label: "Evaluation Started" },
  { value: "evaluation_completed", label: "Evaluation Completed" },
  { value: "kill_switch_activated", label: "Kill Switch Activated" },
  { value: "kill_switch_deactivated", label: "Kill Switch Deactivated" },
  { value: "execution_mode_changed", label: "Mode Changed" },
  { value: "scope_rule_modified", label: "Scope Rule Modified" },
  { value: "rate_limit_exceeded", label: "Rate Limit Exceeded" },
  { value: "unauthorized_target_blocked", label: "Unauthorized Blocked" },
  { value: "live_execution_authorized", label: "Live Execution Authorized" },
  { value: "batch_job_started", label: "Batch Job Started" },
  { value: "simulation_run", label: "Simulation Run" },
];

export default function Governance() {
  const { toast } = useToast();
  const [isAddRuleOpen, setIsAddRuleOpen] = useState(false);
  const [actionFilter, setActionFilter] = useState("all");
  const [logsLimit, setLogsLimit] = useState(25);
  
  const [newRule, setNewRule] = useState({
    name: "",
    ruleType: "block",
    targetType: "hostname",
    targetValue: "",
  });

  const { data: governance, isLoading: govLoading } = useQuery<OrganizationGovernance>({
    queryKey: ["/api/governance", ORG_ID],
  });

  const { data: scopeRules = [], isLoading: rulesLoading } = useQuery<ScopeRule[]>({
    queryKey: ["/api/scope-rules", ORG_ID],
  });

  const { data: authLogs = [], isLoading: logsLoading } = useQuery<AuthorizationLog[]>({
    queryKey: ["/api/authorization-logs", ORG_ID],
  });

  interface RateLimitStatus {
    name: string;
    displayName: string;
    windowMs: number;
    maxRequests: number;
    currentUsage: number;
    remaining: number;
    resetInSeconds: number;
  }

  const { data: rateLimits = [] } = useQuery<RateLimitStatus[]>({
    queryKey: ["/api/governance/rate-limits"],
    refetchInterval: 10000,
  });

  const updateGovernanceMutation = useMutation({
    mutationFn: async (updates: Partial<OrganizationGovernance>) => {
      const response = await apiRequest("PATCH", `/api/governance/${ORG_ID}`, updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/governance", ORG_ID] });
      toast({
        title: "Settings updated",
        description: "Governance settings have been updated",
      });
    },
    onError: (error) => {
      toast({
        title: "Update failed",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const killSwitchMutation = useMutation({
    mutationFn: async (activate: boolean) => {
      const response = await apiRequest("POST", `/api/governance/${ORG_ID}/kill-switch`, { 
        activate,
        activatedBy: "System Admin"
      });
      return response.json();
    },
    onSuccess: (_, activate) => {
      queryClient.invalidateQueries({ queryKey: ["/api/governance", ORG_ID] });
      queryClient.invalidateQueries({ queryKey: ["/api/authorization-logs", ORG_ID] });
      toast({
        title: activate ? "Kill Switch Activated" : "Kill Switch Deactivated",
        description: activate ? "All operations have been halted" : "Operations have resumed",
        variant: activate ? "destructive" : "default",
      });
    },
    onError: (error) => {
      toast({
        title: "Kill switch toggle failed",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const createRuleMutation = useMutation({
    mutationFn: async (data: typeof newRule) => {
      const response = await apiRequest("POST", "/api/scope-rules", {
        ...data,
        organizationId: ORG_ID,
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scope-rules", ORG_ID] });
      setIsAddRuleOpen(false);
      setNewRule({ name: "", ruleType: "block", targetType: "hostname", targetValue: "" });
      toast({
        title: "Rule created",
        description: "Scope rule has been added",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to create rule",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/scope-rules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scope-rules", ORG_ID] });
      toast({
        title: "Rule deleted",
        description: "Scope rule has been removed",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to delete rule",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const handleModeChange = (mode: "safe" | "live" | "simulation") => {
    updateGovernanceMutation.mutate({ executionMode: mode });
  };

  const handleCreateRule = () => {
    if (!newRule.name || !newRule.targetValue) {
      toast({
        title: "Validation error",
        description: "Name and target value are required",
        variant: "destructive",
      });
      return;
    }
    createRuleMutation.mutate(newRule);
  };

  const filteredLogs = actionFilter === "all" 
    ? authLogs 
    : authLogs.filter(log => log.action === actionFilter);

  const displayedLogs = filteredLogs.slice(0, logsLimit);

  const currentMode = (governance?.executionMode as keyof typeof executionModeConfig) || "safe";
  const modeConfig = executionModeConfig[currentMode];
  const ModeIcon = modeConfig.icon;

  const getRiskBadge = (riskLevel: string | null) => {
    const styles: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return styles[riskLevel || "low"] || styles.low;
  };

  if (govLoading) {
    return (
      <div className="space-y-6" data-testid="governance-loading">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-64 bg-muted rounded" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-40 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="governance-page">
      <div>
        <h1 className="text-2xl font-bold text-foreground" data-testid="text-governance-title">
          Governance & Safety Controls
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure execution modes, rate limits, scope rules, and audit red-team activities
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card data-testid="card-execution-mode">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              <CardTitle className="text-lg">Execution Mode</CardTitle>
            </div>
            <CardDescription>Control how evaluations are performed</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className={`p-4 rounded-lg border ${modeConfig.bgColor} ${modeConfig.borderColor}`}>
              <div className="flex items-center gap-3">
                <ModeIcon className={`h-8 w-8 ${modeConfig.color}`} />
                <div>
                  <div className={`font-semibold ${modeConfig.color}`} data-testid="text-current-mode">
                    {modeConfig.label}
                  </div>
                  <div className="text-sm text-muted-foreground">{modeConfig.description}</div>
                </div>
              </div>
            </div>

            <Tabs value={currentMode} onValueChange={(v) => handleModeChange(v as "safe" | "live" | "simulation")}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="safe" data-testid="tab-safe-mode">
                  <ShieldCheck className="w-4 h-4 mr-1" />
                  Safe
                </TabsTrigger>
                <TabsTrigger value="simulation" data-testid="tab-simulation-mode">
                  <Play className="w-4 h-4 mr-1" />
                  Simulation
                </TabsTrigger>
                <TabsTrigger value="live" data-testid="tab-live-mode">
                  <AlertTriangle className="w-4 h-4 mr-1" />
                  Live
                </TabsTrigger>
              </TabsList>
            </Tabs>

            {currentMode === "live" && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-300">
                <AlertTriangle className="w-4 h-4 inline mr-2" />
                Live mode executes actual exploitation attempts. Ensure proper authorization is in place.
              </div>
            )}
          </CardContent>
        </Card>

        <Card data-testid="card-kill-switch">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Power className="h-5 w-5 text-red-400" />
              <CardTitle className="text-lg">Emergency Kill Switch</CardTitle>
            </div>
            <CardDescription>Immediately halt all evaluation operations</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className={`p-4 rounded-lg border ${
              governance?.killSwitchActive 
                ? "bg-red-500/10 border-red-500/30" 
                : "bg-emerald-500/10 border-emerald-500/30"
            }`}>
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  {governance?.killSwitchActive ? (
                    <ShieldAlert className="h-8 w-8 text-red-400" />
                  ) : (
                    <ShieldCheck className="h-8 w-8 text-emerald-400" />
                  )}
                  <div>
                    <div className={`font-semibold ${governance?.killSwitchActive ? "text-red-400" : "text-emerald-400"}`} data-testid="text-kill-switch-status">
                      {governance?.killSwitchActive ? "Kill Switch ACTIVE" : "Operations Normal"}
                    </div>
                    {governance?.killSwitchActive && governance.killSwitchActivatedBy && (
                      <div className="text-xs text-muted-foreground">
                        Activated by {governance.killSwitchActivatedBy} at {governance.killSwitchActivatedAt ? format(new Date(governance.killSwitchActivatedAt), "PPpp") : "Unknown"}
                      </div>
                    )}
                  </div>
                </div>
                
                {governance?.killSwitchActive ? (
                  <Button
                    variant="outline"
                    onClick={() => killSwitchMutation.mutate(false)}
                    disabled={killSwitchMutation.isPending}
                    data-testid="btn-deactivate-kill-switch"
                  >
                    {killSwitchMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Deactivate
                  </Button>
                ) : (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="destructive" data-testid="btn-activate-kill-switch">
                        <Power className="w-4 h-4 mr-2" />
                        Activate Kill Switch
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Activate Emergency Kill Switch?</AlertDialogTitle>
                        <AlertDialogDescription>
                          This will immediately halt all ongoing and queued evaluations. 
                          All in-progress operations will be terminated. This action is logged for audit purposes.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => killSwitchMutation.mutate(true)}
                          className="bg-red-600 text-white"
                          data-testid="btn-confirm-kill-switch"
                        >
                          Activate Kill Switch
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                <div className="text-sm text-muted-foreground">Auto-kill on Critical</div>
                <Switch
                  checked={governance?.autoKillOnCritical ?? true}
                  onCheckedChange={(checked) => updateGovernanceMutation.mutate({ autoKillOnCritical: checked })}
                  data-testid="switch-auto-kill"
                />
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                <div className="text-sm text-muted-foreground">Require Live Auth</div>
                <Switch
                  checked={governance?.requireAuthorizationForLive ?? true}
                  onCheckedChange={(checked) => updateGovernanceMutation.mutate({ requireAuthorizationForLive: checked })}
                  data-testid="switch-require-live-auth"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card data-testid="card-rate-limits">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Gauge className="h-5 w-5 text-amber-400" />
              <CardTitle className="text-lg">Rate Limits</CardTitle>
            </div>
            <CardDescription>Real-time API rate limit status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              {rateLimits.length > 0 ? (
                rateLimits.slice(0, 5).map((limit) => {
                  const usagePercent = limit.maxRequests > 0 
                    ? (limit.currentUsage / limit.maxRequests) * 100 
                    : 0;
                  const isWarning = usagePercent > 75;
                  const isCritical = usagePercent > 90;
                  return (
                    <div key={limit.name}>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-muted-foreground">{limit.displayName}</span>
                        <span className={`font-mono ${isCritical ? "text-red-400" : isWarning ? "text-amber-400" : ""}`} data-testid={`text-limit-${limit.name}`}>
                          {limit.currentUsage} / {limit.maxRequests}
                          {limit.resetInSeconds > 0 && (
                            <span className="text-xs text-muted-foreground ml-2">
                              (resets in {limit.resetInSeconds}s)
                            </span>
                          )}
                        </span>
                      </div>
                      <Progress 
                        value={usagePercent} 
                        className={`h-2 ${isCritical ? "[&>div]:bg-red-500" : isWarning ? "[&>div]:bg-amber-500" : ""}`} 
                      />
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-4 text-muted-foreground">
                  <Activity className="h-6 w-6 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No rate limit activity yet</p>
                </div>
              )}
            </div>

            <div className="grid grid-cols-3 gap-3 pt-2">
              {rateLimits.slice(0, 3).map((limit) => (
                <div key={limit.name} className="p-3 rounded-lg bg-muted/50 text-center">
                  <div className="text-xl font-bold text-foreground">{limit.remaining}</div>
                  <div className="text-xs text-muted-foreground">{limit.displayName} Left</div>
                </div>
              ))}
              {rateLimits.length === 0 && (
                <>
                  <div className="p-3 rounded-lg bg-muted/50 text-center">
                    <div className="text-xl font-bold text-foreground">100</div>
                    <div className="text-xs text-muted-foreground">API/min</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50 text-center">
                    <div className="text-xl font-bold text-foreground">30</div>
                    <div className="text-xs text-muted-foreground">Evaluations/min</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50 text-center">
                    <div className="text-xl font-bold text-foreground">3</div>
                    <div className="text-xs text-muted-foreground">Simulations/5min</div>
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>

        <Card data-testid="card-scope-rules">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <Target className="h-5 w-5 text-cyan-400" />
                <CardTitle className="text-lg">Scope Rules</CardTitle>
              </div>
              <Dialog open={isAddRuleOpen} onOpenChange={setIsAddRuleOpen}>
                <DialogTrigger asChild>
                  <Button size="sm" data-testid="btn-add-rule">
                    <Plus className="w-4 h-4 mr-1" />
                    Add Rule
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Scope Rule</DialogTitle>
                    <DialogDescription>Define allowed or blocked target patterns</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label>Rule Name</Label>
                      <Input
                        value={newRule.name}
                        onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                        placeholder="e.g., Block Production Servers"
                        data-testid="input-rule-name"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Rule Type</Label>
                        <Select
                          value={newRule.ruleType}
                          onValueChange={(v) => setNewRule({ ...newRule, ruleType: v })}
                        >
                          <SelectTrigger data-testid="select-rule-type">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {ruleTypes.map((rt) => (
                              <SelectItem key={rt.value} value={rt.value}>{rt.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Target Type</Label>
                        <Select
                          value={newRule.targetType}
                          onValueChange={(v) => setNewRule({ ...newRule, targetType: v })}
                        >
                          <SelectTrigger data-testid="select-target-type">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {targetTypes.map((tt) => (
                              <SelectItem key={tt.value} value={tt.value}>{tt.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>Target Value</Label>
                      <Input
                        value={newRule.targetValue}
                        onChange={(e) => setNewRule({ ...newRule, targetValue: e.target.value })}
                        placeholder="e.g., *.production.example.com"
                        data-testid="input-target-value"
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setIsAddRuleOpen(false)}>
                      Cancel
                    </Button>
                    <Button 
                      onClick={handleCreateRule}
                      disabled={createRuleMutation.isPending}
                      data-testid="btn-save-rule"
                    >
                      {createRuleMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                      Save Rule
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
            <CardDescription>Allow/block patterns for target assets</CardDescription>
          </CardHeader>
          <CardContent>
            {rulesLoading ? (
              <div className="text-center py-6 text-muted-foreground">Loading rules...</div>
            ) : scopeRules.length === 0 ? (
              <div className="text-center py-6">
                <Target className="h-10 w-10 mx-auto mb-2 text-muted-foreground opacity-30" />
                <p className="text-muted-foreground text-sm">No scope rules defined</p>
                <p className="text-muted-foreground text-xs">Add rules to control target access</p>
              </div>
            ) : (
              <div className="max-h-48 overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scopeRules.map((rule) => (
                      <TableRow key={rule.id} data-testid={`row-rule-${rule.id}`}>
                        <TableCell className="font-medium">{rule.name}</TableCell>
                        <TableCell>
                          <Badge className={rule.ruleType === "allow" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-red-500/10 text-red-400 border-red-500/30"}>
                            {rule.ruleType.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[200px] truncate" title={rule.targetValue}>
                          {rule.targetValue}
                        </TableCell>
                        <TableCell>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => deleteRuleMutation.mutate(rule.id)}
                            disabled={deleteRuleMutation.isPending}
                            data-testid={`btn-delete-rule-${rule.id}`}
                          >
                            <Trash2 className="w-4 h-4 text-muted-foreground" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card data-testid="card-authorization-logs">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <History className="h-5 w-5 text-cyan-400" />
              <CardTitle className="text-lg">Authorization Logs</CardTitle>
            </div>
            <Select value={actionFilter} onValueChange={setActionFilter}>
              <SelectTrigger className="w-[200px]" data-testid="select-action-filter">
                <SelectValue placeholder="Filter by action" />
              </SelectTrigger>
              <SelectContent>
                {actionTypes.map((at) => (
                  <SelectItem key={at.value} value={at.value}>{at.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <CardDescription>Audit trail of red-team activities and authorization events</CardDescription>
        </CardHeader>
        <CardContent>
          {logsLoading ? (
            <div className="text-center py-6 text-muted-foreground">Loading logs...</div>
          ) : authLogs.length === 0 ? (
            <div className="text-center py-6">
              <History className="h-10 w-10 mx-auto mb-2 text-muted-foreground opacity-30" />
              <p className="text-muted-foreground text-sm">No authorization logs yet</p>
              <p className="text-muted-foreground text-xs">Activity will appear here as evaluations run</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>Risk Level</TableHead>
                      <TableHead>Authorized</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {displayedLogs.map((log) => (
                      <TableRow key={log.id} data-testid={`row-log-${log.id}`}>
                        <TableCell className="font-mono text-xs whitespace-nowrap">
                          {log.createdAt ? format(new Date(log.createdAt), "MMM d, HH:mm:ss") : "N/A"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {log.action?.replace(/_/g, " ").toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.userName || log.userId || "System"}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[150px] truncate" title={log.targetAsset || ""}>
                          {log.targetAsset || "-"}
                        </TableCell>
                        <TableCell>
                          {log.riskLevel && (
                            <Badge className={getRiskBadge(log.riskLevel)}>
                              {log.riskLevel.toUpperCase()}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {log.authorized ? (
                            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                          ) : (
                            <XCircle className="w-5 h-5 text-red-400" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              
              {filteredLogs.length > logsLimit && (
                <div className="flex justify-center mt-4">
                  <Button
                    variant="outline"
                    onClick={() => setLogsLimit(prev => prev + 25)}
                    data-testid="btn-load-more-logs"
                  >
                    Load More ({filteredLogs.length - logsLimit} remaining)
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
