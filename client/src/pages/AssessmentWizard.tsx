import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import {
  Target,
  Crosshair,
  Settings2,
  Rocket,
  ChevronRight,
  ChevronLeft,
  Check,
  Globe,
  Server,
  Shield,
  Zap,
  AlertTriangle,
  ScanSearch,
  Link2,
  Loader2,
  Key,
  Cloud,
  Container,
  Network,
  Lock,
} from "lucide-react";

// ============================================================================
// Types
// ============================================================================

type AssessmentType = "full_assessment" | "breach_chain" | "both";
type ExecutionMode = "safe" | "simulation" | "live";

interface WizardState {
  // Step 1: Target
  targetUrl: string;
  targetName: string;
  targetDescription: string;
  selectedAssetIds: string[];

  // Step 2: Scope
  assessmentType: AssessmentType;

  // Step 3: Configure
  executionMode: ExecutionMode;
  // Full Assessment options
  assessmentMode: "agent" | "external";
  enableWebAppRecon: boolean;
  enableParallelAgents: boolean;
  maxConcurrentAgents: number;
  enableLLMValidation: boolean;
  // Breach Chain options
  pauseOnCritical: boolean;
  enabledPhases: string[];
}

const INITIAL_STATE: WizardState = {
  targetUrl: "",
  targetName: "",
  targetDescription: "",
  selectedAssetIds: [],
  assessmentType: "full_assessment",
  executionMode: "safe",
  assessmentMode: "external",
  enableWebAppRecon: true,
  enableParallelAgents: true,
  maxConcurrentAgents: 5,
  enableLLMValidation: true,
  pauseOnCritical: false,
  enabledPhases: [
    "application_compromise",
    "credential_extraction",
    "cloud_iam_escalation",
    "container_k8s_breakout",
    "lateral_movement",
    "impact_assessment",
  ],
};

const ALL_PHASES = [
  { id: "application_compromise", label: "App Compromise", icon: Crosshair, color: "text-red-500", description: "Exploit application-layer vulnerabilities" },
  { id: "credential_extraction", label: "Credential Extraction", icon: Key, color: "text-amber-500", description: "Harvest credentials from compromised apps" },
  { id: "cloud_iam_escalation", label: "Cloud IAM Escalation", icon: Cloud, color: "text-cyan-500", description: "Escalate via IAM misconfigurations" },
  { id: "container_k8s_breakout", label: "K8s Breakout", icon: Container, color: "text-purple-500", description: "Container escape and RBAC abuse" },
  { id: "lateral_movement", label: "Lateral Movement", icon: Network, color: "text-blue-500", description: "Pivot across network segments" },
  { id: "impact_assessment", label: "Impact Assessment", icon: AlertTriangle, color: "text-orange-500", description: "Aggregate business impact" },
];

const STEPS = [
  { id: "target", label: "Target", icon: Target },
  { id: "scope", label: "Scope", icon: Crosshair },
  { id: "configure", label: "Configure", icon: Settings2 },
  { id: "launch", label: "Launch", icon: Rocket },
];

// ============================================================================
// Step Components
// ============================================================================

function StepTarget({ state, setState }: { state: WizardState; setState: (s: Partial<WizardState>) => void }) {
  const { data: assets = [] } = useQuery<any[]>({ queryKey: ["/api/assets"] });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">What are you testing?</h2>
        <p className="text-sm text-muted-foreground">
          Enter a target URL, IP, or select from your registered assets.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="text-sm font-medium block mb-1.5">Target URL or IP</label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={state.targetUrl}
              onChange={(e) => setState({ targetUrl: e.target.value })}
              placeholder="https://app.example.com or 10.0.1.50"
              className="pl-10"
              data-testid="wizard-target-url"
            />
          </div>
        </div>

        <div>
          <label className="text-sm font-medium block mb-1.5">Assessment Name</label>
          <Input
            value={state.targetName}
            onChange={(e) => setState({ targetName: e.target.value })}
            placeholder="Q1 2026 Production Assessment"
            data-testid="wizard-target-name"
          />
        </div>

        <div>
          <label className="text-sm font-medium block mb-1.5">Description (optional)</label>
          <Textarea
            value={state.targetDescription}
            onChange={(e) => setState({ targetDescription: e.target.value })}
            placeholder="Describe the scope and objectives..."
            rows={3}
            data-testid="wizard-target-description"
          />
        </div>
      </div>

      {assets.length > 0 && (
        <>
          <Separator />
          <div>
            <label className="text-sm font-medium block mb-2">Or select registered assets</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
              {assets.slice(0, 20).map((asset: any) => {
                const selected = state.selectedAssetIds.includes(asset.id);
                return (
                  <button
                    key={asset.id}
                    type="button"
                    onClick={() => {
                      const ids = selected
                        ? state.selectedAssetIds.filter((id) => id !== asset.id)
                        : [...state.selectedAssetIds, asset.id];
                      setState({ selectedAssetIds: ids });
                    }}
                    className={`flex items-center gap-3 p-3 rounded-md border text-left transition-all ${
                      selected
                        ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <Server className="h-4 w-4 text-muted-foreground shrink-0" />
                    <div className="min-w-0">
                      <div className="text-sm font-medium truncate">{asset.name || asset.id}</div>
                      {asset.hostname && (
                        <div className="text-xs text-muted-foreground truncate">{asset.hostname}</div>
                      )}
                    </div>
                    {selected && <Check className="h-4 w-4 text-primary ml-auto shrink-0" />}
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function StepScope({ state, setState }: { state: WizardState; setState: (s: Partial<WizardState>) => void }) {
  const types: { id: AssessmentType; label: string; icon: typeof ScanSearch; description: string; badge?: string }[] = [
    {
      id: "full_assessment",
      label: "Full Assessment",
      icon: ScanSearch,
      description: "Infrastructure-wide posture scan. Discovers assets, tests vulnerabilities, analyzes attack surfaces across all registered systems.",
      badge: "Recommended for first run",
    },
    {
      id: "breach_chain",
      label: "Breach Chain",
      icon: Link2,
      description: "Cross-domain attack simulation. Chains app compromise → credential extraction → cloud escalation → K8s breakout → lateral movement into a single breach path.",
      badge: "Advanced",
    },
    {
      id: "both",
      label: "Full Assessment + Breach Chain",
      icon: Zap,
      description: "Run both sequentially. Full Assessment discovers the attack surface, then Breach Chain validates exploitability with a multi-domain attack chain.",
      badge: "Comprehensive",
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">What kind of assessment?</h2>
        <p className="text-sm text-muted-foreground">
          Choose the assessment type based on your security objectives.
        </p>
      </div>

      <div className="space-y-3">
        {types.map((type) => {
          const Icon = type.icon;
          const active = state.assessmentType === type.id;
          return (
            <button
              key={type.id}
              type="button"
              onClick={() => setState({ assessmentType: type.id })}
              className={`w-full flex items-start gap-4 p-4 rounded-lg border text-left transition-all ${
                active
                  ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                  : "border-border hover:border-primary/50"
              }`}
              data-testid={`wizard-scope-${type.id}`}
            >
              <div className={`mt-0.5 p-2 rounded-md ${active ? "bg-primary/10" : "bg-muted"}`}>
                <Icon className={`h-5 w-5 ${active ? "text-primary" : "text-muted-foreground"}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium">{type.label}</span>
                  {type.badge && (
                    <Badge variant="outline" className="text-[10px]">
                      {type.badge}
                    </Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">{type.description}</p>
              </div>
              {active && <Check className="h-5 w-5 text-primary mt-0.5 shrink-0" />}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function StepConfigure({ state, setState }: { state: WizardState; setState: (s: Partial<WizardState>) => void }) {
  const showFullAssessment = state.assessmentType === "full_assessment" || state.assessmentType === "both";
  const showBreachChain = state.assessmentType === "breach_chain" || state.assessmentType === "both";

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">Configure your assessment</h2>
        <p className="text-sm text-muted-foreground">
          Set execution mode and fine-tune options. Defaults work well for most environments.
        </p>
      </div>

      {/* Execution Mode — always shown */}
      <div className="space-y-3">
        <label className="text-sm font-medium flex items-center gap-2">
          <Shield className="h-4 w-4" />
          Execution Mode
        </label>
        <div className="grid grid-cols-3 gap-2">
          {([
            { id: "safe", label: "Safe", desc: "Read-only reconnaissance", color: "text-emerald-500", borderColor: "border-emerald-500/30" },
            { id: "simulation", label: "Simulation", desc: "Safe payloads, no exploit", color: "text-amber-500", borderColor: "border-amber-500/30" },
            { id: "live", label: "Live", desc: "Full exploitation (requires CISO approval)", color: "text-red-500", borderColor: "border-red-500/30" },
          ] as const).map((mode) => {
            const active = state.executionMode === mode.id;
            return (
              <button
                key={mode.id}
                type="button"
                onClick={() => setState({ executionMode: mode.id })}
                className={`p-3 rounded-md border text-center transition-all ${
                  active
                    ? `${mode.borderColor} bg-${mode.id === "safe" ? "emerald" : mode.id === "simulation" ? "amber" : "red"}-500/5 ring-1 ring-${mode.id === "safe" ? "emerald" : mode.id === "simulation" ? "amber" : "red"}-500/30`
                    : "border-border hover:border-primary/50"
                }`}
                data-testid={`wizard-mode-${mode.id}`}
              >
                <div className={`text-sm font-medium ${active ? mode.color : ""}`}>{mode.label}</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">{mode.desc}</div>
              </button>
            );
          })}
        </div>
        {state.executionMode === "live" && (
          <div className="flex items-center gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/20 text-sm">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span className="text-red-300">Live mode executes real exploits. Requires CISO-level approval and governance policy.</span>
          </div>
        )}
      </div>

      {showFullAssessment && (
        <>
          <Separator />
          <div className="space-y-4">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <ScanSearch className="h-4 w-4 text-cyan-500" />
              Full Assessment Options
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium block mb-1.5">Assessment Mode</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setState({ assessmentMode: "agent" })}
                    className={`p-3 rounded-md border text-left transition-all ${
                      state.assessmentMode === "agent" ? "border-primary bg-primary/5" : "border-border"
                    }`}
                  >
                    <div className="text-sm font-medium">Agent-Based</div>
                    <div className="text-[11px] text-muted-foreground">Requires endpoint agents</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setState({ assessmentMode: "external" })}
                    className={`p-3 rounded-md border text-left transition-all ${
                      state.assessmentMode === "external" ? "border-primary bg-primary/5" : "border-border"
                    }`}
                  >
                    <div className="text-sm font-medium">External</div>
                    <div className="text-[11px] text-muted-foreground">No agents needed</div>
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-sm">Web App Reconnaissance</label>
                  <Switch checked={state.enableWebAppRecon} onCheckedChange={(v) => setState({ enableWebAppRecon: v })} />
                </div>
                <div className="flex items-center justify-between">
                  <label className="text-sm">Parallel Agents</label>
                  <Switch checked={state.enableParallelAgents} onCheckedChange={(v) => setState({ enableParallelAgents: v })} />
                </div>
                <div className="flex items-center justify-between">
                  <label className="text-sm">LLM-Powered Validation</label>
                  <Switch checked={state.enableLLMValidation} onCheckedChange={(v) => setState({ enableLLMValidation: v })} />
                </div>
                {state.enableParallelAgents && (
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Max Concurrent Agents</label>
                    <Select
                      value={String(state.maxConcurrentAgents)}
                      onValueChange={(v) => setState({ maxConcurrentAgents: Number(v) })}
                    >
                      <SelectTrigger className="w-20 h-8">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {[3, 5, 8, 10].map((n) => (
                          <SelectItem key={n} value={String(n)}>{n}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {showBreachChain && (
        <>
          <Separator />
          <div className="space-y-4">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Link2 className="h-4 w-4 text-purple-500" />
              Breach Chain Options
            </h3>

            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Pause on Critical</label>
                <p className="text-[11px] text-muted-foreground">Halt chain when a critical finding is detected</p>
              </div>
              <Switch checked={state.pauseOnCritical} onCheckedChange={(v) => setState({ pauseOnCritical: v })} />
            </div>

            <div>
              <label className="text-sm font-medium block mb-2">Attack Phases</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ALL_PHASES.map((phase) => {
                  const PhaseIcon = phase.icon;
                  const enabled = state.enabledPhases.includes(phase.id);
                  return (
                    <button
                      key={phase.id}
                      type="button"
                      onClick={() => {
                        const phases = enabled
                          ? state.enabledPhases.filter((p) => p !== phase.id)
                          : [...state.enabledPhases, phase.id];
                        setState({ enabledPhases: phases });
                      }}
                      className={`flex items-center gap-3 p-2.5 rounded-md border text-left transition-all ${
                        enabled ? "border-primary/50 bg-primary/5" : "border-border opacity-60"
                      }`}
                    >
                      <PhaseIcon className={`h-4 w-4 shrink-0 ${enabled ? phase.color : "text-muted-foreground"}`} />
                      <div className="min-w-0">
                        <div className="text-sm font-medium">{phase.label}</div>
                        <div className="text-[10px] text-muted-foreground truncate">{phase.description}</div>
                      </div>
                      {enabled && <Check className="h-3.5 w-3.5 text-primary ml-auto shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function StepLaunch({ state, isLaunching }: { state: WizardState; isLaunching: boolean }) {
  const target = state.targetUrl || (state.selectedAssetIds.length > 0 ? `${state.selectedAssetIds.length} asset(s)` : "—");
  const scopeLabel =
    state.assessmentType === "full_assessment" ? "Full Assessment" :
    state.assessmentType === "breach_chain" ? "Breach Chain" :
    "Full Assessment + Breach Chain";

  const modeColors: Record<ExecutionMode, string> = {
    safe: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    simulation: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    live: "bg-red-500/20 text-red-400 border-red-500/30",
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold mb-1">Review & Launch</h2>
        <p className="text-sm text-muted-foreground">
          Confirm your assessment configuration before starting.
        </p>
      </div>

      <div className="space-y-4">
        <div className="p-4 rounded-lg border space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Target</span>
            <span className="text-sm font-medium truncate max-w-[60%] text-right">{target}</span>
          </div>
          {state.targetName && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Name</span>
              <span className="text-sm font-medium">{state.targetName}</span>
            </div>
          )}
          <Separator />
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Scope</span>
            <span className="text-sm font-medium">{scopeLabel}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Execution Mode</span>
            <Badge variant="outline" className={modeColors[state.executionMode]}>
              {state.executionMode.charAt(0).toUpperCase() + state.executionMode.slice(1)}
            </Badge>
          </div>

          {(state.assessmentType === "full_assessment" || state.assessmentType === "both") && (
            <>
              <Separator />
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Assessment Mode</span>
                <span className="text-sm font-medium capitalize">{state.assessmentMode}</span>
              </div>
            </>
          )}

          {(state.assessmentType === "breach_chain" || state.assessmentType === "both") && (
            <>
              <Separator />
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Phases</span>
                <span className="text-sm font-medium">{state.enabledPhases.length} of 6</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Pause on Critical</span>
                <span className="text-sm font-medium">{state.pauseOnCritical ? "Yes" : "No"}</span>
              </div>
            </>
          )}
        </div>

        {state.executionMode === "live" && (
          <div className="flex items-center gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/20 text-sm">
            <Lock className="h-4 w-4 text-red-400 shrink-0" />
            <span className="text-red-300">This will execute live exploits against your target. Governance approval may be required.</span>
          </div>
        )}

        {isLaunching && (
          <div className="flex items-center justify-center gap-3 p-4">
            <Loader2 className="h-5 w-5 animate-spin text-primary" />
            <span className="text-sm text-muted-foreground">Launching assessment...</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Wizard
// ============================================================================

export default function AssessmentWizard() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const [step, setStep] = useState(0);
  const [state, setStateRaw] = useState<WizardState>(INITIAL_STATE);
  const [launchError, setLaunchError] = useState<string | null>(null);

  const setState = (partial: Partial<WizardState>) => {
    setStateRaw((prev) => ({ ...prev, ...partial }));
  };

  // Validation per step
  const canAdvance = (): boolean => {
    switch (step) {
      case 0: // Target
        return !!(state.targetUrl.trim() || state.selectedAssetIds.length > 0);
      case 1: // Scope
        return !!state.assessmentType;
      case 2: // Configure
        if (state.assessmentType === "breach_chain" || state.assessmentType === "both") {
          return state.enabledPhases.length > 0;
        }
        return true;
      case 3: // Launch
        return true;
      default:
        return false;
    }
  };

  // Full Assessment mutation
  const fullAssessmentMutation = useMutation({
    mutationFn: async () => {
      return apiRequest("POST", "/api/full-assessments", {
        name: state.targetName || `Assessment - ${state.targetUrl || "Multi-asset"}`,
        description: state.targetDescription || undefined,
        assessmentMode: state.assessmentMode,
        targetUrl: state.targetUrl.trim() || undefined,
        enableWebAppRecon: state.enableWebAppRecon,
        enableParallelAgents: state.enableParallelAgents,
        maxConcurrentAgents: state.maxConcurrentAgents,
        enableLLMValidation: state.enableLLMValidation,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/full-assessments"] });
    },
  });

  // Breach Chain mutation
  const breachChainMutation = useMutation({
    mutationFn: async () => {
      const assetIds = state.selectedAssetIds.length > 0
        ? state.selectedAssetIds
        : state.targetUrl.trim()
          ? [state.targetUrl.trim()]
          : [];

      const res = await apiRequest("POST", "/api/breach-chains", {
        name: state.targetName || `Breach Chain - ${state.targetUrl || "Multi-asset"}`,
        description: state.targetDescription || undefined,
        assetIds,
        targetDomains: ["application", "cloud", "k8s", "network"],
        config: {
          enabledPhases: state.enabledPhases,
          executionMode: state.executionMode,
          pauseOnCritical: state.pauseOnCritical,
        },
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
    },
  });

  const isLaunching = fullAssessmentMutation.isPending || breachChainMutation.isPending;

  const handleLaunch = async () => {
    setLaunchError(null);

    try {
      if (state.assessmentType === "full_assessment" || state.assessmentType === "both") {
        await fullAssessmentMutation.mutateAsync();
      }
      if (state.assessmentType === "breach_chain" || state.assessmentType === "both") {
        await breachChainMutation.mutateAsync();
      }

      toast({
        title: "Assessment Launched",
        description: state.assessmentType === "both"
          ? "Full Assessment and Breach Chain are now running."
          : state.assessmentType === "full_assessment"
            ? "Full Assessment is now running."
            : "Breach Chain is now running.",
      });

      // Navigate to the appropriate results page
      if (state.assessmentType === "breach_chain") {
        navigate("/breach-chains");
      } else {
        navigate("/full-assessment");
      }
    } catch (err: any) {
      const message = err?.message || "Failed to launch assessment";
      setLaunchError(message);
      toast({ title: "Launch Failed", description: message, variant: "destructive" });
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Zap className="h-6 w-6 text-primary" />
          Assessment Wizard
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure and launch a security assessment in four steps.
        </p>
      </div>

      {/* Step indicator */}
      <div className="flex items-center gap-1">
        {STEPS.map((s, i) => {
          const StepIcon = s.icon;
          const isCompleted = i < step;
          const isCurrent = i === step;
          return (
            <div key={s.id} className="flex items-center flex-1">
              <button
                type="button"
                onClick={() => i < step && setStep(i)}
                disabled={i > step}
                className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all w-full ${
                  isCurrent
                    ? "bg-primary/10 text-primary border border-primary/30"
                    : isCompleted
                      ? "text-muted-foreground hover:text-foreground cursor-pointer"
                      : "text-muted-foreground/50 cursor-not-allowed"
                }`}
              >
                <div className={`flex items-center justify-center w-6 h-6 rounded-full text-xs ${
                  isCurrent ? "bg-primary text-primary-foreground" :
                  isCompleted ? "bg-emerald-500/20 text-emerald-400" :
                  "bg-muted text-muted-foreground"
                }`}>
                  {isCompleted ? <Check className="h-3 w-3" /> : <StepIcon className="h-3 w-3" />}
                </div>
                <span className="hidden sm:inline">{s.label}</span>
              </button>
              {i < STEPS.length - 1 && (
                <ChevronRight className="h-4 w-4 text-muted-foreground/30 shrink-0 mx-1" />
              )}
            </div>
          );
        })}
      </div>

      {/* Step content */}
      <Card>
        <CardContent className="pt-6">
          {step === 0 && <StepTarget state={state} setState={setState} />}
          {step === 1 && <StepScope state={state} setState={setState} />}
          {step === 2 && <StepConfigure state={state} setState={setState} />}
          {step === 3 && <StepLaunch state={state} isLaunching={isLaunching} />}
        </CardContent>
      </Card>

      {/* Error display */}
      {launchError && (
        <div className="flex items-center gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/20 text-sm">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <span className="text-red-300">{launchError}</span>
        </div>
      )}

      {/* Navigation buttons */}
      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          onClick={() => step === 0 ? navigate("/") : setStep(step - 1)}
          disabled={isLaunching}
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          {step === 0 ? "Dashboard" : "Back"}
        </Button>

        {step < 3 ? (
          <Button
            onClick={() => setStep(step + 1)}
            disabled={!canAdvance()}
            data-testid="wizard-next"
          >
            Next
            <ChevronRight className="h-4 w-4 ml-1" />
          </Button>
        ) : (
          <Button
            onClick={handleLaunch}
            disabled={isLaunching || !hasPermission("evaluations:create")}
            className="bg-gradient-to-r from-cyan-600 to-blue-600 glow-cyan-sm"
            data-testid="wizard-launch"
          >
            {isLaunching ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Launching...
              </>
            ) : (
              <>
                <Rocket className="h-4 w-4 mr-2" />
                Launch Assessment
              </>
            )}
          </Button>
        )}
      </div>
    </div>
  );
}
