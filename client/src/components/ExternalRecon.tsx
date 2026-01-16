import { useState, useEffect, useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  Globe, 
  Shield, 
  Lock, 
  Server, 
  Wifi, 
  AlertTriangle, 
  CheckCircle,
  XCircle,
  Loader2,
  Search,
  FileWarning,
  ArrowRight,
  Swords,
  Sparkles
} from "lucide-react";
import { useLocation } from "wouter";

interface ScanProgress {
  phase: 'dns' | 'ports' | 'ssl' | 'http' | 'complete';
  progress: number;
  message: string;
  portsFound: number;
  vulnerabilitiesFound: number;
}

const PHASE_INFO = {
  dns: { icon: Wifi, label: 'DNS Enumeration', color: 'text-blue-400' },
  ports: { icon: Server, label: 'Port Scanning', color: 'text-cyan-400' },
  ssl: { icon: Lock, label: 'SSL/TLS Check', color: 'text-green-400' },
  http: { icon: Shield, label: 'HTTP Fingerprint', color: 'text-yellow-400' },
  complete: { icon: CheckCircle, label: 'Complete', color: 'text-green-500' },
};

function ScanProgressTracker({ scanId, progress }: { scanId: string; progress: ScanProgress | null }) {
  // Show initializing state when progress is null
  const displayProgress = progress || {
    phase: 'dns' as const,
    progress: 2,
    message: 'Initializing scan...',
    portsFound: 0,
    vulnerabilitiesFound: 0,
  };

  const phases: Array<'dns' | 'ports' | 'ssl' | 'http'> = ['dns', 'ports', 'ssl', 'http'];
  const currentPhaseIndex = phases.indexOf(displayProgress.phase as any);
  
  return (
    <div className="space-y-4 p-4 bg-muted/30 rounded-md border" data-testid="scan-progress-tracker">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
          <span className="text-sm font-medium">{displayProgress.message}</span>
        </div>
        <span className="text-sm text-muted-foreground">{displayProgress.progress}%</span>
      </div>
      
      <Progress value={displayProgress.progress} className="h-2" />
      
      <div className="grid grid-cols-4 gap-2">
        {phases.map((phase, idx) => {
          const info = PHASE_INFO[phase];
          const Icon = info.icon;
          const isActive = phase === displayProgress.phase;
          const isComplete = currentPhaseIndex > idx || displayProgress.phase === 'complete';
          
          return (
            <div 
              key={phase}
              className={`flex flex-col items-center gap-1 p-2 rounded-md transition-all ${
                isActive ? 'bg-primary/10 ring-1 ring-primary/30' : 
                isComplete ? 'opacity-100' : 'opacity-40'
              }`}
              data-testid={`phase-${phase}`}
            >
              <div className={`${isComplete ? 'text-green-500' : isActive ? info.color : 'text-muted-foreground'}`}>
                {isComplete ? <CheckCircle className="h-5 w-5" /> : <Icon className="h-5 w-5" />}
              </div>
              <span className="text-xs text-center">{info.label}</span>
            </div>
          );
        })}
      </div>
      
      {(displayProgress.portsFound > 0 || displayProgress.vulnerabilitiesFound > 0) && (
        <div className="flex gap-4 text-sm">
          {displayProgress.portsFound > 0 && (
            <div className="flex items-center gap-1">
              <Server className="h-3 w-3 text-cyan-400" />
              <span>{displayProgress.portsFound} open ports</span>
            </div>
          )}
          {displayProgress.vulnerabilitiesFound > 0 && (
            <div className="flex items-center gap-1">
              <AlertTriangle className="h-3 w-3 text-yellow-400" />
              <span>{displayProgress.vulnerabilitiesFound} issues found</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface PortScanResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  banner?: string;
}

interface SSLCheckResult {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  protocol?: string;
  cipher?: string;
  vulnerabilities: string[];
}

interface HTTPFingerprintResult {
  server?: string;
  poweredBy?: string;
  technologies: string[];
  headers: Record<string, string>;
  statusCode?: number;
  redirectsTo?: string;
  securityHeaders: {
    present: string[];
    missing: string[];
  };
}

interface DNSEnumResult {
  ipv4: string[];
  ipv6: string[];
  mx: { priority: number; exchange: string }[];
  ns: string[];
  txt: string[];
  cname: string[];
}

interface AuthenticationSurfaceResult {
  loginPages: Array<{
    path: string;
    method: string;
    indicators: string[];
    riskLevel: 'high' | 'medium' | 'low';
  }>;
  adminPanels: Array<{
    path: string;
    detected: boolean;
    technology?: string;
    protected: boolean;
  }>;
  oauthEndpoints: Array<{
    path: string;
    provider?: string;
    scopes?: string[];
  }>;
  passwordResetForms: Array<{
    path: string;
    method: string;
    tokenBased: boolean;
  }>;
  apiAuthentication: {
    bearerTokenSupported: boolean;
    apiKeySupported: boolean;
    basicAuthSupported: boolean;
    jwtDetected: boolean;
  };
  vulnerabilities: string[];
}

interface TransportSecurityResult {
  tlsVersion: string;
  cipherSuite: string;
  forwardSecrecy: boolean;
  hstsEnabled: boolean;
  hstsMaxAge?: number;
  hstsIncludeSubdomains: boolean;
  hstsPreload: boolean;
  certificateTransparency: boolean;
  ocspStapling: boolean;
  downgradeRisks: Array<{
    type: 'protocol' | 'cipher' | 'header' | 'redirect';
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    mitigiation: string;
  }>;
  gradeEstimate: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

interface InfrastructureResult {
  hostingProvider?: string;
  cdnProvider?: string;
  dnsProvider?: string;
  cloudPlatform?: string;
  subdomains: string[];
  relatedDomains: string[];
  shadowAssets: Array<{
    hostname: string;
    type: 'subdomain' | 'related' | 'historical';
    risk: string;
  }>;
  spfRecord?: string;
  dmarcRecord?: string;
  mailSecurityIssues: string[];
}

interface AttackReadinessSummary {
  overallScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
  executiveSummary: string;
  categoryScores: {
    networkExposure: number;
    transportSecurity: number;
    applicationIdentity: number;
    authenticationSurface: number;
    dnsInfrastructure: number;
  };
  aevNextActions: Array<{
    priority: number;
    action: string;
    exploitType: string;
    targetVector: string;
    confidence: number;
    requiredMode: 'observe' | 'passive' | 'active' | 'exploit';
  }>;
  attackVectors: Array<{
    vector: string;
    mitreAttackId: string;
    feasibility: 'confirmed' | 'likely' | 'possible' | 'unlikely';
    prerequisites: string[];
  }>;
  prioritizedRemediations: Array<{
    priority: number;
    finding: string;
    remediation: string;
    effort: 'quick' | 'moderate' | 'significant';
    impact: 'high' | 'medium' | 'low';
  }>;
}

interface ReconResult {
  target: string;
  scanTime: string;
  portScan?: PortScanResult[];
  networkExposure?: {
    openPorts: number;
    highRiskPorts: number;
    serviceVersions: Array<{ port: number; service: string; version?: string }>;
    protocolFindings: Array<{ protocol: string; finding: string; severity: string }>;
  };
  sslCheck?: SSLCheckResult;
  transportSecurity?: TransportSecurityResult;
  httpFingerprint?: HTTPFingerprintResult;
  applicationIdentity?: {
    frameworks: string[];
    cms?: string;
    webServer?: string;
    language?: string;
    libraries: string[];
    wafDetected?: string;
  };
  authenticationSurface?: AuthenticationSurfaceResult;
  dnsEnum?: DNSEnumResult;
  infrastructure?: InfrastructureResult;
  attackReadiness?: AttackReadinessSummary;
  errors: string[];
}

interface Exposure {
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string;
  exploitChainSignal?: {
    exploitType: string;
    mitreAttackId?: string;
    chainPosition: string;
    requiredMode: string;
    confidence: number;
  };
}

interface ScanResponse {
  scanId: string;
  message: string;
  target: string;
}

function EvaluationSuccess({ openPorts, exposuresCount }: { openPorts: number; exposuresCount: number }) {
  const [, navigate] = useLocation();
  
  return (
    <div className="bg-green-500/10 border border-green-500/30 rounded-md p-4 space-y-3" data-testid="evaluation-success">
      <div className="flex items-center gap-2 text-green-500">
        <Sparkles className="h-5 w-5" />
        <span className="font-medium">Evaluation Created Successfully</span>
      </div>
      <p className="text-sm text-muted-foreground">
        Your live scan data is ready for AI analysis. Here's what you can do next:
      </p>
      <div className="grid gap-2">
        <Button 
          className="w-full" 
          variant="default" 
          onClick={() => navigate("/simulations")}
          data-testid="button-go-to-simulations"
        >
          <Swords className="h-4 w-4 mr-2" />
          Run AI vs AI Simulation with This Data
        </Button>
        <Button 
          className="w-full" 
          variant="outline" 
          onClick={() => navigate("/evaluations")}
          data-testid="button-go-to-evaluations"
        >
          <Shield className="h-4 w-4 mr-2" />
          View Evaluation Details
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        The simulation will use real ports ({openPorts} open), 
        SSL data, and {exposuresCount} vulnerabilities from your scan.
      </p>
    </div>
  );
}

interface ResultsResponse {
  scanId: string;
  status?: "completed" | "failed";
  result: ReconResult;
  exposures: Exposure[];
  canCreateEvaluation: boolean;
  error?: string;
}

export function ExternalRecon() {
  const [target, setTarget] = useState("");
  const [scanTypes, setScanTypes] = useState({
    portScan: true,
    sslCheck: true,
    httpFingerprint: true,
    dnsEnum: true,
  });
  const [scanId, setScanId] = useState<string | null>(null);
  const [results, setResults] = useState<ResultsResponse | null>(null);
  const [selectedExposures, setSelectedExposures] = useState<number[]>([]);
  const [polling, setPolling] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const { toast } = useToast();

  // Track if we've received real WebSocket progress
  const hasRealProgressRef = useRef(false);
  
  // Simulate progress when WebSocket events aren't available
  useEffect(() => {
    if (!polling || !scanStartTime) {
      hasRealProgressRef.current = false;
      return;
    }
    
    const phases: Array<'dns' | 'ports' | 'ssl' | 'http'> = ['dns', 'ports', 'ssl', 'http'];
    const phaseMessages = {
      dns: 'Resolving DNS records...',
      ports: 'Scanning ports...',
      ssl: 'Checking SSL certificates...',
      http: 'Fingerprinting HTTP services...',
    };
    
    // Estimate ~30 seconds total scan time, simulate progress
    const estimatedDuration = 30000;
    
    const updateSimulatedProgress = () => {
      // If we've received real WebSocket progress, stop simulating
      if (hasRealProgressRef.current) return;
      
      const elapsed = Date.now() - scanStartTime;
      const rawProgress = Math.min(95, Math.round((elapsed / estimatedDuration) * 100));
      const phaseIndex = Math.min(3, Math.floor((rawProgress / 100) * 4));
      const currentPhase = phases[phaseIndex];
      
      setScanProgress({
        phase: currentPhase,
        progress: rawProgress,
        message: phaseMessages[currentPhase],
        portsFound: 0,
        vulnerabilitiesFound: 0,
      });
    };
    
    // Start with initial progress
    updateSimulatedProgress();
    
    const interval = setInterval(updateSimulatedProgress, 500);
    
    return () => clearInterval(interval);
  }, [polling, scanStartTime]);

  // WebSocket connection for real-time progress updates
  useEffect(() => {
    if (!scanId || !polling) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'recon_progress' && data.scanId === scanId) {
            // Mark that we received real progress, stop simulation
            hasRealProgressRef.current = true;
            setScanProgress({
              phase: data.phase,
              progress: data.progress,
              message: data.message,
              portsFound: data.portsFound || 0,
              vulnerabilitiesFound: data.vulnerabilitiesFound || 0,
            });
          }
        } catch {
          // Ignore parse errors
        }
      };

      ws.onerror = () => {
        // WebSocket error, fall back to simulated progress
      };

      return () => {
        ws.close();
        wsRef.current = null;
      };
    } catch {
      // WebSocket creation failed, continue with simulated progress
    }
  }, [scanId, polling]);

  const startScan = useMutation({
    mutationFn: async (): Promise<ScanResponse> => {
      const response = await apiRequest("POST", "/api/recon/scan", { target, scanTypes });
      return response.json();
    },
    onSuccess: (data) => {
      setScanId(data.scanId);
      setPolling(true);
      setScanStartTime(Date.now());
      setScanProgress(null);
      setResults(null);
      setSelectedExposures([]);
      setCreatedEvaluationId(null);
      toast({
        title: "Scan Started",
        description: `Scanning ${data.target}...`,
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const [createdEvaluationId, setCreatedEvaluationId] = useState<string | null>(null);

  const createEvaluation = useMutation({
    mutationFn: async (): Promise<{ evaluationId: string }> => {
      const response = await apiRequest("POST", "/api/recon/create-evaluation", { scanId, selectedExposures });
      return response.json();
    },
    onSuccess: (data) => {
      setCreatedEvaluationId(data.evaluationId);
      toast({
        title: "Evaluation Created",
        description: `Created evaluation ${data.evaluationId} from reconnaissance findings`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/live-scans"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Create Evaluation",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Poll for results
  useEffect(() => {
    if (!polling || !scanId) return;

    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/recon/results/${scanId}`);
        const data = await response.json();
        
        // 202 means still pending - continue polling
        if (response.status === 202) {
          return;
        }
        
        // 404 means scan not found
        if (response.status === 404) {
          setPolling(false);
          toast({
            title: "Scan Not Found",
            description: "The scan was not found. Please try again.",
            variant: "destructive",
          });
          return;
        }
        
        // 200 means completed or failed - check status field
        if (response.ok) {
          setResults(data);
          setPolling(false);
          
          // Show toast for failed scans
          if (data.status === "failed") {
            toast({
              title: "Scan Failed",
              description: data.error || "The scan encountered an error. Partial results may be available.",
              variant: "destructive",
            });
          }
        }
      } catch {
        // Network error, continue polling
      }
    }, 2000);

    // Stop polling after 2 minutes
    const timeout = setTimeout(() => {
      setPolling(false);
      toast({
        title: "Scan Timeout",
        description: "The scan is taking longer than expected. Results may still appear.",
        variant: "destructive",
      });
    }, 120000);

    return () => {
      clearInterval(pollInterval);
      clearTimeout(timeout);
    };
  }, [polling, scanId, toast]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const toggleExposure = (index: number) => {
    setSelectedExposures(prev => 
      prev.includes(index) 
        ? prev.filter(i => i !== index)
        : [...prev, index]
    );
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            External Reconnaissance
          </CardTitle>
          <CardDescription>
            Scan internet-facing assets without installing agents. Discovers open ports, SSL issues, server technologies, and DNS records.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target">Target (domain or IP)</Label>
            <div className="flex gap-2">
              <Input
                id="target"
                placeholder="example.com or https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                data-testid="input-recon-target"
              />
              <Button 
                onClick={() => startScan.mutate()}
                disabled={!target || startScan.isPending || polling}
                data-testid="button-start-scan"
              >
                {startScan.isPending || polling ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span className="ml-2">Scan</span>
              </Button>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Scan Types</Label>
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="portScan" 
                  checked={scanTypes.portScan}
                  onCheckedChange={(checked) => setScanTypes(s => ({ ...s, portScan: !!checked }))}
                  data-testid="checkbox-port-scan"
                />
                <label htmlFor="portScan" className="text-sm flex items-center gap-1">
                  <Server className="h-3 w-3" /> Port Scan
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="sslCheck" 
                  checked={scanTypes.sslCheck}
                  onCheckedChange={(checked) => setScanTypes(s => ({ ...s, sslCheck: !!checked }))}
                  data-testid="checkbox-ssl-check"
                />
                <label htmlFor="sslCheck" className="text-sm flex items-center gap-1">
                  <Lock className="h-3 w-3" /> SSL/TLS Check
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="httpFingerprint" 
                  checked={scanTypes.httpFingerprint}
                  onCheckedChange={(checked) => setScanTypes(s => ({ ...s, httpFingerprint: !!checked }))}
                  data-testid="checkbox-http-fingerprint"
                />
                <label htmlFor="httpFingerprint" className="text-sm flex items-center gap-1">
                  <Shield className="h-3 w-3" /> HTTP Fingerprint
                </label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="dnsEnum" 
                  checked={scanTypes.dnsEnum}
                  onCheckedChange={(checked) => setScanTypes(s => ({ ...s, dnsEnum: !!checked }))}
                  data-testid="checkbox-dns-enum"
                />
                <label htmlFor="dnsEnum" className="text-sm flex items-center gap-1">
                  <Wifi className="h-3 w-3" /> DNS Enumeration
                </label>
              </div>
            </div>
          </div>

          {polling && scanId && (
            <ScanProgressTracker scanId={scanId} progress={scanProgress} />
          )}
        </CardContent>
      </Card>

      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {results.status === "failed" ? (
                <XCircle className="h-5 w-5 text-red-500" />
              ) : (
                <CheckCircle className="h-5 w-5 text-green-500" />
              )}
              Scan Results: {results.result.target}
            </CardTitle>
            <CardDescription>
              Scanned at {new Date(results.result.scanTime).toLocaleString()}
              {results.status === "failed" && (
                <span className="text-red-400 ml-2">(Scan failed)</span>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {results.status === "failed" && (
              <div className="mb-4 p-4 rounded-md bg-red-500/10 border border-red-500/30" data-testid="scan-failed-alert">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
                  <div>
                    <p className="font-medium text-red-400">Scan Failed</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      {results.error || "The scan encountered an error. This may be due to network restrictions or an unreachable target."}
                    </p>
                    {results.result.errors && results.result.errors.length > 0 && (
                      <ul className="mt-2 text-sm text-muted-foreground list-disc list-inside">
                        {results.result.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            )}
            <Tabs defaultValue="summary" className="w-full">
              <TabsList className="grid w-full grid-cols-4 lg:grid-cols-7">
                <TabsTrigger value="summary" data-testid="tab-summary">
                  <AlertTriangle className="h-4 w-4 mr-1" />
                  Summary
                </TabsTrigger>
                <TabsTrigger value="network" data-testid="tab-network">
                  <Server className="h-4 w-4 mr-1" />
                  Network
                </TabsTrigger>
                <TabsTrigger value="transport" data-testid="tab-transport">
                  <Lock className="h-4 w-4 mr-1" />
                  Transport
                </TabsTrigger>
                <TabsTrigger value="app" data-testid="tab-app">
                  <Globe className="h-4 w-4 mr-1" />
                  App
                </TabsTrigger>
                <TabsTrigger value="auth" data-testid="tab-auth">
                  <Shield className="h-4 w-4 mr-1" />
                  Auth
                </TabsTrigger>
                <TabsTrigger value="infra" data-testid="tab-infra">
                  <Wifi className="h-4 w-4 mr-1" />
                  Infra
                </TabsTrigger>
                <TabsTrigger value="findings" data-testid="tab-findings">
                  <FileWarning className="h-4 w-4 mr-1" />
                  ({results.exposures.length})
                </TabsTrigger>
              </TabsList>

              {/* Section 6: Attack Readiness Summary */}
              <TabsContent value="summary" className="space-y-4 mt-4">
                {results.result.attackReadiness ? (
                  <div className="space-y-6" data-testid="attack-readiness-summary">
                    {/* Overall Score and Risk Level */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                      <Card className={`${
                        results.result.attackReadiness.riskLevel === 'critical' ? 'border-red-500/50 bg-red-500/5' :
                        results.result.attackReadiness.riskLevel === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
                        results.result.attackReadiness.riskLevel === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
                        'border-green-500/50 bg-green-500/5'
                      }`}>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-muted-foreground">Exposure Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-3xl font-bold">
                            {results.result.attackReadiness.overallScore}/100
                          </div>
                          <Badge className={`mt-2 ${
                            results.result.attackReadiness.riskLevel === 'critical' ? 'bg-red-500' :
                            results.result.attackReadiness.riskLevel === 'high' ? 'bg-orange-500' :
                            results.result.attackReadiness.riskLevel === 'medium' ? 'bg-yellow-500' :
                            'bg-green-500'
                          }`}>
                            {results.result.attackReadiness.riskLevel.toUpperCase()}
                          </Badge>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-muted-foreground">Attack Vectors</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-3xl font-bold">
                            {results.result.attackReadiness.attackVectors.length}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">identified paths</p>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-muted-foreground">AEV Actions</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-3xl font-bold">
                            {results.result.attackReadiness.aevNextActions.length}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">recommended</p>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm text-muted-foreground">Remediations</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-3xl font-bold">
                            {results.result.attackReadiness.prioritizedRemediations.length}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">prioritized</p>
                        </CardContent>
                      </Card>
                    </div>
                    
                    {/* Executive Summary */}
                    <Card>
                      <CardContent className="pt-4">
                        <p className="text-sm">{results.result.attackReadiness.executiveSummary}</p>
                      </CardContent>
                    </Card>
                    
                    {/* Category Breakdown */}
                    <div className="space-y-3">
                      <h4 className="font-medium">Category Scores</h4>
                      <div className="space-y-2">
                        {Object.entries(results.result.attackReadiness.categoryScores).map(([category, score]) => (
                          <div key={category} className="flex items-center gap-3">
                            <span className="text-sm w-40 capitalize">{category.replace(/([A-Z])/g, ' $1').trim()}</span>
                            <div className="flex-1 bg-muted rounded-full h-2">
                              <div 
                                className={`h-2 rounded-full ${
                                  score >= 75 ? 'bg-red-500' :
                                  score >= 50 ? 'bg-orange-500' :
                                  score >= 25 ? 'bg-yellow-500' :
                                  'bg-green-500'
                                }`}
                                style={{ width: `${score}%` }}
                              />
                            </div>
                            <span className="text-sm w-10 text-right">{score}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    {/* AEV Next Actions */}
                    {results.result.attackReadiness.aevNextActions.length > 0 && (
                      <div className="space-y-3">
                        <h4 className="font-medium">AEV Next Actions</h4>
                        <div className="space-y-2">
                          {results.result.attackReadiness.aevNextActions.map((action, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 bg-muted/50 rounded-md">
                              <Badge variant="outline" className="shrink-0">P{action.priority}</Badge>
                              <div className="flex-1">
                                <p className="text-sm font-medium">{action.action}</p>
                                <div className="flex flex-wrap gap-2 mt-1">
                                  <Badge variant="secondary" className="text-xs">{action.exploitType}</Badge>
                                  <Badge variant="outline" className="text-xs">{action.requiredMode}</Badge>
                                  <span className="text-xs text-muted-foreground">{action.confidence}% confidence</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Prioritized Remediations */}
                    {results.result.attackReadiness.prioritizedRemediations.length > 0 && (
                      <div className="space-y-3">
                        <h4 className="font-medium">Prioritized Remediations</h4>
                        <div className="space-y-2">
                          {results.result.attackReadiness.prioritizedRemediations.map((rem, i) => (
                            <div key={i} className="p-3 bg-muted/50 rounded-md">
                              <div className="flex items-start justify-between gap-2">
                                <div>
                                  <p className="text-sm font-medium">{rem.finding}</p>
                                  <p className="text-sm text-muted-foreground mt-1">{rem.remediation}</p>
                                </div>
                                <div className="flex gap-1 shrink-0">
                                  <Badge variant={rem.effort === 'quick' ? 'default' : 'secondary'} className="text-xs">
                                    {rem.effort}
                                  </Badge>
                                  <Badge variant={rem.impact === 'high' ? 'destructive' : 'outline'} className="text-xs">
                                    {rem.impact}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No attack readiness summary available</p>
                    <p className="text-sm mt-1">Run a full scan to generate the summary</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Section 1: Network Exposure */}
              <TabsContent value="network" className="space-y-4 mt-4">
                {results.result.portScan && results.result.portScan.length > 0 ? (
                  <div className="space-y-4" data-testid="network-exposure">
                    {/* Network Stats */}
                    {results.result.networkExposure && (
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        <Card>
                          <CardContent className="pt-4">
                            <div className="text-2xl font-bold">{results.result.networkExposure.openPorts}</div>
                            <p className="text-xs text-muted-foreground">Open Ports</p>
                          </CardContent>
                        </Card>
                        <Card className={results.result.networkExposure.highRiskPorts > 0 ? 'border-red-500/50' : ''}>
                          <CardContent className="pt-4">
                            <div className="text-2xl font-bold text-red-400">{results.result.networkExposure.highRiskPorts}</div>
                            <p className="text-xs text-muted-foreground">High-Risk Ports</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-4">
                            <div className="text-2xl font-bold">{results.result.networkExposure.serviceVersions.length}</div>
                            <p className="text-xs text-muted-foreground">Version Disclosed</p>
                          </CardContent>
                        </Card>
                        <Card>
                          <CardContent className="pt-4">
                            <div className="text-2xl font-bold">{results.result.networkExposure.protocolFindings.length}</div>
                            <p className="text-xs text-muted-foreground">Protocol Issues</p>
                          </CardContent>
                        </Card>
                      </div>
                    )}
                    
                    {/* Port List */}
                    <div className="space-y-2">
                      <h4 className="font-medium">Open Ports & Services</h4>
                      {results.result.portScan.map((port, index) => (
                        <div key={index} className="flex items-center justify-between p-2 bg-muted/50 rounded-md">
                          <div className="flex items-center gap-2">
                            <Badge variant={port.state === 'open' ? 'default' : 'secondary'}>
                              {port.port}
                            </Badge>
                            <span className="text-sm">{port.service || 'Unknown'}</span>
                            {port.banner && (
                              <span className="text-xs text-muted-foreground font-mono truncate max-w-xs">{port.banner}</span>
                            )}
                          </div>
                          <Badge variant={[21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017].includes(port.port) ? 'destructive' : 'outline'}>
                            {port.state}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Server className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No open ports detected on common ports</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Section 2: Transport Security */}
              <TabsContent value="transport" className="space-y-4 mt-4">
                {results.result.sslCheck || results.result.transportSecurity ? (
                  <div className="space-y-4" data-testid="transport-security">
                    {/* TLS Grade */}
                    {results.result.transportSecurity && (
                      <div className="flex items-center gap-4">
                        <div className={`text-4xl font-bold p-4 rounded-lg ${
                          results.result.transportSecurity.gradeEstimate === 'A+' || results.result.transportSecurity.gradeEstimate === 'A' ? 'bg-green-500/20 text-green-400' :
                          results.result.transportSecurity.gradeEstimate === 'B' ? 'bg-yellow-500/20 text-yellow-400' :
                          results.result.transportSecurity.gradeEstimate === 'C' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {results.result.transportSecurity.gradeEstimate}
                        </div>
                        <div>
                          <h4 className="font-medium">TLS Security Grade</h4>
                          <p className="text-sm text-muted-foreground">
                            {results.result.transportSecurity.tlsVersion} / {results.result.transportSecurity.cipherSuite}
                          </p>
                        </div>
                      </div>
                    )}
                    
                    {/* TLS Features */}
                    {results.result.transportSecurity && (
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                          {results.result.transportSecurity.forwardSecrecy ? 
                            <CheckCircle className="h-4 w-4 text-green-500" /> : 
                            <XCircle className="h-4 w-4 text-red-500" />
                          }
                          <span className="text-sm">Forward Secrecy</span>
                        </div>
                        <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                          {results.result.transportSecurity.hstsEnabled ? 
                            <CheckCircle className="h-4 w-4 text-green-500" /> : 
                            <XCircle className="h-4 w-4 text-red-500" />
                          }
                          <span className="text-sm">HSTS Enabled</span>
                        </div>
                        <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                          {results.result.transportSecurity.hstsPreload ? 
                            <CheckCircle className="h-4 w-4 text-green-500" /> : 
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          }
                          <span className="text-sm">HSTS Preload</span>
                        </div>
                        <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-md">
                          {results.result.transportSecurity.certificateTransparency ? 
                            <CheckCircle className="h-4 w-4 text-green-500" /> : 
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          }
                          <span className="text-sm">CT Logs</span>
                        </div>
                      </div>
                    )}
                    
                    {/* Downgrade Risks */}
                    {results.result.transportSecurity?.downgradeRisks && results.result.transportSecurity.downgradeRisks.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium text-red-400">Downgrade Risks</h4>
                        {results.result.transportSecurity.downgradeRisks.map((risk, i) => (
                          <div key={i} className="p-3 bg-red-500/10 border border-red-500/30 rounded-md">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <p className="text-sm font-medium">{risk.description}</p>
                                <p className="text-xs text-muted-foreground mt-1">{risk.mitigiation}</p>
                              </div>
                              <Badge variant="destructive" className="shrink-0">{risk.severity}</Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {/* Certificate Info */}
                    {results.result.sslCheck && (
                      <div className="space-y-3">
                        <h4 className="font-medium">Certificate Details</h4>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-muted-foreground">Subject:</span>
                            <p className="font-mono">{results.result.sslCheck.subject || 'N/A'}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Issuer:</span>
                            <p className="font-mono">{results.result.sslCheck.issuer || 'N/A'}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Protocol:</span>
                            <p className="font-mono">{results.result.sslCheck.protocol || 'N/A'}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Expires in:</span>
                            <p className={results.result.sslCheck.daysUntilExpiry !== undefined && results.result.sslCheck.daysUntilExpiry < 30 ? 'text-yellow-500' : ''}>
                              {results.result.sslCheck.daysUntilExpiry !== undefined ? `${results.result.sslCheck.daysUntilExpiry} days` : 'N/A'}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Lock className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No transport security data available</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Section 3: Application Identity */}
              <TabsContent value="app" className="space-y-4 mt-4">
                {results.result.httpFingerprint || results.result.applicationIdentity ? (
                  <div className="space-y-4" data-testid="application-identity">
                    {/* Application Identity */}
                    {results.result.applicationIdentity && (
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        {results.result.applicationIdentity.webServer && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">Web Server</p>
                              <p className="font-mono text-sm truncate">{results.result.applicationIdentity.webServer}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.applicationIdentity.language && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">Language</p>
                              <p className="font-mono text-sm">{results.result.applicationIdentity.language}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.applicationIdentity.cms && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">CMS</p>
                              <p className="font-mono text-sm">{results.result.applicationIdentity.cms}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.applicationIdentity.wafDetected && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">WAF</p>
                              <p className="font-mono text-sm">{results.result.applicationIdentity.wafDetected}</p>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    )}
                    
                    {/* Technologies */}
                    {results.result.httpFingerprint?.technologies && results.result.httpFingerprint.technologies.length > 0 && (
                      <div>
                        <h4 className="font-medium mb-2">Technologies Detected</h4>
                        <div className="flex flex-wrap gap-2">
                          {results.result.httpFingerprint.technologies.map((tech, i) => (
                            <Badge key={i} variant="secondary">{tech}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Security Headers */}
                    {results.result.httpFingerprint && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-medium text-green-400 mb-2">Present Headers</h4>
                          <div className="space-y-1">
                            {results.result.httpFingerprint.securityHeaders.present.map((header, i) => (
                              <div key={i} className="flex items-center gap-2 text-sm text-green-400">
                                <CheckCircle className="h-3 w-3" />
                                {header}
                              </div>
                            ))}
                            {results.result.httpFingerprint.securityHeaders.present.length === 0 && (
                              <p className="text-sm text-muted-foreground">None detected</p>
                            )}
                          </div>
                        </div>
                        <div>
                          <h4 className="font-medium text-yellow-400 mb-2">Missing Headers</h4>
                          <div className="space-y-1">
                            {results.result.httpFingerprint.securityHeaders.missing.map((header, i) => (
                              <div key={i} className="flex items-center gap-2 text-sm text-yellow-400">
                                <XCircle className="h-3 w-3" />
                                {header}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Globe className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No application identity data available</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Section 4: Authentication Surface */}
              <TabsContent value="auth" className="space-y-4 mt-4">
                {results.result.authenticationSurface ? (
                  <div className="space-y-4" data-testid="auth-surface">
                    {/* Auth Stats */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                      <Card>
                        <CardContent className="pt-4">
                          <div className="text-2xl font-bold">{results.result.authenticationSurface.loginPages.length}</div>
                          <p className="text-xs text-muted-foreground">Login Pages</p>
                        </CardContent>
                      </Card>
                      <Card className={results.result.authenticationSurface.adminPanels.some(p => !p.protected) ? 'border-red-500/50' : ''}>
                        <CardContent className="pt-4">
                          <div className="text-2xl font-bold">{results.result.authenticationSurface.adminPanels.length}</div>
                          <p className="text-xs text-muted-foreground">Admin Panels</p>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardContent className="pt-4">
                          <div className="text-2xl font-bold">{results.result.authenticationSurface.oauthEndpoints.length}</div>
                          <p className="text-xs text-muted-foreground">OAuth Endpoints</p>
                        </CardContent>
                      </Card>
                      <Card className={results.result.authenticationSurface.vulnerabilities.length > 0 ? 'border-red-500/50' : ''}>
                        <CardContent className="pt-4">
                          <div className="text-2xl font-bold text-red-400">{results.result.authenticationSurface.vulnerabilities.length}</div>
                          <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                        </CardContent>
                      </Card>
                    </div>
                    
                    {/* Login Pages */}
                    {results.result.authenticationSurface.loginPages.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium">Login Pages</h4>
                        {results.result.authenticationSurface.loginPages.map((login, i) => (
                          <div key={i} className="flex items-center justify-between p-2 bg-muted/50 rounded-md">
                            <code className="text-sm">{login.path}</code>
                            <Badge variant={login.riskLevel === 'high' ? 'destructive' : 'outline'}>
                              {login.riskLevel}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {/* Admin Panels */}
                    {results.result.authenticationSurface.adminPanels.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium">Admin Panels</h4>
                        {results.result.authenticationSurface.adminPanels.map((panel, i) => (
                          <div key={i} className={`flex items-center justify-between p-2 rounded-md ${
                            !panel.protected ? 'bg-red-500/10 border border-red-500/30' : 'bg-muted/50'
                          }`}>
                            <code className="text-sm">{panel.path}</code>
                            <Badge variant={panel.protected ? 'default' : 'destructive'}>
                              {panel.protected ? 'Protected' : 'UNPROTECTED'}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {/* API Authentication */}
                    <div className="space-y-2">
                      <h4 className="font-medium">API Authentication Methods</h4>
                      <div className="flex flex-wrap gap-2">
                        {results.result.authenticationSurface.apiAuthentication.bearerTokenSupported && (
                          <Badge>Bearer Token</Badge>
                        )}
                        {results.result.authenticationSurface.apiAuthentication.apiKeySupported && (
                          <Badge>API Key</Badge>
                        )}
                        {results.result.authenticationSurface.apiAuthentication.basicAuthSupported && (
                          <Badge variant="outline">Basic Auth</Badge>
                        )}
                        {results.result.authenticationSurface.apiAuthentication.jwtDetected && (
                          <Badge>JWT</Badge>
                        )}
                        {!results.result.authenticationSurface.apiAuthentication.bearerTokenSupported &&
                         !results.result.authenticationSurface.apiAuthentication.apiKeySupported &&
                         !results.result.authenticationSurface.apiAuthentication.basicAuthSupported && (
                          <span className="text-sm text-muted-foreground">No API auth methods detected</span>
                        )}
                      </div>
                    </div>
                    
                    {/* Vulnerabilities */}
                    {results.result.authenticationSurface.vulnerabilities.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium text-red-400">Authentication Vulnerabilities</h4>
                        {results.result.authenticationSurface.vulnerabilities.map((vuln, i) => (
                          <div key={i} className="flex items-center gap-2 text-sm text-red-400 p-2 bg-red-500/10 rounded-md">
                            <AlertTriangle className="h-4 w-4 shrink-0" />
                            {vuln}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No authentication surface data available</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Section 5: DNS & Infrastructure */}
              <TabsContent value="infra" className="space-y-4 mt-4">
                {results.result.dnsEnum || results.result.infrastructure ? (
                  <div className="space-y-4" data-testid="dns-infrastructure">
                    {/* Infrastructure Info */}
                    {results.result.infrastructure && (
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        {results.result.infrastructure.hostingProvider && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">Hosting</p>
                              <p className="font-medium">{results.result.infrastructure.hostingProvider}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.infrastructure.cdnProvider && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">CDN</p>
                              <p className="font-medium">{results.result.infrastructure.cdnProvider}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.infrastructure.dnsProvider && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">DNS Provider</p>
                              <p className="font-medium">{results.result.infrastructure.dnsProvider}</p>
                            </CardContent>
                          </Card>
                        )}
                        {results.result.infrastructure.cloudPlatform && (
                          <Card>
                            <CardContent className="pt-4">
                              <p className="text-xs text-muted-foreground">Cloud Platform</p>
                              <p className="font-medium">{results.result.infrastructure.cloudPlatform}</p>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    )}
                    
                    {/* Mail Security */}
                    {results.result.infrastructure?.mailSecurityIssues && results.result.infrastructure.mailSecurityIssues.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="font-medium text-yellow-400">Mail Security Issues</h4>
                        {results.result.infrastructure.mailSecurityIssues.map((issue, i) => (
                          <div key={i} className="flex items-center gap-2 text-sm text-yellow-400 p-2 bg-yellow-500/10 rounded-md">
                            <AlertTriangle className="h-4 w-4 shrink-0" />
                            {issue}
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {/* DNS Records */}
                    {results.result.dnsEnum && (
                      <div className="space-y-4 text-sm">
                        {results.result.dnsEnum.ipv4.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">IPv4 Addresses:</span>
                            <div className="flex flex-wrap gap-2 mt-1">
                              {results.result.dnsEnum.ipv4.map((ip, i) => (
                                <Badge key={i} variant="outline" className="font-mono">{ip}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                        {results.result.dnsEnum.ns.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Name Servers:</span>
                            <div className="flex flex-wrap gap-2 mt-1">
                              {results.result.dnsEnum.ns.map((ns, i) => (
                                <Badge key={i} variant="outline" className="font-mono">{ns}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                        {results.result.dnsEnum.mx.length > 0 && (
                          <div>
                            <span className="text-muted-foreground">Mail Servers (MX):</span>
                            <div className="space-y-1 mt-1">
                              {results.result.dnsEnum.mx.map((mx, i) => (
                                <div key={i} className="font-mono text-xs">
                                  {mx.priority} - {mx.exchange}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Wifi className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No infrastructure data available</p>
                  </div>
                )}
              </TabsContent>
              
              {/* Findings (exposures for evaluation) */}
              <TabsContent value="findings" className="space-y-4 mt-4">
                {results.exposures.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500" />
                    <p>No security issues detected</p>
                  </div>
                ) : (
                  <>
                    <div className="space-y-2">
                      {results.exposures.map((exposure, index) => (
                        <div 
                          key={index}
                          className={`p-3 rounded-md border ${getSeverityColor(exposure.severity)} flex items-start gap-3`}
                          data-testid={`finding-${index}`}
                        >
                          <Checkbox 
                            checked={selectedExposures.includes(index)}
                            onCheckedChange={() => toggleExposure(index)}
                            data-testid={`checkbox-finding-${index}`}
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className={getSeverityColor(exposure.severity)}>
                                {exposure.severity.toUpperCase()}
                              </Badge>
                              <span className="font-medium">{exposure.description}</span>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">{exposure.evidence}</p>
                          </div>
                        </div>
                      ))}
                    </div>

                    {createdEvaluationId ? (
                      <EvaluationSuccess 
                        openPorts={results.result.portScan?.filter(p => p.state === 'open').length || 0}
                        exposuresCount={results.exposures.length}
                      />
                    ) : results.canCreateEvaluation && selectedExposures.length > 0 && (
                      <Button 
                        onClick={() => createEvaluation.mutate()}
                        disabled={createEvaluation.isPending}
                        className="w-full"
                        data-testid="button-create-evaluation"
                      >
                        {createEvaluation.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin mr-2" />
                        ) : (
                          <ArrowRight className="h-4 w-4 mr-2" />
                        )}
                        Create Evaluation from {selectedExposures.length} Finding(s)
                      </Button>
                    )}
                  </>
                )}
              </TabsContent>

            </Tabs>

            {results.result.errors.length > 0 && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-md">
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="font-medium">Errors during scan:</span>
                </div>
                <ul className="mt-2 space-y-1 text-sm text-red-400">
                  {results.result.errors.map((error, i) => (
                    <li key={i}>{error}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
