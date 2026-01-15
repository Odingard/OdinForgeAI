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

interface ReconResult {
  target: string;
  scanTime: string;
  portScan?: PortScanResult[];
  sslCheck?: SSLCheckResult;
  httpFingerprint?: HTTPFingerprintResult;
  dnsEnum?: DNSEnumResult;
  errors: string[];
}

interface Exposure {
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string;
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
            <Tabs defaultValue="findings" className="w-full">
              <TabsList className="grid w-full grid-cols-5">
                <TabsTrigger value="findings" data-testid="tab-findings">
                  <FileWarning className="h-4 w-4 mr-1" />
                  Findings ({results.exposures.length})
                </TabsTrigger>
                <TabsTrigger value="ports" data-testid="tab-ports">
                  <Server className="h-4 w-4 mr-1" />
                  Ports
                </TabsTrigger>
                <TabsTrigger value="ssl" data-testid="tab-ssl">
                  <Lock className="h-4 w-4 mr-1" />
                  SSL
                </TabsTrigger>
                <TabsTrigger value="http" data-testid="tab-http">
                  <Shield className="h-4 w-4 mr-1" />
                  HTTP
                </TabsTrigger>
                <TabsTrigger value="dns" data-testid="tab-dns">
                  <Wifi className="h-4 w-4 mr-1" />
                  DNS
                </TabsTrigger>
              </TabsList>

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

              <TabsContent value="ports" className="mt-4">
                {results.result.portScan && results.result.portScan.length > 0 ? (
                  <div className="space-y-2">
                    {results.result.portScan.map((port, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-muted/50 rounded-md">
                        <div className="flex items-center gap-2">
                          <Badge variant={port.state === 'open' ? 'default' : 'secondary'}>
                            {port.port}
                          </Badge>
                          <span className="text-sm">{port.service || 'Unknown'}</span>
                        </div>
                        <Badge variant={port.state === 'open' ? 'destructive' : 'outline'}>
                          {port.state}
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Server className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No open ports detected on common ports</p>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="ssl" className="mt-4">
                {results.result.sslCheck ? (
                  <div className="space-y-4">
                    <div className="flex items-center gap-2">
                      {results.result.sslCheck.valid ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-500" />
                      )}
                      <span className="font-medium">
                        Certificate {results.result.sslCheck.valid ? 'Valid' : 'Invalid'}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      {results.result.sslCheck.subject && (
                        <div>
                          <span className="text-muted-foreground">Subject:</span>
                          <p className="font-mono">{results.result.sslCheck.subject}</p>
                        </div>
                      )}
                      {results.result.sslCheck.issuer && (
                        <div>
                          <span className="text-muted-foreground">Issuer:</span>
                          <p className="font-mono">{results.result.sslCheck.issuer}</p>
                        </div>
                      )}
                      {results.result.sslCheck.protocol && (
                        <div>
                          <span className="text-muted-foreground">Protocol:</span>
                          <p className="font-mono">{results.result.sslCheck.protocol}</p>
                        </div>
                      )}
                      {results.result.sslCheck.daysUntilExpiry !== undefined && (
                        <div>
                          <span className="text-muted-foreground">Expires in:</span>
                          <p className={results.result.sslCheck.daysUntilExpiry < 30 ? 'text-yellow-500' : ''}>
                            {results.result.sslCheck.daysUntilExpiry} days
                          </p>
                        </div>
                      )}
                    </div>

                    {results.result.sslCheck.vulnerabilities.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-sm font-medium text-red-400">Vulnerabilities:</span>
                        {results.result.sslCheck.vulnerabilities.map((vuln, i) => (
                          <div key={i} className="flex items-center gap-2 text-sm text-red-400">
                            <AlertTriangle className="h-4 w-4" />
                            {vuln}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Lock className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No SSL/TLS data available</p>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="http" className="mt-4">
                {results.result.httpFingerprint ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      {results.result.httpFingerprint.server && (
                        <div>
                          <span className="text-muted-foreground">Server:</span>
                          <p className="font-mono">{results.result.httpFingerprint.server}</p>
                        </div>
                      )}
                      {results.result.httpFingerprint.poweredBy && (
                        <div>
                          <span className="text-muted-foreground">Powered By:</span>
                          <p className="font-mono">{results.result.httpFingerprint.poweredBy}</p>
                        </div>
                      )}
                      {results.result.httpFingerprint.statusCode && (
                        <div>
                          <span className="text-muted-foreground">Status Code:</span>
                          <p className="font-mono">{results.result.httpFingerprint.statusCode}</p>
                        </div>
                      )}
                    </div>

                    {results.result.httpFingerprint.technologies.length > 0 && (
                      <div>
                        <span className="text-sm font-medium">Technologies Detected:</span>
                        <div className="flex flex-wrap gap-2 mt-2">
                          {results.result.httpFingerprint.technologies.map((tech, i) => (
                            <Badge key={i} variant="secondary">{tech}</Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <span className="text-sm font-medium text-green-400">Security Headers Present:</span>
                        <div className="space-y-1 mt-2">
                          {results.result.httpFingerprint.securityHeaders.present.map((header, i) => (
                            <div key={i} className="flex items-center gap-2 text-sm text-green-400">
                              <CheckCircle className="h-3 w-3" />
                              {header}
                            </div>
                          ))}
                          {results.result.httpFingerprint.securityHeaders.present.length === 0 && (
                            <p className="text-sm text-muted-foreground">None</p>
                          )}
                        </div>
                      </div>
                      <div>
                        <span className="text-sm font-medium text-yellow-400">Security Headers Missing:</span>
                        <div className="space-y-1 mt-2">
                          {results.result.httpFingerprint.securityHeaders.missing.map((header, i) => (
                            <div key={i} className="flex items-center gap-2 text-sm text-yellow-400">
                              <XCircle className="h-3 w-3" />
                              {header}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No HTTP data available</p>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="dns" className="mt-4">
                {results.result.dnsEnum ? (
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
                    {results.result.dnsEnum.ipv6.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">IPv6 Addresses:</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {results.result.dnsEnum.ipv6.map((ip, i) => (
                            <Badge key={i} variant="outline" className="font-mono text-xs">{ip}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {results.result.dnsEnum.mx.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Mail Servers (MX):</span>
                        <div className="space-y-1 mt-1">
                          {results.result.dnsEnum.mx.map((mx, i) => (
                            <div key={i} className="font-mono">
                              {mx.priority} - {mx.exchange}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {results.result.dnsEnum.ns.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Name Servers (NS):</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {results.result.dnsEnum.ns.map((ns, i) => (
                            <Badge key={i} variant="outline" className="font-mono">{ns}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Wifi className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No DNS data available</p>
                  </div>
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
