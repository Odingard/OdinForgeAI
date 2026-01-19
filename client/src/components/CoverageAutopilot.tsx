import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { 
  Copy, 
  Check, 
  RefreshCw, 
  Key, 
  Cloud, 
  Server, 
  Terminal,
  Shield,
  AlertTriangle,
  CheckCircle2
} from "lucide-react";
import { SiGooglecloud, SiKubernetes } from "react-icons/si";
import { FaAws, FaMicrosoft } from "react-icons/fa";
import { apiRequest, queryClient } from "@/lib/queryClient";

interface BootstrapCommands {
  host: {
    linux: string;
    windows: string;
  };
  cloud: {
    aws: { userDataLinux: string; userDataWindows: string };
    azure: { vmssLinux: string; vmssWindows: string };
    gcp: { startupLinux: string; startupWindows: string };
  };
  k8s: {
    apply: string;
    verify: string;
  };
}

interface CoverageStats {
  totalAssets: number;
  agentCount: number;
  missingAssets: number;
  byProvider: { provider: string; assets: number; agents: number }[];
}

interface EnrollmentToken {
  token: string;
  tokenId: string;
  tokenHint: string;
  expiresAt: string;
  expiresInMinutes: number;
}

export function CoverageAutopilot() {
  const { toast } = useToast();
  const [enrollmentToken, setEnrollmentToken] = useState<EnrollmentToken | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const coverageQuery = useQuery<CoverageStats>({
    queryKey: ["/api/coverage"],
    refetchInterval: 30000,
  });

  // WebSocket listener for real-time coverage updates when assets are discovered
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'assets_updated' || data.type === 'agent_registered') {
            // Auto-refresh coverage stats when assets or agents change
            queryClient.invalidateQueries({ queryKey: ["/api/coverage"] });
          }
        } catch {
          // Ignore parse errors
        }
      };

      ws.onerror = () => {
        // Silent fallback - polling will handle updates
      };

      ws.onclose = () => {
        wsRef.current = null;
      };

    } catch {
      // WebSocket not available - polling will handle updates
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, []);

  const bootstrapQuery = useQuery<BootstrapCommands>({
    queryKey: ["/api/bootstrap", enrollmentToken?.token],
    enabled: !!enrollmentToken?.token,
    queryFn: async () => {
      const res = await fetch(`/api/bootstrap?token=${enrollmentToken?.token}`);
      if (!res.ok) throw new Error("Failed to fetch bootstrap commands");
      return res.json();
    },
  });

  const createTokenMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/enrollment/token", {});
      return res.json();
    },
    onSuccess: (data: EnrollmentToken) => {
      setEnrollmentToken(data);
      toast({
        title: "Enrollment Token Created",
        description: `Token expires in ${data.expiresInMinutes} minutes.`,
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create enrollment token",
        variant: "destructive",
      });
    },
  });

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedCommand(label);
    toast({
      title: "Copied",
      description: `${label} command copied to clipboard`,
    });
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const coverage = coverageQuery.data;
  const coveragePercent = coverage && coverage.totalAssets > 0 
    ? Math.round((coverage.agentCount / coverage.totalAssets) * 100)
    : 0;

  const CopyButton = ({ text, label }: { text: string; label: string }) => (
    <Button
      size="icon"
      variant="ghost"
      onClick={() => copyToClipboard(text, label)}
      data-testid={`btn-copy-${label.toLowerCase().replace(/\s+/g, '-')}`}
    >
      {copiedCommand === label ? (
        <Check className="h-4 w-4 text-green-500" />
      ) : (
        <Copy className="h-4 w-4" />
      )}
    </Button>
  );

  const CommandBlock = ({ 
    title, 
    command, 
    icon: Icon,
    testId 
  }: { 
    title: string; 
    command: string; 
    icon: React.ElementType;
    testId: string;
  }) => (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Icon className="h-4 w-4" />
        {title}
      </div>
      <div className="relative">
        <pre 
          className="bg-muted p-3 rounded-md text-xs overflow-x-auto font-mono"
          data-testid={testId}
        >
          {command}
        </pre>
        <div className="absolute top-1 right-1">
          <CopyButton text={command} label={title} />
        </div>
      </div>
    </div>
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Coverage Autopilot
            </CardTitle>
            <CardDescription>
              Automated agent deployment across your infrastructure
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/coverage"] })}
            data-testid="btn-refresh-coverage"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Assets</p>
                  <p className="text-2xl font-bold" data-testid="text-total-assets">
                    {coverage?.totalAssets ?? 0}
                  </p>
                </div>
                <Cloud className="h-8 w-8 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Agents Deployed</p>
                  <p className="text-2xl font-bold" data-testid="text-agent-count">
                    {coverage?.agentCount ?? 0}
                  </p>
                </div>
                <Server className="h-8 w-8 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Missing Coverage</p>
                  <p className="text-2xl font-bold" data-testid="text-missing-assets">
                    {coverage?.missingAssets ?? 0}
                  </p>
                </div>
                {coverage && coverage.missingAssets > 0 ? (
                  <AlertTriangle className="h-8 w-8 text-yellow-500" />
                ) : (
                  <CheckCircle2 className="h-8 w-8 text-green-500" />
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span>Coverage Progress</span>
            <span className="font-medium">{coveragePercent}%</span>
          </div>
          <Progress value={coveragePercent} className="h-2" />
        </div>

        {coverage?.byProvider && coverage.byProvider.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {coverage.byProvider.map((p) => (
              <Badge key={p.provider} variant="secondary">
                {p.provider}: {p.agents}/{p.assets} agents
              </Badge>
            ))}
          </div>
        )}

        <div className="border-t pt-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold">Bootstrap Scripts</h3>
              <p className="text-sm text-muted-foreground">
                Generate commands to deploy agents across your infrastructure
              </p>
            </div>
            <Button
              onClick={() => createTokenMutation.mutate()}
              disabled={createTokenMutation.isPending}
              data-testid="btn-generate-token"
            >
              <Key className="h-4 w-4 mr-2" />
              {createTokenMutation.isPending ? "Generating..." : "Generate Token"}
            </Button>
          </div>

          {enrollmentToken && (
            <div className="mb-4 p-3 bg-muted rounded-md">
              <div className="flex items-center justify-between">
                <div className="text-sm">
                  <span className="font-medium">Token ID:</span>{" "}
                  <code>{enrollmentToken.tokenId}</code>
                  <span className="text-muted-foreground ml-2">
                    (expires {new Date(enrollmentToken.expiresAt).toLocaleTimeString()})
                  </span>
                </div>
                <Badge variant="outline">Active</Badge>
              </div>
            </div>
          )}

          {enrollmentToken && bootstrapQuery.data && (
            <Tabs defaultValue="host" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="host" data-testid="tab-host-bootstrap">
                  Host Install
                </TabsTrigger>
                <TabsTrigger value="container" data-testid="tab-container-bootstrap">
                  Container Install
                </TabsTrigger>
              </TabsList>

              <TabsContent value="host" className="space-y-4 mt-4">
                <CommandBlock
                  title="Linux"
                  command={bootstrapQuery.data.host.linux}
                  icon={Terminal}
                  testId="cmd-host-linux"
                />
                <CommandBlock
                  title="Windows"
                  command={bootstrapQuery.data.host.windows}
                  icon={Terminal}
                  testId="cmd-host-windows"
                />

                <div className="border-t pt-4 mt-4">
                  <h4 className="text-sm font-medium mb-3">Cloud Bootstrap Scripts</h4>
                  <Tabs defaultValue="aws">
                    <TabsList>
                      <TabsTrigger value="aws" className="gap-2">
                        <FaAws className="h-4 w-4" />
                        AWS
                      </TabsTrigger>
                      <TabsTrigger value="azure" className="gap-2">
                        <FaMicrosoft className="h-4 w-4" />
                        Azure
                      </TabsTrigger>
                      <TabsTrigger value="gcp" className="gap-2">
                        <SiGooglecloud className="h-4 w-4" />
                        GCP
                      </TabsTrigger>
                    </TabsList>
                    <TabsContent value="aws" className="space-y-4 mt-4">
                      <CommandBlock
                        title="AWS User Data (Linux)"
                        command={bootstrapQuery.data.cloud.aws.userDataLinux}
                        icon={FaAws}
                        testId="cmd-aws-linux"
                      />
                      <CommandBlock
                        title="AWS User Data (Windows)"
                        command={bootstrapQuery.data.cloud.aws.userDataWindows}
                        icon={FaAws}
                        testId="cmd-aws-windows"
                      />
                    </TabsContent>
                    <TabsContent value="azure" className="space-y-4 mt-4">
                      <CommandBlock
                        title="Azure VMSS (Linux)"
                        command={bootstrapQuery.data.cloud.azure.vmssLinux}
                        icon={FaMicrosoft}
                        testId="cmd-azure-linux"
                      />
                      <CommandBlock
                        title="Azure VMSS (Windows)"
                        command={bootstrapQuery.data.cloud.azure.vmssWindows}
                        icon={FaMicrosoft}
                        testId="cmd-azure-windows"
                      />
                    </TabsContent>
                    <TabsContent value="gcp" className="space-y-4 mt-4">
                      <CommandBlock
                        title="GCP Startup Script (Linux)"
                        command={bootstrapQuery.data.cloud.gcp.startupLinux}
                        icon={SiGooglecloud}
                        testId="cmd-gcp-linux"
                      />
                      <CommandBlock
                        title="GCP Startup Script (Windows)"
                        command={bootstrapQuery.data.cloud.gcp.startupWindows}
                        icon={SiGooglecloud}
                        testId="cmd-gcp-windows"
                      />
                    </TabsContent>
                  </Tabs>
                </div>
              </TabsContent>

              <TabsContent value="container" className="space-y-4 mt-4">
                <div className="flex items-center gap-2 text-sm font-medium mb-2">
                  <SiKubernetes className="h-4 w-4" />
                  Kubernetes (kubectl apply)
                </div>
                <CommandBlock
                  title="K8s Apply"
                  command={bootstrapQuery.data.k8s.apply}
                  icon={SiKubernetes}
                  testId="cmd-k8s-apply"
                />
                <CommandBlock
                  title="K8s Verify"
                  command={bootstrapQuery.data.k8s.verify}
                  icon={Terminal}
                  testId="cmd-k8s-verify"
                />
              </TabsContent>
            </Tabs>
          )}

          {!enrollmentToken && (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Click "Generate Token" to create bootstrap scripts</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
