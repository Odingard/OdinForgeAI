import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { Copy, Check, Server, Monitor, Terminal, Loader2, RefreshCw, Key } from "lucide-react";
import { FaLinux, FaWindows, FaDocker } from "react-icons/fa";
import { SiKubernetes } from "react-icons/si";

interface InstallWizardProps {
  serverUrl?: string;
}

interface InstallCommandResponse {
  installCommand: string;
  scriptUrl: string;
  platform: string;
  tokenId: string;
  organizationId: string;
  expiresAt: string;
  expiresInHours: number;
  message: string;
}

export function InstallWizard({ serverUrl }: InstallWizardProps) {
  const { toast } = useToast();
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [hostPlatform, setHostPlatform] = useState<"linux" | "windows">("linux");
  const [containerMethod, setContainerMethod] = useState<"docker" | "kubernetes">("docker");
  const [generatedCommand, setGeneratedCommand] = useState<InstallCommandResponse | null>(null);
  const [enrollmentToken, setEnrollmentToken] = useState<string | null>(null);
  const [enrollmentPlatform, setEnrollmentPlatform] = useState<"linux" | "windows">("linux");

  const generateCommandMutation = useMutation({
    mutationFn: async (platform: string) => {
      const baseUrl = serverUrl || window.location.origin;
      const response = await apiRequest("POST", "/api/agents/install-command", {
        platform,
        serverUrl: baseUrl,
      });
      return response.json() as Promise<InstallCommandResponse>;
    },
    onSuccess: (data) => {
      setGeneratedCommand(data);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to generate command",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      toast({
        title: "Copied to clipboard",
        description: "Command copied - paste and run on your target machine.",
      });
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Please copy the command manually.",
        variant: "destructive",
      });
    }
  };

  const generateEnrollmentTokenMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/enrollment/token", {
        expiresInHours: 720, // 30 days default
      });
      return response.json() as Promise<{ token: string; expiresAt: string; expiresInHours: number }>;
    },
    onSuccess: (data) => {
      setEnrollmentToken(data.token);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to create enrollment token",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const getEnrollmentCommand = (platform: "linux" | "windows", token: string) => {
    const base = serverUrl || window.location.origin;
    if (platform === "windows") {
      return `Invoke-WebRequest -Uri "${base}/api/agents/download/windows-amd64" -OutFile odinforge-agent.exe; .\\odinforge-agent.exe install --server-url "${base}" --registration-token "${token}"`;
    }
    return `curl -fsSL ${base}/api/agents/download/linux-amd64 -o odinforge-agent && chmod +x odinforge-agent && sudo ./odinforge-agent install --server-url "${base}" --registration-token "${token}"`;
  };

  const baseUrl = serverUrl || window.location.origin;

  const getDockerCommand = () => {
    return `docker run -d \\
  --name odinforge-agent \\
  --restart unless-stopped \\
  -e ODINFORGE_SERVER_URL=${baseUrl} \\
  -e ODINFORGE_API_KEY=YOUR_API_KEY \\
  -e ODINFORGE_TENANT_ID=default \\
  -v odinforge-data:/var/lib/odinforge-agent \\
  ghcr.io/odinforge/agent:latest`;
  };

  const getHelmCommand = () => {
    return `# Clone the repo first, then:
helm install odinforge-agent ./odinforge-agent/deploy/helm \\
  --namespace odinforge \\
  --create-namespace \\
  --set odinforge.serverUrl=${baseUrl} \\
  --set odinforge.apiKey=YOUR_API_KEY \\
  --set odinforge.tenantId=default`;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-5 w-5" />
          Install Agent
        </CardTitle>
        <CardDescription>
          Deploy the OdinForge agent to your infrastructure in under 2 minutes
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="enrollment" className="w-full">
          <TabsList className="grid w-full grid-cols-3 mb-6">
            <TabsTrigger value="enrollment" className="flex items-center gap-2" data-testid="tab-enrollment-install">
              <Key className="h-4 w-4" />
              Enrollment Token
            </TabsTrigger>
            <TabsTrigger value="host" className="flex items-center gap-2" data-testid="tab-host-install">
              <Monitor className="h-4 w-4" />
              Single-Use Token
            </TabsTrigger>
            <TabsTrigger value="container" className="flex items-center gap-2" data-testid="tab-container-install">
              <FaDocker className="h-4 w-4" />
              Container Install
            </TabsTrigger>
          </TabsList>

          <TabsContent value="enrollment" className="space-y-4">
            <div className="flex flex-col gap-4">
              <Alert>
                <AlertDescription className="text-sm">
                  Enrollment tokens are reusable — deploy the same command on multiple machines. Recommended for bulk deployments.
                </AlertDescription>
              </Alert>

              <div className="flex items-center gap-4">
                <span className="text-sm font-medium text-muted-foreground">Platform:</span>
                <div className="flex gap-2">
                  <Button
                    variant={enrollmentPlatform === "linux" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setEnrollmentPlatform("linux")}
                    className="flex items-center gap-2"
                  >
                    <FaLinux className="h-4 w-4" />
                    Linux
                  </Button>
                  <Button
                    variant={enrollmentPlatform === "windows" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setEnrollmentPlatform("windows")}
                    className="flex items-center gap-2"
                  >
                    <FaWindows className="h-4 w-4" />
                    Windows
                  </Button>
                </div>
              </div>

              {!enrollmentToken ? (
                <Button
                  onClick={() => generateEnrollmentTokenMutation.mutate()}
                  disabled={generateEnrollmentTokenMutation.isPending}
                  className="flex items-center gap-2"
                  data-testid="btn-generate-enrollment"
                >
                  {generateEnrollmentTokenMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Key className="h-4 w-4" />
                  )}
                  Generate Enrollment Token
                </Button>
              ) : (
                <div className="space-y-3">
                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap break-all">
                      {getEnrollmentCommand(enrollmentPlatform, enrollmentToken)}
                    </pre>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(getEnrollmentCommand(enrollmentPlatform, enrollmentToken), "enroll-cmd")}
                      data-testid="btn-copy-enrollment-command"
                    >
                      {copiedId === "enroll-cmd" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setEnrollmentToken(null);
                        generateEnrollmentTokenMutation.mutate();
                      }}
                    >
                      <RefreshCw className="h-4 w-4 mr-2" />
                      Generate New Token
                    </Button>
                  </div>

                  <div className="text-xs text-muted-foreground">
                    <p>This token expires in 30 days. Manage tokens in the Enrollment Tokens tab.</p>
                  </div>
                </div>
              )}

              {!enrollmentToken && (
                <div className="bg-muted/50 rounded-lg p-4 text-sm text-muted-foreground">
                  <p className="font-medium mb-2">How enrollment tokens work:</p>
                  <ol className="list-decimal list-inside space-y-1">
                    <li>Generate a reusable enrollment token</li>
                    <li>Run the same command on any number of machines</li>
                    <li>Each machine auto-registers with your organization</li>
                    <li>Revoke the token anytime from the Enrollment Tokens tab</li>
                  </ol>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="host" className="space-y-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium text-muted-foreground">Platform:</span>
                <div className="flex gap-2">
                  <Button
                    variant={hostPlatform === "linux" ? "default" : "outline"}
                    size="sm"
                    onClick={() => {
                      setHostPlatform("linux");
                      setGeneratedCommand(null);
                    }}
                    className="flex items-center gap-2"
                    data-testid="btn-platform-linux"
                  >
                    <FaLinux className="h-4 w-4" />
                    Linux
                  </Button>
                  <Button
                    variant={hostPlatform === "windows" ? "default" : "outline"}
                    size="sm"
                    onClick={() => {
                      setHostPlatform("windows");
                      setGeneratedCommand(null);
                    }}
                    className="flex items-center gap-2"
                    data-testid="btn-platform-windows"
                  >
                    <FaWindows className="h-4 w-4" />
                    Windows
                  </Button>
                </div>
              </div>

              <div className="flex gap-2">
                <Button
                  onClick={() => generateCommandMutation.mutate(hostPlatform)}
                  disabled={generateCommandMutation.isPending}
                  className="flex items-center gap-2"
                  data-testid="btn-generate-command"
                >
                  {generateCommandMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : generatedCommand ? (
                    <RefreshCw className="h-4 w-4" />
                  ) : (
                    <Terminal className="h-4 w-4" />
                  )}
                  {generatedCommand ? "Generate New Command" : "Generate Install Command"}
                </Button>
              </div>

              {generatedCommand && (
                <div className="space-y-3">
                  <Alert>
                    <AlertDescription className="text-sm">
                      This command includes a single-use token that expires in {generatedCommand.expiresInHours} hours.
                      Run it on your target machine - no interaction required.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm font-mono">
                      {generatedCommand.installCommand}
                    </pre>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(generatedCommand.installCommand, "host-cmd")}
                      data-testid="btn-copy-host-command"
                    >
                      {copiedId === "host-cmd" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>

                  <div className="text-xs text-muted-foreground space-y-1">
                    <p><strong>Token ID:</strong> {generatedCommand.tokenId}</p>
                    <p><strong>Expires:</strong> {new Date(generatedCommand.expiresAt).toLocaleString()}</p>
                  </div>
                </div>
              )}

              {!generatedCommand && (
                <div className="bg-muted/50 rounded-lg p-4 text-sm text-muted-foreground">
                  <p className="font-medium mb-2">How it works:</p>
                  <ol className="list-decimal list-inside space-y-1">
                    <li>Click "Generate Install Command" above</li>
                    <li>Copy the one-liner command</li>
                    <li>Paste and run on your {hostPlatform === "linux" ? "Linux server" : "Windows machine"}</li>
                    <li>Agent auto-registers and starts reporting</li>
                  </ol>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="container" className="space-y-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium text-muted-foreground">Method:</span>
                <div className="flex gap-2">
                  <Button
                    variant={containerMethod === "docker" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setContainerMethod("docker")}
                    className="flex items-center gap-2"
                    data-testid="btn-method-docker"
                  >
                    <FaDocker className="h-4 w-4" />
                    Docker
                  </Button>
                  <Button
                    variant={containerMethod === "kubernetes" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setContainerMethod("kubernetes")}
                    className="flex items-center gap-2"
                    data-testid="btn-method-kubernetes"
                  >
                    <SiKubernetes className="h-4 w-4" />
                    Kubernetes
                  </Button>
                </div>
              </div>

              {containerMethod === "docker" && (
                <div className="space-y-3">
                  <Alert>
                    <AlertDescription className="text-sm">
                      Replace <code className="bg-muted px-1 rounded">YOUR_API_KEY</code> with your agent API key.
                      Get one from the "Register Agent" dialog.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre">
                      {getDockerCommand()}
                    </pre>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(getDockerCommand(), "docker-cmd")}
                      data-testid="btn-copy-docker-command"
                    >
                      {copiedId === "docker-cmd" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>

                  <div className="bg-muted/50 rounded-lg p-4 text-sm text-muted-foreground">
                    <p className="font-medium mb-2">Management commands:</p>
                    <ul className="space-y-1 font-mono text-xs">
                      <li>View logs: <code>docker logs -f odinforge-agent</code></li>
                      <li>Stop: <code>docker stop odinforge-agent</code></li>
                      <li>Remove: <code>docker rm -f odinforge-agent</code></li>
                    </ul>
                  </div>
                </div>
              )}

              {containerMethod === "kubernetes" && (
                <div className="space-y-3">
                  <Alert>
                    <AlertDescription className="text-sm">
                      Deploy as a DaemonSet using Helm. Replace <code className="bg-muted px-1 rounded">YOUR_API_KEY</code> with your agent API key.
                    </AlertDescription>
                  </Alert>

                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre">
                      {getHelmCommand()}
                    </pre>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(getHelmCommand(), "helm-cmd")}
                      data-testid="btn-copy-helm-command"
                    >
                      {copiedId === "helm-cmd" ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>

                  <div className="bg-muted/50 rounded-lg p-4 text-sm text-muted-foreground">
                    <p className="font-medium mb-2">Features:</p>
                    <ul className="list-disc list-inside space-y-1">
                      <li>Deploys as DaemonSet (one agent per node)</li>
                      <li>Includes RBAC and ServiceAccount</li>
                      <li>Supports mTLS (optional)</li>
                      <li>Persistent storage for queue data</li>
                    </ul>
                  </div>

                  <div className="bg-muted/50 rounded-lg p-4 text-sm text-muted-foreground">
                    <p className="font-medium mb-2">Management commands:</p>
                    <ul className="space-y-1 font-mono text-xs">
                      <li>Status: <code>kubectl get daemonset -n odinforge</code></li>
                      <li>Logs: <code>kubectl logs -l app.kubernetes.io/name=odinforge-agent -n odinforge -f</code></li>
                      <li>Uninstall: <code>helm uninstall odinforge-agent -n odinforge</code></li>
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
