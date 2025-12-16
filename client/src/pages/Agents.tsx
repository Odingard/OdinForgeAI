import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import { 
  Server, 
  Activity, 
  AlertTriangle, 
  Trash2, 
  Plus, 
  Copy, 
  CheckCircle2, 
  XCircle,
  MonitorSmartphone,
  Wifi,
  WifiOff,
  Terminal,
  Eye
} from "lucide-react";

interface EndpointAgent {
  id: string;
  agentName: string;
  hostname: string | null;
  platform: string | null;
  platformVersion: string | null;
  architecture: string | null;
  ipAddresses: string[] | null;
  status: string;
  lastHeartbeat: string | null;
  lastTelemetry: string | null;
  environment: string | null;
  tags: string[] | null;
  registeredAt: string;
}

interface AgentFinding {
  id: string;
  agentId: string;
  findingType: string;
  severity: string;
  title: string;
  description: string | null;
  affectedComponent: string | null;
  status: string;
  detectedAt: string;
  aevEvaluationId: string | null;
  autoEvaluationTriggered: boolean;
}

interface AgentStats {
  totalAgents: number;
  onlineAgents: number;
  offlineAgents: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  newFindings: number;
}

export default function Agents() {
  const { toast } = useToast();
  const [registerDialogOpen, setRegisterDialogOpen] = useState(false);
  const [newAgentName, setNewAgentName] = useState("");
  const [newAgentPlatform, setNewAgentPlatform] = useState("linux");
  const [newAgentEnvironment, setNewAgentEnvironment] = useState("production");
  const [registeredApiKey, setRegisteredApiKey] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgent | null>(null);
  const [scriptDialogOpen, setScriptDialogOpen] = useState(false);

  const { data: agents = [], isLoading: agentsLoading } = useQuery<EndpointAgent[]>({
    queryKey: ["/api/agents"],
  });

  const { data: stats } = useQuery<AgentStats>({
    queryKey: ["/api/agents/stats/summary"],
  });

  const { data: findings = [] } = useQuery<AgentFinding[]>({
    queryKey: ["/api/agent-findings"],
  });

  const registerAgentMutation = useMutation({
    mutationFn: async (data: { agentName: string; platform: string; environment: string }) => {
      const response = await apiRequest("POST", "/api/agents/register", data);
      return response.json();
    },
    onSuccess: (data) => {
      setRegisteredApiKey(data.apiKey);
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Registration Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteAgentMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/agents/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Agent Deleted",
        description: "The agent has been removed.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    },
  });

  const handleRegister = () => {
    if (!newAgentName.trim()) {
      toast({
        title: "Error",
        description: "Agent name is required",
        variant: "destructive",
      });
      return;
    }
    registerAgentMutation.mutate({
      agentName: newAgentName,
      platform: newAgentPlatform,
      environment: newAgentEnvironment,
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "API key copied to clipboard",
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "secondary";
      case "low": return "outline";
      default: return "outline";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "online": return <Wifi className="h-4 w-4 text-green-500" />;
      case "offline": return <WifiOff className="h-4 w-4 text-muted-foreground" />;
      case "stale": return <WifiOff className="h-4 w-4 text-yellow-500" />;
      default: return <WifiOff className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const pythonAgentScript = `#!/usr/bin/env python3
"""
OdinForge Endpoint Agent
Collects system telemetry and sends to OdinForge for security analysis.
"""

import os
import sys
import json
import socket
import platform
import subprocess
import time
import requests
from datetime import datetime

# Configuration
ODINFORGE_URL = "${window.location.origin}"
API_KEY = "YOUR_API_KEY_HERE"  # Replace with your agent API key
TELEMETRY_INTERVAL = 300  # 5 minutes

def get_system_info():
    """Collect system information."""
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system().lower(),
        "platformVersion": platform.release(),
        "kernel": platform.version(),
        "architecture": platform.machine(),
        "uptime": get_uptime(),
        "bootTime": datetime.now().isoformat(),
    }

def get_uptime():
    """Get system uptime in seconds."""
    try:
        with open('/proc/uptime', 'r') as f:
            return int(float(f.read().split()[0]))
    except:
        return 0

def get_resource_metrics():
    """Collect resource usage metrics."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            "cpuUsage": psutil.cpu_percent(interval=1),
            "memoryTotal": mem.total,
            "memoryUsed": mem.used,
            "memoryPercent": mem.percent,
            "diskTotal": disk.total,
            "diskUsed": disk.used,
            "diskPercent": disk.percent,
        }
    except ImportError:
        return {"error": "psutil not installed"}

def get_open_ports():
    """Get list of open ports."""
    ports = []
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\\n')[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    addr = parts[3]
                    if ':' in addr:
                        port = addr.split(':')[-1]
                        ports.append({
                            "port": int(port),
                            "protocol": "tcp",
                            "state": "listen",
                            "localAddress": addr,
                        })
    except Exception as e:
        print(f"Error getting ports: {e}")
    return ports

def get_running_services():
    """Get list of running services with versions."""
    services = []
    
    # Check common services
    service_checks = [
        ("apache2", "apache2 -v"),
        ("nginx", "nginx -v"),
        ("mysql", "mysql --version"),
        ("postgresql", "psql --version"),
        ("redis", "redis-server --version"),
        ("mongodb", "mongod --version"),
        ("sshd", "ssh -V"),
    ]
    
    for name, cmd in service_checks:
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 or result.stderr:
                version = (result.stdout + result.stderr).strip().split('\\n')[0][:100]
                services.append({
                    "name": name,
                    "version": version,
                    "status": "running",
                })
        except:
            pass
    
    return services

def detect_security_issues():
    """Detect potential security issues."""
    findings = []
    
    # Check for root SSH login
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            config = f.read()
            if 'PermitRootLogin yes' in config:
                findings.append({
                    "type": "weak_config",
                    "severity": "high",
                    "title": "SSH Root Login Enabled",
                    "description": "SSH is configured to allow root login, which is a security risk.",
                    "affectedComponent": "sshd",
                    "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                })
    except:
        pass
    
    # Check for world-writable files in /etc
    try:
        result = subprocess.run(
            ["find", "/etc", "-type", "f", "-perm", "-o+w"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            files = result.stdout.strip().split('\\n')[:5]
            findings.append({
                "type": "weak_config",
                "severity": "medium",
                "title": "World-Writable Config Files",
                "description": f"Found {len(files)} world-writable files in /etc: {', '.join(files)}",
                "affectedComponent": "filesystem",
                "recommendation": "Remove world-write permissions from sensitive config files",
            })
    except:
        pass
    
    # Check for outdated packages (Ubuntu/Debian)
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=60
        )
        upgradable = [l for l in result.stdout.split('\\n') if 'security' in l.lower()]
        if len(upgradable) > 5:
            findings.append({
                "type": "outdated_software",
                "severity": "high",
                "title": "Security Updates Available",
                "description": f"{len(upgradable)} security updates are pending installation.",
                "affectedComponent": "system-packages",
                "recommendation": "Run 'apt upgrade' to install security updates",
            })
    except:
        pass
    
    return findings

def send_telemetry():
    """Send telemetry to OdinForge."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "systemInfo": get_system_info(),
        "resourceMetrics": get_resource_metrics(),
        "services": get_running_services(),
        "openPorts": get_open_ports(),
        "securityFindings": detect_security_issues(),
        "collectedAt": datetime.now().isoformat(),
    }
    
    try:
        response = requests.post(
            f"{ODINFORGE_URL}/api/agents/telemetry",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        print(f"[{datetime.now()}] Telemetry sent. Findings created: {result.get('findingsCreated', 0)}")
        return True
    except Exception as e:
        print(f"[{datetime.now()}] Error sending telemetry: {e}")
        return False

def send_heartbeat():
    """Send heartbeat to OdinForge."""
    headers = {"Authorization": f"Bearer {API_KEY}"}
    try:
        requests.post(
            f"{ODINFORGE_URL}/api/agents/heartbeat",
            headers=headers,
            timeout=10
        )
    except:
        pass

def main():
    print(f"OdinForge Agent starting...")
    print(f"Server: {ODINFORGE_URL}")
    print(f"Telemetry interval: {TELEMETRY_INTERVAL}s")
    
    while True:
        send_telemetry()
        
        # Send heartbeats between telemetry
        for _ in range(TELEMETRY_INTERVAL // 60):
            time.sleep(60)
            send_heartbeat()

if __name__ == "__main__":
    main()
`;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">Endpoint Agents</h1>
          <p className="text-muted-foreground">
            Deploy agents on your infrastructure for live security monitoring
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setScriptDialogOpen(true)} data-testid="btn-view-script">
            <Terminal className="h-4 w-4 mr-2" />
            View Agent Script
          </Button>
          <Dialog open={registerDialogOpen} onOpenChange={(open) => {
            setRegisterDialogOpen(open);
            if (!open) {
              setRegisteredApiKey(null);
              setNewAgentName("");
            }
          }}>
            <DialogTrigger asChild>
              <Button data-testid="btn-register-agent">
                <Plus className="h-4 w-4 mr-2" />
                Register Agent
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Register New Agent</DialogTitle>
                <DialogDescription>
                  Create credentials for a new endpoint agent
                </DialogDescription>
              </DialogHeader>
              
              {registeredApiKey ? (
                <div className="space-y-4">
                  <div className="bg-green-500/10 border border-green-500/20 rounded-md p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <span className="font-medium">Agent Registered Successfully</span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-4">
                      Copy the API key below. It will not be shown again.
                    </p>
                    <div className="flex gap-2">
                      <Input 
                        value={registeredApiKey} 
                        readOnly 
                        className="font-mono text-sm"
                        data-testid="input-api-key"
                      />
                      <Button 
                        variant="outline" 
                        size="icon"
                        onClick={() => copyToClipboard(registeredApiKey)}
                        data-testid="btn-copy-api-key"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <Button 
                    className="w-full" 
                    onClick={() => {
                      setRegisterDialogOpen(false);
                      setRegisteredApiKey(null);
                      setNewAgentName("");
                    }}
                    data-testid="btn-close-dialog"
                  >
                    Done
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="agentName">Agent Name</Label>
                    <Input
                      id="agentName"
                      placeholder="e.g., prod-webserver-01"
                      value={newAgentName}
                      onChange={(e) => setNewAgentName(e.target.value)}
                      data-testid="input-agent-name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Platform</Label>
                    <Select value={newAgentPlatform} onValueChange={setNewAgentPlatform}>
                      <SelectTrigger data-testid="select-platform">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="linux">Linux</SelectItem>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="macos">macOS</SelectItem>
                        <SelectItem value="container">Container</SelectItem>
                        <SelectItem value="kubernetes">Kubernetes</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Environment</Label>
                    <Select value={newAgentEnvironment} onValueChange={setNewAgentEnvironment}>
                      <SelectTrigger data-testid="select-environment">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="production">Production</SelectItem>
                        <SelectItem value="staging">Staging</SelectItem>
                        <SelectItem value="development">Development</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button 
                    className="w-full" 
                    onClick={handleRegister}
                    disabled={registerAgentMutation.isPending}
                    data-testid="btn-submit-register"
                  >
                    {registerAgentMutation.isPending ? "Registering..." : "Register Agent"}
                  </Button>
                </div>
              )}
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-agents">
              {stats?.totalAgents ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Online</CardTitle>
            <Activity className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600" data-testid="text-online-agents">
              {stats?.onlineAgents ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600" data-testid="text-critical-findings">
              {stats?.criticalFindings ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">New Findings</CardTitle>
            <MonitorSmartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-new-findings">
              {stats?.newFindings ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="agents" className="space-y-4">
        <TabsList>
          <TabsTrigger value="agents" data-testid="tab-agents">Agents</TabsTrigger>
          <TabsTrigger value="findings" data-testid="tab-findings">Findings</TabsTrigger>
        </TabsList>

        <TabsContent value="agents" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Connected Agents</CardTitle>
              <CardDescription>
                Endpoint agents reporting telemetry to OdinForge
              </CardDescription>
            </CardHeader>
            <CardContent>
              {agentsLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading agents...</div>
              ) : agents.length === 0 ? (
                <div className="text-center py-8">
                  <Server className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-medium mb-2">No Agents Registered</h3>
                  <p className="text-muted-foreground text-sm mb-4">
                    Register an agent to start collecting live security data
                  </p>
                  <Button onClick={() => setRegisterDialogOpen(true)} data-testid="btn-register-first-agent">
                    <Plus className="h-4 w-4 mr-2" />
                    Register First Agent
                  </Button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Hostname</TableHead>
                      <TableHead>Platform</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead>Last Seen</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agents.map((agent) => (
                      <TableRow key={agent.id} data-testid={`row-agent-${agent.id}`}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getStatusIcon(agent.status)}
                            <span className="capitalize text-sm">{agent.status}</span>
                          </div>
                        </TableCell>
                        <TableCell className="font-medium">{agent.agentName}</TableCell>
                        <TableCell>{agent.hostname || "-"}</TableCell>
                        <TableCell className="capitalize">{agent.platform || "-"}</TableCell>
                        <TableCell>
                          {agent.environment && (
                            <Badge variant="outline" className="capitalize">
                              {agent.environment}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {agent.lastHeartbeat
                            ? formatDistanceToNow(new Date(agent.lastHeartbeat), { addSuffix: true })
                            : "Never"}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setSelectedAgent(agent)}
                              data-testid={`btn-view-agent-${agent.id}`}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => deleteAgentMutation.mutate(agent.id)}
                              data-testid={`btn-delete-agent-${agent.id}`}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Findings</CardTitle>
              <CardDescription>
                Issues detected by endpoint agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="h-12 w-12 mx-auto text-green-500 mb-4" />
                  <h3 className="font-medium mb-2">No Findings Yet</h3>
                  <p className="text-muted-foreground text-sm">
                    Agent findings will appear here when detected
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Component</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Detected</TableHead>
                      <TableHead>Auto-Eval</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((finding) => (
                      <TableRow key={finding.id} data-testid={`row-finding-${finding.id}`}>
                        <TableCell>
                          <Badge variant={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium max-w-xs truncate">
                          {finding.title}
                        </TableCell>
                        <TableCell className="capitalize">
                          {finding.findingType.replace(/_/g, " ")}
                        </TableCell>
                        <TableCell>{finding.affectedComponent || "-"}</TableCell>
                        <TableCell className="capitalize">{finding.status}</TableCell>
                        <TableCell>
                          {formatDistanceToNow(new Date(finding.detectedAt), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          {finding.autoEvaluationTriggered ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={scriptDialogOpen} onOpenChange={setScriptDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>OdinForge Agent Script</DialogTitle>
            <DialogDescription>
              Python script to deploy on your endpoints for live security monitoring
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-auto">
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                className="absolute right-2 top-2"
                onClick={() => {
                  navigator.clipboard.writeText(pythonAgentScript);
                  toast({ title: "Copied", description: "Script copied to clipboard" });
                }}
                data-testid="btn-copy-script"
              >
                <Copy className="h-4 w-4 mr-2" />
                Copy
              </Button>
              <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs font-mono">
                {pythonAgentScript}
              </pre>
            </div>
          </div>
          <div className="pt-4 border-t">
            <h4 className="font-medium mb-2">Quick Start:</h4>
            <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
              <li>Register an agent above to get an API key</li>
              <li>Replace YOUR_API_KEY_HERE in the script</li>
              <li>Install dependencies: pip install requests psutil</li>
              <li>Run the script: python odinforge_agent.py</li>
            </ol>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
