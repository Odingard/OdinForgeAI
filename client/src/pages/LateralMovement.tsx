import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Key,
  Network,
  Activity,
  AlertTriangle,
  Play,
  Search,
  Target,
  GitBranch,
  Lock,
  Unlock,
  Server
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { apiRequest } from "@/lib/queryClient";

interface Credential {
  id: string;
  sourceType: string;
  sourceHost: string;
  credentialType: string;
  username: string;
  domain?: string;
  privilegeLevel: string;
  discoveredAt: string;
}

interface PivotPoint {
  id: string;
  hostname: string;
  ipAddress: string;
  accessibleHosts: number;
  credentials: number;
  techniques: string[];
  risk: string;
  discoveredAt: string;
}

interface AttackPath {
  id: string;
  source: string;
  target: string;
  hops: number;
  techniques: string[];
  credentials: string[];
  feasibility: string;
  discoveredAt: string;
}

interface Finding {
  id: string;
  type: string;
  severity: string;
  source: string;
  target: string;
  technique: string;
  description: string;
  discoveredAt: string;
}

interface Technique {
  id: string;
  name: string;
  description: string;
  protocols: string[];
  requiresCredentials: boolean;
  stealthLevel: string;
}

export default function LateralMovement() {
  const queryClient = useQueryClient();
  const [selectedTab, setSelectedTab] = useState("overview");

  // Queries
  const { data: credentials = [] } = useQuery<Credential[]>({
    queryKey: ["/api/lateral-movement/credentials"],
  });

  const { data: pivotPoints = [] } = useQuery<PivotPoint[]>({
    queryKey: ["/api/lateral-movement/pivot-points"],
  });

  const { data: attackPaths = [] } = useQuery<AttackPath[]>({
    queryKey: ["/api/lateral-movement/attack-paths"],
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ["/api/lateral-movement/findings"],
  });

  const { data: techniques = [] } = useQuery<Technique[]>({
    queryKey: ["/api/lateral-movement/techniques"],
  });

  // Stats
  const stats = {
    totalCredentials: credentials.length,
    highPrivilegeCredentials: credentials.filter(c => c.privilegeLevel === "high").length,
    pivotPoints: pivotPoints.length,
    attackPaths: attackPaths.length,
    criticalFindings: findings.filter(f => f.severity === "critical").length,
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <GitBranch className="h-8 w-8" />
          Lateral Movement Analysis
        </h1>
        <p className="text-muted-foreground mt-2">
          Discover credential reuse, pivot points, and attack paths across your infrastructure
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Discovered Credentials</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalCredentials}</div>
            <p className="text-xs text-muted-foreground">
              {stats.highPrivilegeCredentials} high privilege
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pivot Points</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.pivotPoints}</div>
            <p className="text-xs text-muted-foreground">
              Identified hosts
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attack Paths</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.attackPaths}</div>
            <p className="text-xs text-muted-foreground">
              Possible routes
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{findings.length}</div>
            <p className="text-xs text-muted-foreground">
              {stats.criticalFindings} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Techniques</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{techniques.length}</div>
            <p className="text-xs text-muted-foreground">
              Available tests
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="credentials">Credentials</TabsTrigger>
          <TabsTrigger value="pivots">Pivot Points</TabsTrigger>
          <TabsTrigger value="paths">Attack Paths</TabsTrigger>
          <TabsTrigger value="test">Testing</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Recent Findings */}
            <Card>
              <CardHeader>
                <CardTitle>Recent Findings</CardTitle>
                <CardDescription>Latest lateral movement discoveries</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {findings.slice(0, 10).map((finding) => (
                    <div key={finding.id} className="mb-4 last:mb-0">
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <p className="text-sm font-medium">{finding.technique}</p>
                          <p className="text-sm text-muted-foreground">{finding.description}</p>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Server className="h-3 w-3" />
                            {finding.source} → {finding.target}
                          </div>
                        </div>
                        <Badge variant={finding.severity === "critical" ? "destructive" : "default"}>
                          {finding.severity}
                        </Badge>
                      </div>
                      <Separator className="mt-2" />
                    </div>
                  ))}
                </ScrollArea>
              </CardContent>
            </Card>

            {/* Top Pivot Points */}
            <Card>
              <CardHeader>
                <CardTitle>High-Value Pivot Points</CardTitle>
                <CardDescription>Hosts with extensive lateral movement potential</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {pivotPoints
                    .sort((a, b) => b.accessibleHosts - a.accessibleHosts)
                    .slice(0, 10)
                    .map((pivot) => (
                      <div key={pivot.id} className="mb-4 last:mb-0">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <p className="text-sm font-medium">{pivot.hostname}</p>
                            <p className="text-xs text-muted-foreground">{pivot.ipAddress}</p>
                            <div className="flex items-center gap-4 text-xs">
                              <span>{pivot.accessibleHosts} reachable hosts</span>
                              <span>{pivot.credentials} credentials</span>
                            </div>
                          </div>
                          <Badge variant={pivot.risk === "high" ? "destructive" : "default"}>
                            {pivot.risk} risk
                          </Badge>
                        </div>
                        <Separator className="mt-2" />
                      </div>
                    ))}
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Credentials Tab */}
        <TabsContent value="credentials" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Credential Vault</CardTitle>
              <CardDescription>Discovered credentials from various sources</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {credentials.map((cred) => (
                    <Card key={cred.id}>
                      <CardContent className="pt-6">
                        <div className="flex items-start justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2">
                              {cred.privilegeLevel === "high" ? (
                                <Unlock className="h-4 w-4 text-destructive" />
                              ) : (
                                <Lock className="h-4 w-4 text-muted-foreground" />
                              )}
                              <span className="font-medium">
                                {cred.domain ? `${cred.domain}\\` : ""}{cred.username}
                              </span>
                            </div>
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <span className="text-muted-foreground">Type: </span>
                                <span>{cred.credentialType}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Source: </span>
                                <span>{cred.sourceType}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Host: </span>
                                <span>{cred.sourceHost}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Discovered: </span>
                                <span>{new Date(cred.discoveredAt).toLocaleDateString()}</span>
                              </div>
                            </div>
                          </div>
                          <div className="flex flex-col gap-2">
                            <Badge variant={cred.privilegeLevel === "high" ? "destructive" : "default"}>
                              {cred.privilegeLevel} privilege
                            </Badge>
                            <Button size="sm" variant="outline">
                              <Play className="h-3 w-3 mr-1" />
                              Test Reuse
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Pivot Points Tab */}
        <TabsContent value="pivots" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Pivot Points</CardTitle>
              <CardDescription>Hosts that can be used to access other systems</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {pivotPoints.map((pivot) => (
                    <Card key={pivot.id}>
                      <CardContent className="pt-6">
                        <div className="flex items-start justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2">
                              <Network className="h-4 w-4" />
                              <span className="font-medium">{pivot.hostname}</span>
                            </div>
                            <p className="text-sm text-muted-foreground">{pivot.ipAddress}</p>
                            <div className="grid grid-cols-3 gap-4 text-sm mt-2">
                              <div>
                                <span className="text-muted-foreground">Accessible Hosts: </span>
                                <span className="font-medium">{pivot.accessibleHosts}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Credentials: </span>
                                <span className="font-medium">{pivot.credentials}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Techniques: </span>
                                <span className="font-medium">{pivot.techniques.length}</span>
                              </div>
                            </div>
                            <div className="flex flex-wrap gap-1 mt-2">
                              {pivot.techniques.map((tech, idx) => (
                                <Badge key={idx} variant="outline" className="text-xs">
                                  {tech}
                                </Badge>
                              ))}
                            </div>
                          </div>
                          <Badge variant={pivot.risk === "high" ? "destructive" : pivot.risk === "medium" ? "default" : "secondary"}>
                            {pivot.risk} risk
                          </Badge>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack Paths Tab */}
        <TabsContent value="paths" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Attack Paths</CardTitle>
              <CardDescription>Discovered routes for lateral movement</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                <div className="space-y-4">
                  {attackPaths.map((path) => (
                    <Card key={path.id}>
                      <CardContent className="pt-6">
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <GitBranch className="h-4 w-4" />
                              <span className="font-medium">{path.source} → {path.target}</span>
                            </div>
                            <Badge variant={path.feasibility === "high" ? "destructive" : "default"}>
                              {path.feasibility} feasibility
                            </Badge>
                          </div>
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">Hops: </span>
                              <span className="font-medium">{path.hops}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Discovered: </span>
                              <span>{new Date(path.discoveredAt).toLocaleDateString()}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-sm text-muted-foreground mb-1">Techniques:</p>
                            <div className="flex flex-wrap gap-1">
                              {path.techniques.map((tech, idx) => (
                                <Badge key={idx} variant="outline" className="text-xs">
                                  {tech}
                                </Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <p className="text-sm text-muted-foreground mb-1">Required Credentials:</p>
                            <div className="flex flex-wrap gap-1">
                              {path.credentials.map((cred, idx) => (
                                <Badge key={idx} variant="secondary" className="text-xs">
                                  <Key className="h-3 w-3 mr-1" />
                                  {cred}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Testing Tab */}
        <TabsContent value="test" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Credential Reuse Test */}
            <Card>
              <CardHeader>
                <CardTitle>Test Credential Reuse</CardTitle>
                <CardDescription>Check if credentials work on other hosts</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Select Credential</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Choose a credential" />
                    </SelectTrigger>
                    <SelectContent>
                      {credentials.map((cred) => (
                        <SelectItem key={cred.id} value={cred.id}>
                          {cred.domain ? `${cred.domain}\\` : ""}{cred.username}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Target Hosts (comma-separated)</Label>
                  <Input placeholder="192.168.1.10, server01, 10.0.0.5" />
                </div>
                <Button className="w-full">
                  <Play className="h-4 w-4 mr-2" />
                  Test Reuse
                </Button>
              </CardContent>
            </Card>

            {/* Probe Host */}
            <Card>
              <CardHeader>
                <CardTitle>Probe Host</CardTitle>
                <CardDescription>Scan for lateral movement protocols</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Target Host</Label>
                  <Input placeholder="192.168.1.10 or hostname" />
                </div>
                <div className="space-y-2">
                  <Label>Protocols</Label>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">SMB</Badge>
                    <Badge variant="outline">WinRM</Badge>
                    <Badge variant="outline">SSH</Badge>
                    <Badge variant="outline">RDP</Badge>
                    <Badge variant="outline">PSExec</Badge>
                  </div>
                </div>
                <Button className="w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Probe Host
                </Button>
              </CardContent>
            </Card>

            {/* Discover Pivots */}
            <Card>
              <CardHeader>
                <CardTitle>Discover Pivot Points</CardTitle>
                <CardDescription>Find hosts that can access multiple systems</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Starting Host</Label>
                  <Input placeholder="Initial host to scan from" />
                </div>
                <div className="space-y-2">
                  <Label>Scan Depth</Label>
                  <Select defaultValue="2">
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 hop</SelectItem>
                      <SelectItem value="2">2 hops</SelectItem>
                      <SelectItem value="3">3 hops</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button className="w-full">
                  <Target className="h-4 w-4 mr-2" />
                  Discover Pivots
                </Button>
              </CardContent>
            </Card>

            {/* Available Techniques */}
            <Card>
              <CardHeader>
                <CardTitle>Available Techniques</CardTitle>
                <CardDescription>Lateral movement methods you can test</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[200px]">
                  <div className="space-y-2">
                    {techniques.map((tech) => (
                      <div key={tech.id} className="flex items-center justify-between p-2 rounded-lg border">
                        <div>
                          <p className="text-sm font-medium">{tech.name}</p>
                          <p className="text-xs text-muted-foreground">{tech.description}</p>
                        </div>
                        <Badge variant="outline">{tech.stealthLevel}</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
