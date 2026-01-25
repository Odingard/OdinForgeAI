import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  FileCode,
  Key,
  Container,
  Play,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  FileJson,
  Lock,
  ShieldAlert,
  Bug,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

async function securityApiRequest(url: string, data: unknown, adminPassword: string): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Password": adminPassword,
    },
    body: JSON.stringify(data),
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/10 text-gray-400 border-gray-500/30",
};

const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case "critical":
    case "high":
      return <XCircle className="h-4 w-4" />;
    case "medium":
      return <AlertTriangle className="h-4 w-4" />;
    case "low":
      return <Info className="h-4 w-4" />;
    default:
      return <CheckCircle2 className="h-4 w-4" />;
  }
};

interface Finding {
  id: string;
  title: string;
  severity: string;
  description: string;
  evidence?: string;
  recommendation?: string;
  mitreAttackId?: string;
  cisControl?: string;
  cwe?: string;
  category?: string;
}

function FindingCard({ finding }: { finding: Finding }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card className="mb-2">
        <CollapsibleTrigger asChild>
          <CardHeader className="py-3 cursor-pointer hover-elevate">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                {getSeverityIcon(finding.severity)}
                <span className="font-medium truncate">{finding.title}</span>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <Badge className={severityColors[finding.severity] || severityColors.info}>
                  {finding.severity}
                </Badge>
                {finding.mitreAttackId && (
                  <Badge variant="outline" className="text-xs">
                    {finding.mitreAttackId}
                  </Badge>
                )}
                {finding.cisControl && (
                  <Badge variant="outline" className="text-xs">
                    {finding.cisControl}
                  </Badge>
                )}
                {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="pt-0 space-y-3">
            <p className="text-sm text-muted-foreground">{finding.description}</p>
            {finding.evidence && (
              <div>
                <Label className="text-xs text-muted-foreground">Evidence</Label>
                <pre className="mt-1 p-2 bg-muted/50 rounded text-xs overflow-x-auto">
                  {finding.evidence}
                </pre>
              </div>
            )}
            {finding.recommendation && (
              <div>
                <Label className="text-xs text-muted-foreground">Recommendation</Label>
                <p className="mt-1 text-sm">{finding.recommendation}</p>
              </div>
            )}
            {finding.cwe && (
              <Badge variant="secondary" className="text-xs">
                {finding.cwe}
              </Badge>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

function ApiFuzzingTab({ adminPassword }: { adminPassword: string }) {
  const { toast } = useToast();
  const [openApiSpec, setOpenApiSpec] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [parsedSpec, setParsedSpec] = useState<any>(null);
  const [testCases, setTestCases] = useState<any[]>([]);
  const [categories, setCategories] = useState<string[]>([
    "type_mutation",
    "null_injection",
    "boundary_value",
    "injection",
  ]);

  const allCategories = [
    { id: "type_mutation", label: "Type Mutation" },
    { id: "null_injection", label: "Null Injection" },
    { id: "boundary_value", label: "Boundary Values" },
    { id: "format_violation", label: "Format Violations" },
    { id: "encoding", label: "Encoding" },
    { id: "injection", label: "Injection" },
    { id: "overflow", label: "Overflow" },
  ];

  const handleParseSpec = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!openApiSpec.trim()) {
      toast({ title: "Please enter an OpenAPI specification", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/fuzz/openapi/parse", { spec: openApiSpec }, adminPassword);
      setParsedSpec(result);
      toast({ title: "OpenAPI spec parsed successfully" });
    } catch (error: any) {
      toast({ title: "Failed to parse spec", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateTests = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!parsedSpec) {
      toast({ title: "Please parse an OpenAPI spec first", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/fuzz/generate", {
        apiDefinition: {
          baseUrl: parsedSpec.baseUrl || "https://api.example.com",
          endpoints: parsedSpec.endpoints || [],
        },
        options: {
          categories: categories,
          maxTestsPerEndpoint: 10,
        },
      }, adminPassword);
      setTestCases(result.testCases || []);
      toast({ title: `Generated ${result.totalTestCases || 0} test cases` });
    } catch (error: any) {
      toast({ title: "Failed to generate tests", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const toggleCategory = (categoryId: string) => {
    setCategories((prev) =>
      prev.includes(categoryId)
        ? prev.filter((c) => c !== categoryId)
        : [...prev, categoryId]
    );
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileJson className="h-5 w-5" />
            OpenAPI Specification
          </CardTitle>
          <CardDescription>
            Paste your OpenAPI/Swagger specification to discover endpoints and generate fuzz tests
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder='{"openapi": "3.0.0", "paths": {...}}'
            className="min-h-[200px] font-mono text-sm"
            value={openApiSpec}
            onChange={(e) => setOpenApiSpec(e.target.value)}
            data-testid="input-openapi-spec"
          />
          <Button onClick={handleParseSpec} disabled={isLoading} data-testid="button-parse-spec">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <FileCode className="h-4 w-4 mr-2" />}
            Parse Specification
          </Button>
        </CardContent>
      </Card>

      {parsedSpec && (
        <Card>
          <CardHeader>
            <CardTitle>Parsed Endpoints</CardTitle>
            <CardDescription>
              Found {parsedSpec.endpoints?.length || 0} endpoints
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[150px]">
              <div className="space-y-2">
                {parsedSpec.endpoints?.map((ep: any, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm">
                    <Badge variant="outline" className="uppercase font-mono">
                      {ep.method}
                    </Badge>
                    <span className="font-mono text-muted-foreground">{ep.path}</span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bug className="h-5 w-5" />
            Fuzzing Categories
          </CardTitle>
          <CardDescription>Select which types of fuzz tests to generate</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {allCategories.map((cat) => (
              <div key={cat.id} className="flex items-center space-x-2">
                <Checkbox
                  id={cat.id}
                  checked={categories.includes(cat.id)}
                  onCheckedChange={() => toggleCategory(cat.id)}
                  data-testid={`checkbox-${cat.id}`}
                />
                <Label htmlFor={cat.id} className="text-sm cursor-pointer">
                  {cat.label}
                </Label>
              </div>
            ))}
          </div>
          <Separator className="my-4" />
          <Button
            onClick={handleGenerateTests}
            disabled={isLoading || !parsedSpec}
            data-testid="button-generate-tests"
          >
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
            Generate Test Cases
          </Button>
        </CardContent>
      </Card>

      {testCases.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Generated Test Cases</CardTitle>
            <CardDescription>{testCases.length} test cases ready for execution</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px]">
              <div className="space-y-2">
                {testCases.slice(0, 20).map((tc, idx) => (
                  <div key={idx} className="p-3 border rounded-md">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className="uppercase font-mono text-xs">
                        {tc.method}
                      </Badge>
                      <span className="font-mono text-sm">{tc.path}</span>
                      <Badge className={severityColors[tc.riskLevel] || severityColors.medium}>
                        {tc.category}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{tc.description}</p>
                  </div>
                ))}
                {testCases.length > 20 && (
                  <p className="text-sm text-muted-foreground text-center py-2">
                    ... and {testCases.length - 20} more test cases
                  </p>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AuthTestingTab({ adminPassword }: { adminPassword: string }) {
  const { toast } = useToast();
  const [jwtToken, setJwtToken] = useState("");
  const [jwtAnalysis, setJwtAnalysis] = useState<any>(null);
  const [jwtTestResults, setJwtTestResults] = useState<any>(null);
  const [redirectUri, setRedirectUri] = useState("");
  const [allowedDomains, setAllowedDomains] = useState("example.com");
  const [oauthResults, setOauthResults] = useState<any>(null);
  const [samlAssertion, setSamlAssertion] = useState("");
  const [samlAnalysis, setSamlAnalysis] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAnalyzeJwt = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!jwtToken.trim()) {
      toast({ title: "Please enter a JWT token", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/auth-test/jwt/analyze", { token: jwtToken }, adminPassword);
      setJwtAnalysis(result);
      toast({ title: "JWT analyzed successfully" });
    } catch (error: any) {
      toast({ title: "Failed to analyze JWT", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestJwt = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!jwtToken.trim()) {
      toast({ title: "Please enter a JWT token", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/auth-test/jwt/test", { token: jwtToken }, adminPassword);
      setJwtTestResults(result);
      toast({ title: `Found ${result.vulnerabilities?.length || 0} vulnerabilities` });
    } catch (error: any) {
      toast({ title: "Failed to test JWT", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestOAuthRedirect = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!redirectUri.trim()) {
      toast({ title: "Please enter a redirect URI", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/auth-test/oauth/redirect", {
        redirectUri,
        allowedDomains: allowedDomains.split(",").map((d) => d.trim()),
      }, adminPassword);
      setOauthResults(result);
      toast({ title: "OAuth redirect tested" });
    } catch (error: any) {
      toast({ title: "Failed to test redirect", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeSaml = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!samlAssertion.trim()) {
      toast({ title: "Please enter a SAML assertion", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/auth-test/saml/analyze", { assertion: samlAssertion }, adminPassword);
      setSamlAnalysis(result);
      toast({ title: "SAML assertion analyzed" });
    } catch (error: any) {
      toast({ title: "Failed to analyze SAML", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            JWT Token Analysis
          </CardTitle>
          <CardDescription>
            Analyze JWT tokens for security vulnerabilities including algorithm confusion and weak secrets
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            className="min-h-[100px] font-mono text-sm"
            value={jwtToken}
            onChange={(e) => setJwtToken(e.target.value)}
            data-testid="input-jwt-token"
          />
          <div className="flex gap-2">
            <Button onClick={handleAnalyzeJwt} disabled={isLoading} data-testid="button-analyze-jwt">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Analyze Token
            </Button>
            <Button variant="secondary" onClick={handleTestJwt} disabled={isLoading} data-testid="button-test-jwt">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <ShieldAlert className="h-4 w-4 mr-2" />}
              Run Security Tests
            </Button>
          </div>
        </CardContent>
      </Card>

      {jwtAnalysis && (
        <Card>
          <CardHeader>
            <CardTitle>JWT Structure</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-muted-foreground">Header</Label>
              <pre className="mt-1 p-3 bg-muted/50 rounded text-sm font-mono overflow-x-auto">
                {JSON.stringify(jwtAnalysis.header, null, 2)}
              </pre>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Payload</Label>
              <pre className="mt-1 p-3 bg-muted/50 rounded text-sm font-mono overflow-x-auto">
                {JSON.stringify(jwtAnalysis.payload, null, 2)}
              </pre>
            </div>
            {jwtAnalysis.warnings?.length > 0 && (
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">Warnings</Label>
                {jwtAnalysis.warnings.map((w: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-yellow-500">
                    <AlertTriangle className="h-4 w-4" />
                    {w}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {jwtTestResults?.vulnerabilities?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-red-400">JWT Vulnerabilities Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {jwtTestResults.vulnerabilities.map((v: any, idx: number) => (
                <FindingCard
                  key={idx}
                  finding={{
                    id: `jwt-${idx}`,
                    title: v.name || v.type,
                    severity: v.severity || "high",
                    description: v.description,
                    evidence: v.evidence,
                    recommendation: v.recommendation,
                    mitreAttackId: v.mitreAttackId,
                    cwe: v.cve,
                  }}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            OAuth Redirect Validation
          </CardTitle>
          <CardDescription>
            Test redirect URIs for open redirect vulnerabilities and validation bypass
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="redirect-uri">Redirect URI to Test</Label>
            <Input
              id="redirect-uri"
              placeholder="https://example.com/callback"
              value={redirectUri}
              onChange={(e) => setRedirectUri(e.target.value)}
              data-testid="input-redirect-uri"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="allowed-domains">Allowed Domains (comma-separated)</Label>
            <Input
              id="allowed-domains"
              placeholder="example.com, app.example.com"
              value={allowedDomains}
              onChange={(e) => setAllowedDomains(e.target.value)}
              data-testid="input-allowed-domains"
            />
          </div>
          <Button onClick={handleTestOAuthRedirect} disabled={isLoading} data-testid="button-test-oauth">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
            Test Redirect
          </Button>
        </CardContent>
      </Card>

      {oauthResults && (
        <Card>
          <CardHeader>
            <CardTitle>OAuth Redirect Results</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 mb-4">
              {oauthResults.isValid ? (
                <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
                  <CheckCircle2 className="h-3 w-3 mr-1" />
                  Valid Redirect
                </Badge>
              ) : (
                <Badge className={severityColors.high}>
                  <XCircle className="h-3 w-3 mr-1" />
                  Invalid/Vulnerable
                </Badge>
              )}
            </div>
            {oauthResults.vulnerabilities?.length > 0 && (
              <div className="space-y-2">
                {oauthResults.vulnerabilities.map((v: any, idx: number) => (
                  <FindingCard
                    key={idx}
                    finding={{
                      id: `oauth-${idx}`,
                      title: v.type,
                      severity: v.severity || "high",
                      description: v.description,
                      evidence: v.evidence,
                      recommendation: v.recommendation,
                      mitreAttackId: v.mitreAttackId,
                    }}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            SAML Assertion Analysis
          </CardTitle>
          <CardDescription>
            Analyze SAML assertions for signature bypass, XXE, and XML Signature Wrapping attacks
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="<samlp:Response>...</samlp:Response>"
            className="min-h-[150px] font-mono text-sm"
            value={samlAssertion}
            onChange={(e) => setSamlAssertion(e.target.value)}
            data-testid="input-saml-assertion"
          />
          <Button onClick={handleAnalyzeSaml} disabled={isLoading} data-testid="button-analyze-saml">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <ShieldAlert className="h-4 w-4 mr-2" />}
            Analyze SAML
          </Button>
        </CardContent>
      </Card>

      {samlAnalysis && (
        <Card>
          <CardHeader>
            <CardTitle>SAML Analysis Results</CardTitle>
          </CardHeader>
          <CardContent>
            {samlAnalysis.assertions && (
              <div className="mb-4">
                <Label className="text-xs text-muted-foreground">Parsed Assertions</Label>
                <pre className="mt-1 p-3 bg-muted/50 rounded text-sm font-mono overflow-x-auto max-h-[200px]">
                  {JSON.stringify(samlAnalysis.assertions, null, 2)}
                </pre>
              </div>
            )}
            {samlAnalysis.vulnerabilities?.length > 0 && (
              <div className="space-y-2">
                {samlAnalysis.vulnerabilities.map((v: any, idx: number) => (
                  <FindingCard
                    key={idx}
                    finding={{
                      id: `saml-${idx}`,
                      title: v.type || v.name,
                      severity: v.severity || "high",
                      description: v.description,
                      evidence: v.evidence,
                      recommendation: v.recommendation,
                      mitreAttackId: v.mitreAttackId,
                    }}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function ContainerSecurityTab({ adminPassword }: { adminPassword: string }) {
  const { toast } = useToast();
  const [dockerfile, setDockerfile] = useState("");
  const [imageName, setImageName] = useState("myapp");
  const [dockerfileResults, setDockerfileResults] = useState<any>(null);
  const [k8sManifest, setK8sManifest] = useState("");
  const [k8sResults, setK8sResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleScanDockerfile = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!dockerfile.trim()) {
      toast({ title: "Please enter a Dockerfile", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/container-security/scan-dockerfile", { content: dockerfile, imageName }, adminPassword);
      setDockerfileResults(result);
      toast({ title: `Found ${result.totalFindings || 0} issues` });
    } catch (error: any) {
      toast({ title: "Failed to scan Dockerfile", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleScanK8sManifest = async () => {
    if (!adminPassword) {
      toast({ title: "Please enter admin password first", variant: "destructive" });
      return;
    }
    if (!k8sManifest.trim()) {
      toast({ title: "Please enter a Kubernetes manifest", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const result = await securityApiRequest("/api/container-security/scan-manifests", { content: k8sManifest }, adminPassword);
      setK8sResults(result);
      const total =
        (result.summary?.criticalIssues || 0) +
        (result.summary?.highIssues || 0) +
        (result.summary?.mediumIssues || 0) +
        (result.summary?.lowIssues || 0);
      toast({ title: `Found ${total} security issues` });
    } catch (error: any) {
      toast({ title: "Failed to scan manifest", description: error.message, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="h-5 w-5" />
            Dockerfile Scanner
          </CardTitle>
          <CardDescription>
            Scan Dockerfiles for security issues including root user, world-writable permissions, and hardcoded secrets
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="image-name">Image Name</Label>
            <Input
              id="image-name"
              placeholder="myapp"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              data-testid="input-image-name"
            />
          </div>
          <Textarea
            placeholder="FROM ubuntu:latest&#10;RUN apt-get update&#10;USER root"
            className="min-h-[200px] font-mono text-sm"
            value={dockerfile}
            onChange={(e) => setDockerfile(e.target.value)}
            data-testid="input-dockerfile"
          />
          <Button onClick={handleScanDockerfile} disabled={isLoading} data-testid="button-scan-dockerfile">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Shield className="h-4 w-4 mr-2" />}
            Scan Dockerfile
          </Button>
        </CardContent>
      </Card>

      {dockerfileResults && (
        <Card>
          <CardHeader>
            <CardTitle>Dockerfile Scan Results</CardTitle>
            <CardDescription>
              <div className="flex items-center gap-4 mt-2">
                <Badge className={severityColors.critical}>
                  Critical: {dockerfileResults.criticalFindings || 0}
                </Badge>
                <Badge className={severityColors.high}>High: {dockerfileResults.highFindings || 0}</Badge>
                <Badge className={severityColors.medium}>Medium: {dockerfileResults.mediumFindings || 0}</Badge>
                <Badge className={severityColors.low}>Low: {dockerfileResults.lowFindings || 0}</Badge>
              </div>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[400px]">
              <div className="space-y-2">
                {dockerfileResults.findings?.map((f: any, idx: number) => (
                  <FindingCard
                    key={idx}
                    finding={{
                      id: f.id || `df-${idx}`,
                      title: f.title,
                      severity: f.severity,
                      description: f.description,
                      evidence: f.evidence,
                      recommendation: f.recommendation,
                      cisControl: f.cisControl,
                      cwe: f.cwe,
                      category: f.category,
                    }}
                  />
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Container className="h-5 w-5" />
            Kubernetes Manifest Scanner
          </CardTitle>
          <CardDescription>
            Analyze K8s manifests for privileged containers, network policy gaps, RBAC issues, and CIS Benchmark compliance
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="apiVersion: v1&#10;kind: Pod&#10;metadata:&#10;  name: myapp&#10;spec:&#10;  containers:&#10;    - name: web&#10;      image: nginx"
            className="min-h-[250px] font-mono text-sm"
            value={k8sManifest}
            onChange={(e) => setK8sManifest(e.target.value)}
            data-testid="input-k8s-manifest"
          />
          <Button onClick={handleScanK8sManifest} disabled={isLoading} data-testid="button-scan-k8s">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Shield className="h-4 w-4 mr-2" />}
            Scan Manifest
          </Button>
        </CardContent>
      </Card>

      {k8sResults && (
        <Card>
          <CardHeader>
            <CardTitle>Kubernetes Security Analysis</CardTitle>
            <CardDescription>
              <div className="flex items-center gap-4 mt-2">
                <Badge className={severityColors.critical}>
                  Critical: {k8sResults.summary?.criticalIssues || 0}
                </Badge>
                <Badge className={severityColors.high}>High: {k8sResults.summary?.highIssues || 0}</Badge>
                <Badge className={severityColors.medium}>Medium: {k8sResults.summary?.mediumIssues || 0}</Badge>
                <Badge className={severityColors.low}>Low: {k8sResults.summary?.lowIssues || 0}</Badge>
              </div>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[500px]">
              <div className="space-y-4">
                {k8sResults.containerFindings?.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2">Container Findings</h4>
                    <div className="space-y-2">
                      {k8sResults.containerFindings.map((f: any, idx: number) => (
                        <FindingCard
                          key={idx}
                          finding={{
                            id: f.id || `k8s-${idx}`,
                            title: f.title,
                            severity: f.severity,
                            description: f.description,
                            evidence: f.evidence,
                            recommendation: f.recommendation,
                            mitreAttackId: f.mitreAttackId,
                            cisControl: f.cisControl,
                            category: f.category,
                          }}
                        />
                      ))}
                    </div>
                  </div>
                )}

                {k8sResults.networkPolicyFindings?.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2">Network Policy Findings</h4>
                    <div className="space-y-2">
                      {k8sResults.networkPolicyFindings.map((f: any, idx: number) => (
                        <FindingCard
                          key={idx}
                          finding={{
                            id: f.id || `netpol-${idx}`,
                            title: f.title,
                            severity: f.severity,
                            description: f.description,
                            evidence: f.evidence,
                            recommendation: f.recommendation,
                            cisControl: f.cisControl,
                          }}
                        />
                      ))}
                    </div>
                  </div>
                )}

                {k8sResults.rbacFindings?.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2">RBAC Findings</h4>
                    <div className="space-y-2">
                      {k8sResults.rbacFindings.map((f: any, idx: number) => (
                        <FindingCard
                          key={idx}
                          finding={{
                            id: f.id || `rbac-${idx}`,
                            title: f.title,
                            severity: f.severity,
                            description: f.description,
                            evidence: f.evidence,
                            recommendation: f.recommendation,
                            mitreAttackId: f.mitreAttackId,
                            cisControl: f.cisControl,
                          }}
                        />
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function SecurityTesting() {
  const [adminPassword, setAdminPassword] = useState("");

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Testing</h1>
          <p className="text-muted-foreground">
            API fuzzing, authentication protocol testing, and container security analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor="admin-password" className="text-sm text-muted-foreground whitespace-nowrap">
            Admin Password:
          </Label>
          <Input
            id="admin-password"
            type="password"
            placeholder="Enter admin password"
            value={adminPassword}
            onChange={(e) => setAdminPassword(e.target.value)}
            className="w-48"
            data-testid="input-admin-password"
          />
        </div>
      </div>

      {!adminPassword && (
        <Card className="border-yellow-500/50 bg-yellow-500/5">
          <CardContent className="py-3">
            <div className="flex items-center gap-2 text-sm text-yellow-500">
              <AlertTriangle className="h-4 w-4" />
              <span>Enter your admin password above to use security testing features</span>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="api-fuzzing" className="space-y-6">
        <TabsList className="grid w-full grid-cols-3" data-testid="security-testing-tabs">
          <TabsTrigger value="api-fuzzing" data-testid="tab-api-fuzzing">
            <FileCode className="h-4 w-4 mr-2" />
            API Fuzzing
          </TabsTrigger>
          <TabsTrigger value="auth-testing" data-testid="tab-auth-testing">
            <Key className="h-4 w-4 mr-2" />
            Auth Testing
          </TabsTrigger>
          <TabsTrigger value="container-security" data-testid="tab-container-security">
            <Container className="h-4 w-4 mr-2" />
            Container Security
          </TabsTrigger>
        </TabsList>

        <TabsContent value="api-fuzzing">
          <ApiFuzzingTab adminPassword={adminPassword} />
        </TabsContent>

        <TabsContent value="auth-testing">
          <AuthTestingTab adminPassword={adminPassword} />
        </TabsContent>

        <TabsContent value="container-security">
          <ContainerSecurityTab adminPassword={adminPassword} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
