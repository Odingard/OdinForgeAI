import { useState, useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import {
  Download,
  Copy,
  Check,
  Monitor,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Shield,
  ExternalLink,
  FileCode,
  Apple,
  Terminal
} from "lucide-react";
import { FaLinux, FaWindows } from "react-icons/fa";
import type { AgentRelease, PlatformRelease } from "@shared/agent-releases";

interface DownloadCenterProps {
  serverUrl?: string;
  registrationToken?: string;
}

interface ReleaseData {
  release: AgentRelease;
  instructions: Record<string, { title: string; steps: string[] }>;
}

function detectOSSync(): { os: string; arch: string; platform: string } {
  const userAgent = navigator.userAgent.toLowerCase();
  const platformStr = navigator.platform?.toLowerCase() || "";
  
  let os = "linux";
  let arch = "amd64";
  
  if (userAgent.includes("win") || platformStr.includes("win")) {
    os = "windows";
  } else if (userAgent.includes("mac") || platformStr.includes("mac")) {
    os = "darwin";
    // Sync detection for ARM - check userAgent and platform
    if (userAgent.includes("arm") || userAgent.includes("aarch64")) {
      arch = "arm64";
    } else if (platformStr.includes("arm") || platformStr.includes("aarch64")) {
      arch = "arm64";
    }
  }
  
  // For Linux, try to detect ARM
  if (os === "linux" && (userAgent.includes("arm") || userAgent.includes("aarch64"))) {
    arch = "arm64";
  }

  return { os, arch, platform: `${os}-${arch}` };
}

async function detectOSAsync(): Promise<{ os: string; arch: string; platform: string }> {
  // Start with sync detection
  const syncResult = detectOSSync();
  
  // If macOS detected, try async methods for more accurate architecture detection
  if (syncResult.os === "darwin" && syncResult.arch === "amd64") {
    // Method 1: Try userAgentData.getHighEntropyValues (Chrome/Edge on Mac)
    try {
      const uaData = (navigator as any).userAgentData;
      if (uaData && typeof uaData.getHighEntropyValues === "function") {
        const hints = await uaData.getHighEntropyValues(["architecture", "bitness"]);
        if (hints.architecture) {
          const archLower = hints.architecture.toLowerCase();
          if (archLower === "arm" || archLower === "arm64" || archLower === "aarch64") {
            return { os: "darwin", arch: "arm64", platform: "darwin-arm64" };
          }
        }
      }
    } catch (e) {
      // userAgentData not available or blocked
    }
    
    // Method 2: Try WebGL renderer detection
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        const debugInfo = (gl as WebGLRenderingContext).getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          const renderer = (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          // Apple Silicon GPUs contain "Apple M" or "Apple GPU" in renderer string
          if (renderer && typeof renderer === "string") {
            if (renderer.includes("Apple M") || renderer.includes("Apple GPU")) {
              return { os: "darwin", arch: "arm64", platform: "darwin-arm64" };
            }
          }
        }
      }
    } catch (e) {
      // WebGL not available
    }
    
    // Method 3: Heuristic - Modern Macs with 5 touch points are likely Apple Silicon (iPad mode)
    // Combined with platform being MacIntel (legacy string)
    if (navigator.platform === "MacIntel" && navigator.maxTouchPoints === 5) {
      return { os: "darwin", arch: "arm64", platform: "darwin-arm64" };
    }
  }
  
  return syncResult;
}

function getPlatformIcon(os: string, className: string = "h-5 w-5") {
  switch (os) {
    case "darwin":
      return <Apple className={className} />;
    case "windows":
      return <FaWindows className={className} />;
    case "linux":
    default:
      return <FaLinux className={className} />;
  }
}

function getOSDisplayName(os: string): string {
  switch (os) {
    case "darwin":
      return "macOS";
    case "windows":
      return "Windows";
    case "linux":
    default:
      return "Linux";
  }
}

export function DownloadCenter({ serverUrl, registrationToken }: DownloadCenterProps) {
  const { toast } = useToast();
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showAllPlatforms, setShowAllPlatforms] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState<string | null>(null);
  const [detectedOS, setDetectedOS] = useState(() => detectOSSync());
  
  // Run async OS detection on mount for more accurate results
  useEffect(() => {
    detectOSAsync().then(result => {
      setDetectedOS(result);
    });
  }, []);
  
  const { data, isLoading, error } = useQuery<ReleaseData>({
    queryKey: ["/api/agent-releases/latest"],
  });

  // Find the recommended platform based on OS detection
  const recommendedPlatform = useMemo(() => {
    if (!data?.release.platforms) return null;
    return data.release.platforms.find(p => p.platform === detectedOS.platform) ||
           data.release.platforms.find(p => p.os === detectedOS.os) ||
           data.release.platforms[0];
  }, [data, detectedOS]);

  useEffect(() => {
    if (recommendedPlatform && !selectedPlatform) {
      setSelectedPlatform(recommendedPlatform.platform);
    }
  }, [recommendedPlatform, selectedPlatform]);

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      toast({
        title: "Copied to clipboard",
        description: "The value has been copied to your clipboard.",
      });
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Please copy the value manually.",
        variant: "destructive",
      });
    }
  };

  const getInstallCommand = (platform: PlatformRelease) => {
    const baseUrl = serverUrl || window.location.origin;
    const token = registrationToken || "YOUR_REGISTRATION_TOKEN";
    
    if (platform.os === "windows") {
      return `.\\${platform.filename} install \`\n  --server-url ${baseUrl} \`\n  --registration-token ${token}`;
    }
    return `sudo ./${platform.filename} install \\\n  --server-url ${baseUrl} \\\n  --registration-token ${token}`;
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Download Center
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Download Center
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            Unable to load release information. Please try again later.
          </div>
        </CardContent>
      </Card>
    );
  }

  const { release, instructions } = data;
  const currentPlatform = release.platforms.find(p => p.platform === selectedPlatform) || recommendedPlatform;

  return (
    <Card data-testid="download-center">
      <CardHeader>
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              Download OdinForge Agent
            </CardTitle>
            <CardDescription className="mt-1">
              Version {release.version} - Released {new Date(release.releaseDate).toLocaleDateString()}
            </CardDescription>
          </div>
          <Badge variant="outline" className="font-mono">
            v{release.version}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Platform Selection */}
        {currentPlatform && (
          <div className="bg-primary/5 border border-primary/20 rounded-lg p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 bg-primary/10 rounded-lg">
                {getPlatformIcon(currentPlatform.os, "h-8 w-8 text-primary")}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="font-semibold text-lg">
                    {currentPlatform.displayName}
                  </h3>
                  {currentPlatform.platform === detectedOS.platform && (
                    <Badge variant="secondary" className="text-xs">
                      <Monitor className="h-3 w-3 mr-1" />
                      Auto-detected
                    </Badge>
                  )}
                </div>
                
                {/* Quick Platform Selector */}
                <div className="flex items-center gap-2 mb-4 flex-wrap">
                  <span className="text-sm text-muted-foreground">Select your platform:</span>
                  {release.platforms.map((p) => (
                    <Button
                      key={p.platform}
                      variant={selectedPlatform === p.platform ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSelectedPlatform(p.platform)}
                      data-testid={`btn-select-${p.platform}`}
                    >
                      {getPlatformIcon(p.os, "h-4 w-4 mr-1")}
                      {p.os === "darwin" && p.arch === "arm64" ? "Apple Silicon" : 
                       p.os === "darwin" && p.arch === "amd64" ? "Intel" :
                       p.arch === "arm64" ? "ARM" : "x64"}
                    </Button>
                  ))}
                </div>

                <div className="flex items-center gap-3 flex-wrap">
                  <Button 
                    asChild 
                    size="lg"
                    data-testid="btn-download-selected"
                  >
                    <a 
                      href={currentPlatform.downloadUrl} 
                      download={currentPlatform.filename}
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download {currentPlatform.filename}
                    </a>
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    {currentPlatform.fileSize}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* All Platforms Section */}
        <div>
          <Button
            variant="ghost"
            onClick={() => setShowAllPlatforms(!showAllPlatforms)}
            className="w-full justify-between"
            data-testid="btn-toggle-platforms"
          >
            <span className="flex items-center gap-2">
              <FileCode className="h-4 w-4" />
              All Available Platforms ({release.platforms.length})
            </span>
            {showAllPlatforms ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </Button>

          {showAllPlatforms && (
            <div className="mt-4 border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Platform</TableHead>
                    <TableHead>File</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>SHA256 Checksum</TableHead>
                    <TableHead className="w-[100px]">Download</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {release.platforms.map((platform) => (
                    <TableRow 
                      key={platform.platform}
                      data-testid={`row-platform-${platform.platform}`}
                      className={selectedPlatform === platform.platform ? "bg-muted/50" : ""}
                    >
                      <TableCell>
                        <div 
                          className="flex items-center gap-2 cursor-pointer"
                          onClick={() => setSelectedPlatform(platform.platform)}
                        >
                          {getPlatformIcon(platform.os, "h-4 w-4")}
                          <span className="font-medium">{platform.displayName}</span>
                          {platform.platform === recommendedPlatform?.platform && (
                            <Badge variant="secondary" className="text-xs">
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                              Recommended
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs bg-muted px-2 py-1 rounded">
                          {platform.filename}
                        </code>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {platform.fileSize}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <code className="text-xs bg-muted px-2 py-1 rounded font-mono truncate max-w-[180px]" title={platform.sha256}>
                            {platform.sha256.substring(0, 16)}...
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => copyToClipboard(platform.sha256, `sha-${platform.platform}`)}
                            data-testid={`btn-copy-sha-${platform.platform}`}
                          >
                            {copiedId === `sha-${platform.platform}` ? (
                              <Check className="h-3 w-3 text-green-500" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Button 
                          variant="outline" 
                          size="sm" 
                          asChild
                          data-testid={`btn-download-${platform.platform}`}
                        >
                          <a href={platform.downloadUrl} download={platform.filename}>
                            <Download className="h-3 w-3" />
                          </a>
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>

        {/* Installation Instructions */}
        {currentPlatform && (
          <div className="border rounded-lg overflow-hidden">
            <Tabs value={selectedPlatform || ""} onValueChange={setSelectedPlatform}>
              <div className="border-b bg-muted/30 px-4">
                <TabsList className="bg-transparent h-auto p-0">
                  {release.platforms.map((platform) => (
                    <TabsTrigger
                      key={platform.platform}
                      value={platform.platform}
                      className="data-[state=active]:bg-background rounded-none border-b-2 border-transparent data-[state=active]:border-primary py-3"
                      data-testid={`tab-${platform.platform}`}
                    >
                      <span className="flex items-center gap-2">
                        {getPlatformIcon(platform.os, "h-4 w-4")}
                        {getOSDisplayName(platform.os)}
                        {platform.arch === "arm64" && <span className="text-xs">(ARM)</span>}
                      </span>
                    </TabsTrigger>
                  ))}
                </TabsList>
              </div>

              {release.platforms.map((platform) => (
                <TabsContent key={platform.platform} value={platform.platform} className="m-0">
                  <div className="p-4 space-y-4">
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                      <h4 className="font-medium">Quick Start Installation</h4>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(getInstallCommand(platform), `install-${platform.platform}`)}
                        data-testid={`btn-copy-install-${platform.platform}`}
                      >
                        {copiedId === `install-${platform.platform}` ? (
                          <>
                            <Check className="h-3 w-3 mr-2 text-green-500" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3 mr-2" />
                            Copy Command
                          </>
                        )}
                      </Button>
                    </div>

                    <ScrollArea className="h-auto max-h-64">
                      <pre className="bg-muted/50 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
                        {instructions[platform.platform]?.steps.join("\n") || getInstallCommand(platform)}
                      </pre>
                    </ScrollArea>

                    {/* Security Note */}
                    <div className="flex items-start gap-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                      <Shield className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
                      <div className="text-sm">
                        <p className="font-medium text-amber-600 dark:text-amber-400">Verify Checksum</p>
                        <p className="text-muted-foreground mt-1">
                          For security, always verify the SHA256 checksum before installation:
                        </p>
                        <code className="block mt-2 text-xs bg-muted px-2 py-1 rounded break-all">
                          {platform.sha256}
                        </code>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              ))}
            </Tabs>
          </div>
        )}

        {/* Release Notes Link */}
        <div className="flex items-center justify-between gap-4 pt-2 border-t">
          <p className="text-sm text-muted-foreground">
            {release.releaseNotes}
          </p>
          <Button variant="ghost" size="sm" asChild>
            <a 
              href={release.releaseUrl} 
              target="_blank" 
              rel="noopener noreferrer"
            >
              View Release Notes
              <ExternalLink className="h-3 w-3 ml-2" />
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
