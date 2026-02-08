import { useQuery, useMutation } from "@tanstack/react-query";
import { Server, AlertTriangle, CheckCircle, Clock, Trash2, MoreVertical, Cloud, Monitor, Database, Info, CheckSquare, Square, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useState, useEffect, useRef } from "react";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import type { DiscoveredAsset } from "@shared/schema";

interface Evaluation {
  id: string;
  assetId: string;
  exposureType: string;
  priority: string;
  status: string;
  createdAt: string;
  exploitable?: boolean;
  score?: number;
}

interface UnifiedAsset {
  id: string;
  displayName: string;
  assetType: string;
  status: string;
  source: "discovered" | "evaluation";
  cloudProvider?: string;
  ipAddresses?: string[];
  hostname?: string;
  evaluationIds: string[];
  evaluationCount: number;
  exploitableCount: number;
  highestPriority: string;
  latestEvaluation: string;
  avgScore: number;
  exposureTypes: string[];
}

export default function Assets() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const [deleteAsset, setDeleteAsset] = useState<UnifiedAsset | null>(null);
  const [removeAsset, setRemoveAsset] = useState<UnifiedAsset | null>(null);
  const [deletingAssetId, setDeletingAssetId] = useState<string | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [showBulkConfirm, setShowBulkConfirm] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: discoveredAssets = [], isLoading: loadingAssets } = useQuery<DiscoveredAsset[]>({
    queryKey: ["/api/assets"],
  });

  // WebSocket listener for real-time asset updates
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'assets_updated') {
            // Auto-refresh assets when new ones are discovered
            queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
            queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
            
            if (data.newAssets > 0) {
              toast({
                title: "New assets discovered",
                description: `${data.newAssets} new asset(s) from ${data.provider?.toUpperCase() || 'cloud'} discovery`,
              });
            }
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
  }, [toast]);

  const { data: evaluations = [], isLoading: loadingEvals } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const isLoading = loadingAssets || loadingEvals;

  const deleteEvaluationMutation = useMutation({
    mutationFn: async (evaluationId: string) => {
      await apiRequest("DELETE", `/api/aev/evaluations/${evaluationId}`);
    },
  });

  const handleDeleteAsset = async (asset: UnifiedAsset) => {
    if (asset.evaluationCount === 0) {
      toast({
        title: "No evaluations to delete",
        description: "This asset has no associated evaluations.",
      });
      setDeleteAsset(null);
      return;
    }

    setDeletingAssetId(asset.id);
    let successCount = 0;
    let failCount = 0;
    
    try {
      for (const evalId of asset.evaluationIds) {
        try {
          await deleteEvaluationMutation.mutateAsync(evalId);
          successCount++;
        } catch {
          failCount++;
        }
      }
      
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      
      if (failCount === 0) {
        toast({
          title: "Evaluations deleted",
          description: `Successfully deleted ${successCount} evaluation(s) for "${asset.displayName}"`,
        });
      } else {
        toast({
          title: "Partial deletion",
          description: `Deleted ${successCount} of ${asset.evaluationCount} evaluation(s). ${failCount} failed.`,
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Delete failed",
        description: "Failed to delete asset evaluations. Please try again.",
        variant: "destructive",
      });
    } finally {
      setDeletingAssetId(null);
      setDeleteAsset(null);
    }
  };

  const deleteAssetMutation = useMutation({
    mutationFn: async (assetId: string) => {
      await apiRequest("DELETE", `/api/assets/${assetId}`);
    },
  });

  const handleRemoveAsset = async (asset: UnifiedAsset) => {
    setDeletingAssetId(asset.id);
    try {
      if (asset.evaluationCount > 0) {
        for (const evalId of asset.evaluationIds) {
          try {
            await deleteEvaluationMutation.mutateAsync(evalId);
          } catch {
          }
        }
      }

      if (asset.source === "discovered") {
        await deleteAssetMutation.mutateAsync(asset.id);
      }

      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });

      toast({
        title: "Asset removed",
        description: `Successfully removed "${asset.displayName}" and its evaluations.`,
      });
    } catch {
      toast({
        title: "Remove failed",
        description: "Failed to remove the asset. Please try again.",
        variant: "destructive",
      });
    } finally {
      setDeletingAssetId(null);
      setRemoveAsset(null);
    }
  };

  const toggleAssetSelection = (assetId: string) => {
    setSelectedAssets(prev => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  };

  const selectAllAssets = (assets: UnifiedAsset[]) => {
    if (selectedAssets.size === assets.length) {
      setSelectedAssets(new Set());
    } else {
      setSelectedAssets(new Set(assets.map(a => a.id)));
    }
  };

  const handleBulkDelete = async () => {
    if (selectedAssets.size === 0) return;
    setBulkDeleting(true);

    try {
      const selectedList = unifiedAssets.filter(a => selectedAssets.has(a.id));

      // Delete all evaluations for selected assets first
      const allEvalIds = selectedList.flatMap(a => a.evaluationIds);
      for (const evalId of allEvalIds) {
        try {
          await deleteEvaluationMutation.mutateAsync(evalId);
        } catch { /* continue */ }
      }

      // Bulk delete the discovered assets
      const discoveredIds = selectedList.filter(a => a.source === "discovered").map(a => a.id);
      if (discoveredIds.length > 0) {
        await apiRequest("POST", "/api/assets/bulk-delete", { assetIds: discoveredIds });
      }

      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });

      toast({
        title: "Assets removed",
        description: `Successfully removed ${selectedAssets.size} asset(s) and ${allEvalIds.length} evaluation(s).`,
      });
      setSelectedAssets(new Set());
    } catch {
      toast({
        title: "Bulk delete failed",
        description: "Some assets could not be removed. Please try again.",
        variant: "destructive",
      });
    } finally {
      setBulkDeleting(false);
      setShowBulkConfirm(false);
    }
  };

  const unifiedAssets: UnifiedAsset[] = (() => {
    const assetMap = new Map<string, UnifiedAsset>();
    
    discoveredAssets.forEach(asset => {
      const assetEvals = evaluations.filter(e => 
        e.assetId === asset.id || 
        e.assetId === asset.assetIdentifier ||
        e.assetId === asset.hostname ||
        (asset.ipAddresses && asset.ipAddresses.includes(e.assetId))
      );
      
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...assetEvals].sort((a, b) => 
        (priorityOrder[a.priority as keyof typeof priorityOrder] ?? 4) - 
        (priorityOrder[b.priority as keyof typeof priorityOrder] ?? 4)
      );
      
      const scores = assetEvals.filter(e => e.score !== undefined).map(e => e.score!);
      const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
      
      assetMap.set(asset.id, {
        id: asset.id,
        displayName: asset.displayName || asset.assetIdentifier || asset.hostname || asset.id,
        assetType: asset.assetType,
        status: asset.status || "active",
        source: "discovered",
        cloudProvider: asset.cloudProvider || undefined,
        ipAddresses: asset.ipAddresses || undefined,
        hostname: asset.hostname || undefined,
        evaluationIds: assetEvals.map(e => e.id),
        evaluationCount: assetEvals.length,
        exploitableCount: assetEvals.filter(e => e.exploitable).length,
        highestPriority: sorted[0]?.priority || "none",
        latestEvaluation: assetEvals.length > 0 
          ? assetEvals.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]?.createdAt 
          : "",
        avgScore,
        exposureTypes: Array.from(new Set(assetEvals.map(e => e.exposureType))),
      });
    });

    const matchedAssetIds = new Set<string>();
    discoveredAssets.forEach(asset => {
      evaluations.forEach(e => {
        if (e.assetId === asset.id || 
            e.assetId === asset.assetIdentifier ||
            e.assetId === asset.hostname ||
            (asset.ipAddresses && asset.ipAddresses.includes(e.assetId))) {
          matchedAssetIds.add(e.assetId);
        }
      });
    });

    const unmatchedEvals = evaluations.filter(e => !matchedAssetIds.has(e.assetId));
    const evalAssetMap = new Map<string, Evaluation[]>();
    
    unmatchedEvals.forEach(e => {
      const existing = evalAssetMap.get(e.assetId) || [];
      evalAssetMap.set(e.assetId, [...existing, e]);
    });

    evalAssetMap.forEach((evals, assetId) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...evals].sort((a, b) => 
        (priorityOrder[a.priority as keyof typeof priorityOrder] ?? 4) - 
        (priorityOrder[b.priority as keyof typeof priorityOrder] ?? 4)
      );
      
      const scores = evals.filter(e => e.score !== undefined).map(e => e.score!);
      const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
      
      assetMap.set(assetId, {
        id: assetId,
        displayName: assetId,
        assetType: "unknown",
        status: "evaluated",
        source: "evaluation",
        evaluationIds: evals.map(e => e.id),
        evaluationCount: evals.length,
        exploitableCount: evals.filter(e => e.exploitable).length,
        highestPriority: sorted[0]?.priority || "low",
        latestEvaluation: evals.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]?.createdAt || "",
        avgScore,
        exposureTypes: Array.from(new Set(evals.map(e => e.exposureType))),
      });
    });

    return Array.from(assetMap.values()).sort((a, b) => {
      if (b.exploitableCount !== a.exploitableCount) return b.exploitableCount - a.exploitableCount;
      return b.evaluationCount - a.evaluationCount;
    });
  })();

  const hasDiscoveredAssets = discoveredAssets.length > 0;
  const evaluationOnlyAssets = unifiedAssets.filter(a => a.source === "evaluation").length;

  const getPriorityBadge = (priority: string) => {
    const styles: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      none: "bg-muted text-muted-foreground border-muted-foreground/30",
    };
    return styles[priority] || styles.low;
  };

  const getAssetIcon = (asset: UnifiedAsset) => {
    if (asset.cloudProvider) {
      return <Cloud className="h-4 w-4 text-cyan-400" />;
    }
    if (asset.assetType === "database") {
      return <Database className="h-4 w-4 text-cyan-400" />;
    }
    if (asset.assetType === "server" || asset.assetType === "vm") {
      return <Monitor className="h-4 w-4 text-cyan-400" />;
    }
    return <Server className="h-4 w-4 text-cyan-400" />;
  };

  const canDelete = hasPermission("assets:delete");

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-muted rounded" />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-40 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="assets-page">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Assets</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Overview of all discovered and evaluated assets
        </p>
      </div>

      {!hasDiscoveredAssets && evaluationOnlyAssets > 0 && (
        <div className="flex items-center gap-2 p-3 bg-muted/50 border border-border rounded-md text-sm" data-testid="evaluation-only-notice">
          <Info className="h-4 w-4 text-muted-foreground flex-shrink-0" />
          <span className="text-muted-foreground">
            Showing {evaluationOnlyAssets} asset(s) from evaluations. Run cloud discovery or network scans to populate the full asset inventory.
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Assets</CardTitle>
            <Server className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-total-assets">
              {unifiedAssets.length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Discovered</CardTitle>
            <Cloud className="h-4 w-4 text-blue-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-discovered">
              {discoveredAssets.length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">At Risk</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-at-risk">
              {unifiedAssets.filter(a => a.exploitableCount > 0).length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Secure</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-secure">
              {unifiedAssets.filter(a => a.exploitableCount === 0 && a.evaluationCount > 0).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {canDelete && unifiedAssets.length > 0 && (
        <div className="flex items-center justify-between gap-4 p-3 bg-muted/30 border border-border rounded-md">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => selectAllAssets(unifiedAssets)}
              data-testid="select-all-assets"
            >
              {selectedAssets.size === unifiedAssets.length ? (
                <CheckSquare className="h-4 w-4 mr-2 text-cyan-400" />
              ) : (
                <Square className="h-4 w-4 mr-2" />
              )}
              {selectedAssets.size === unifiedAssets.length ? "Deselect All" : "Select All"}
            </Button>
            {selectedAssets.size > 0 && (
              <span className="text-sm text-muted-foreground">
                {selectedAssets.size} selected
              </span>
            )}
          </div>
          {selectedAssets.size > 0 && (
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedAssets(new Set())}
              >
                <XCircle className="h-4 w-4 mr-1" />
                Clear
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShowBulkConfirm(true)}
                disabled={bulkDeleting}
                data-testid="bulk-delete-assets"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete {selectedAssets.size} Asset{selectedAssets.size !== 1 ? "s" : ""}
              </Button>
            </div>
          )}
        </div>
      )}

      {unifiedAssets.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Server className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
            <p className="text-muted-foreground">No assets found</p>
            <p className="text-sm text-muted-foreground mt-1">
              Run cloud discovery, network scans, or evaluations to populate assets
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {unifiedAssets.map((asset) => (
            <Card 
              key={asset.id} 
              className={`hover-elevate ${deletingAssetId === asset.id ? "opacity-50" : ""}`} 
              data-testid={`asset-card-${asset.id}`}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    {canDelete && (
                      <button
                        onClick={(e) => { e.stopPropagation(); toggleAssetSelection(asset.id); }}
                        className="flex-shrink-0"
                        data-testid={`select-asset-${asset.id}`}
                      >
                        {selectedAssets.has(asset.id) ? (
                          <CheckSquare className="h-5 w-5 text-cyan-400" />
                        ) : (
                          <Square className="h-5 w-5 text-muted-foreground hover:text-foreground" />
                        )}
                      </button>
                    )}
                    <div className="p-2 rounded-lg bg-muted/50">
                      {getAssetIcon(asset)}
                    </div>
                    <div className="min-w-0">
                      <CardTitle className="text-sm font-medium truncate" title={asset.displayName}>
                        {asset.displayName}
                      </CardTitle>
                      {asset.source === "discovered" && (
                        <span className="text-xs text-muted-foreground">
                          {asset.assetType}{asset.cloudProvider ? ` \u00B7 ${asset.cloudProvider.toUpperCase()}` : ""}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {asset.evaluationCount > 0 && (
                      <Badge className={getPriorityBadge(asset.highestPriority)}>
                        {asset.highestPriority.toUpperCase()}
                      </Badge>
                    )}
                    {asset.source === "evaluation" && (
                      <Badge variant="outline" className="text-xs">
                        Eval Only
                      </Badge>
                    )}
                    {canDelete && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" data-testid={`asset-menu-${asset.id}`}>
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          {asset.evaluationCount > 0 && (
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onClick={() => setDeleteAsset(asset)}
                              data-testid={`delete-evals-${asset.id}`}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete Evaluations
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => setRemoveAsset(asset)}
                            data-testid={`delete-asset-${asset.id}`}
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Remove Asset
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Evaluations</span>
                  <span className="font-mono">{asset.evaluationCount}</span>
                </div>
                
                {asset.evaluationCount > 0 && (
                  <>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Exploitable</span>
                      <span className={`font-mono ${asset.exploitableCount > 0 ? "text-red-400" : "text-emerald-400"}`}>
                        {asset.exploitableCount}
                      </span>
                    </div>

                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-muted-foreground">Avg Risk Score</span>
                        <span className="font-mono">{asset.avgScore}</span>
                      </div>
                      <Progress value={asset.avgScore} className="h-1.5" />
                    </div>

                    {asset.exposureTypes.length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap">
                        {asset.exposureTypes.slice(0, 3).map((type) => (
                          <Badge key={type} variant="outline" className="text-xs">
                            {type.replace("_", " ")}
                          </Badge>
                        ))}
                        {asset.exposureTypes.length > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{asset.exposureTypes.length - 3}
                          </Badge>
                        )}
                      </div>
                    )}

                    {asset.latestEvaluation && (
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        <span>Last: {new Date(asset.latestEvaluation).toLocaleDateString()}</span>
                      </div>
                    )}
                  </>
                )}

                {asset.evaluationCount === 0 && (
                  <div className="text-xs text-muted-foreground text-center py-2">
                    No evaluations yet
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <AlertDialog open={!!deleteAsset} onOpenChange={() => setDeleteAsset(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Evaluations?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete all {deleteAsset?.evaluationCount} evaluation(s) 
              for asset "{deleteAsset?.displayName}". This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="cancel-delete-evals">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground"
              onClick={() => deleteAsset && handleDeleteAsset(deleteAsset)}
              data-testid="confirm-delete-evals"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={!!removeAsset} onOpenChange={() => setRemoveAsset(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Asset?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently remove "{removeAsset?.displayName}"
              {removeAsset && removeAsset.evaluationCount > 0
                ? ` and its ${removeAsset.evaluationCount} evaluation(s)`
                : ""
              }. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="cancel-remove-asset">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground"
              onClick={() => removeAsset && handleRemoveAsset(removeAsset)}
              data-testid="confirm-remove-asset"
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showBulkConfirm} onOpenChange={setShowBulkConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {selectedAssets.size} Asset{selectedAssets.size !== 1 ? "s" : ""}?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently remove {selectedAssets.size} asset(s) and all their associated evaluations. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleting} data-testid="cancel-bulk-delete">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground"
              onClick={handleBulkDelete}
              disabled={bulkDeleting}
              data-testid="confirm-bulk-delete"
            >
              {bulkDeleting ? "Deleting..." : "Delete All"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
