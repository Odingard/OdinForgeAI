import { useQuery, useMutation } from "@tanstack/react-query";
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

function chipClass(priority: string) {
  if (priority === "critical") return "f-chip f-chip-crit";
  if (priority === "high") return "f-chip f-chip-high";
  if (priority === "medium") return "f-chip f-chip-med";
  return "f-chip f-chip-low";
}

function assetTypeIcon(asset: UnifiedAsset) {
  if (asset.cloudProvider) return "☁";
  if (asset.assetType === "database") return "⛁";
  if (asset.assetType === "server" || asset.assetType === "vm") return "⊞";
  return "⬡";
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
            queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
            queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
            if (data.newAssets > 0) {
              toast({
                title: "New assets discovered",
                description: `${data.newAssets} new asset(s) from ${data.provider?.toUpperCase() || 'cloud'} discovery`,
              });
            }
          }
        } catch { /* ignore */ }
      };
      ws.onerror = () => {};
      ws.onclose = () => { wsRef.current = null; };
    } catch { /* WebSocket not available */ }
    return () => { if (wsRef.current) { wsRef.current.close(); wsRef.current = null; } };
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
      toast({ title: "No evaluations to delete", description: "This asset has no associated evaluations." });
      setDeleteAsset(null);
      return;
    }
    setDeletingAssetId(asset.id);
    let successCount = 0;
    let failCount = 0;
    try {
      for (const evalId of asset.evaluationIds) {
        try { await deleteEvaluationMutation.mutateAsync(evalId); successCount++; } catch { failCount++; }
      }
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      if (failCount === 0) {
        toast({ title: "Evaluations deleted", description: `Successfully deleted ${successCount} evaluation(s) for "${asset.displayName}"` });
      } else {
        toast({ title: "Partial deletion", description: `Deleted ${successCount} of ${asset.evaluationCount} evaluation(s). ${failCount} failed.`, variant: "destructive" });
      }
    } catch {
      toast({ title: "Delete failed", description: "Failed to delete asset evaluations. Please try again.", variant: "destructive" });
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
          try { await deleteEvaluationMutation.mutateAsync(evalId); } catch { /* continue */ }
        }
      }
      if (asset.source === "discovered") {
        await deleteAssetMutation.mutateAsync(asset.id);
      }
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({ title: "Asset removed", description: `Successfully removed "${asset.displayName}" and its evaluations.` });
    } catch {
      toast({ title: "Remove failed", description: "Failed to remove the asset. Please try again.", variant: "destructive" });
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
    if (selectedAssets.size === assets.length) setSelectedAssets(new Set());
    else setSelectedAssets(new Set(assets.map(a => a.id)));
  };

  const handleBulkDelete = async () => {
    if (selectedAssets.size === 0) return;
    setBulkDeleting(true);
    try {
      const selectedList = unifiedAssets.filter(a => selectedAssets.has(a.id));
      const allEvalIds = selectedList.flatMap(a => a.evaluationIds);
      for (const evalId of allEvalIds) {
        try { await deleteEvaluationMutation.mutateAsync(evalId); } catch { /* continue */ }
      }
      const discoveredIds = selectedList.filter(a => a.source === "discovered").map(a => a.id);
      if (discoveredIds.length > 0) {
        await apiRequest("POST", "/api/assets/bulk-delete", { assetIds: discoveredIds });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({ title: "Assets removed", description: `Successfully removed ${selectedAssets.size} asset(s) and ${allEvalIds.length} evaluation(s).` });
      setSelectedAssets(new Set());
    } catch {
      toast({ title: "Bulk delete failed", description: "Some assets could not be removed. Please try again.", variant: "destructive" });
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
  const canDelete = hasPermission("assets:delete");
  const atRiskCount = unifiedAssets.filter(a => a.exploitableCount > 0).length;
  const secureCount = unifiedAssets.filter(a => a.exploitableCount === 0 && a.evaluationCount > 0).length;

  const GRID_COLS = "1.5fr 100px 100px 100px 80px 80px 90px";

  if (isLoading) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ color: "var(--falcon-t3)", fontSize: 12 }}>Loading assets...</div>
      </div>
    );
  }

  return (
    <div data-testid="assets-page">
      {/* Page header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Assets</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            // discovered and evaluated asset inventory
          </p>
        </div>
        {canDelete && selectedAssets.size > 0 && (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ fontSize: 11, color: "var(--falcon-t3)" }}>{selectedAssets.size} selected</span>
            <button className="f-btn f-btn-ghost" onClick={() => setSelectedAssets(new Set())}>Clear</button>
            <button className="f-btn f-btn-primary" onClick={() => setShowBulkConfirm(true)} disabled={bulkDeleting}
              data-testid="bulk-delete-assets">
              Delete {selectedAssets.size}
            </button>
          </div>
        )}
      </div>

      {/* KPI strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot b" />Total Assets</div>
          <div className="f-kpi-val b" data-testid="stat-total-assets">{unifiedAssets.length}</div>
          <div className="f-kpi-foot">{discoveredAssets.length} discovered</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot" style={{ background: "var(--falcon-blue-hi)" }} />Discovered</div>
          <div className="f-kpi-val b" data-testid="stat-discovered">{discoveredAssets.length}</div>
          <div className="f-kpi-foot">{evaluationOnlyAssets > 0 ? `${evaluationOnlyAssets} eval-only` : "from cloud/network"}</div>
        </div>
        <div className={`f-kpi ${atRiskCount > 0 ? "hot" : ""}`}>
          <div className="f-kpi-lbl"><span className={`f-kpi-dot ${atRiskCount > 0 ? "r" : ""}`} />At Risk</div>
          <div className={`f-kpi-val ${atRiskCount > 0 ? "r" : ""}`} data-testid="stat-at-risk">{atRiskCount}</div>
          <div className="f-kpi-foot">
            {atRiskCount > 0 ? <span className="f-kpi-tag r">exploitable</span> : "no exploitable assets"}
          </div>
        </div>
        <div className={`f-kpi ${secureCount > 0 ? "ok" : ""}`}>
          <div className="f-kpi-lbl"><span className="f-kpi-dot g" />Secure</div>
          <div className="f-kpi-val g" data-testid="stat-secure">{secureCount}</div>
          <div className="f-kpi-foot">evaluated, no exploits</div>
        </div>
      </div>

      {!hasDiscoveredAssets && evaluationOnlyAssets > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", marginBottom: 16,
          background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)", borderRadius: 6, fontSize: 11, color: "var(--falcon-t3)" }}
          data-testid="evaluation-only-notice">
          Showing {evaluationOnlyAssets} asset(s) from evaluations. Run cloud discovery or network scans to populate the full asset inventory.
        </div>
      )}

      {/* Asset table */}
      <div className="f-panel" style={{ flex: 1, minHeight: 0 }}>
        <div className="f-panel-head">
          <div className="f-panel-title">
            <span className="f-panel-dot b" />
            Asset Inventory
          </div>
          {canDelete && unifiedAssets.length > 0 && (
            <span className="f-panel-link" onClick={() => selectAllAssets(unifiedAssets)} data-testid="select-all-assets">
              {selectedAssets.size === unifiedAssets.length ? "Deselect all" : "Select all"} →
            </span>
          )}
        </div>
        <div className="f-tbl" style={{ flex: 1 }}>
          <div className="f-tbl-head" style={{ gridTemplateColumns: GRID_COLS }}>
            <span className="f-th">Asset</span>
            <span className="f-th">Type</span>
            <span className="f-th">Priority</span>
            <span className="f-th">Evaluations</span>
            <span className="f-th">Exploits</span>
            <span className="f-th">Risk</span>
            <span className="f-th">Actions</span>
          </div>
          <div className="f-tbl-body">
            {unifiedAssets.length === 0 ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "40px 0" }}>
                <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>No assets found</span>
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", marginTop: 4 }}>Run cloud discovery, network scans, or evaluations to populate assets</span>
              </div>
            ) : (
              unifiedAssets.map((asset) => (
                <div
                  key={asset.id}
                  className="f-tbl-row"
                  style={{
                    gridTemplateColumns: GRID_COLS,
                    opacity: deletingAssetId === asset.id ? 0.4 : 1,
                    cursor: canDelete ? "pointer" : "default",
                    background: selectedAssets.has(asset.id) ? "rgba(59,130,246,0.06)" : undefined,
                  }}
                  onClick={canDelete ? () => toggleAssetSelection(asset.id) : undefined}
                  data-testid={`asset-card-${asset.id}`}
                >
                  {/* Asset name */}
                  <div>
                    <div className="f-td n" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 14 }}>{assetTypeIcon(asset)}</span>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={asset.displayName}>
                        {asset.displayName}
                      </span>
                    </div>
                    {asset.hostname && asset.hostname !== asset.displayName && (
                      <div className="f-td sub">{asset.hostname}</div>
                    )}
                  </div>

                  {/* Type */}
                  <div>
                    <span className="f-chip f-chip-gray">{asset.assetType.toUpperCase()}</span>
                    {asset.source === "evaluation" && (
                      <div style={{ marginTop: 2 }}><span className="f-chip f-chip-gray" style={{ fontSize: 8 }}>EVAL ONLY</span></div>
                    )}
                  </div>

                  {/* Priority */}
                  <div>
                    {asset.evaluationCount > 0 ? (
                      <span className={chipClass(asset.highestPriority)}>{asset.highestPriority.toUpperCase()}</span>
                    ) : (
                      <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>—</span>
                    )}
                  </div>

                  {/* Evaluations */}
                  <div className="f-td m">{asset.evaluationCount}</div>

                  {/* Exploits */}
                  <div className="f-td m" style={{
                    color: asset.exploitableCount > 0 ? "var(--falcon-red)" : "var(--falcon-green)",
                  }}>
                    {asset.exploitableCount}
                  </div>

                  {/* Risk score */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div className="f-tb-track">
                      <div
                        className={`f-tb-fill ${asset.avgScore >= 70 ? "f-tf-r" : asset.avgScore >= 40 ? "f-tf-o" : "f-tf-g"}`}
                        style={{ width: `${asset.avgScore}%` }}
                      />
                    </div>
                    <span className="f-td m" style={{ width: 24, textAlign: "right" }}>{asset.avgScore}</span>
                  </div>

                  {/* Actions */}
                  <div style={{ display: "flex", gap: 4 }} onClick={(e) => e.stopPropagation()}>
                    {canDelete && asset.evaluationCount > 0 && (
                      <button className="f-btn f-btn-ghost" style={{ fontSize: 10, padding: "2px 6px" }}
                        onClick={() => setDeleteAsset(asset)} data-testid={`delete-evals-${asset.id}`}>
                        Del Evals
                      </button>
                    )}
                    {canDelete && (
                      <button className="f-btn f-btn-ghost" style={{ fontSize: 10, padding: "2px 6px", color: "var(--falcon-red)" }}
                        onClick={() => setRemoveAsset(asset)} data-testid={`delete-asset-${asset.id}`}>
                        Remove
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Delete evaluations modal */}
      {deleteAsset && (
        <div className="f-modal-overlay" onClick={() => setDeleteAsset(null)}>
          <div className="f-modal" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <h2 className="f-modal-title">Delete Evaluations?</h2>
              <p className="f-modal-desc">
                This will permanently delete all {deleteAsset.evaluationCount} evaluation(s)
                for asset "{deleteAsset.displayName}". This action cannot be undone.
              </p>
            </div>
            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => setDeleteAsset(null)} data-testid="cancel-delete-evals">Cancel</button>
              <button className="f-btn f-btn-primary" onClick={() => handleDeleteAsset(deleteAsset)} data-testid="confirm-delete-evals">Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Remove asset modal */}
      {removeAsset && (
        <div className="f-modal-overlay" onClick={() => setRemoveAsset(null)}>
          <div className="f-modal" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <h2 className="f-modal-title">Remove Asset?</h2>
              <p className="f-modal-desc">
                This will permanently remove "{removeAsset.displayName}"
                {removeAsset.evaluationCount > 0
                  ? ` and its ${removeAsset.evaluationCount} evaluation(s)`
                  : ""
                }. This action cannot be undone.
              </p>
            </div>
            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => setRemoveAsset(null)} data-testid="cancel-remove-asset">Cancel</button>
              <button className="f-btn f-btn-primary" onClick={() => handleRemoveAsset(removeAsset)} data-testid="confirm-remove-asset">Remove</button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk delete modal */}
      {showBulkConfirm && (
        <div className="f-modal-overlay" onClick={() => !bulkDeleting && setShowBulkConfirm(false)}>
          <div className="f-modal" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <h2 className="f-modal-title">Delete {selectedAssets.size} Asset{selectedAssets.size !== 1 ? "s" : ""}?</h2>
              <p className="f-modal-desc">
                This will permanently remove {selectedAssets.size} asset(s) and all their associated evaluations. This action cannot be undone.
              </p>
            </div>
            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => setShowBulkConfirm(false)} disabled={bulkDeleting} data-testid="cancel-bulk-delete">Cancel</button>
              <button className="f-btn f-btn-primary" onClick={handleBulkDelete} disabled={bulkDeleting} data-testid="confirm-bulk-delete">
                {bulkDeleting ? "Deleting..." : "Delete All"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
