import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  ShieldAlert,
  Code,
  Target,
  Info,
  History,
  Filter,
  RefreshCw,
} from "lucide-react";
import { format } from "date-fns";
import type { HitlApprovalRequest } from "@shared/schema";

interface ApprovalDetailDialogProps {
  approval: HitlApprovalRequest | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onApprove: (approvalId: string) => void;
  onReject: (approvalId: string, reason: string) => void;
  isApproving: boolean;
  isRejecting: boolean;
}

function ApprovalDetailDialog({
  approval,
  open,
  onOpenChange,
  onApprove,
  onReject,
  isApproving,
  isRejecting,
}: ApprovalDetailDialogProps) {
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");

  if (!approval) return null;

  const riskLevelConfig = {
    critical: { color: "text-red-500", bgColor: "bg-red-500/10", label: "Critical Risk" },
    high: { color: "text-orange-500", bgColor: "bg-orange-500/10", label: "High Risk" },
    medium: { color: "text-yellow-500", bgColor: "bg-yellow-500/10", label: "Medium Risk" },
  };

  const config = riskLevelConfig[approval.riskLevel as keyof typeof riskLevelConfig] || riskLevelConfig.medium;

  const handleReject = () => {
    if (!rejectionReason.trim()) {
      return;
    }
    onReject(approval.id, rejectionReason);
    setRejectDialogOpen(false);
    setRejectionReason("");
  };

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Approval Request
            </DialogTitle>
            <DialogDescription>
              Review and approve or reject this high-risk operation
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6">
            {/* Risk Level Banner */}
            <Card className={`${config.bgColor} border-2 border-${approval.riskLevel}-500/30`}>
              <CardContent className="pt-6">
                <div className="flex items-center gap-3">
                  <AlertTriangle className={`h-6 w-6 ${config.color}`} />
                  <div className="flex-1">
                    <div className="font-semibold">{config.label}</div>
                    <div className="text-sm text-muted-foreground mt-1">
                      {approval.riskReason}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Operation Details */}
            <div className="space-y-4">
              <div>
                <div className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                  <Code className="h-4 w-4" />
                  Agent & Command
                </div>
                <div className="bg-muted/50 rounded-lg p-4 font-mono text-sm">
                  <div className="mb-2">
                    <span className="text-muted-foreground">Agent:</span>{" "}
                    <span className="font-semibold">{approval.agentName}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Command:</span>{" "}
                    <code className="bg-background px-2 py-1 rounded">{approval.command}</code>
                  </div>
                </div>
              </div>

              {approval.target && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    Target
                  </div>
                  <div className="bg-muted/50 rounded-lg p-3 font-mono text-sm">
                    {approval.target}
                  </div>
                </div>
              )}

              {/* Matched Policies */}
              {approval.matchedPolicies && approval.matchedPolicies.length > 0 && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-2 flex items-center gap-2">
                    <Info className="h-4 w-4" />
                    Matched Policies ({approval.matchedPolicies.length})
                  </div>
                  <div className="space-y-2">
                    {approval.matchedPolicies.map((policy, idx) => (
                      <Card key={idx}>
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between gap-2 mb-2">
                            <div className="font-medium text-sm">{policy.policyType}</div>
                            <Badge variant="outline">
                              {(policy.similarity * 100).toFixed(0)}% match
                            </Badge>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {policy.matchedContent}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}

              {/* Metadata */}
              {approval.metadata && Object.keys(approval.metadata).length > 0 && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-2">
                    Additional Information
                  </div>
                  <div className="bg-muted/50 rounded-lg p-3">
                    <pre className="text-xs overflow-auto">
                      {JSON.stringify(approval.metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground">Requested At</div>
                  <div className="font-medium">
                    {format(new Date(approval.requestedAt), "PPp")}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Expires At</div>
                  <div className="font-medium text-orange-500">
                    {format(new Date(approval.expiresAt), "PPp")}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => setRejectDialogOpen(true)}
              disabled={isApproving || isRejecting}
              className="gap-2"
            >
              <XCircle className="h-4 w-4" />
              Reject
            </Button>
            <Button
              onClick={() => onApprove(approval.id)}
              disabled={isApproving || isRejecting}
              className="gap-2 bg-emerald-600 hover:bg-emerald-700"
            >
              {isApproving ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )}
              Approve Operation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rejection Dialog */}
      <AlertDialog open={rejectDialogOpen} onOpenChange={setRejectDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Reject Approval Request</AlertDialogTitle>
            <AlertDialogDescription>
              Please provide a reason for rejecting this operation. This will be logged for audit purposes.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Textarea
            placeholder="Enter rejection reason..."
            value={rejectionReason}
            onChange={(e) => setRejectionReason(e.target.value)}
            className="min-h-[100px]"
          />
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setRejectionReason("")}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleReject}
              disabled={!rejectionReason.trim() || isRejecting}
              className="bg-red-600 hover:bg-red-700"
            >
              {isRejecting ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <XCircle className="h-4 w-4 mr-2" />
              )}
              Reject Request
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

export default function Approvals() {
  const { toast } = useToast();
  const [selectedApproval, setSelectedApproval] = useState<HitlApprovalRequest | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);

  // Fetch pending approvals
  const { data: pendingApprovals = [], isLoading, refetch } = useQuery<HitlApprovalRequest[]>({
    queryKey: ["/api/hitl/pending"],
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Approve mutation
  const approveMutation = useMutation({
    mutationFn: async (approvalId: string) => {
      const nonce = Math.random().toString(36).substring(7);
      return apiRequest("POST", `/api/hitl/${approvalId}/approve`, { nonce
      });
    },
    onSuccess: () => {
      toast({
        title: "Request Approved",
        description: "The operation has been approved and will proceed.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/hitl/pending"] });
      setDetailDialogOpen(false);
      setSelectedApproval(null);
    },
    onError: (error: any) => {
      toast({
        title: "Approval Failed",
        description: error.message || "Failed to approve the request",
        variant: "destructive",
      });
    },
  });

  // Reject mutation
  const rejectMutation = useMutation({
    mutationFn: async ({ approvalId, reason }: { approvalId: string; reason: string }) => {
      const nonce = Math.random().toString(36).substring(7);
      return apiRequest("POST", `/api/hitl/${approvalId}/reject`, { nonce, reason
      });
    },
    onSuccess: () => {
      toast({
        title: "Request Rejected",
        description: "The operation has been rejected.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/hitl/pending"] });
      setDetailDialogOpen(false);
      setSelectedApproval(null);
    },
    onError: (error: any) => {
      toast({
        title: "Rejection Failed",
        description: error.message || "Failed to reject the request",
        variant: "destructive",
      });
    },
  });

  const handleViewDetails = (approval: HitlApprovalRequest) => {
    setSelectedApproval(approval);
    setDetailDialogOpen(true);
  };

  const handleApprove = (approvalId: string) => {
    approveMutation.mutate(approvalId);
  };

  const handleReject = (approvalId: string, reason: string) => {
    rejectMutation.mutate({ approvalId, reason });
  };

  const getRiskBadge = (riskLevel: string) => {
    switch (riskLevel) {
      case "critical":
        return <Badge variant="destructive" className="gap-1"><AlertTriangle className="h-3 w-3" />Critical</Badge>;
      case "high":
        return <Badge className="bg-orange-500 hover:bg-orange-600 gap-1"><AlertTriangle className="h-3 w-3" />High</Badge>;
      case "medium":
        return <Badge className="bg-yellow-500 hover:bg-yellow-600 gap-1"><AlertTriangle className="h-3 w-3" />Medium</Badge>;
      default:
        return <Badge variant="outline">{riskLevel}</Badge>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "pending":
        return <Badge variant="outline" className="gap-1"><Clock className="h-3 w-3" />Pending</Badge>;
      case "approved":
        return <Badge className="bg-emerald-500 hover:bg-emerald-600 gap-1"><CheckCircle2 className="h-3 w-3" />Approved</Badge>;
      case "rejected":
        return <Badge variant="destructive" className="gap-1"><XCircle className="h-3 w-3" />Rejected</Badge>;
      case "expired":
        return <Badge variant="secondary" className="gap-1"><Clock className="h-3 w-3" />Expired</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <ShieldAlert className="h-8 w-8 text-primary" />
            Approval Requests
          </h1>
          <p className="text-muted-foreground mt-1">
            Review and approve high-risk security operations
          </p>
        </div>
        <Button onClick={() => refetch()} variant="outline" className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-yellow-500" />
              Pending Approvals
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {pendingApprovals.length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              Critical Risk
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {pendingApprovals.filter(a => a.riskLevel === "critical").length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              High Risk
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {pendingApprovals.filter(a => a.riskLevel === "high").length}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Approvals Table */}
      <Card>
        <CardHeader>
          <CardTitle>Pending Requests</CardTitle>
          <CardDescription>
            Review and take action on high-risk operations requiring approval
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : pendingApprovals.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <CheckCircle2 className="h-12 w-12 text-emerald-500 mb-3" />
              <h3 className="text-lg font-semibold">No Pending Approvals</h3>
              <p className="text-muted-foreground text-sm max-w-md mt-1">
                All high-risk operations have been reviewed. New requests will appear here automatically.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Risk</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Command</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Requested</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pendingApprovals.map((approval) => (
                  <TableRow key={approval.id} className="cursor-pointer hover:bg-muted/50">
                    <TableCell>{getRiskBadge(approval.riskLevel)}</TableCell>
                    <TableCell className="font-medium">{approval.agentName}</TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-2 py-1 rounded">
                        {approval.command.length > 40
                          ? approval.command.substring(0, 40) + "..."
                          : approval.command}
                      </code>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {approval.target || "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {format(new Date(approval.requestedAt), "MMM d, HH:mm")}
                    </TableCell>
                    <TableCell className="text-sm text-orange-500">
                      {format(new Date(approval.expiresAt), "MMM d, HH:mm")}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleViewDetails(approval)}
                      >
                        Review
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Approval Detail Dialog */}
      <ApprovalDetailDialog
        approval={selectedApproval}
        open={detailDialogOpen}
        onOpenChange={setDetailDialogOpen}
        onApprove={handleApprove}
        onReject={handleReject}
        isApproving={approveMutation.isPending}
        isRejecting={rejectMutation.isPending}
      />
    </div>
  );
}
