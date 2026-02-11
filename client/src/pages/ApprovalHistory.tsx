import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { apiRequest } from "@/lib/queryClient";
import {
  History,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Download,
  Filter,
  Search,
  Calendar,
  User,
  FileText,
} from "lucide-react";
import type { HitlApprovalRequest } from "@shared/schema";
import { formatDTG } from "@/lib/utils";

type ApprovalHistoryItem = HitlApprovalRequest;

export default function ApprovalHistory() {
  const [selectedApproval, setSelectedApproval] = useState<ApprovalHistoryItem | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [filters, setFilters] = useState({
    status: "all",
    riskLevel: "all",
    searchQuery: "",
    dateFrom: "",
    dateTo: "",
  });

  // Mock data - in production, fetch from API
  const mockHistory: ApprovalHistoryItem[] = [
    {
      id: "hitl-1",
      evaluationId: "eval-123",
      executionId: "exec-456",
      organizationId: "default",
      agentName: "ExploitAgent",
      command: "rm -rf /tmp/test",
      target: "192.168.1.100",
      riskLevel: "critical",
      riskReason: "Forbidden pattern detected: rm -rf",
      matchedPolicies: [],
      status: "approved",
      requestedAt: new Date(Date.now() - 1000 * 60 * 60 * 2), // 2 hours ago
      expiresAt: new Date(Date.now() - 1000 * 60 * 60 * 1.9),
      respondedAt: new Date(Date.now() - 1000 * 60 * 60 * 1.95),
      respondedBy: "admin@company.com",
      responseSignature: "sig-123",
      responseNonce: "nonce-123",
      metadata: null,
      rejectionReason: null,
    },
    {
      id: "hitl-2",
      evaluationId: "eval-124",
      executionId: "exec-457",
      organizationId: "default",
      agentName: "LateralMovementAgent",
      command: "ssh root@production-db",
      target: "production-db.internal",
      riskLevel: "high",
      riskReason: "Accessing production database server",
      matchedPolicies: [],
      status: "rejected",
      requestedAt: new Date(Date.now() - 1000 * 60 * 60 * 5), // 5 hours ago
      expiresAt: new Date(Date.now() - 1000 * 60 * 60 * 4.9),
      respondedAt: new Date(Date.now() - 1000 * 60 * 60 * 4.95),
      respondedBy: "security@company.com",
      responseSignature: "sig-124",
      responseNonce: "nonce-124",
      metadata: null,
      rejectionReason: "Production database access not authorized for this evaluation",
    },
    {
      id: "hitl-3",
      evaluationId: "eval-125",
      executionId: "exec-458",
      organizationId: "default",
      agentName: "ReconAgent",
      command: "nmap -sS -p- 10.0.0.0/8",
      target: "10.0.0.0/8",
      riskLevel: "medium",
      riskReason: "Large network range scan",
      matchedPolicies: [],
      status: "expired",
      requestedAt: new Date(Date.now() - 1000 * 60 * 60 * 24), // 1 day ago
      expiresAt: new Date(Date.now() - 1000 * 60 * 60 * 23.9),
      respondedAt: null,
      respondedBy: null,
      metadata: null,
      responseSignature: null,
      responseNonce: null,
      rejectionReason: null,
    },
  ];

  const filteredHistory = mockHistory.filter(item => {
    if (filters.status !== "all" && item.status !== filters.status) return false;
    if (filters.riskLevel !== "all" && item.riskLevel !== filters.riskLevel) return false;
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      return (
        item.command.toLowerCase().includes(query) ||
        item.agentName.toLowerCase().includes(query) ||
        item.riskReason.toLowerCase().includes(query) ||
        (item.target && item.target.toLowerCase().includes(query))
      );
    }
    return true;
  });

  const stats = {
    total: mockHistory.length,
    approved: mockHistory.filter(h => h.status === "approved").length,
    rejected: mockHistory.filter(h => h.status === "rejected").length,
    expired: mockHistory.filter(h => h.status === "expired").length,
    avgResponseTime: "2.5 min",
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
      case "approved":
        return <Badge className="bg-emerald-500 hover:bg-emerald-600 gap-1"><CheckCircle2 className="h-3 w-3" />Approved</Badge>;
      case "rejected":
        return <Badge variant="destructive" className="gap-1"><XCircle className="h-3 w-3" />Rejected</Badge>;
      case "expired":
        return <Badge variant="secondary" className="gap-1"><Clock className="h-3 w-3" />Expired</Badge>;
      case "pending":
        return <Badge variant="outline" className="gap-1"><Clock className="h-3 w-3" />Pending</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const handleViewDetails = (approval: ApprovalHistoryItem) => {
    setSelectedApproval(approval);
    setDetailDialogOpen(true);
  };

  const handleExportCSV = () => {
    const csv = [
      ["ID", "Agent", "Command", "Target", "Risk Level", "Status", "Requested At", "Responded By", "Responded At", "Rejection Reason"].join(","),
      ...filteredHistory.map(item => [
        item.id,
        item.agentName,
        `"${item.command.replace(/"/g, '""')}"`,
        item.target || "",
        item.riskLevel,
        item.status,
        formatDTG(item.requestedAt),
        item.respondedBy || "",
        item.respondedAt ? formatDTG(item.respondedAt) : "",
        item.rejectionReason ? `"${item.rejectionReason.replace(/"/g, '""')}"` : "",
      ].join(","))
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `approval-history-${formatDTG(new Date())}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <History className="h-8 w-8 text-primary" />
            Approval History
          </h1>
          <p className="text-muted-foreground mt-1">
            Complete audit trail of all approval decisions
          </p>
        </div>
        <Button onClick={handleExportCSV} variant="outline" className="gap-2">
          <Download className="h-4 w-4" />
          Export CSV
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-500" />
              Total Requests
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              Approved
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats.approved}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {((stats.approved / stats.total) * 100).toFixed(0)}% approval rate
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              Rejected
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats.rejected}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {((stats.rejected / stats.total) * 100).toFixed(0)}% rejection rate
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Clock className="h-4 w-4 text-gray-500" />
              Expired
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats.expired}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Calendar className="h-4 w-4 text-purple-500" />
              Avg Response
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats.avgResponseTime}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-4 w-4" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Search</label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search command, agent, target..."
                  value={filters.searchQuery}
                  onChange={(e) => setFilters({ ...filters, searchQuery: e.target.value })}
                  className="pl-8"
                />
              </div>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Status</label>
              <Select
                value={filters.status}
                onValueChange={(value) => setFilters({ ...filters, status: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="rejected">Rejected</SelectItem>
                  <SelectItem value="expired">Expired</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Risk Level</label>
              <Select
                value={filters.riskLevel}
                onValueChange={(value) => setFilters({ ...filters, riskLevel: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end">
              <Button
                variant="outline"
                onClick={() => setFilters({
                  status: "all",
                  riskLevel: "all",
                  searchQuery: "",
                  dateFrom: "",
                  dateTo: "",
                })}
                className="w-full"
              >
                Clear Filters
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* History Table */}
      <Card>
        <CardHeader>
          <CardTitle>Approval Records</CardTitle>
          <CardDescription>
            Showing {filteredHistory.length} of {mockHistory.length} records
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Risk</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Command</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Requested</TableHead>
                <TableHead>Responded By</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredHistory.map((item) => (
                <TableRow key={item.id} className="cursor-pointer hover:bg-muted/50">
                  <TableCell>{getRiskBadge(item.riskLevel)}</TableCell>
                  <TableCell>{getStatusBadge(item.status)}</TableCell>
                  <TableCell className="font-medium">{item.agentName}</TableCell>
                  <TableCell>
                    <code className="text-xs bg-muted px-2 py-1 rounded">
                      {item.command.length > 40
                        ? item.command.substring(0, 40) + "..."
                        : item.command}
                    </code>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {item.target || "—"}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground font-mono">
                    {formatDTG(item.requestedAt)}
                  </TableCell>
                  <TableCell className="text-sm">
                    {item.respondedBy ? (
                      <div className="flex items-center gap-1">
                        <User className="h-3 w-3 text-muted-foreground" />
                        {item.respondedBy.split("@")[0]}
                      </div>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleViewDetails(item)}
                    >
                      Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Detail Dialog */}
      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Approval Detail
            </DialogTitle>
            <DialogDescription>
              Complete information for approval request {selectedApproval?.id}
            </DialogDescription>
          </DialogHeader>

          {selectedApproval && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Status</div>
                  <div className="mt-1">{getStatusBadge(selectedApproval.status)}</div>
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Risk Level</div>
                  <div className="mt-1">{getRiskBadge(selectedApproval.riskLevel)}</div>
                </div>
              </div>

              <div>
                <div className="text-sm font-medium text-muted-foreground">Agent</div>
                <div className="mt-1 font-medium">{selectedApproval.agentName}</div>
              </div>

              <div>
                <div className="text-sm font-medium text-muted-foreground">Command</div>
                <div className="mt-1 bg-muted rounded-lg p-3 font-mono text-sm">
                  {selectedApproval.command}
                </div>
              </div>

              {selectedApproval.target && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Target</div>
                  <div className="mt-1 font-mono text-sm">{selectedApproval.target}</div>
                </div>
              )}

              <div>
                <div className="text-sm font-medium text-muted-foreground">Risk Reason</div>
                <div className="mt-1">{selectedApproval.riskReason}</div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Requested At</div>
                  <div className="mt-1 text-sm font-mono">
                    {formatDTG(selectedApproval.requestedAt)}
                  </div>
                </div>
                {selectedApproval.respondedAt && (
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">Responded At</div>
                    <div className="mt-1 text-sm font-mono">
                      {formatDTG(selectedApproval.respondedAt)}
                    </div>
                  </div>
                )}
              </div>

              {selectedApproval.respondedBy && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Responded By</div>
                  <div className="mt-1">{selectedApproval.respondedBy}</div>
                </div>
              )}

              {selectedApproval.rejectionReason && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Rejection Reason</div>
                  <div className="mt-1 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900 rounded-lg p-3">
                    {selectedApproval.rejectionReason}
                  </div>
                </div>
              )}

              {selectedApproval.responseSignature && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Signature (Non-repudiation)</div>
                  <div className="mt-1 font-mono text-xs bg-muted p-2 rounded break-all">
                    {selectedApproval.responseSignature}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
