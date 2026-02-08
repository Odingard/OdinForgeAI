import { useState } from "react";
import { formatDistanceToNow, formatDuration, intervalToDuration } from "date-fns";
import {
  useSessions,
  useSessionEvents,
  useSessionStats,
  useTerminateSession,
  useFlagSession,
  useExportSession,
  Session,
  SessionEvent,
} from "@/hooks/useSessions";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid } from "@/components/shared/MetricsGrid";
import { StatusTimeline, TimelineEvent } from "@/components/shared/StatusTimeline";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  UserCheck,
  Eye,
  Download,
  Flag,
  XCircle,
  Clock,
  Activity,
  AlertTriangle,
  Shield,
} from "lucide-react";

export default function Sessions() {
  const { toast } = useToast();
  const [selectedSession, setSelectedSession] = useState<Session | null>(null);
  const [flagDialogOpen, setFlagDialogOpen] = useState(false);
  const [flagReason, setFlagReason] = useState("");
  const [sessionToFlag, setSessionToFlag] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<"json" | "csv" | "pdf">("json");

  const { data: stats } = useSessionStats();
  const { data: sessions = [], isLoading } = useSessions();
  const { data: sessionEvents = [] } = useSessionEvents(selectedSession?.id || null);
  const terminateSession = useTerminateSession();
  const flagSession = useFlagSession();
  const exportSession = useExportSession();

  // Metrics
  const metrics = [
    {
      label: "Total Sessions",
      value: stats?.totalSessions || 0,
      icon: UserCheck,
      trend: undefined,
    },
    {
      label: "Suspicious Sessions",
      value: stats?.suspiciousSessions || 0,
      icon: AlertTriangle,
      variant: "warning" as const,
      trend: undefined,
    },
    {
      label: "Avg Duration",
      value: stats?.averageDuration
        ? `${Math.floor(stats.averageDuration / 60)}m`
        : "-",
      icon: Clock,
      trend: undefined,
    },
    {
      label: "Avg Risk Score",
      value: stats?.averageRiskScore?.toFixed(1) || "-",
      icon: Shield,
      variant: (stats?.averageRiskScore || 0) > 7 ? "danger" as const : undefined,
      trend: undefined,
    },
  ];

  // Table columns
  const columns: DataTableColumn<Session>[] = [
    {
      key: "username",
      header: "User",
      cell: (session) => (
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <span className="text-xs font-bold text-white">
              {session.username.charAt(0).toUpperCase()}
            </span>
          </div>
          <span className="font-medium">{session.username}</span>
        </div>
      ),
      sortable: true,
    },
    {
      key: "duration",
      header: "Duration",
      cell: (session) => {
        if (!session.duration) return <span className="text-sm text-muted-foreground">Active</span>;
        const duration = intervalToDuration({ start: 0, end: session.duration * 1000 });
        return (
          <span className="text-sm">
            {duration.hours ? `${duration.hours}h ` : ""}
            {duration.minutes ? `${duration.minutes}m ` : ""}
            {duration.seconds}s
          </span>
        );
      },
      sortable: true,
    },
    {
      key: "eventCount",
      header: "Events",
      cell: (session) => (
        <Badge variant="outline">
          <Activity className="h-3 w-3 mr-1" />
          {session.eventCount}
        </Badge>
      ),
      sortable: true,
    },
    {
      key: "riskScore",
      header: "Risk Score",
      cell: (session) => {
        const color = session.riskScore >= 8
          ? "text-red-500"
          : session.riskScore >= 5
          ? "text-orange-500"
          : "text-green-500";
        return <span className={`font-medium ${color}`}>{session.riskScore.toFixed(1)}</span>;
      },
      sortable: true,
    },
    {
      key: "riskLevel",
      header: "Risk Level",
      cell: (session) => {
        const variantMap = {
          low: "outline",
          medium: "secondary",
          high: "default",
          critical: "destructive",
        } as const;
        return <Badge variant={variantMap[session.riskLevel]}>{session.riskLevel}</Badge>;
      },
      sortable: true,
    },
    {
      key: "suspicious",
      header: "Status",
      cell: (session) => (
        session.suspicious ? (
          <Badge variant="destructive">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Suspicious
          </Badge>
        ) : (
          <Badge variant="outline">Normal</Badge>
        )
      ),
    },
    {
      key: "startTime",
      header: "Started",
      cell: (session) => (
        <span className="text-sm text-muted-foreground">
          {formatDistanceToNow(new Date(session.startTime), { addSuffix: true })}
        </span>
      ),
      sortable: true,
    },
  ];

  // Table actions
  const actions: DataTableAction<Session>[] = [
    {
      label: "View Details",
      icon: <Eye className="h-4 w-4" />,
      onClick: (session) => setSelectedSession(session),
      variant: "ghost",
    },
    {
      label: "Flag Session",
      icon: <Flag className="h-4 w-4" />,
      onClick: (session) => {
        setSessionToFlag(session.id);
        setFlagDialogOpen(true);
      },
      variant: "ghost",
    },
    {
      label: "Export",
      icon: <Download className="h-4 w-4" />,
      onClick: (session) => exportSession.mutate({ sessionId: session.id, format: exportFormat }),
      variant: "ghost",
      disabled: () => exportSession.isPending,
    },
    {
      label: "Terminate",
      icon: <XCircle className="h-4 w-4" />,
      onClick: (session) => terminateSession.mutate(session.id),
      variant: "ghost",
      hidden: (session) => !!session.endTime,
      disabled: () => terminateSession.isPending,
    },
  ];

  // Convert session events to timeline events
  const getEventTimeline = (events: SessionEvent[]): TimelineEvent[] => {
    return events.map(event => ({
      id: event.id,
      title: event.action,
      description: event.resource ? `${event.type} - ${event.resource}` : event.type,
      timestamp: event.timestamp,
      status: event.riskScore && event.riskScore > 7 ? "error" : "info",
      metadata: event.details,
    }));
  };

  const handleFlagSession = async () => {
    if (!sessionToFlag || !flagReason.trim()) {
      toast({
        title: "Missing Information",
        description: "Please enter a reason for flagging this session",
        variant: "destructive",
      });
      return;
    }

    await flagSession.mutateAsync({ sessionId: sessionToFlag, reason: flagReason });
    setFlagDialogOpen(false);
    setFlagReason("");
    setSessionToFlag(null);
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold" data-testid="text-page-title">
          Session Replay Viewer
        </h1>
        <p className="text-muted-foreground mt-1">
          Monitor and analyze user session activity
        </p>
      </div>

      {/* Metrics */}
      <MetricsGrid metrics={metrics} />

      {/* Export Format Selector */}
      <div className="flex items-center gap-4">
        <Label>Export Format:</Label>
        <Select value={exportFormat} onValueChange={(v) => setExportFormat(v as any)}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="json">JSON</SelectItem>
            <SelectItem value="csv">CSV</SelectItem>
            <SelectItem value="pdf">PDF</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Sessions Table */}
      <Card>
        <CardHeader>
          <CardTitle>Active & Recent Sessions</CardTitle>
          <CardDescription>
            User session activity with risk scoring and event tracking
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={sessions}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <UserCheck className="h-12 w-12" />,
              title: "No Sessions",
              description: "No user sessions to display",
            }}
            searchable={true}
            searchPlaceholder="Search sessions..."
            searchKeys={["username", "ipAddress"]}
            paginated={true}
            pageSize={20}
            data-testid="sessions-table"
          />
        </CardContent>
      </Card>

      {/* Session Details Dialog */}
      <Dialog open={!!selectedSession} onOpenChange={() => setSelectedSession(null)}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Session Details</DialogTitle>
            <DialogDescription>
              <code className="text-xs">{selectedSession?.id}</code>
            </DialogDescription>
          </DialogHeader>

          {selectedSession && (
            <div className="space-y-6">
              {/* Session Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">User:</span>{" "}
                  <span className="font-medium">{selectedSession.username}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Risk Score:</span>{" "}
                  <span className="font-medium">{selectedSession.riskScore.toFixed(1)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">IP Address:</span>{" "}
                  <span className="font-medium">{selectedSession.ipAddress || "Unknown"}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Location:</span>{" "}
                  <span className="font-medium">{selectedSession.location || "Unknown"}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">User Agent:</span>{" "}
                  <span className="text-xs">{selectedSession.userAgent || "Unknown"}</span>
                </div>
              </div>

              {/* Event Timeline */}
              <div>
                <h3 className="font-medium mb-4">Session Activity Timeline</h3>
                {sessionEvents.length > 0 ? (
                  <StatusTimeline events={getEventTimeline(sessionEvents)} />
                ) : (
                  <p className="text-sm text-muted-foreground">No events recorded</p>
                )}
              </div>

              {/* Actions */}
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setSessionToFlag(selectedSession.id);
                    setFlagDialogOpen(true);
                  }}
                >
                  <Flag className="h-4 w-4 mr-2" />
                  Flag Session
                </Button>
                <Button
                  variant="outline"
                  onClick={() => exportSession.mutate({ sessionId: selectedSession.id, format: exportFormat })}
                  disabled={exportSession.isPending}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </Button>
                {!selectedSession.endTime && (
                  <Button
                    variant="destructive"
                    onClick={() => {
                      terminateSession.mutate(selectedSession.id);
                      setSelectedSession(null);
                    }}
                    disabled={terminateSession.isPending}
                  >
                    <XCircle className="h-4 w-4 mr-2" />
                    Terminate
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Flag Session Dialog */}
      <Dialog open={flagDialogOpen} onOpenChange={setFlagDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Flag Session for Review</DialogTitle>
            <DialogDescription>
              Provide a reason for flagging this session
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Reason</Label>
              <Textarea
                placeholder="Describe why this session is suspicious..."
                value={flagReason}
                onChange={(e) => setFlagReason(e.target.value)}
                rows={4}
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setFlagDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleFlagSession} disabled={flagSession.isPending}>
              {flagSession.isPending ? "Flagging..." : "Flag Session"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
