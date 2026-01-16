import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bell, Check, CheckCheck, Clock, AlertTriangle, Shield, Bot, Globe, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatDistanceToNow } from "date-fns";

interface NotificationItem {
  id: string;
  type: "evaluation" | "scan" | "agent" | "alert";
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
  severity?: "info" | "warning" | "critical";
}

export function NotificationsPopover() {
  const [open, setOpen] = useState(false);
  const [readIds, setReadIds] = useState<Set<string>>(() => {
    const stored = localStorage.getItem("odinforge_read_notifications");
    return stored ? new Set(JSON.parse(stored)) : new Set();
  });

  const { data: evaluations = [] } = useQuery<any[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const { data: agents = [] } = useQuery<any[]>({
    queryKey: ["/api/agents"],
  });

  const notifications: NotificationItem[] = [];

  evaluations.slice(0, 5).forEach((evaluation: any) => {
    const id = `eval-${evaluation.id}`;
    notifications.push({
      id,
      type: "evaluation",
      title: evaluation.status === "completed" 
        ? `Evaluation ${evaluation.exploitable ? "Found Exploitable" : "Completed Safe"}`
        : `Evaluation ${evaluation.status}`,
      message: `${evaluation.assetId}: ${evaluation.exposureType || "Security scan"}`,
      timestamp: new Date(evaluation.createdAt || Date.now()),
      read: readIds.has(id),
      severity: evaluation.exploitable ? "critical" : "info",
    });
  });

  agents.slice(0, 3).forEach((agent: any) => {
    if (agent.status === "offline" || agent.status === "stale") {
      const id = `agent-${agent.id}`;
      notifications.push({
        id,
        type: "agent",
        title: `Agent ${agent.status === "offline" ? "Offline" : "Stale"}`,
        message: `${agent.hostname || agent.name}: Last seen ${agent.lastHeartbeat ? formatDistanceToNow(new Date(agent.lastHeartbeat), { addSuffix: true }) : "unknown"}`,
        timestamp: new Date(agent.lastHeartbeat || agent.registeredAt || Date.now()),
        read: readIds.has(id),
        severity: "warning",
      });
    }
  });

  notifications.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  const unreadCount = notifications.filter(n => !n.read).length;

  useEffect(() => {
    localStorage.setItem("odinforge_read_notifications", JSON.stringify(Array.from(readIds)));
  }, [readIds]);

  const markAsRead = (id: string) => {
    setReadIds(prev => {
      const newSet = new Set(Array.from(prev));
      newSet.add(id);
      return newSet;
    });
  };

  const markAllAsRead = () => {
    const allIds = notifications.map(n => n.id);
    setReadIds(prev => {
      const newSet = new Set(Array.from(prev));
      allIds.forEach(id => newSet.add(id));
      return newSet;
    });
  };

  const getIcon = (type: string, severity?: string) => {
    switch (type) {
      case "evaluation":
        return severity === "critical" 
          ? <AlertTriangle className="h-4 w-4 text-destructive" />
          : <Shield className="h-4 w-4 text-emerald-400" />;
      case "agent":
        return <Bot className="h-4 w-4 text-amber-400" />;
      case "scan":
        return <Globe className="h-4 w-4 text-cyan-400" />;
      default:
        return <Bell className="h-4 w-4 text-muted-foreground" />;
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button 
          variant="ghost" 
          size="icon" 
          className="relative" 
          data-testid="button-notifications"
        >
          <Bell className="h-4 w-4" />
          {unreadCount > 0 && (
            <span className="absolute top-1.5 right-1.5 h-2 w-2 bg-red-500 rounded-full" />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="end">
        <div className="flex items-center justify-between p-3 border-b">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-semibold">Notifications</h4>
            {unreadCount > 0 && (
              <Badge variant="secondary" className="text-xs">
                {unreadCount} new
              </Badge>
            )}
          </div>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={markAllAsRead}
              data-testid="button-mark-all-read"
            >
              <CheckCheck className="h-3 w-3 mr-1" />
              Mark all read
            </Button>
          )}
        </div>

        <ScrollArea className="h-[300px]">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[200px] text-muted-foreground">
              <Bell className="h-8 w-8 mb-2 opacity-50" />
              <p className="text-sm">No notifications</p>
            </div>
          ) : (
            <div className="divide-y">
              {notifications.map((notification) => (
                <div
                  key={notification.id}
                  className={`p-3 hover-elevate cursor-pointer transition-colors ${
                    notification.read ? "opacity-60" : "bg-accent/30"
                  }`}
                  onClick={() => markAsRead(notification.id)}
                  data-testid={`notification-${notification.id}`}
                >
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">
                      {getIcon(notification.type, notification.severity)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium truncate">
                          {notification.title}
                        </p>
                        {!notification.read && (
                          <span className="h-2 w-2 bg-cyan-500 rounded-full flex-shrink-0" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        {notification.message}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
                      </p>
                    </div>
                    {!notification.read && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 flex-shrink-0"
                        onClick={(e) => {
                          e.stopPropagation();
                          markAsRead(notification.id);
                        }}
                        data-testid={`mark-read-${notification.id}`}
                      >
                        <Check className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>

        {notifications.length > 0 && (
          <div className="p-2 border-t">
            <Button
              variant="ghost"
              size="sm"
              className="w-full text-xs text-muted-foreground"
              onClick={() => setOpen(false)}
              data-testid="button-close-notifications"
            >
              Close
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
