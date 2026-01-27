import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Brain, 
  Shield, 
  Target, 
  Search, 
  GitBranch, 
  Building2, 
  Zap, 
  MessageSquare,
  Layers,
  ChevronDown,
  ChevronUp,
  Pause,
  Play,
  Trash2,
  Database
} from "lucide-react";

type ReasoningTraceAgentType = 
  | "policy_guardian"
  | "exploit_agent"
  | "critic_agent"
  | "recon_agent"
  | "lateral_agent"
  | "business_logic_agent"
  | "impact_agent"
  | "debate_module"
  | "orchestrator";

interface ReasoningTraceEntry {
  id: string;
  type: "reasoning_trace" | "shared_memory_update";
  evaluationId: string;
  agentType: ReasoningTraceAgentType;
  agentName: string;
  thought?: string;
  memoryKey?: string;
  summary?: string;
  context?: string;
  policiesChecked?: string[];
  decision?: "ALLOW" | "DENY" | "MODIFY" | "VERIFIED" | "DISPUTED" | "FALSE_POSITIVE";
  confidence?: number;
  timestamp: string;
}

interface ReasoningTracePanelProps {
  evaluationId: string;
  isLive?: boolean;
}

const AGENT_CONFIG: Record<ReasoningTraceAgentType, { 
  icon: typeof Brain; 
  color: string; 
  bgColor: string;
  label: string;
}> = {
  policy_guardian: { 
    icon: Shield, 
    color: "text-yellow-400", 
    bgColor: "bg-yellow-400/10",
    label: "PolicyGuardian" 
  },
  exploit_agent: { 
    icon: Target, 
    color: "text-red-400", 
    bgColor: "bg-red-400/10",
    label: "ExploitAgent" 
  },
  critic_agent: { 
    icon: MessageSquare, 
    color: "text-cyan-400", 
    bgColor: "bg-cyan-400/10",
    label: "CriticAgent" 
  },
  recon_agent: { 
    icon: Search, 
    color: "text-blue-400", 
    bgColor: "bg-blue-400/10",
    label: "ReconAgent" 
  },
  lateral_agent: { 
    icon: GitBranch, 
    color: "text-purple-400", 
    bgColor: "bg-purple-400/10",
    label: "LateralAgent" 
  },
  business_logic_agent: { 
    icon: Building2, 
    color: "text-orange-400", 
    bgColor: "bg-orange-400/10",
    label: "BusinessLogicAgent" 
  },
  impact_agent: { 
    icon: Zap, 
    color: "text-pink-400", 
    bgColor: "bg-pink-400/10",
    label: "ImpactAgent" 
  },
  debate_module: { 
    icon: Brain, 
    color: "text-emerald-400", 
    bgColor: "bg-emerald-400/10",
    label: "DebateModule" 
  },
  orchestrator: { 
    icon: Layers, 
    color: "text-gray-400", 
    bgColor: "bg-gray-400/10",
    label: "Orchestrator" 
  },
};

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString("en-US", { 
    hour12: false, 
    hour: "2-digit", 
    minute: "2-digit", 
    second: "2-digit",
    fractionalSecondDigits: 3
  });
}

function getDecisionBadge(decision: ReasoningTraceEntry["decision"]) {
  if (!decision) return null;
  
  const config: Record<string, { variant: "default" | "destructive" | "outline" | "secondary"; className: string }> = {
    ALLOW: { variant: "default", className: "bg-green-500/20 text-green-400 border-green-500/30" },
    DENY: { variant: "destructive", className: "bg-red-500/20 text-red-400 border-red-500/30" },
    MODIFY: { variant: "secondary", className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
    VERIFIED: { variant: "default", className: "bg-green-500/20 text-green-400 border-green-500/30" },
    DISPUTED: { variant: "secondary", className: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
    FALSE_POSITIVE: { variant: "destructive", className: "bg-red-500/20 text-red-400 border-red-500/30" },
  };
  
  const { variant, className } = config[decision] || { variant: "outline" as const, className: "" };
  
  return (
    <Badge variant={variant} className={`text-xs font-mono ${className}`}>
      {decision}
    </Badge>
  );
}

export function ReasoningTracePanel({ evaluationId, isLive = false }: ReasoningTracePanelProps) {
  const [entries, setEntries] = useState<ReasoningTraceEntry[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [isExpanded, setIsExpanded] = useState(true);
  const [isHovered, setIsHovered] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const entryIdCounter = useRef(0);

  const addEntry = useCallback((entry: Omit<ReasoningTraceEntry, "id">) => {
    if (isPaused) return;
    
    setEntries((prev) => {
      const newEntry = { ...entry, id: `entry-${entryIdCounter.current++}` };
      const updated = [...prev, newEntry];
      return updated.slice(-500);
    });
  }, [isPaused]);

  useEffect(() => {
    if (!isLive) return;
    
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "subscribe", channel: `evaluation:${evaluationId}` }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === "reasoning_trace" && data.evaluationId === evaluationId) {
          addEntry({
            type: "reasoning_trace",
            evaluationId: data.evaluationId,
            agentType: data.agentType,
            agentName: data.agentName,
            thought: data.thought,
            context: data.context,
            policiesChecked: data.policiesChecked,
            decision: data.decision,
            confidence: data.confidence,
            timestamp: data.timestamp,
          });
        }
        
        if (data.type === "shared_memory_update" && data.evaluationId === evaluationId) {
          addEntry({
            type: "shared_memory_update",
            evaluationId: data.evaluationId,
            agentType: data.agentType,
            agentName: data.agentName,
            memoryKey: data.memoryKey,
            summary: data.summary,
            timestamp: data.timestamp,
          });
        }
      } catch {
        // Ignore parse errors
      }
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "unsubscribe", channel: `evaluation:${evaluationId}` }));
      }
      ws.close();
    };
  }, [evaluationId, isLive, addEntry]);

  useEffect(() => {
    if (!isPaused && !isHovered && scrollRef.current) {
      const scrollContainer = scrollRef.current.querySelector("[data-radix-scroll-area-viewport]");
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight;
      }
    }
  }, [entries, isPaused, isHovered]);

  const handleClear = () => {
    setEntries([]);
    entryIdCounter.current = 0;
  };

  return (
    <Card className="bg-black/90 border-gray-800">
      <CardHeader className="py-3 px-4">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-cyan-400" />
            <CardTitle className="text-sm font-mono text-gray-200">
              Reasoning Trace
            </CardTitle>
            {isLive && (
              <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/30">
                LIVE
              </Badge>
            )}
            <Badge variant="outline" className="text-xs font-mono text-gray-400">
              {entries.length} entries
            </Badge>
          </div>
          <div className="flex items-center gap-1">
            <Button
              size="icon"
              variant="ghost"
              className="h-7 w-7"
              onClick={() => setIsPaused(!isPaused)}
              data-testid="button-toggle-pause"
            >
              {isPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="h-7 w-7"
              onClick={handleClear}
              data-testid="button-clear-trace"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="h-7 w-7"
              onClick={() => setIsExpanded(!isExpanded)}
              data-testid="button-toggle-expand"
            >
              {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="p-0">
          <ScrollArea 
            ref={scrollRef}
            className="h-80 font-mono text-xs"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
          >
            <div className="p-2 space-y-1">
              {entries.length === 0 ? (
                <div className="text-gray-500 text-center py-8">
                  {isLive ? "Waiting for agent reasoning..." : "No reasoning traces available"}
                </div>
              ) : (
                entries.map((entry) => {
                  const config = AGENT_CONFIG[entry.agentType] || AGENT_CONFIG.orchestrator;
                  const Icon = config.icon;
                  
                  return (
                    <div 
                      key={entry.id} 
                      className={`p-2 rounded ${config.bgColor} border border-transparent hover:border-gray-700 transition-colors`}
                      data-testid={`trace-entry-${entry.agentType}`}
                    >
                      <div className="flex items-start gap-2">
                        <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${config.color}`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`font-semibold ${config.color}`}>
                              {config.label}
                            </span>
                            <span className="text-gray-500">
                              {formatTimestamp(entry.timestamp)}
                            </span>
                            {entry.decision && getDecisionBadge(entry.decision)}
                            {entry.confidence !== undefined && (
                              <span className="text-gray-400">
                                ({Math.round(entry.confidence * 100)}% conf)
                              </span>
                            )}
                          </div>
                          
                          {entry.type === "reasoning_trace" && entry.thought && (
                            <p className="text-gray-300 mt-1 whitespace-pre-wrap break-words">
                              {entry.thought}
                            </p>
                          )}
                          
                          {entry.type === "shared_memory_update" && (
                            <div className="mt-1 flex items-start gap-1.5">
                              <Database className="h-3 w-3 mt-0.5 text-gray-500" />
                              <div>
                                <span className="text-gray-400">Memory Update: </span>
                                <span className="text-blue-400">{entry.memoryKey}</span>
                                {entry.summary && (
                                  <p className="text-gray-400 mt-0.5">{entry.summary}</p>
                                )}
                              </div>
                            </div>
                          )}
                          
                          {entry.policiesChecked && entry.policiesChecked.length > 0 && (
                            <div className="mt-1.5 flex flex-wrap gap-1">
                              {entry.policiesChecked.map((policy, i) => (
                                <Badge 
                                  key={i} 
                                  variant="outline" 
                                  className="text-[10px] bg-yellow-400/5 text-yellow-400/80 border-yellow-400/20"
                                >
                                  {policy}
                                </Badge>
                              ))}
                            </div>
                          )}
                          
                          {entry.context && (
                            <p className="text-gray-500 mt-1 text-[10px]">
                              Context: {entry.context}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </ScrollArea>
        </CardContent>
      )}
    </Card>
  );
}
