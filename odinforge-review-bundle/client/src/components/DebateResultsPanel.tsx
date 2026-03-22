import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle, XCircle, MessageSquare, ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import type { DebateSummary, DebateChainResult } from "@shared/schema";

export type { DebateSummary, DebateChainResult } from "@shared/schema";

interface DebateResultsPanelProps {
  debateSummary: DebateSummary;
  showTitle?: boolean;
}

export function DebateResultsPanel({ debateSummary, showTitle = true }: DebateResultsPanelProps) {
  const [expandedChains, setExpandedChains] = useState<Set<string>>(new Set());

  const toggleChain = (name: string) => {
    const newExpanded = new Set(expandedChains);
    if (newExpanded.has(name)) {
      newExpanded.delete(name);
    } else {
      newExpanded.add(name);
    }
    setExpandedChains(newExpanded);
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "verified":
        return <Badge variant="default" className="bg-green-500/20 text-green-400 border-green-500/30" data-testid="badge-verdict-verified"><CheckCircle className="w-3 h-3 mr-1" /> Verified</Badge>;
      case "disputed":
        return <Badge variant="default" className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30" data-testid="badge-verdict-disputed"><AlertTriangle className="w-3 h-3 mr-1" /> Disputed</Badge>;
      case "false_positive":
        return <Badge variant="default" className="bg-red-500/20 text-red-400 border-red-500/30" data-testid="badge-verdict-false-positive"><XCircle className="w-3 h-3 mr-1" /> False Positive</Badge>;
      case "rejected":
        return <Badge variant="outline" className="text-red-400 border-red-500/30" data-testid="badge-status-rejected"><XCircle className="w-3 h-3 mr-1" /> Rejected</Badge>;
      default:
        return <Badge variant="secondary">{verdict}</Badge>;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "verified":
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case "disputed":
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case "rejected":
        return <XCircle className="w-4 h-4 text-red-400" />;
      default:
        return null;
    }
  };

  const verifiedCount = debateSummary.verifiedChains.filter(c => c.verificationStatus === "verified").length;
  const disputedCount = debateSummary.verifiedChains.filter(c => c.verificationStatus === "disputed").length;
  const rejectedCount = debateSummary.verifiedChains.filter(c => c.verificationStatus === "rejected").length;

  return (
    <div className="space-y-4" data-testid="panel-debate-results">
      {showTitle && (
        <div className="flex items-center gap-2">
          <MessageSquare className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold">AI Debate Module Results</h3>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-muted/50 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Final Verdict</div>
          {getVerdictBadge(debateSummary.finalVerdict)}
        </div>
        <div className="bg-muted/50 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Consensus</div>
          <Badge variant={debateSummary.consensusReached ? "default" : "secondary"} className={debateSummary.consensusReached ? "bg-green-500/20 text-green-400" : ""}>
            {debateSummary.consensusReached ? "Reached" : "Not Reached"}
          </Badge>
        </div>
        <div className="bg-muted/50 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Adjusted Confidence</div>
          <div className="text-lg font-mono font-semibold" data-testid="text-adjusted-confidence">{(debateSummary.adjustedConfidence * 100).toFixed(0)}%</div>
        </div>
        <div className="bg-muted/50 rounded-lg p-3">
          <div className="text-xs text-muted-foreground mb-1">Critic Model</div>
          <div className="text-sm font-mono truncate" title={debateSummary.criticModelUsed} data-testid="text-critic-model">
            {debateSummary.criticModelUsed.split("/").pop()}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4 text-sm">
        <span className="text-muted-foreground">Chain Status:</span>
        <span className="text-green-400" data-testid="text-verified-count">{verifiedCount} verified</span>
        <span className="text-yellow-400" data-testid="text-disputed-count">{disputedCount} disputed</span>
        <span className="text-red-400" data-testid="text-rejected-count">{rejectedCount} rejected</span>
      </div>

      {debateSummary.criticReasoning && (
        <div className="bg-muted/30 rounded-lg p-4 border border-border">
          <div className="text-xs text-muted-foreground mb-2 uppercase tracking-wider">CriticAgent Reasoning</div>
          <p className="text-sm text-foreground/80" data-testid="text-critic-reasoning">{debateSummary.criticReasoning}</p>
        </div>
      )}

      {debateSummary.verifiedChains.length > 0 && (
        <div className="space-y-2">
          <div className="text-sm font-medium text-muted-foreground mb-2">Exploit Chain Analysis</div>
          {debateSummary.verifiedChains.map((chain, idx) => (
            <div key={idx} className="border border-border rounded-lg overflow-hidden" data-testid={`card-chain-${idx}`}>
              <button
                className="w-full flex items-center gap-3 p-3 hover-elevate text-left"
                onClick={() => toggleChain(chain.name)}
                data-testid={`button-expand-chain-${idx}`}
              >
                {expandedChains.has(chain.name) ? (
                  <ChevronDown className="w-4 h-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                )}
                {getStatusIcon(chain.verificationStatus)}
                <span className="font-medium flex-1">{chain.name}</span>
                <Badge variant="outline" className="text-xs font-mono" data-testid={`badge-technique-${idx}`}>{chain.technique}</Badge>
                {getVerdictBadge(chain.verificationStatus)}
              </button>
              {expandedChains.has(chain.name) && (
                <div className="p-3 pt-0 border-t border-border bg-muted/20">
                  <p className="text-sm text-muted-foreground mb-2">{chain.description}</p>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-muted-foreground">Success Likelihood:</span>
                    <Badge variant="outline" className="text-xs">{chain.success_likelihood}</Badge>
                  </div>
                  {chain.challengeNotes && (
                    <div className="mt-2 p-2 bg-yellow-500/10 border border-yellow-500/20 rounded text-sm text-yellow-200" data-testid={`text-challenge-notes-${idx}`}>
                      <span className="font-medium">Challenge Notes:</span> {chain.challengeNotes}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="text-xs text-muted-foreground pt-2">
        Debate completed in {debateSummary.processingTime}ms over {debateSummary.debateRounds} round(s)
      </div>
    </div>
  );
}
