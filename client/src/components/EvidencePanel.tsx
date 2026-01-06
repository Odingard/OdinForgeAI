import { useState } from "react";
import { Download, Clock, FileCode, Terminal, FileText, ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import pdfMake from "pdfmake/build/pdfmake";
import type { EvidenceArtifact } from "@shared/schema";

interface EvidencePanelProps {
  artifacts: EvidenceArtifact[];
  evaluationId: string;
}

export function EvidencePanel({ artifacts, evaluationId }: EvidencePanelProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [isExporting, setIsExporting] = useState(false);
  const { toast } = useToast();

  const toggleExpanded = (id: string) => {
    const newSet = new Set(expandedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setExpandedIds(newSet);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "request_response":
        return <FileCode className="h-4 w-4" />;
      case "execution_trace":
        return <Terminal className="h-4 w-4" />;
      case "log_capture":
        return <FileText className="h-4 w-4" />;
      default:
        return <FileText className="h-4 w-4" />;
    }
  };

  const getTypeBadge = (type: string) => {
    const typeLabels: Record<string, { label: string; className: string }> = {
      request_response: { label: "HTTP", className: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
      execution_trace: { label: "Trace", className: "bg-purple-500/10 text-purple-400 border-purple-500/30" },
      log_capture: { label: "Logs", className: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
      screenshot: { label: "Screenshot", className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
      configuration_dump: { label: "Config", className: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" },
      data_sample: { label: "Data", className: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
      network_capture: { label: "Network", className: "bg-red-500/10 text-red-400 border-red-500/30" },
      timeline_event: { label: "Event", className: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30" },
    };
    const config = typeLabels[type] || { label: type, className: "bg-gray-500/10 text-gray-400 border-gray-500/30" };
    return <Badge className={config.className}>{config.label}</Badge>;
  };

  const exportEvidence = async (format: "json" | "pdf") => {
    setIsExporting(true);
    try {
      const response = await apiRequest("POST", `/api/evidence/${evaluationId}/export`, { format });
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || "Export failed");
      }
      
      const { data } = result;
      
      if (format === "json") {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `evidence-${evaluationId}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else if (format === "pdf") {
        // Generate PDF with the AI-enhanced narratives
        const docDefinition: any = {
          content: [
            { text: "Evidence Package", style: "header" },
            { text: `Evaluation ID: ${evaluationId}`, style: "subheader" },
            { text: `Generated: ${data.metadata.generatedAt}`, style: "metadata" },
            { text: " " },
            
            { text: "Executive Summary", style: "sectionHeader" },
            { text: data.executiveSummary, style: "paragraph" },
            { text: " " },
            
            { text: "Timeline of Events", style: "sectionHeader" },
            { text: data.timelineNarrative, style: "paragraph" },
            { text: " " },
            
            { text: "Key Findings", style: "sectionHeader" },
            { text: data.findingsNarrative, style: "paragraph" },
            { text: " " },
            
            { text: "Technical Details", style: "sectionHeader" },
            { text: data.technicalDetails, style: "paragraph" },
            { text: " " },
            
            { text: "Evidence Artifacts", style: "sectionHeader" },
            {
              ul: data.artifacts.slice(0, 20).map((a: any) => ({
                text: [
                  { text: `${a.title}`, bold: true },
                  { text: ` (${a.type})` },
                  a.description ? { text: ` - ${a.description.substring(0, 100)}${a.description.length > 100 ? "..." : ""}` } : "",
                ],
              })),
            },
          ],
          styles: {
            header: { fontSize: 22, bold: true, margin: [0, 0, 0, 10] },
            subheader: { fontSize: 14, color: "#666", margin: [0, 0, 0, 5] },
            metadata: { fontSize: 10, color: "#999", margin: [0, 0, 0, 20] },
            sectionHeader: { fontSize: 14, bold: true, margin: [0, 10, 0, 5], color: "#333" },
            paragraph: { fontSize: 11, lineHeight: 1.4, margin: [0, 0, 0, 10] },
          },
          defaultStyle: { font: "Helvetica" },
          pageMargins: [40, 40, 40, 40],
        };
        
        try {
          const pdfDoc = pdfMake.createPdf(docDefinition);
          pdfDoc.download(`evidence-${evaluationId}.pdf`);
        } catch (pdfError) {
          console.error("PDF generation error:", pdfError);
          throw new Error("PDF generation failed - try JSON export instead");
        }
      }
      
      toast({
        title: "Export Successful",
        description: `Evidence package exported as ${format.toUpperCase()}`,
      });
    } catch (error: any) {
      console.error("Export failed:", error);
      toast({
        title: "Export Failed",
        description: error?.message || "Failed to generate evidence package. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsExporting(false);
    }
  };

  if (!artifacts || artifacts.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <FileText className="h-12 w-12 mx-auto mb-3 opacity-30" />
        <p>No evidence artifacts captured</p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="evidence-panel">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm text-muted-foreground">
          {artifacts.length} artifact{artifacts.length !== 1 ? "s" : ""} captured
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" disabled={isExporting} data-testid="button-download-evidence">
              {isExporting ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Download className="h-4 w-4 mr-2" />
              )}
              {isExporting ? "Generating..." : "Export"}
              <ChevronDown className="h-3 w-3 ml-2" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem 
              onClick={() => exportEvidence("pdf")}
              data-testid="button-export-pdf"
            >
              <FileText className="h-4 w-4 mr-2" />
              Export as PDF
            </DropdownMenuItem>
            <DropdownMenuItem 
              onClick={() => exportEvidence("json")}
              data-testid="button-export-json"
            >
              <FileCode className="h-4 w-4 mr-2" />
              Export as JSON
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <ScrollArea className="h-[400px]">
        <div className="space-y-2 pr-4">
          {artifacts.map((artifact) => (
            <Collapsible
              key={artifact.id}
              open={expandedIds.has(artifact.id)}
              onOpenChange={() => toggleExpanded(artifact.id)}
            >
              <div className="border border-border rounded-lg overflow-visible" data-testid={`evidence-artifact-${artifact.id}`}>
                <CollapsibleTrigger className="w-full" data-testid={`button-expand-artifact-${artifact.id}`}>
                  <div className="flex items-center gap-3 p-3 hover-elevate">
                    <div className="text-muted-foreground">
                      {expandedIds.has(artifact.id) ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </div>
                    <div className="p-2 rounded-lg bg-muted/50">
                      {getTypeIcon(artifact.type)}
                    </div>
                    <div className="flex-1 text-left">
                      <div className="font-medium text-sm text-foreground">{artifact.title}</div>
                      <div className="text-xs text-muted-foreground flex items-center gap-2 mt-0.5">
                        <Clock className="h-3 w-3" />
                        {new Date(artifact.timestamp).toLocaleString()}
                      </div>
                    </div>
                    {getTypeBadge(artifact.type)}
                    {artifact.isSanitized && (
                      <Badge variant="outline" className="text-xs">Sanitized</Badge>
                    )}
                  </div>
                </CollapsibleTrigger>

                <CollapsibleContent>
                  <div className="border-t border-border p-4 space-y-4 bg-muted/20">
                    <p className="text-sm text-muted-foreground">{artifact.description}</p>

                    {artifact.data.request && (
                      <div className="space-y-2">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Request</div>
                        <div className="bg-background rounded-lg p-3 font-mono text-xs">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                              {artifact.data.request.method}
                            </Badge>
                            <span className="text-foreground truncate">{artifact.data.request.url}</span>
                          </div>
                          {artifact.data.request.body && (
                            <pre className="text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                              {artifact.data.request.body}
                            </pre>
                          )}
                        </div>
                      </div>
                    )}

                    {artifact.data.response && (
                      <div className="space-y-2">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Response</div>
                        <div className="bg-background rounded-lg p-3 font-mono text-xs">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className={
                              artifact.data.response.statusCode < 400
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                : "bg-red-500/10 text-red-400 border-red-500/30"
                            }>
                              {artifact.data.response.statusCode}
                            </Badge>
                            {artifact.data.response.timing && (
                              <span className="text-muted-foreground">{artifact.data.response.timing}ms</span>
                            )}
                          </div>
                          {artifact.data.response.body && (
                            <pre className="text-muted-foreground overflow-x-auto whitespace-pre-wrap max-h-40">
                              {artifact.data.response.body.substring(0, 500)}
                              {artifact.data.response.body.length > 500 && "..."}
                            </pre>
                          )}
                        </div>
                      </div>
                    )}

                    {artifact.data.trace && artifact.data.trace.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Execution Trace</div>
                        <div className="space-y-1">
                          {artifact.data.trace.map((step, idx) => (
                            <div key={idx} className="flex items-start gap-3 p-2 bg-background rounded-lg">
                              <div className="min-w-[24px] h-6 flex items-center justify-center rounded bg-muted text-xs font-mono">
                                {step.step}
                              </div>
                              <div className="flex-1">
                                <div className="text-sm font-medium text-foreground">{step.action}</div>
                                <div className="text-xs text-muted-foreground">{step.result}</div>
                              </div>
                              {step.duration && (
                                <div className="text-xs text-muted-foreground">{step.duration}ms</div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {artifact.data.logs && artifact.data.logs.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Log Entries</div>
                        <div className="bg-background rounded-lg p-3 font-mono text-xs space-y-1 max-h-40 overflow-y-auto">
                          {artifact.data.logs.map((log, idx) => (
                            <div key={idx} className="flex items-start gap-2">
                              <Badge className={
                                log.level === "error" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                                log.level === "warn" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                                log.level === "info" ? "bg-blue-500/10 text-blue-400 border-blue-500/30" :
                                "bg-gray-500/10 text-gray-400 border-gray-500/30"
                              }>
                                {log.level}
                              </Badge>
                              <span className="text-muted-foreground">{log.message}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {artifact.tags && artifact.tags.length > 0 && (
                      <div className="flex items-center gap-2 flex-wrap">
                        {artifact.tags.map((tag) => (
                          <Badge key={tag} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </CollapsibleContent>
              </div>
            </Collapsible>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
