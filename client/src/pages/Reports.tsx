import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  FileText, 
  Download, 
  Trash2, 
  Calendar, 
  FileSpreadsheet, 
  FileJson, 
  BarChart3, 
  Shield, 
  Briefcase,
  Loader2,
  Plus,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileType,
} from "lucide-react";
import pdfMake from "pdfmake/build/pdfmake";
import pdfFonts from "pdfmake/build/vfs_fonts";

pdfMake.vfs = pdfFonts.vfs;
import { format } from "date-fns";
import type { Report } from "@shared/schema";

const reportTypes = [
  { value: "executive_summary", label: "Executive Summary", icon: Briefcase, description: "High-level overview for leadership" },
  { value: "technical_deep_dive", label: "Technical Deep-Dive", icon: FileText, description: "Detailed findings for engineers" },
  { value: "compliance_mapping", label: "Compliance Report", icon: Shield, description: "Framework-specific compliance status" },
];

const complianceFrameworks = [
  { value: "soc2", label: "SOC 2" },
  { value: "pci_dss", label: "PCI DSS" },
  { value: "hipaa", label: "HIPAA" },
  { value: "gdpr", label: "GDPR" },
  { value: "ccpa", label: "CCPA" },
  { value: "iso27001", label: "ISO 27001" },
  { value: "nist_csf", label: "NIST CSF" },
  { value: "fedramp", label: "FedRAMP" },
];

const exportFormats = [
  { value: "pdf", label: "PDF", icon: FileType },
  { value: "json", label: "JSON", icon: FileJson },
  { value: "csv", label: "CSV", icon: FileSpreadsheet },
];

export default function Reports() {
  const { toast } = useToast();
  const [isGenerateOpen, setIsGenerateOpen] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("executive_summary");
  const [selectedFormat, setSelectedFormat] = useState<string>("pdf");
  const [selectedFramework, setSelectedFramework] = useState<string>("soc2");
  const [dateFrom, setDateFrom] = useState<string>(
    format(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), "yyyy-MM-dd")
  );
  const [dateTo, setDateTo] = useState<string>(format(new Date(), "yyyy-MM-dd"));
  const [previewData, setPreviewData] = useState<any>(null);

  const { data: reports = [], isLoading } = useQuery<Report[]>({
    queryKey: ["/api/reports"],
  });

  const generateMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await apiRequest("POST", "/api/reports/generate", data);
      return response.json();
    },
    onSuccess: (data) => {
      setPreviewData(data);
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      toast({
        title: "Report generated",
        description: `Successfully generated: ${data.title}`,
      });
    },
    onError: (error) => {
      toast({
        title: "Generation failed",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/reports/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      toast({
        title: "Report deleted",
        description: "Report has been removed",
      });
    },
  });

  const handleGenerate = () => {
    generateMutation.mutate({
      type: selectedType,
      format: selectedFormat,
      from: dateFrom,
      to: dateTo,
      framework: selectedType === "compliance_mapping" ? selectedFramework : undefined,
    });
  };

  const handleDownload = (report: Report, downloadFormat: "pdf" | "json" | "csv" = "pdf") => {
    const filename = report.title.replace(/\s+/g, "_");
    
    if (downloadFormat === "pdf") {
      generatePdf(report);
    } else if (downloadFormat === "json") {
      const content = JSON.stringify(report.content, null, 2);
      const blob = new Blob([content], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${filename}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else if (downloadFormat === "csv") {
      const csvContent = convertToCSV(report.content);
      const blob = new Blob([csvContent], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${filename}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const convertToCSV = (data: any): string => {
    if (!data) return "";
    const rows: string[] = [];
    
    const flatten = (obj: any, prefix = ""): Record<string, string> => {
      const result: Record<string, string> = {};
      for (const key in obj) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        if (typeof obj[key] === "object" && obj[key] !== null && !Array.isArray(obj[key])) {
          Object.assign(result, flatten(obj[key], newKey));
        } else if (Array.isArray(obj[key])) {
          result[newKey] = obj[key].join("; ");
        } else {
          result[newKey] = String(obj[key] ?? "");
        }
      }
      return result;
    };
    
    const flat = flatten(data);
    rows.push(Object.keys(flat).join(","));
    rows.push(Object.values(flat).map(v => `"${v.replace(/"/g, '""')}"`).join(","));
    return rows.join("\n");
  };

  const generatePdf = (report: Report) => {
    const content = report.content as any;
    const reportTypeLabel = reportTypes.find(t => t.value === report.reportType)?.label || report.reportType;
    
    const docDefinition: any = {
      pageSize: "A4",
      pageMargins: [40, 60, 40, 60],
      info: {
        title: report.title,
        author: "OdinForge AI",
        subject: `${reportTypeLabel} - Security Assessment`,
      },
      header: {
        columns: [
          { text: "OdinForge AI", style: "headerText", margin: [40, 20, 0, 0] },
          { text: reportTypeLabel, style: "headerText", alignment: "right", margin: [0, 20, 40, 0] },
        ],
      },
      footer: (currentPage: number, pageCount: number) => ({
        columns: [
          { text: `Generated: ${format(new Date(report.createdAt || new Date()), "MMM d, yyyy HH:mm")}`, style: "footerText", margin: [40, 0, 0, 0] },
          { text: `Page ${currentPage} of ${pageCount}`, style: "footerText", alignment: "right", margin: [0, 0, 40, 0] },
        ],
      }),
      content: [
        { text: report.title, style: "title" },
        { text: `Date Range: ${format(new Date(report.dateRangeFrom), "MMM d, yyyy")} - ${format(new Date(report.dateRangeTo), "MMM d, yyyy")}`, style: "subtitle" },
        report.framework && { text: `Compliance Framework: ${report.framework.toUpperCase()}`, style: "subtitle" },
        { text: "", margin: [0, 10, 0, 10] },
        ...buildPdfContent(content, report.reportType),
      ].filter(Boolean),
      styles: {
        title: { fontSize: 22, bold: true, margin: [0, 0, 0, 10], color: "#1a365d" },
        subtitle: { fontSize: 11, color: "#64748b", margin: [0, 0, 0, 5] },
        sectionHeader: { fontSize: 14, bold: true, margin: [0, 15, 0, 8], color: "#0f172a" },
        subHeader: { fontSize: 12, bold: true, margin: [0, 10, 0, 5], color: "#334155" },
        bodyText: { fontSize: 10, margin: [0, 0, 0, 5], lineHeight: 1.4 },
        tableHeader: { fontSize: 10, bold: true, fillColor: "#f1f5f9", color: "#0f172a" },
        tableCell: { fontSize: 9 },
        criticalBadge: { fontSize: 9, bold: true, color: "#dc2626" },
        highBadge: { fontSize: 9, bold: true, color: "#ea580c" },
        mediumBadge: { fontSize: 9, bold: true, color: "#ca8a04" },
        lowBadge: { fontSize: 9, bold: true, color: "#16a34a" },
        headerText: { fontSize: 9, color: "#64748b" },
        footerText: { fontSize: 8, color: "#94a3b8" },
        listItem: { fontSize: 10, margin: [0, 2, 0, 2] },
      },
      defaultStyle: { font: "Roboto" },
    };

    pdfMake.createPdf(docDefinition).download(`${report.title.replace(/\s+/g, "_")}.pdf`);
    toast({
      title: "PDF Downloaded",
      description: `${report.title}.pdf has been downloaded`,
    });
  };

  const buildPdfContent = (data: any, reportType: string): any[] => {
    const content: any[] = [];
    
    if (!data) {
      content.push({ text: "No data available for this report.", style: "bodyText" });
      return content;
    }

    if (data.executiveSummary || reportType === "executive_summary") {
      content.push({ text: "Executive Summary", style: "sectionHeader" });
      if (data.executiveSummary) {
        content.push({ text: data.executiveSummary, style: "bodyText" });
      }
      
      if (data.keyMetrics) {
        content.push({ text: "Key Metrics", style: "subHeader" });
        const metricsTable = {
          table: {
            headerRows: 1,
            widths: ["*", "*"],
            body: [
              [{ text: "Metric", style: "tableHeader" }, { text: "Value", style: "tableHeader" }],
              ...Object.entries(data.keyMetrics).map(([key, value]) => [
                { text: key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase()), style: "tableCell" },
                { text: String(value), style: "tableCell" },
              ]),
            ],
          },
          layout: "lightHorizontalLines",
          margin: [0, 5, 0, 10],
        };
        content.push(metricsTable);
      }
    }

    if (data.findings && Array.isArray(data.findings)) {
      content.push({ text: "Security Findings", style: "sectionHeader" });
      const findingsTable = {
        table: {
          headerRows: 1,
          widths: ["auto", "*", "auto", "auto"],
          body: [
            [
              { text: "Severity", style: "tableHeader" },
              { text: "Finding", style: "tableHeader" },
              { text: "Status", style: "tableHeader" },
              { text: "Risk Score", style: "tableHeader" },
            ],
            ...data.findings.slice(0, 20).map((finding: any) => [
              { text: finding.severity?.toUpperCase() || "N/A", style: getSeverityStyle(finding.severity) },
              { text: finding.title || finding.description || "N/A", style: "tableCell" },
              { text: finding.status || "Open", style: "tableCell" },
              { text: String(finding.riskScore || finding.score || "N/A"), style: "tableCell" },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 5, 0, 10],
      };
      content.push(findingsTable);
    }

    if (data.recommendations && Array.isArray(data.recommendations)) {
      content.push({ text: "Recommendations", style: "sectionHeader" });
      const recList = {
        ul: data.recommendations.slice(0, 10).map((rec: any) => {
          if (typeof rec === "string") return rec;
          if (rec.action) {
            const priority = rec.priority ? `Priority ${rec.priority}: ` : "";
            const impact = rec.impact ? ` (${rec.impact})` : "";
            return `${priority}${rec.action}${impact}`;
          }
          return rec.description || rec.title || rec.text || "Recommendation pending";
        }),
        style: "listItem",
        margin: [0, 5, 0, 10],
      };
      content.push(recList);
    }

    if (data.complianceStatus) {
      content.push({ text: "Compliance Status", style: "sectionHeader" });
      const complianceTable = {
        table: {
          headerRows: 1,
          widths: ["*", "auto", "auto"],
          body: [
            [
              { text: "Control", style: "tableHeader" },
              { text: "Status", style: "tableHeader" },
              { text: "Coverage", style: "tableHeader" },
            ],
            ...Object.entries(data.complianceStatus).slice(0, 15).map(([control, status]: [string, any]) => [
              { text: control, style: "tableCell" },
              { text: typeof status === "object" ? status.status : String(status), style: "tableCell" },
              { text: typeof status === "object" && status.coverage ? `${status.coverage}%` : "N/A", style: "tableCell" },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 5, 0, 10],
      };
      content.push(complianceTable);
    }

    if (data.riskBreakdown) {
      content.push({ text: "Risk Breakdown", style: "sectionHeader" });
      const riskTable = {
        table: {
          headerRows: 1,
          widths: ["*", "auto"],
          body: [
            [{ text: "Category", style: "tableHeader" }, { text: "Count", style: "tableHeader" }],
            ...Object.entries(data.riskBreakdown).map(([category, count]) => [
              { text: category.charAt(0).toUpperCase() + category.slice(1), style: "tableCell" },
              { text: String(count), style: "tableCell" },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 5, 0, 10],
      };
      content.push(riskTable);
    }

    if (content.length === 0) {
      content.push({ text: "Report Data", style: "sectionHeader" });
      content.push({ text: JSON.stringify(data, null, 2), style: "bodyText", preserveLeadingSpaces: true });
    }

    return content;
  };

  const getSeverityStyle = (severity: string): string => {
    switch (severity?.toLowerCase()) {
      case "critical": return "criticalBadge";
      case "high": return "highBadge";
      case "medium": return "mediumBadge";
      case "low": return "lowBadge";
      default: return "tableCell";
    }
  };

  const getReportIcon = (type: string) => {
    switch (type) {
      case "executive_summary": return <Briefcase className="w-4 h-4" />;
      case "technical_deep_dive": return <FileText className="w-4 h-4" />;
      case "compliance_mapping": return <Shield className="w-4 h-4" />;
      default: return <FileText className="w-4 h-4" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return <Badge variant="default" className="bg-green-500/20 text-green-400 border-green-500/30"><CheckCircle2 className="w-3 h-3 mr-1" />Completed</Badge>;
      case "generating":
        return <Badge variant="secondary"><Clock className="w-3 h-3 mr-1" />Generating</Badge>;
      case "failed":
        return <Badge variant="destructive"><AlertTriangle className="w-3 h-3 mr-1" />Failed</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-reports-title">Enterprise Reports</h1>
          <p className="text-muted-foreground">Generate executive, technical, and compliance reports</p>
        </div>
        <Dialog open={isGenerateOpen} onOpenChange={setIsGenerateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-generate-report">
              <Plus className="w-4 h-4 mr-2" />
              Generate Report
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Generate New Report</DialogTitle>
              <DialogDescription>Configure and generate a security assessment report</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Report Type</Label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {reportTypes.map((type) => (
                    <Card
                      key={type.value}
                      className={`cursor-pointer transition-colors hover-elevate ${
                        selectedType === type.value ? "border-primary bg-primary/5" : ""
                      }`}
                      onClick={() => setSelectedType(type.value)}
                      data-testid={`card-report-type-${type.value}`}
                    >
                      <CardContent className="p-4">
                        <div className="flex flex-col items-center text-center gap-2">
                          <type.icon className="w-6 h-6 text-primary" />
                          <span className="font-medium text-sm">{type.label}</span>
                          <span className="text-xs text-muted-foreground">{type.description}</span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>

              {selectedType === "compliance_mapping" && (
                <div className="space-y-2">
                  <Label>Compliance Framework</Label>
                  <Select value={selectedFramework} onValueChange={setSelectedFramework}>
                    <SelectTrigger data-testid="select-framework">
                      <SelectValue placeholder="Select framework" />
                    </SelectTrigger>
                    <SelectContent>
                      {complianceFrameworks.map((fw) => (
                        <SelectItem key={fw.value} value={fw.value}>{fw.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Date From</Label>
                  <Input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    data-testid="input-date-from"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Date To</Label>
                  <Input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    data-testid="input-date-to"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Export Format</Label>
                <div className="flex gap-2">
                  {exportFormats.map((fmt) => (
                    <Button
                      key={fmt.value}
                      variant={selectedFormat === fmt.value ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSelectedFormat(fmt.value)}
                      data-testid={`btn-format-${fmt.value}`}
                    >
                      <fmt.icon className="w-4 h-4 mr-2" />
                      {fmt.label}
                    </Button>
                  ))}
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsGenerateOpen(false)}>Cancel</Button>
              <Button 
                onClick={handleGenerate} 
                disabled={generateMutation.isPending}
                data-testid="btn-confirm-generate"
              >
                {generateMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Generate Report
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="reports" className="space-y-4">
        <TabsList>
          <TabsTrigger value="reports" data-testid="tab-reports">
            <FileText className="w-4 h-4 mr-2" />
            Generated Reports
          </TabsTrigger>
          <TabsTrigger value="preview" data-testid="tab-preview" disabled={!previewData}>
            <BarChart3 className="w-4 h-4 mr-2" />
            Latest Preview
          </TabsTrigger>
        </TabsList>

        <TabsContent value="reports" className="space-y-4">
          {isLoading ? (
            <Card>
              <CardContent className="flex items-center justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
              </CardContent>
            </Card>
          ) : reports.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <FileText className="w-12 h-12 text-muted-foreground mb-4" />
                <h3 className="font-medium mb-2">No reports generated yet</h3>
                <p className="text-muted-foreground text-sm mb-4">
                  Generate your first report to see it here
                </p>
                <Button onClick={() => setIsGenerateOpen(true)} data-testid="btn-generate-first">
                  <Plus className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {reports.map((report) => (
                <Card key={report.id} data-testid={`card-report-${report.id}`}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/10 rounded-md">
                          {getReportIcon(report.reportType)}
                        </div>
                        <div>
                          <h3 className="font-medium">{report.title}</h3>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <Calendar className="w-3 h-3" />
                            <span>
                              {format(new Date(report.dateRangeFrom), "MMM d, yyyy")} - {format(new Date(report.dateRangeTo), "MMM d, yyyy")}
                            </span>
                            {report.framework && (
                              <Badge variant="outline" className="text-xs">
                                {report.framework.toUpperCase()}
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getStatusBadge(report.status)}
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              size="icon"
                              variant="ghost"
                              data-testid={`btn-download-${report.id}`}
                            >
                              <Download className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem 
                              onClick={() => handleDownload(report, "pdf")}
                              data-testid={`btn-download-pdf-${report.id}`}
                            >
                              <FileType className="w-4 h-4 mr-2" />
                              Download PDF
                            </DropdownMenuItem>
                            <DropdownMenuItem 
                              onClick={() => handleDownload(report, "json")}
                              data-testid={`btn-download-json-${report.id}`}
                            >
                              <FileJson className="w-4 h-4 mr-2" />
                              Download JSON
                            </DropdownMenuItem>
                            <DropdownMenuItem 
                              onClick={() => handleDownload(report, "csv")}
                              data-testid={`btn-download-csv-${report.id}`}
                            >
                              <FileSpreadsheet className="w-4 h-4 mr-2" />
                              Download CSV
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(report.id)}
                          disabled={deleteMutation.isPending}
                          data-testid={`btn-delete-${report.id}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="preview">
          {previewData && (
            <Card>
              <CardHeader>
                <CardTitle>{previewData.title}</CardTitle>
                <CardDescription>Generated report preview</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <div className="space-y-6">
                    {previewData.data.executiveSummary && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Executive Summary</h3>
                        <p className="text-muted-foreground">{previewData.data.executiveSummary}</p>
                      </div>
                    )}
                    
                    {previewData.data.keyMetrics && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Key Metrics</h3>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          {Object.entries(previewData.data.keyMetrics).map(([key, value]) => (
                            <div key={key} className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">{key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase())}</div>
                              <div className="text-lg font-semibold">{String(value)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {previewData.data.recommendations && Array.isArray(previewData.data.recommendations) && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Recommendations</h3>
                        <ul className="list-disc list-inside space-y-2">
                          {previewData.data.recommendations.map((rec: any, idx: number) => (
                            <li key={idx} className="text-muted-foreground">
                              {typeof rec === "string" ? rec : (
                                rec.action ? (
                                  <span>
                                    {rec.priority && <Badge className="mr-2">Priority {rec.priority}</Badge>}
                                    {rec.action}
                                    {rec.impact && <span className="text-sm italic ml-2">({rec.impact})</span>}
                                  </span>
                                ) : (rec.description || rec.title || rec.text || "Recommendation pending")
                              )}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {previewData.data.findings && Array.isArray(previewData.data.findings) && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Findings</h3>
                        <div className="space-y-3">
                          {previewData.data.findings.slice(0, 10).map((finding: any, idx: number) => (
                            <div key={idx} className="bg-muted p-3 rounded-md">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant={finding.severity === "critical" ? "destructive" : "secondary"}>
                                  {finding.severity?.toUpperCase() || "N/A"}
                                </Badge>
                                <span className="font-medium">{finding.title || "Untitled Finding"}</span>
                              </div>
                              <p className="text-sm text-muted-foreground">{finding.description}</p>
                              {finding.recommendation && (
                                <p className="text-sm mt-2"><span className="font-medium">Recommendation:</span> {finding.recommendation}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {!previewData.data.executiveSummary && !previewData.data.recommendations && (
                      <pre className="text-sm font-mono bg-muted p-4 rounded-md overflow-x-auto">
                        {JSON.stringify(previewData.data, null, 2)}
                      </pre>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
