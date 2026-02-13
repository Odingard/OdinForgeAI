import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ParticleBackground, GradientOrb } from "@/components/ui/animated-background";
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
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
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
  Lock,
  Sparkles,
  Link2,
} from "lucide-react";
// pdfmake loaded dynamically in downloadPdf() to avoid 830KB in initial chunk
import { format, startOfDay, subDays } from "date-fns";
import type { Report } from "@shared/schema";
import { DTGRangeDisplay } from "@/components/ui/dtg-display";
import { formatDTG, formatDTGWithLocal } from "@/lib/utils";
import { TimeSeriesChart } from "@/components/shared/TimeSeriesChart";

const baseReportTypes = [
  { value: "executive_summary", label: "Executive Summary", icon: Briefcase, description: "High-level overview for leadership", v2Only: false },
  { value: "technical_deep_dive", label: "Technical Deep-Dive", icon: FileText, description: "Detailed findings for engineers", v2Only: false },
  { value: "compliance_mapping", label: "Compliance Report", icon: Shield, description: "Framework-specific compliance status", v2Only: false },
  { value: "breach_chain_analysis", label: "Breach Chain Analysis", icon: Link2, description: "Cross-domain breach chain progression and impact", v2Only: true },
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
  const { hasPermission, needsSanitizedView } = useAuth();
  
  const canGenerateReport = hasPermission("reports:generate");
  const canDeleteReport = hasPermission("reports:delete");
  const canExportReport = hasPermission("reports:export");
  const isExecutiveView = needsSanitizedView();
  
  const { data: reports = [], isLoading } = useQuery<Report[]>({
    queryKey: ["/api/reports"],
  });

  const { data: v2FeatureStatus } = useQuery<{ enabled: boolean }>({
    queryKey: ["/api/reports/v2/feature-status"],
  });

  const isV2Enabled = v2FeatureStatus?.enabled ?? false;

  const [isGenerateOpen, setIsGenerateOpen] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("executive_summary");
  const [selectedFormat, setSelectedFormat] = useState<string>("pdf");
  const [selectedFramework, setSelectedFramework] = useState<string>("soc2");
  // Auto-detect report version: use V2 narrative when available, V1 otherwise
  const reportVersion = isV2Enabled ? "v2_narrative" : "v1_template";
  // Only show V2-exclusive report types when V2 is enabled
  const reportTypes = baseReportTypes.filter(t => !t.v2Only || isV2Enabled);
  const [dateFrom, setDateFrom] = useState<string>(
    format(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), "yyyy-MM-dd")
  );
  const [dateTo, setDateTo] = useState<string>(format(new Date(), "yyyy-MM-dd"));
  const [previewData, setPreviewData] = useState<any>(null);

  // Engagement metadata state
  const [clientName, setClientName] = useState<string>("");
  const [methodology, setMethodology] = useState<string>("OWASP");
  const [testingApproach, setTestingApproach] = useState<string>("gray_box");
  const [leadTester, setLeadTester] = useState<string>("");
  const [showEngagementOptions, setShowEngagementOptions] = useState(false);

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

  const generateV2Mutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await apiRequest("POST", "/api/reports/v2/generate", data);
      return response.json();
    },
    onSuccess: (data) => {
      setPreviewData(data.report);
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      setIsGenerateOpen(false);
      if (data.fallbackReason) {
        toast({
          title: "Report generated (V1 fallback)",
          description: data.fallbackReason,
          variant: "default",
        });
      } else {
        toast({
          title: "AI Narrative Report generated",
          description: `Successfully generated ${data.sectionsGenerated?.join(", ")} sections`,
        });
      }
    },
    onError: (error) => {
      toast({
        title: "V2 Report generation failed",
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
    // Build engagement metadata if provided
    const engagementMetadata = showEngagementOptions ? {
      clientName: clientName || undefined,
      assessmentPeriod: {
        startDate: dateFrom,
        endDate: dateTo,
      },
      methodology: {
        framework: methodology as "OWASP" | "PTES" | "NIST" | "OSSTMM" | "ISSAF" | "custom",
        testingApproach: testingApproach as "black_box" | "gray_box" | "white_box",
      },
      assessmentTeam: leadTester ? [{
        name: leadTester,
        role: "Lead Tester",
      }] : undefined,
    } : undefined;
    
    if (reportVersion === "v2_narrative") {
      const reportTypesMap: Record<string, string[]> = {
        "executive_summary": ["executive"],
        "technical_deep_dive": ["technical", "evidence"],
        "compliance_mapping": ["compliance"],
        "breach_chain_analysis": ["breach_validation", "executive"],
      };
      generateV2Mutation.mutate({
        dateRange: { from: dateFrom, to: dateTo },
        reportTypes: reportTypesMap[selectedType] || ["executive"],
        reportVersion: "v2_narrative",
        customerContext: {
          riskTolerance: "medium",
        },
        engagementMetadata,
      });
    } else {
      // V1 only supports these types — map anything else to technical_deep_dive
      const v1ValidTypes = ["executive_summary", "technical_deep_dive", "compliance_mapping"];
      const v1Type = v1ValidTypes.includes(selectedType) ? selectedType : "technical_deep_dive";
      generateMutation.mutate({
        type: v1Type,
        format: selectedFormat,
        from: dateFrom,
        to: dateTo,
        framework: v1Type === "compliance_mapping" ? selectedFramework : undefined,
        engagementMetadata,
      });
    }
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
    const sections: string[] = [];
    
    const escapeCSV = (value: any): string => {
      const str = String(value ?? "");
      if (str.includes(",") || str.includes("\n") || str.includes('"')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    // Executive Summary section
    if (data.executiveSummary) {
      sections.push("EXECUTIVE SUMMARY");
      sections.push(escapeCSV(data.executiveSummary));
      sections.push("");
    }

    // Key Metrics section
    if (data.keyMetrics) {
      sections.push("KEY METRICS");
      sections.push("Metric,Value");
      for (const [key, value] of Object.entries(data.keyMetrics)) {
        const label = key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase());
        sections.push(`${escapeCSV(label)},${escapeCSV(value)}`);
      }
      sections.push("");
    }

    // Findings section
    if (data.findings && Array.isArray(data.findings)) {
      sections.push("SECURITY FINDINGS");
      sections.push("Severity,Title,Description,Recommendation,Score");
      for (const f of data.findings.slice(0, 50)) {
        sections.push([
          escapeCSV(f.severity?.toUpperCase() || "N/A"),
          escapeCSV(f.title || "Untitled"),
          escapeCSV(f.description || ""),
          escapeCSV(f.recommendation || ""),
          escapeCSV(f.score || f.riskScore || "N/A"),
        ].join(","));
      }
      sections.push("");
    }

    // Recommendations section
    if (data.recommendations && Array.isArray(data.recommendations)) {
      sections.push("RECOMMENDATIONS");
      sections.push("Priority,Action,Impact,Effort");
      for (const rec of data.recommendations.slice(0, 20)) {
        if (typeof rec === "string") {
          sections.push(`1,${escapeCSV(rec)},,`);
        } else if (rec.action) {
          sections.push([
            escapeCSV(rec.priority || ""),
            escapeCSV(rec.action),
            escapeCSV(rec.impact || ""),
            escapeCSV(rec.effort || ""),
          ].join(","));
        } else {
          sections.push(`1,${escapeCSV(rec.description || rec.title || rec.text || "")},,`);
        }
      }
      sections.push("");
    }

    // Attack Paths section (for technical reports)
    if (data.attackPaths && Array.isArray(data.attackPaths)) {
      sections.push("ATTACK PATHS");
      sections.push("Asset,Complexity,Time to Compromise,Steps");
      for (const path of data.attackPaths.slice(0, 20)) {
        const stepsText = path.steps?.map((s: any) => s.technique || s.description || s.action).join(" -> ") || "";
        sections.push([
          escapeCSV(path.assetId || ""),
          escapeCSV(path.complexity || ""),
          escapeCSV(path.timeToCompromise || ""),
          escapeCSV(stepsText),
        ].join(","));
      }
      sections.push("");
    }

    // Compliance Status section
    if (data.complianceStatus) {
      sections.push("COMPLIANCE STATUS");
      sections.push("Control,Status,Coverage");
      for (const [control, status] of Object.entries(data.complianceStatus)) {
        const statusObj = status as any;
        sections.push([
          escapeCSV(control),
          escapeCSV(typeof statusObj === "object" ? statusObj.status : String(statusObj)),
          escapeCSV(typeof statusObj === "object" && statusObj.coverage ? `${statusObj.coverage}%` : "N/A"),
        ].join(","));
      }
      sections.push("");
    }

    // Gaps section (for compliance reports)
    if (data.gaps && Array.isArray(data.gaps)) {
      sections.push("COMPLIANCE GAPS");
      sections.push("Control ID,Gap Description,Severity,Remediation Guidance");
      for (const gap of data.gaps) {
        sections.push([
          escapeCSV(gap.controlId || ""),
          escapeCSV(gap.gapDescription || ""),
          escapeCSV(gap.severity || ""),
          escapeCSV(gap.remediationGuidance || ""),
        ].join(","));
      }
      sections.push("");
    }

    // Top Risks section (for executive reports)
    if (data.topRisks && Array.isArray(data.topRisks)) {
      sections.push("TOP RISKS");
      sections.push("Asset,Severity,Risk Description,Financial Impact");
      for (const risk of data.topRisks) {
        sections.push([
          escapeCSV(risk.assetId || ""),
          escapeCSV(risk.severity || ""),
          escapeCSV(risk.riskDescription || ""),
          escapeCSV(risk.financialImpact || ""),
        ].join(","));
      }
      sections.push("");
    }

    return sections.join("\n");
  };

  const generatePdf = async (report: Report) => {
    const content = report.content as any;
    const reportTypeLabel = reportTypes.find(t => t.value === report.reportType)?.label
      || (report.reportType === "breach_chain" ? "Breach Chain Analysis" : report.reportType);
    
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
        stack: [
          {
            columns: [
              { text: `CONFIDENTIAL — ${formatDTGWithLocal(report.createdAt || new Date())}`, style: "footerText", margin: [40, 0, 0, 0] },
              { text: `Page ${currentPage} of ${pageCount}`, style: "footerText", alignment: "right", margin: [0, 0, 40, 0] },
            ],
          },
          { text: "OdinForge AI Security Assessment Platform", style: "footerText", alignment: "center", margin: [0, 2, 0, 0] },
        ],
      }),
      content: [
        // Professional Cover Page
        { text: "CONFIDENTIAL", style: "classification", alignment: "center" },
        { text: "", margin: [0, 40, 0, 0] },
        { text: report.title, style: "coverTitle", alignment: "center" },
        { text: "", margin: [0, 10, 0, 0] },
        {
          canvas: [{ type: "line", x1: 140, y1: 0, x2: 375, y2: 0, lineWidth: 2, lineColor: "#0ea5e9" }],
        },
        { text: "", margin: [0, 15, 0, 0] },
        { text: `Assessment Period: ${formatDTG(report.dateRangeFrom)} — ${formatDTG(report.dateRangeTo)}`, style: "coverMeta", alignment: "center" },
        { text: `Report Date: ${formatDTGWithLocal(report.createdAt || new Date())}`, style: "coverMeta", alignment: "center" },
        report.framework && { text: `Compliance Framework: ${report.framework.toUpperCase()}`, style: "coverMeta", alignment: "center" },
        { text: `Document Version: 1.0`, style: "coverMeta", alignment: "center" },
        { text: "", margin: [0, 30, 0, 0] },
        {
          table: {
            widths: ["*", "*"],
            body: [
              [
                { text: "Prepared By", style: "coverLabel", alignment: "center", border: [false, false, false, false] },
                { text: "Prepared For", style: "coverLabel", alignment: "center", border: [false, false, false, false] },
              ],
              [
                { text: "OdinForge AI Security Assessment Platform", style: "coverValue", alignment: "center", border: [false, false, false, false] },
                { text: content.clientName || content.organizationId || "Client Organization", style: "coverValue", alignment: "center", border: [false, false, false, false] },
              ],
            ],
          },
          layout: "noBorders",
          margin: [0, 0, 0, 20],
        },
        { text: "", pageBreak: "after" },
        // End Cover Page — Begin Report Body
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
        // Professional cover page styles
        classification: { fontSize: 12, bold: true, color: "#dc2626", margin: [0, 10, 0, 0] },
        coverTitle: { fontSize: 26, bold: true, color: "#0f172a", margin: [0, 0, 0, 10] },
        coverMeta: { fontSize: 11, color: "#475569", margin: [0, 3, 0, 3] },
        coverLabel: { fontSize: 9, color: "#94a3b8", margin: [0, 5, 0, 2] },
        coverValue: { fontSize: 11, bold: true, color: "#1e293b", margin: [0, 0, 0, 5] },
        // Methodology and disclaimer styles
        methodologyText: { fontSize: 9, margin: [0, 0, 0, 4], lineHeight: 1.3, color: "#334155" },
        disclaimerText: { fontSize: 8, margin: [0, 0, 0, 3], lineHeight: 1.3, color: "#64748b", italics: true },
        listLabel: { fontSize: 10, bold: true, margin: [0, 5, 0, 2], color: "#334155" },
      },
      defaultStyle: { font: "Roboto" },
    };

    try {
      const [{ default: pdfMake }, { default: pdfFonts }] = await Promise.all([
        import("pdfmake/build/pdfmake"),
        import("pdfmake/build/vfs_fonts"),
      ]);
      pdfMake.vfs = pdfFonts.vfs;
      const pdfDoc = pdfMake.createPdf(docDefinition);
      pdfDoc.download(`${report.title.replace(/\s+/g, "_")}.pdf`);
      toast({
        title: "PDF Downloaded",
        description: `${report.title}.pdf has been downloaded`,
      });
    } catch (error) {
      console.error("PDF generation error:", error);
      toast({
        title: "PDF Export Failed",
        description: "There was an error generating the PDF. Try downloading as JSON instead.",
        variant: "destructive",
      });
    }
  };

  const buildPdfContent = (data: any, reportType: string): any[] => {
    const content: any[] = [];
    
    if (!data) {
      content.push({ text: "No data available for this report.", style: "bodyText" });
      return content;
    }

    // Handle Web App Scan Report structure
    if (data.scanMetadata || data.technicalFindings || data.reconResult) {
      return buildWebAppScanPdfContent(data);
    }

    // Breach Chain — inject phase execution and breach metrics sections
    if (data.reportType === "breach_chain" || reportType === "breach_chain") {
      // Phase Execution Summary (before standard sections)
      if (data.phases && Array.isArray(data.phases) && data.phases.length > 0) {
        content.push({ text: "Breach Chain Phase Execution", style: "sectionHeader" });
        content.push({
          text: `The simulation executed ${data.phases.length} attack phases against the target environment. The following table summarizes the outcome of each phase:`,
          style: "bodyText",
        });
        const phaseTable = {
          table: {
            headerRows: 1,
            widths: ["*", "auto", "auto", "auto"],
            body: [
              [
                { text: "Phase", style: "tableHeader" },
                { text: "Status", style: "tableHeader" },
                { text: "Findings", style: "tableHeader" },
                { text: "Duration", style: "tableHeader" },
              ],
              ...data.phases.map((p: any) => [
                { text: p.name || "Unknown", style: "tableCell" },
                { text: (p.status || "unknown").toUpperCase(), style: "tableCell", color: p.status === "completed" ? "#16a34a" : p.status === "failed" ? "#dc2626" : "#64748b" },
                { text: String(p.findingCount || 0), style: "tableCell" },
                { text: p.durationMs ? `${Math.round(p.durationMs / 1000)}s` : "—", style: "tableCell" },
              ]),
            ],
          },
          layout: "lightHorizontalLines",
          margin: [0, 5, 0, 15],
        };
        content.push(phaseTable);
      }

      // Breach Metrics Summary
      if (data.overallRiskScore !== undefined) {
        content.push({ text: "Breach Impact Summary", style: "sectionHeader" });
        const metricsRows: any[][] = [
          [{ text: "Metric", style: "tableHeader" }, { text: "Value", style: "tableHeader" }],
        ];
        metricsRows.push([{ text: "Overall Risk Score", style: "tableCell" }, { text: `${data.overallRiskScore}/100 (${data.riskTier || "N/A"})`, style: "tableCell", bold: true, color: data.overallRiskScore >= 80 ? "#dc2626" : data.overallRiskScore >= 60 ? "#ea580c" : data.overallRiskScore >= 40 ? "#ca8a04" : "#16a34a" }]);
        if (data.assetsCompromised) metricsRows.push([{ text: "Assets Compromised", style: "tableCell" }, { text: String(data.assetsCompromised), style: "tableCell" }]);
        if (data.credentialsHarvested) metricsRows.push([{ text: "Credentials Harvested", style: "tableCell" }, { text: String(data.credentialsHarvested), style: "tableCell" }]);
        if (data.maxPrivilegeAchieved && data.maxPrivilegeAchieved !== "none") metricsRows.push([{ text: "Maximum Privilege Achieved", style: "tableCell" }, { text: data.maxPrivilegeAchieved.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase()), style: "tableCell" }]);
        if (data.domainsBreached?.length > 0) metricsRows.push([{ text: "Domains Breached", style: "tableCell" }, { text: data.domainsBreached.map((d: string) => d.replace(/_/g, " ")).join(", "), style: "tableCell" }]);
        if (data.executionMode) metricsRows.push([{ text: "Execution Mode", style: "tableCell" }, { text: data.executionMode.replace(/\b\w/g, (c: string) => c.toUpperCase()), style: "tableCell" }]);

        content.push({
          table: { headerRows: 1, widths: ["*", "*"], body: metricsRows },
          layout: "lightHorizontalLines",
          margin: [0, 5, 0, 15],
        });
      }
    }

    if (data.executiveSummary || reportType === "executive_summary") {
      content.push({ text: "1. Executive Summary", style: "sectionHeader" });
      if (data.executiveSummary) {
        // Handle both string and object executiveSummary
        if (typeof data.executiveSummary === "string") {
          // Split by double newlines to create proper paragraphs
          const paragraphs = data.executiveSummary.split(/\n\n+/).filter((p: string) => p.trim());
          paragraphs.forEach((p: string) => {
            content.push({ text: p.trim(), style: "bodyText", margin: [0, 0, 0, 8] });
          });
        } else if (typeof data.executiveSummary === "object") {
          if (data.executiveSummary.overview) {
            content.push({ text: data.executiveSummary.overview, style: "bodyText" });
          }
        }
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

    // Methodology Section — breach chain vs standard
    content.push({ text: "2. Assessment Methodology", style: "sectionHeader" });
    if (data.reportType === "breach_chain" || reportType === "breach_chain") {
      content.push({
        text: "This assessment was conducted using OdinForge's Cross-Domain Breach Chain Simulation engine. The simulation models real-world adversary behavior by executing a sequence of attack phases across organizational boundaries, validating whether an attacker could traverse from initial compromise to critical asset exfiltration.",
        style: "methodologyText",
      });
      content.push({
        text: "The breach chain methodology follows a structured kill-chain progression:",
        style: "methodologyText",
      });
      content.push({
        ol: [
          "Reconnaissance & Target Enumeration — Identifies exposed assets across target domains, catalogs services, and maps trust relationships between environments.",
          "Initial Access & Exploitation — Validates exploitable entry points using confirmed vulnerability data from prior evaluations and simulated attack techniques.",
          "Credential Harvesting & Privilege Escalation — Assesses credential exposure, tests privilege escalation paths, and determines maximum achievable access level.",
          "Lateral Movement & Domain Traversal — Simulates cross-domain pivot paths, evaluating network segmentation effectiveness and trust boundary enforcement.",
          "Data Collection & Impact Assessment — Quantifies the blast radius of a successful breach including assets compromised, data at risk, and business process disruption.",
        ],
        style: "methodologyText",
        margin: [10, 5, 0, 10],
      });
      content.push({
        text: "Each phase produces findings mapped to the MITRE ATT&CK framework. The overall risk score reflects the cumulative impact of all confirmed attack paths, weighted by exploitability, blast radius, and business criticality of affected assets.",
        style: "methodologyText",
      });
    } else {
      content.push({
        text: "This assessment was conducted using OdinForge's automated multi-agent AI security analysis platform. The platform employs a pipeline of six specialized AI agents that systematically evaluate the target attack surface:",
        style: "methodologyText",
      });
      content.push({
        ol: [
          "Reconnaissance Agent — Maps the attack surface, identifies exposed services, and catalogs potential entry points.",
          "Exploit Validation Agent — Validates identified vulnerabilities through safe exploitation techniques and confirms exploitability.",
          "Lateral Movement Agent — Analyzes pivot paths and identifies opportunities for post-exploitation movement across the environment.",
          "Business Logic Agent — Evaluates application-layer vulnerabilities including authentication bypasses, authorization flaws, and workflow manipulation.",
          "Multi-Vector Agent — Identifies chained attack paths that combine multiple individual findings into compound exploitation scenarios.",
          "Impact Assessment Agent — Quantifies the business impact of confirmed findings including financial exposure, operational disruption, and regulatory implications.",
        ],
        style: "methodologyText",
        margin: [10, 5, 0, 10],
      });
      content.push({
        text: "Findings are mapped to the MITRE ATT&CK framework for technique identification and to the CWE (Common Weakness Enumeration) taxonomy for vulnerability classification. Risk scoring considers exploitability, business impact, and confidence level.",
        style: "methodologyText",
      });
    }

    if (data.findings && Array.isArray(data.findings)) {
      content.push({ text: "3. Security Findings", style: "sectionHeader" });
      content.push({
        text: `${data.findings.length} finding${data.findings.length !== 1 ? "s" : ""} identified during the assessment, sorted by severity and exploitability.`,
        style: "bodyText",
      });
      const findingsTable = {
        table: {
          headerRows: 1,
          widths: ["auto", "*", "auto", "auto"],
          body: [
            [
              { text: "Severity", style: "tableHeader" },
              { text: "Finding", style: "tableHeader" },
              { text: "Exploitable", style: "tableHeader" },
              { text: "Score", style: "tableHeader" },
            ],
            ...data.findings.slice(0, 20).map((finding: any) => [
              { text: finding.severity?.toUpperCase() || "N/A", style: getSeverityStyle(finding.severity) },
              {
                stack: [
                  { text: finding.title || finding.description || "N/A", style: "tableCell", bold: true },
                  ...(finding.cweId || finding.mitreAttackId ? [{
                    text: [finding.cweId, finding.mitreAttackId].filter(Boolean).join(" | "),
                    style: "tableCell",
                    color: "#64748b",
                    fontSize: 8,
                  }] : []),
                ],
              },
              { text: finding.exploitable ? "CONFIRMED" : finding.status || "Open", style: "tableCell" },
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
      content.push({ text: "4. Recommendations", style: "sectionHeader" });
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

    // Top Risks section (for executive reports)
    if (data.topRisks && Array.isArray(data.topRisks) && data.topRisks.length > 0) {
      content.push({ text: "Top Business Risks", style: "sectionHeader" });
      const risksTable = {
        table: {
          headerRows: 1,
          widths: ["auto", "*", "auto", "auto"],
          body: [
            [
              { text: "Severity", style: "tableHeader" },
              { text: "Risk Description", style: "tableHeader" },
              { text: "Asset", style: "tableHeader" },
              { text: "Financial Impact", style: "tableHeader" },
            ],
            ...data.topRisks.slice(0, 10).map((risk: any) => [
              { text: risk.severity?.toUpperCase() || "N/A", style: getSeverityStyle(risk.severity) },
              { text: risk.riskDescription || "Risk requiring attention", style: "tableCell" },
              { text: risk.assetId || "N/A", style: "tableCell" },
              { text: risk.financialImpact || "TBD", style: "tableCell" },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 5, 0, 10],
      };
      content.push(risksTable);
    }

    // Attack Paths section (for technical reports)
    if (data.attackPaths && Array.isArray(data.attackPaths) && data.attackPaths.length > 0) {
      content.push({ text: "Attack Path Analysis", style: "sectionHeader" });
      content.push({ 
        text: "The following attack paths were identified and validated during the security assessment:", 
        style: "bodyText" 
      });
      
      for (const [idx, path] of data.attackPaths.slice(0, 5).entries()) {
        content.push({ text: `Attack Path ${idx + 1}: ${path.assetId || "Target Asset"}`, style: "subHeader" });
        
        const pathInfo = [];
        if (path.complexity) pathInfo.push(`Complexity: ${path.complexity}/100`);
        if (path.timeToCompromise) pathInfo.push(`Estimated Time to Compromise: ${path.timeToCompromise}`);
        if (pathInfo.length > 0) {
          content.push({ text: pathInfo.join(" | "), style: "bodyText", color: "#64748b" });
        }
        
        if (path.steps && Array.isArray(path.steps)) {
          const stepsText = path.steps.map((step: any, i: number) => {
            const technique = step.technique || step.action || step.description || "Action";
            const desc = step.description || step.details || "";
            return `${i + 1}. ${technique}${desc ? `: ${desc}` : ""}`;
          }).join("\n");
          content.push({ text: stepsText, style: "listItem", margin: [10, 5, 0, 10] });
        }
      }
    }

    // Vulnerability Breakdown section (for technical reports)
    if (data.vulnerabilityBreakdown) {
      content.push({ text: "Vulnerability Distribution", style: "sectionHeader" });
      
      if (data.vulnerabilityBreakdown.bySeverity) {
        content.push({ text: "By Severity:", style: "subHeader" });
        const severityItems = Object.entries(data.vulnerabilityBreakdown.bySeverity)
          .map(([sev, count]) => `${sev.charAt(0).toUpperCase() + sev.slice(1)}: ${count}`)
          .join(", ");
        content.push({ text: severityItems, style: "bodyText" });
      }
      
      if (data.vulnerabilityBreakdown.byType) {
        content.push({ text: "By Type:", style: "subHeader" });
        const typeItems = Object.entries(data.vulnerabilityBreakdown.byType)
          .map(([type, count]) => `${type.replace(/_/g, " ")}: ${count}`)
          .join(", ");
        content.push({ text: typeItems, style: "bodyText" });
      }
    }

    // Compliance Gaps section
    if (data.gaps && Array.isArray(data.gaps) && data.gaps.length > 0) {
      content.push({ text: "Compliance Gaps", style: "sectionHeader" });
      const gapsTable = {
        table: {
          headerRows: 1,
          widths: ["auto", "*", "auto"],
          body: [
            [
              { text: "Control ID", style: "tableHeader" },
              { text: "Gap Description", style: "tableHeader" },
              { text: "Severity", style: "tableHeader" },
            ],
            ...data.gaps.slice(0, 15).map((gap: any) => [
              { text: gap.controlId || "N/A", style: "tableCell" },
              { text: gap.gapDescription || "Gap requiring remediation", style: "tableCell" },
              { text: gap.severity?.toUpperCase() || "MEDIUM", style: getSeverityStyle(gap.severity) },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 5, 0, 10],
      };
      content.push(gapsTable);
      
      // Add remediation guidance
      content.push({ text: "Remediation Guidance", style: "subHeader" });
      const remediationList = {
        ul: data.gaps.slice(0, 10).map((gap: any) => 
          `${gap.controlId}: ${gap.remediationGuidance || "Review and implement required controls"}`
        ),
        style: "listItem",
        margin: [0, 5, 0, 10],
      };
      content.push(remediationList);
    }

    // Audit Readiness section (for compliance reports)
    if (data.auditReadiness) {
      content.push({ text: "Audit Readiness Assessment", style: "sectionHeader" });
      
      const readinessInfo = [
        { label: "Overall Readiness Score", value: `${data.auditReadiness.score || 0}%` },
        { label: "Compliant Controls", value: `${data.auditReadiness.readyControls || 0} of ${data.auditReadiness.totalControls || 0}` },
      ];
      
      const readinessTable = {
        table: {
          widths: ["*", "auto"],
          body: readinessInfo.map(item => [
            { text: item.label, style: "tableCell" },
            { text: item.value, style: "tableCell", bold: true },
          ]),
        },
        layout: "noBorders",
        margin: [0, 5, 0, 10],
      };
      content.push(readinessTable);
      
      if (data.auditReadiness.priorityActions && Array.isArray(data.auditReadiness.priorityActions)) {
        content.push({ text: "Priority Actions for Audit Preparation:", style: "subHeader" });
        const actionsList = {
          ol: data.auditReadiness.priorityActions.slice(0, 5),
          style: "listItem",
          margin: [0, 5, 0, 10],
        };
        content.push(actionsList);
      }
    }

    // Risk Rating Methodology Section
    content.push({ text: "Risk Rating Methodology", style: "sectionHeader" });
    content.push({
      text: "Findings are classified using the following severity rating scale, aligned with industry-standard vulnerability scoring frameworks:",
      style: "methodologyText",
    });
    content.push({
      table: {
        headerRows: 1,
        widths: ["auto", "*"],
        body: [
          [
            { text: "Rating", style: "tableHeader" },
            { text: "Definition", style: "tableHeader" },
          ],
          [
            { text: "CRITICAL", style: "criticalBadge" },
            { text: "Findings that present immediate risk of exploitation with severe business impact. Active exploitation paths exist that could result in complete system compromise, large-scale data breach, or significant operational disruption. Requires emergency remediation within 48 hours.", style: "tableCell" },
          ],
          [
            { text: "HIGH", style: "highBadge" },
            { text: "Findings that present material risk and could be exploited by a motivated attacker with moderate effort. Successful exploitation could result in unauthorized access, data exposure, or service disruption. Requires prioritized remediation within 30 days.", style: "tableCell" },
          ],
          [
            { text: "MEDIUM", style: "mediumBadge" },
            { text: "Findings that represent defense-in-depth gaps. While not immediately exploitable in isolation, these findings could be combined with other vulnerabilities or exploited under specific conditions. Requires scheduled remediation within 60 days.", style: "tableCell" },
          ],
          [
            { text: "LOW", style: "lowBadge" },
            { text: "Findings that represent minor security improvements or informational observations. Limited direct business impact but contribute to overall security hygiene. Address during standard maintenance cycles.", style: "tableCell" },
          ],
        ],
      },
      layout: "lightHorizontalLines",
      margin: [0, 5, 0, 15],
    });
    content.push({
      text: "Risk scores (0-100) are calculated by the assessment platform considering: vulnerability severity, confirmed exploitability, attack complexity, potential business impact, and confidence level of the assessment.",
      style: "methodologyText",
    });

    // Disclaimer / Limitations Section
    content.push({ text: "", margin: [0, 15, 0, 0] });
    content.push({
      canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 0.5, lineColor: "#cbd5e1" }],
    });
    content.push({ text: "Assessment Limitations and Disclaimer", style: "subHeader", margin: [0, 10, 0, 5] });
    content.push({
      text: "This report represents a point-in-time assessment of the organization's security posture based on the scope, methodology, and data available at the time of testing. The findings and recommendations contained herein are based on the conditions observed during the assessment period and may not reflect the current state of the environment if changes have been made subsequent to the assessment.",
      style: "disclaimerText",
    });
    content.push({
      text: "This automated assessment employs AI-driven analysis techniques that, while comprehensive, may not identify all potential vulnerabilities. The absence of a finding does not guarantee the absence of a vulnerability. Organizations are encouraged to conduct regular assessments and maintain a layered security approach.",
      style: "disclaimerText",
    });
    content.push({
      text: "This document is classified as CONFIDENTIAL and is intended solely for the use of the organization to which it was issued. Unauthorized distribution, reproduction, or disclosure of this report or its contents is prohibited. The information contained herein should be handled in accordance with the organization's information classification and handling policies.",
      style: "disclaimerText",
    });

    if (content.length <= 3) {
      // Only methodology + disclaimer, no actual data sections
      content.splice(content.length - 8, 0, { text: "Report Data", style: "sectionHeader" });
      content.splice(content.length - 8, 0, { text: JSON.stringify(data, null, 2), style: "bodyText", preserveLeadingSpaces: true });
    }

    return content;
  };

  const buildWebAppScanPdfContent = (data: any): any[] => {
    const content: any[] = [];
    
    // Executive Summary section
    content.push({ text: "Executive Summary", style: "sectionHeader" });
    
    if (data.executiveSummary) {
      const summary = data.executiveSummary;
      if (summary.overview) {
        content.push({ text: summary.overview, style: "bodyText" });
      }
      
      // Key metrics table
      const metricsData = [
        ["Risk Level", summary.riskLevel || "Unknown"],
        ["Findings Count", String(summary.findingsCount || 0)],
      ];
      
      if (data.scanMetadata?.targetUrl) {
        metricsData.unshift(["Target URL", data.scanMetadata.targetUrl]);
      }
      
      const metricsTable = {
        table: {
          widths: ["auto", "*"],
          body: metricsData.map(([label, value]) => [
            { text: label, style: "tableCell", bold: true },
            { text: value, style: "tableCell" },
          ]),
        },
        layout: "lightHorizontalLines",
        margin: [0, 10, 0, 15],
      };
      content.push(metricsTable);
    }
    
    // Attack Surface Analysis section (from reconResult)
    if (data.reconResult) {
      const recon = data.reconResult;
      
      if (recon.attackSurface) {
        content.push({ text: "Attack Surface Analysis", style: "sectionHeader" });
        
        const surfaceData = [
          ["Total Endpoints", String(recon.attackSurface.totalEndpoints || 0)],
          ["High Priority Endpoints", String(recon.attackSurface.highPriorityEndpoints || 0)],
          ["Input Parameters", String(recon.attackSurface.inputParameters || 0)],
          ["Authentication Points", String(recon.attackSurface.authenticationPoints || 0)],
          ["File Upload Points", String(recon.attackSurface.fileUploadPoints || 0)],
          ["API Endpoints", String(recon.attackSurface.apiEndpoints || 0)],
        ];
        
        const surfaceTable = {
          table: {
            widths: ["*", "auto"],
            body: surfaceData.map(([label, value]) => [
              { text: label, style: "tableCell" },
              { text: value, style: "tableCell", alignment: "right" },
            ]),
          },
          layout: "lightHorizontalLines",
          margin: [0, 5, 0, 15],
        };
        content.push(surfaceTable);
      }
      
      // Application Security Headers
      if (recon.applicationInfo) {
        content.push({ text: "Application Security Headers", style: "sectionHeader" });
        
        const appInfo = recon.applicationInfo;
        
        if (appInfo.securityHeaders && Object.keys(appInfo.securityHeaders).length > 0) {
          content.push({ text: "Present Headers:", style: "subHeader" });
          const presentHeaders = Object.entries(appInfo.securityHeaders).map(([header, value]) => 
            `${header}: ${String(value).substring(0, 60)}${String(value).length > 60 ? "..." : ""}`
          );
          content.push({ ul: presentHeaders, style: "listItem", margin: [0, 5, 0, 10] });
        }
        
        if (appInfo.missingSecurityHeaders && appInfo.missingSecurityHeaders.length > 0) {
          content.push({ text: "Missing Headers (Recommended):", style: "subHeader" });
          content.push({ 
            ul: appInfo.missingSecurityHeaders.slice(0, 10), 
            style: "listItem", 
            margin: [0, 5, 0, 15] 
          });
        }
      }
    }
    
    // Technical Findings section
    if (data.technicalFindings && Array.isArray(data.technicalFindings) && data.technicalFindings.length > 0) {
      content.push({ text: "Security Findings", style: "sectionHeader" });
      content.push({ 
        text: `${data.technicalFindings.length} validated finding(s) identified during the assessment.`, 
        style: "bodyText" 
      });
      
      const findingsTable = {
        table: {
          headerRows: 1,
          widths: ["auto", "*", "auto", "auto"],
          body: [
            [
              { text: "Severity", style: "tableHeader" },
              { text: "Vulnerability", style: "tableHeader" },
              { text: "CVSS", style: "tableHeader" },
              { text: "Confidence", style: "tableHeader" },
            ],
            ...data.technicalFindings.slice(0, 20).map((finding: any) => [
              { text: (finding.severity || "medium").toUpperCase(), style: getSeverityStyle(finding.severity) },
              { text: `${finding.vulnerabilityType?.replace(/_/g, " ").toUpperCase() || "Unknown"}\n${finding.endpointPath || ""}`, style: "tableCell" },
              { text: finding.cvssEstimate || "N/A", style: "tableCell" },
              { text: `${finding.confidence || 0}%`, style: "tableCell" },
            ]),
          ],
        },
        layout: "lightHorizontalLines",
        margin: [0, 10, 0, 15],
      };
      content.push(findingsTable);
      
      // Detailed findings
      content.push({ text: "Finding Details", style: "sectionHeader" });
      
      for (const [idx, finding] of data.technicalFindings.slice(0, 10).entries()) {
        content.push({ 
          text: `${idx + 1}. ${finding.vulnerabilityType?.replace(/_/g, " ").toUpperCase() || "Finding"} - ${finding.endpointPath || "Unknown Path"}`, 
          style: "subHeader" 
        });
        
        const findingDetails = [
          `Parameter: ${finding.parameter || "N/A"}`,
          `MITRE ATT&CK: ${finding.mitreAttackId || "N/A"}`,
          `Verdict: ${finding.verdict || "N/A"}`,
        ];
        content.push({ text: findingDetails.join(" | "), style: "bodyText", color: "#64748b" });
        
        // Evidence
        if (finding.evidence && Array.isArray(finding.evidence) && finding.evidence.length > 0) {
          content.push({ text: "Evidence:", style: "listLabel", margin: [0, 5, 0, 2] });
          content.push({ 
            ul: finding.evidence.slice(0, 3).map((e: string) => e.substring(0, 100) + (e.length > 100 ? "..." : "")), 
            style: "listItem",
            margin: [10, 0, 0, 5]
          });
        }
        
        // Reproduction Steps
        if (finding.reproductionSteps && Array.isArray(finding.reproductionSteps)) {
          content.push({ text: "Reproduction Steps:", style: "listLabel", margin: [0, 5, 0, 2] });
          content.push({ 
            ol: finding.reproductionSteps.slice(0, 5), 
            style: "listItem",
            margin: [10, 0, 0, 5]
          });
        }
        
        // Recommendations
        if (finding.recommendations && Array.isArray(finding.recommendations) && finding.recommendations.length > 0) {
          content.push({ text: "Recommendations:", style: "listLabel", margin: [0, 5, 0, 2] });
          content.push({ 
            ul: finding.recommendations.slice(0, 5), 
            style: "listItem",
            margin: [10, 0, 0, 15]
          });
        }
      }
    } else {
      content.push({ text: "Security Findings", style: "sectionHeader" });
      content.push({ text: "No validated security findings were identified during this assessment.", style: "bodyText" });
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
      case "breach_chain":
      case "breach_chain_analysis": return <Link2 className="w-4 h-4" />;
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
    <div className="container mx-auto p-6 space-y-6 relative">
      {/* Animated backgrounds */}
      <ParticleBackground particleCount={30} particleColor="#06b6d4" opacity={0.15} />
      <GradientOrb color1="#ef4444" color2="#f97316" size="lg" className="top-20 right-10" />
      <GradientOrb color1="#06b6d4" color2="#8b5cf6" size="md" className="bottom-40 left-10" />

      {/* Grid overlay */}
      <div className="absolute inset-0 grid-bg opacity-10 pointer-events-none" />

      <div className="relative z-10">
      {isExecutiveView && (
        <Alert>
          <Briefcase className="h-4 w-4" />
          <AlertDescription>
            You are viewing reports in executive mode. Only executive summary reports are available. 
            Technical details and raw findings are not shown.
          </AlertDescription>
        </Alert>
      )}

      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2" data-testid="text-reports-title">
            <FileText className="h-6 w-6 text-cyan-400 glow-cyan-sm" />
            <span className="text-neon-red">Enterprise</span>
            <span>Reports</span>
          </h1>
          <p className="text-muted-foreground">Generate executive, technical, and compliance reports</p>
        </div>
        <Dialog open={isGenerateOpen} onOpenChange={setIsGenerateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-generate-report" disabled={!canGenerateReport}>
              {canGenerateReport ? <Plus className="w-4 h-4 mr-2" /> : <Lock className="w-4 h-4 mr-2" />}
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

              <div className="space-y-2">
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
                {dateFrom && dateTo && (
                  <div className="text-xs text-muted-foreground font-mono flex justify-between px-1">
                    <span>From: {formatDTG(new Date(dateFrom + "T00:00:00Z"))}</span>
                    <span>To: {formatDTG(new Date(dateTo + "T23:59:59Z"))}</span>
                  </div>
                )}
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

              <Separator />
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Engagement Context</Label>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    onClick={() => setShowEngagementOptions(!showEngagementOptions)}
                    className="text-xs"
                    data-testid="btn-toggle-engagement"
                  >
                    {showEngagementOptions ? "Hide Options" : "Add Professional Context"}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Add engagement metadata for consulting-grade deliverables
                </p>
                
                {showEngagementOptions && (
                  <div className="space-y-3 p-3 rounded-md bg-muted/30 border">
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <Label className="text-xs">Client Name</Label>
                        <Input
                          placeholder="Acme Corporation"
                          value={clientName}
                          onChange={(e) => setClientName(e.target.value)}
                          data-testid="input-client-name"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Lead Tester</Label>
                        <Input
                          placeholder="John Smith, OSCP"
                          value={leadTester}
                          onChange={(e) => setLeadTester(e.target.value)}
                          data-testid="input-lead-tester"
                        />
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <Label className="text-xs">Methodology</Label>
                        <Select value={methodology} onValueChange={setMethodology}>
                          <SelectTrigger data-testid="select-methodology">
                            <SelectValue placeholder="Select methodology" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="OWASP">OWASP</SelectItem>
                            <SelectItem value="PTES">PTES</SelectItem>
                            <SelectItem value="NIST">NIST</SelectItem>
                            <SelectItem value="OSSTMM">OSSTMM</SelectItem>
                            <SelectItem value="ISSAF">ISSAF</SelectItem>
                            <SelectItem value="custom">Custom</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Testing Approach</Label>
                        <Select value={testingApproach} onValueChange={setTestingApproach}>
                          <SelectTrigger data-testid="select-testing-approach">
                            <SelectValue placeholder="Select approach" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="black_box">Black Box</SelectItem>
                            <SelectItem value="gray_box">Gray Box</SelectItem>
                            <SelectItem value="white_box">White Box</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {isV2Enabled && (
                <>
                  <Separator />
                  <div className="flex items-center gap-2 p-3 rounded-md bg-cyan-500/10 border border-cyan-500/20">
                    <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="text-xs text-muted-foreground">
                      AI Narrative Engine active — reports use evidence-anchored breach narratives
                    </span>
                  </div>
                </>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsGenerateOpen(false)}>Cancel</Button>
              <Button 
                onClick={handleGenerate} 
                disabled={generateMutation.isPending || generateV2Mutation.isPending}
                data-testid="btn-confirm-generate"
              >
                {(generateMutation.isPending || generateV2Mutation.isPending) && (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                )}
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
          <TabsTrigger value="trends" data-testid="tab-trends">
            <BarChart3 className="w-4 h-4 mr-2" />
            Trends
          </TabsTrigger>
          <TabsTrigger value="preview" data-testid="tab-preview" disabled={!previewData}>
            <FileText className="w-4 h-4 mr-2" />
            Latest Preview
          </TabsTrigger>
        </TabsList>

        <TabsContent value="reports" className="space-y-4">
          {isLoading ? (
            <Card className="glass border-border/50 glow-cyan-sm">
              <CardContent className="flex items-center justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              </CardContent>
            </Card>
          ) : reports.length === 0 ? (
            <Card className="glass border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <FileText className="w-12 h-12 text-cyan-400 glow-cyan-sm mb-4" />
                <h3 className="font-medium mb-2">No reports generated yet</h3>
                <p className="text-muted-foreground text-sm mb-4">
                  Generate your first report to see it here
                </p>
                <Button onClick={() => setIsGenerateOpen(true)} data-testid="btn-generate-first" className="glow-cyan-sm">
                  <Plus className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4">
              {reports.map((report) => (
                <Card key={report.id} data-testid={`card-report-${report.id}`} className="glass border-border/50 hover-elevate scan-line">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between gap-4 flex-wrap">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/10 rounded-md">
                          {getReportIcon(report.reportType)}
                        </div>
                        <div>
                          <h3 className="font-medium">{report.title}</h3>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <DTGRangeDisplay 
                              startDate={report.dateRangeFrom} 
                              endDate={report.dateRangeTo} 
                              compact 
                            />
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
                        {canDeleteReport && (
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => deleteMutation.mutate(report.id)}
                            disabled={deleteMutation.isPending}
                            data-testid={`btn-delete-${report.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="trends">
          <Card className="glass border-border/50 glow-purple-sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5 text-purple-400" />
                Report Generation Trends
              </CardTitle>
              <CardDescription>
                Report generation activity over the last 30 days
              </CardDescription>
            </CardHeader>
            <CardContent>
              {reports.length > 0 ? (
                <TimeSeriesChart
                  data={(() => {
                    const last30Days = Array.from({ length: 30 }, (_, i) => {
                      const date = startOfDay(subDays(new Date(), 29 - i));
                      const dateStr = format(date, "yyyy-MM-dd");
                      const dayReports = reports.filter(r =>
                        r.createdAt && format(new Date(r.createdAt), "yyyy-MM-dd") === dateStr
                      );
                      return {
                        timestamp: dateStr,
                        value: dayReports.length,
                        label: format(date, "MMM d"),
                      };
                    });
                    return last30Days;
                  })()}
                  metrics={[
                    {
                      key: "value",
                      label: "Reports",
                      color: "#3b82f6",
                    },
                  ]}
                  height={300}
                />
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <BarChart3 className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No reports generated yet</p>
                </div>
              )}

              {/* Report Type Distribution */}
              {reports.length > 0 && (
                <div className="mt-6 space-y-4">
                  <h3 className="font-medium">Report Type Distribution</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {reportTypes.map(type => {
                      const count = reports.filter(r => r.reportType === type.value || (type.value === "breach_chain_analysis" && r.reportType === "breach_chain")).length;
                      const percentage = reports.length > 0 ? ((count / reports.length) * 100).toFixed(1) : "0";

                      return (
                        <Card key={type.value} className="p-4">
                          <div className="flex items-center gap-2 mb-2">
                            <type.icon className="h-4 w-4 text-muted-foreground" />
                            <span className="font-medium text-sm">{type.label}</span>
                          </div>
                          <div className="text-2xl font-bold">{count}</div>
                          <div className="text-xs text-muted-foreground">{percentage}% of total</div>
                        </Card>
                      );
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="preview">
          {previewData && (
            <Card className="glass border-border/50 glow-green-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-green-400" />
                  {previewData.title}
                </CardTitle>
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

                    {previewData.data.topRisks && Array.isArray(previewData.data.topRisks) && previewData.data.topRisks.length > 0 && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Top Business Risks</h3>
                        <div className="space-y-3">
                          {previewData.data.topRisks.slice(0, 5).map((risk: any, idx: number) => (
                            <div key={idx} className="bg-muted p-3 rounded-md">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant={risk.severity === "critical" ? "destructive" : "secondary"}>
                                  {risk.severity?.toUpperCase() || "N/A"}
                                </Badge>
                                <span className="font-medium">{risk.assetId || "Asset"}</span>
                                {risk.financialImpact && (
                                  <span className="text-sm text-muted-foreground ml-auto">{risk.financialImpact}</span>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground">{risk.riskDescription}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {previewData.data.attackPaths && Array.isArray(previewData.data.attackPaths) && previewData.data.attackPaths.length > 0 && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Attack Path Analysis</h3>
                        <div className="space-y-3">
                          {previewData.data.attackPaths.slice(0, 3).map((path: any, idx: number) => (
                            <div key={idx} className="bg-muted p-3 rounded-md">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="font-medium">Path {idx + 1}: {path.assetId || "Target"}</span>
                                {path.complexity && <Badge variant="outline">Complexity: {path.complexity}</Badge>}
                                {path.timeToCompromise && <Badge variant="outline">{path.timeToCompromise}</Badge>}
                              </div>
                              {path.steps && Array.isArray(path.steps) && (
                                <div className="text-sm text-muted-foreground">
                                  {path.steps.map((step: any, i: number) => (
                                    <span key={i}>
                                      {i > 0 && " → "}
                                      {step.technique || step.action || step.description || "Step"}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {previewData.data.gaps && Array.isArray(previewData.data.gaps) && previewData.data.gaps.length > 0 && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Compliance Gaps</h3>
                        <div className="space-y-3">
                          {previewData.data.gaps.slice(0, 5).map((gap: any, idx: number) => (
                            <div key={idx} className="bg-muted p-3 rounded-md">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant={gap.severity === "critical" ? "destructive" : "secondary"}>
                                  {gap.severity?.toUpperCase() || "MEDIUM"}
                                </Badge>
                                <span className="font-medium">{gap.controlId}</span>
                              </div>
                              <p className="text-sm text-muted-foreground">{gap.gapDescription}</p>
                              {gap.remediationGuidance && (
                                <p className="text-sm mt-2"><span className="font-medium">Remediation:</span> {gap.remediationGuidance}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {previewData.data.auditReadiness && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Audit Readiness</h3>
                        <div className="bg-muted p-4 rounded-md">
                          <div className="grid grid-cols-2 gap-4 mb-3">
                            <div>
                              <div className="text-sm text-muted-foreground">Readiness Score</div>
                              <div className="text-2xl font-bold">{previewData.data.auditReadiness.score || 0}%</div>
                            </div>
                            <div>
                              <div className="text-sm text-muted-foreground">Compliant Controls</div>
                              <div className="text-2xl font-bold">
                                {previewData.data.auditReadiness.readyControls || 0} / {previewData.data.auditReadiness.totalControls || 0}
                              </div>
                            </div>
                          </div>
                          {previewData.data.auditReadiness.priorityActions && Array.isArray(previewData.data.auditReadiness.priorityActions) && (
                            <div>
                              <div className="text-sm font-medium mb-2">Priority Actions:</div>
                              <ul className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
                                {previewData.data.auditReadiness.priorityActions.slice(0, 3).map((action: string, idx: number) => (
                                  <li key={idx}>{action}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Breach Chain specific preview sections */}
                    {previewData.data.reportType === "breach_chain" && previewData.data.phases && Array.isArray(previewData.data.phases) && previewData.data.phases.length > 0 && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Breach Chain Phase Execution</h3>
                        <div className="space-y-2">
                          {previewData.data.phases.map((phase: any, idx: number) => (
                            <div key={idx} className="bg-muted p-3 rounded-md flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <span className="text-xs font-mono bg-background px-2 py-1 rounded">{idx + 1}</span>
                                <span className="font-medium">{phase.name}</span>
                              </div>
                              <div className="flex items-center gap-3">
                                <Badge variant={phase.status === "completed" ? "default" : phase.status === "failed" ? "destructive" : "secondary"}
                                  className={phase.status === "completed" ? "bg-green-500/20 text-green-400 border-green-500/30" : ""}>
                                  {phase.status?.toUpperCase() || "UNKNOWN"}
                                </Badge>
                                <span className="text-sm text-muted-foreground">{phase.findingCount || 0} findings</span>
                                {phase.durationMs > 0 && (
                                  <span className="text-sm text-muted-foreground">{Math.round(phase.durationMs / 1000)}s</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {previewData.data.reportType === "breach_chain" && previewData.data.overallRiskScore !== undefined && (
                      <div>
                        <h3 className="font-semibold text-lg mb-2">Breach Impact Summary</h3>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                          <div className="bg-muted p-3 rounded-md">
                            <div className="text-sm text-muted-foreground">Risk Score</div>
                            <div className={`text-2xl font-bold ${
                              previewData.data.overallRiskScore >= 80 ? "text-red-500" :
                              previewData.data.overallRiskScore >= 60 ? "text-orange-500" :
                              previewData.data.overallRiskScore >= 40 ? "text-yellow-500" : "text-green-500"
                            }`}>{previewData.data.overallRiskScore}/100</div>
                            <div className="text-xs text-muted-foreground">{previewData.data.riskTier}</div>
                          </div>
                          {previewData.data.assetsCompromised !== undefined && (
                            <div className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">Assets Compromised</div>
                              <div className="text-2xl font-bold">{previewData.data.assetsCompromised}</div>
                            </div>
                          )}
                          {previewData.data.credentialsHarvested !== undefined && (
                            <div className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">Credentials Harvested</div>
                              <div className="text-2xl font-bold">{previewData.data.credentialsHarvested}</div>
                            </div>
                          )}
                          {previewData.data.maxPrivilegeAchieved && previewData.data.maxPrivilegeAchieved !== "none" && (
                            <div className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">Max Privilege</div>
                              <div className="text-lg font-bold">{previewData.data.maxPrivilegeAchieved.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</div>
                            </div>
                          )}
                          {previewData.data.domainsBreached && previewData.data.domainsBreached.length > 0 && (
                            <div className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">Domains Breached</div>
                              <div className="text-lg font-bold">{previewData.data.domainsBreached.length}</div>
                            </div>
                          )}
                          {previewData.data.executionMode && (
                            <div className="bg-muted p-3 rounded-md">
                              <div className="text-sm text-muted-foreground">Execution Mode</div>
                              <div className="text-lg font-bold">{previewData.data.executionMode.replace(/\b\w/g, (c: string) => c.toUpperCase())}</div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {!previewData.data.executiveSummary && !previewData.data.recommendations && !previewData.data.findings && (
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
    </div>
  );
}
