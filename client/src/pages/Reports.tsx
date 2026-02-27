import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
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

function severityChipClass(severity: string | undefined) {
  switch (severity?.toLowerCase()) {
    case "critical": return "f-chip f-chip-crit";
    case "high": return "f-chip f-chip-high";
    case "medium": return "f-chip f-chip-med";
    case "low": return "f-chip f-chip-low";
    default: return "f-chip f-chip-gray";
  }
}

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
  const [reportsTab, setReportsTab] = useState("reports");
  const [downloadMenuId, setDownloadMenuId] = useState<string | null>(null);
  const downloadMenuRef = useRef<HTMLDivElement>(null);

  // Engagement metadata state
  const [clientName, setClientName] = useState<string>("");
  const [methodology, setMethodology] = useState<string>("OWASP");
  const [testingApproach, setTestingApproach] = useState<string>("gray_box");
  const [leadTester, setLeadTester] = useState<string>("");
  const [showEngagementOptions, setShowEngagementOptions] = useState(false);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (downloadMenuRef.current && !downloadMenuRef.current.contains(e.target as Node)) {
        setDownloadMenuId(null);
      }
    };
    if (downloadMenuId) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [downloadMenuId]);

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
      case "executive_summary": return <Briefcase style={{ width: 16, height: 16, color: "var(--falcon-t3)" }} />;
      case "technical_deep_dive": return <FileText style={{ width: 16, height: 16, color: "var(--falcon-t3)" }} />;
      case "compliance_mapping": return <Shield style={{ width: 16, height: 16, color: "var(--falcon-t3)" }} />;
      case "breach_chain":
      case "breach_chain_analysis": return <Link2 style={{ width: 16, height: 16, color: "var(--falcon-t3)" }} />;
      default: return <FileText style={{ width: 16, height: 16, color: "var(--falcon-t3)" }} />;
    }
  };

  const getStatusChip = (status: string) => {
    switch (status) {
      case "completed":
        return (
          <span className="f-chip f-chip-low" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <CheckCircle2 style={{ width: 10, height: 10 }} />Completed
          </span>
        );
      case "generating":
        return (
          <span className="f-chip f-chip-gray" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <Clock style={{ width: 10, height: 10 }} />Generating
          </span>
        );
      case "failed":
        return (
          <span className="f-chip f-chip-crit" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <AlertTriangle style={{ width: 10, height: 10 }} />Failed
          </span>
        );
      default:
        return <span className="f-chip f-chip-gray">{status}</span>;
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ color: "var(--falcon-t3)", fontSize: 12 }}>Loading reports...</div>
      </div>
    );
  }

  return (
    <div data-testid="reports-page">
      {/* Page header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Reports</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            // security report generation and analytics
          </p>
        </div>
        <button className="f-btn f-btn-primary" data-testid="btn-generate-report" disabled={!canGenerateReport}
          onClick={() => setIsGenerateOpen(true)}
          style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          {canGenerateReport ? <Plus style={{ width: 14, height: 14 }} /> : <Lock style={{ width: 14, height: 14 }} />}
          Generate Report
        </button>
      </div>

      {/* Generate Report Modal */}
      {isGenerateOpen && (
        <div className="f-modal-overlay" onClick={() => setIsGenerateOpen(false)}>
          <div className="f-modal f-modal-lg" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <h2 className="f-modal-title">Generate New Report</h2>
              <p className="f-modal-desc">Configure and generate a security assessment report</p>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 16, padding: "16px 0" }}>
              {/* Report Type Selection */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Report Type</label>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                  {reportTypes.map((type) => (
                    <div
                      key={type.value}
                      className="f-panel"
                      style={{
                        cursor: "pointer",
                        padding: 12,
                        borderColor: selectedType === type.value ? "var(--falcon-blue-hi)" : undefined,
                        background: selectedType === type.value ? "rgba(59,130,246,0.06)" : undefined,
                      }}
                      onClick={() => setSelectedType(type.value)}
                      data-testid={`card-report-type-${type.value}`}
                    >
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 8 }}>
                        <type.icon style={{ width: 20, height: 20, color: selectedType === type.value ? "var(--falcon-blue-hi)" : "var(--falcon-t3)" }} />
                        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{type.label}</span>
                        <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>{type.description}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Compliance Framework */}
              {selectedType === "compliance_mapping" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Compliance Framework</label>
                  <select className="f-select" value={selectedFramework} onChange={e => setSelectedFramework(e.target.value)} data-testid="select-framework">
                    {complianceFrameworks.map((fw) => (
                      <option key={fw.value} value={fw.value}>{fw.label}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Date Range */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Date From</label>
                    <input
                      type="date"
                      value={dateFrom}
                      onChange={(e) => setDateFrom(e.target.value)}
                      data-testid="input-date-from"
                      style={{
                        background: "var(--falcon-panel)",
                        border: "1px solid var(--falcon-border)",
                        borderRadius: 4,
                        padding: "6px 10px",
                        fontSize: 12,
                        color: "var(--falcon-t1)",
                        fontFamily: "var(--font-mono)",
                      }}
                    />
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Date To</label>
                    <input
                      type="date"
                      value={dateTo}
                      onChange={(e) => setDateTo(e.target.value)}
                      data-testid="input-date-to"
                      style={{
                        background: "var(--falcon-panel)",
                        border: "1px solid var(--falcon-border)",
                        borderRadius: 4,
                        padding: "6px 10px",
                        fontSize: 12,
                        color: "var(--falcon-t1)",
                        fontFamily: "var(--font-mono)",
                      }}
                    />
                  </div>
                </div>
                {dateFrom && dateTo && (
                  <div style={{ display: "flex", justifyContent: "space-between", padding: "0 4px", fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                    <span>From: {formatDTG(new Date(dateFrom + "T00:00:00Z"))}</span>
                    <span>To: {formatDTG(new Date(dateTo + "T23:59:59Z"))}</span>
                  </div>
                )}
              </div>

              {/* Export Format */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Export Format</label>
                <div style={{ display: "flex", gap: 8 }}>
                  {exportFormats.map((fmt) => (
                    <button
                      key={fmt.value}
                      className={`f-btn ${selectedFormat === fmt.value ? "f-btn-primary" : "f-btn-ghost"}`}
                      style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11 }}
                      onClick={() => setSelectedFormat(fmt.value)}
                      data-testid={`btn-format-${fmt.value}`}
                    >
                      <fmt.icon style={{ width: 14, height: 14 }} />
                      {fmt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Separator */}
              <div style={{ height: 1, background: "var(--falcon-border)", margin: "4px 0" }} />

              {/* Engagement Context */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Engagement Context</label>
                  <button
                    className="f-btn f-btn-ghost"
                    style={{ fontSize: 10 }}
                    onClick={() => setShowEngagementOptions(!showEngagementOptions)}
                    data-testid="btn-toggle-engagement"
                  >
                    {showEngagementOptions ? "Hide Options" : "Add Professional Context"}
                  </button>
                </div>
                <p style={{ fontSize: 10, color: "var(--falcon-t4)" }}>
                  Add engagement metadata for consulting-grade deliverables
                </p>

                {showEngagementOptions && (
                  <div style={{
                    display: "flex", flexDirection: "column", gap: 12, padding: 12, borderRadius: 6,
                    background: "var(--falcon-panel-2)", border: "1px solid var(--falcon-border)",
                  }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        <label style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)" }}>Client Name</label>
                        <input
                          placeholder="Acme Corporation"
                          value={clientName}
                          onChange={(e) => setClientName(e.target.value)}
                          data-testid="input-client-name"
                          style={{
                            background: "var(--falcon-panel)",
                            border: "1px solid var(--falcon-border)",
                            borderRadius: 4,
                            padding: "6px 10px",
                            fontSize: 12,
                            color: "var(--falcon-t1)",
                          }}
                        />
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        <label style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)" }}>Lead Tester</label>
                        <input
                          placeholder="John Smith, OSCP"
                          value={leadTester}
                          onChange={(e) => setLeadTester(e.target.value)}
                          data-testid="input-lead-tester"
                          style={{
                            background: "var(--falcon-panel)",
                            border: "1px solid var(--falcon-border)",
                            borderRadius: 4,
                            padding: "6px 10px",
                            fontSize: 12,
                            color: "var(--falcon-t1)",
                          }}
                        />
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        <label style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)" }}>Methodology</label>
                        <select className="f-select" value={methodology} onChange={e => setMethodology(e.target.value)} data-testid="select-methodology">
                          <option value="OWASP">OWASP</option>
                          <option value="PTES">PTES</option>
                          <option value="NIST">NIST</option>
                          <option value="OSSTMM">OSSTMM</option>
                          <option value="ISSAF">ISSAF</option>
                          <option value="custom">Custom</option>
                        </select>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                        <label style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)" }}>Testing Approach</label>
                        <select className="f-select" value={testingApproach} onChange={e => setTestingApproach(e.target.value)} data-testid="select-testing-approach">
                          <option value="black_box">Black Box</option>
                          <option value="gray_box">Gray Box</option>
                          <option value="white_box">White Box</option>
                        </select>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* V2 AI Notice */}
              {isV2Enabled && (
                <>
                  <div style={{ height: 1, background: "var(--falcon-border)", margin: "4px 0" }} />
                  <div style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderRadius: 6,
                    background: "rgba(6,182,212,0.08)", border: "1px solid rgba(6,182,212,0.2)",
                  }}>
                    <Sparkles style={{ width: 14, height: 14, color: "var(--falcon-blue-hi)", flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: "var(--falcon-t3)" }}>
                      AI Narrative Engine active — reports use evidence-anchored breach narratives
                    </span>
                  </div>
                </>
              )}
            </div>
            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => setIsGenerateOpen(false)}>Cancel</button>
              <button
                className="f-btn f-btn-primary"
                onClick={handleGenerate}
                disabled={generateMutation.isPending || generateV2Mutation.isPending}
                data-testid="btn-confirm-generate"
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
              >
                {(generateMutation.isPending || generateV2Mutation.isPending) && (
                  <Loader2 style={{ width: 14, height: 14, animation: "spin 1s linear infinite" }} />
                )}
                Generate Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Executive view notice */}
      {isExecutiveView && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", marginBottom: 16,
          background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)", borderRadius: 6,
          fontSize: 11, color: "var(--falcon-t3)",
        }}>
          <Briefcase style={{ width: 14, height: 14, flexShrink: 0 }} />
          You are viewing reports in executive mode. Only executive summary reports are available.
          Technical details and raw findings are not shown.
        </div>
      )}

      <div className="f-tab-bar">
        <button className={`f-tab ${reportsTab === "reports" ? "active" : ""}`} onClick={() => setReportsTab("reports")} data-testid="tab-reports">
          <FileText style={{ width: 14, height: 14, marginRight: 6 }} />
          Generated Reports
        </button>
        <button className={`f-tab ${reportsTab === "trends" ? "active" : ""}`} onClick={() => setReportsTab("trends")} data-testid="tab-trends">
          <BarChart3 style={{ width: 14, height: 14, marginRight: 6 }} />
          Trends
        </button>
        <button className={`f-tab ${reportsTab === "preview" ? "active" : ""}`} onClick={() => previewData && setReportsTab("preview")} data-testid="tab-preview" style={{ opacity: previewData ? 1 : 0.4, cursor: previewData ? "pointer" : "default" }}>
          <FileText style={{ width: 14, height: 14, marginRight: 6 }} />
          Latest Preview
        </button>
      </div>

      {/* === Generated Reports Tab === */}
      {reportsTab === "reports" && (
        <>
          {reports.length === 0 ? (
            <div className="f-panel" style={{ padding: "48px 24px", textAlign: "center" }}>
              <FileText style={{ width: 40, height: 40, color: "var(--falcon-t4)", margin: "0 auto 12px" }} />
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>No reports generated yet</div>
              <div style={{ fontSize: 11, color: "var(--falcon-t4)", marginBottom: 16 }}>
                Generate your first report to see it here
              </div>
              <button className="f-btn f-btn-primary" onClick={() => setIsGenerateOpen(true)} data-testid="btn-generate-first"
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                <Plus style={{ width: 14, height: 14 }} />
                Generate Report
              </button>
            </div>
          ) : (
            <div className="f-panel">
              <div className="f-panel-head">
                <div className="f-panel-title">
                  <span className="f-panel-dot b" />
                  Generated Reports
                </div>
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                  {reports.length} report{reports.length !== 1 ? "s" : ""}
                </span>
              </div>
              <div>
                {reports.map((report) => (
                  <div
                    key={report.id}
                    data-testid={`card-report-${report.id}`}
                    style={{
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 16px",
                      borderBottom: "1px solid var(--falcon-border)",
                    }}
                  >
                    <div style={{ padding: 6, background: "var(--falcon-panel-2)", borderRadius: 4 }}>
                      {getReportIcon(report.reportType)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{report.title}</div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 2 }}>
                        <DTGRangeDisplay
                          startDate={report.dateRangeFrom}
                          endDate={report.dateRangeTo}
                          compact
                        />
                        {report.framework && (
                          <span className="f-chip f-chip-gray" style={{ fontSize: 9 }}>
                            {report.framework.toUpperCase()}
                          </span>
                        )}
                      </div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      {getStatusChip(report.status)}
                      <div style={{ position: "relative" }} ref={downloadMenuId === report.id ? downloadMenuRef : undefined}>
                        <button
                          className="f-btn f-btn-ghost"
                          style={{ padding: "4px 6px" }}
                          data-testid={`btn-download-${report.id}`}
                          onClick={() => setDownloadMenuId(downloadMenuId === report.id ? null : report.id)}
                        >
                          <Download style={{ width: 14, height: 14 }} />
                        </button>
                        {downloadMenuId === report.id && (
                          <div style={{
                            position: "absolute", right: 0, top: "100%", marginTop: 4, zIndex: 50,
                            background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)",
                            borderRadius: 6, padding: 4, minWidth: 160, boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
                          }}>
                            <button className="f-btn f-btn-ghost" style={{ width: "100%", justifyContent: "flex-start", padding: "6px 10px", fontSize: 11 }}
                              onClick={() => { handleDownload(report, "pdf"); setDownloadMenuId(null); }}
                              data-testid={`btn-download-pdf-${report.id}`}>
                              <FileType style={{ width: 14, height: 14, marginRight: 8 }} />Download PDF
                            </button>
                            <button className="f-btn f-btn-ghost" style={{ width: "100%", justifyContent: "flex-start", padding: "6px 10px", fontSize: 11 }}
                              onClick={() => { handleDownload(report, "json"); setDownloadMenuId(null); }}
                              data-testid={`btn-download-json-${report.id}`}>
                              <FileJson style={{ width: 14, height: 14, marginRight: 8 }} />Download JSON
                            </button>
                            <button className="f-btn f-btn-ghost" style={{ width: "100%", justifyContent: "flex-start", padding: "6px 10px", fontSize: 11 }}
                              onClick={() => { handleDownload(report, "csv"); setDownloadMenuId(null); }}
                              data-testid={`btn-download-csv-${report.id}`}>
                              <FileSpreadsheet style={{ width: 14, height: 14, marginRight: 8 }} />Download CSV
                            </button>
                          </div>
                        )}
                      </div>
                      {canDeleteReport && (
                        <button
                          className="f-btn f-btn-ghost"
                          style={{ padding: "4px 6px", color: "var(--falcon-red)" }}
                          onClick={() => deleteMutation.mutate(report.id)}
                          disabled={deleteMutation.isPending}
                          data-testid={`btn-delete-${report.id}`}
                        >
                          <Trash2 style={{ width: 14, height: 14 }} />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* === Trends Tab === */}
      {reportsTab === "trends" && (
          <div className="f-panel">
            <div className="f-panel-head">
              <div className="f-panel-title">
                <span className="f-panel-dot" style={{ background: "#a78bfa" }} />
                Report Generation Trends
              </div>
              <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                last 30 days
              </span>
            </div>
            <div style={{ padding: 16 }}>
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
                <div style={{ textAlign: "center", padding: "48px 0" }}>
                  <BarChart3 style={{ width: 40, height: 40, margin: "0 auto 12px", opacity: 0.3, color: "var(--falcon-t4)" }} />
                  <p style={{ fontSize: 11, color: "var(--falcon-t4)" }}>No reports generated yet</p>
                </div>
              )}

              {/* Report Type Distribution */}
              {reports.length > 0 && (
                <div style={{ marginTop: 24 }}>
                  <div style={{ height: 1, background: "var(--falcon-border)", margin: "0 0 16px 0" }} />
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 12 }}>Report Type Distribution</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                    {reportTypes.map(type => {
                      const count = reports.filter(r => r.reportType === type.value || (type.value === "breach_chain_analysis" && r.reportType === "breach_chain")).length;
                      const percentage = reports.length > 0 ? ((count / reports.length) * 100).toFixed(1) : "0";

                      return (
                        <div key={type.value} className="f-panel" style={{ padding: 12 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                            <type.icon style={{ width: 14, height: 14, color: "var(--falcon-t3)" }} />
                            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--falcon-t1)" }}>{type.label}</span>
                          </div>
                          <div style={{ fontSize: 22, fontWeight: 700, color: "var(--falcon-t1)" }}>{count}</div>
                          <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>{percentage}% of total</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
      )}

      {/* === Preview Tab === */}
      {reportsTab === "preview" && previewData && (
            <div className="f-panel">
              <div className="f-panel-head">
                <div className="f-panel-title">
                  <span className="f-panel-dot g" />
                  {previewData.title}
                </div>
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                  generated report preview
                </span>
              </div>
              <div style={{ padding: 16 }}>
                <div style={{ maxHeight: 500, overflowY: "auto" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
                    {/* Executive Summary */}
                    {previewData.data.executiveSummary && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Executive Summary</div>
                        <p style={{ fontSize: 12, color: "var(--falcon-t3)", lineHeight: 1.5 }}>{previewData.data.executiveSummary}</p>
                      </div>
                    )}

                    {/* Key Metrics */}
                    {previewData.data.keyMetrics && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Key Metrics</div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                          {Object.entries(previewData.data.keyMetrics).map(([key, value]) => (
                            <div key={key} style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>{key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase())}</div>
                              <div style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-t1)", marginTop: 4 }}>{String(value)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    {previewData.data.recommendations && Array.isArray(previewData.data.recommendations) && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Recommendations</div>
                        <ul style={{ listStyleType: "disc", paddingLeft: 20, display: "flex", flexDirection: "column", gap: 8 }}>
                          {previewData.data.recommendations.map((rec: any, idx: number) => (
                            <li key={idx} style={{ fontSize: 12, color: "var(--falcon-t3)" }}>
                              {typeof rec === "string" ? rec : (
                                rec.action ? (
                                  <span>
                                    {rec.priority && <span className="f-chip f-chip-gray" style={{ marginRight: 6 }}>Priority {rec.priority}</span>}
                                    {rec.action}
                                    {rec.impact && <span style={{ fontSize: 11, fontStyle: "italic", marginLeft: 6, color: "var(--falcon-t4)" }}>({rec.impact})</span>}
                                  </span>
                                ) : (rec.description || rec.title || rec.text || "Recommendation pending")
                              )}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Findings */}
                    {previewData.data.findings && Array.isArray(previewData.data.findings) && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Findings</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {previewData.data.findings.slice(0, 10).map((finding: any, idx: number) => (
                            <div key={idx} style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                                <span className={severityChipClass(finding.severity)}>
                                  {finding.severity?.toUpperCase() || "N/A"}
                                </span>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{finding.title || "Untitled Finding"}</span>
                              </div>
                              <p style={{ fontSize: 11, color: "var(--falcon-t3)" }}>{finding.description}</p>
                              {finding.recommendation && (
                                <p style={{ fontSize: 11, marginTop: 8, color: "var(--falcon-t3)" }}>
                                  <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>Recommendation:</span> {finding.recommendation}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Top Business Risks */}
                    {previewData.data.topRisks && Array.isArray(previewData.data.topRisks) && previewData.data.topRisks.length > 0 && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Top Business Risks</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {previewData.data.topRisks.slice(0, 5).map((risk: any, idx: number) => (
                            <div key={idx} style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                                <span className={severityChipClass(risk.severity)}>
                                  {risk.severity?.toUpperCase() || "N/A"}
                                </span>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{risk.assetId || "Asset"}</span>
                                {risk.financialImpact && (
                                  <span style={{ fontSize: 11, color: "var(--falcon-t4)", marginLeft: "auto" }}>{risk.financialImpact}</span>
                                )}
                              </div>
                              <p style={{ fontSize: 11, color: "var(--falcon-t3)" }}>{risk.riskDescription}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Attack Path Analysis */}
                    {previewData.data.attackPaths && Array.isArray(previewData.data.attackPaths) && previewData.data.attackPaths.length > 0 && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Attack Path Analysis</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {previewData.data.attackPaths.slice(0, 3).map((path: any, idx: number) => (
                            <div key={idx} style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Path {idx + 1}: {path.assetId || "Target"}</span>
                                {path.complexity && <span className="f-chip f-chip-gray">Complexity: {path.complexity}</span>}
                                {path.timeToCompromise && <span className="f-chip f-chip-gray">{path.timeToCompromise}</span>}
                              </div>
                              {path.steps && Array.isArray(path.steps) && (
                                <div style={{ fontSize: 11, color: "var(--falcon-t3)" }}>
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

                    {/* Compliance Gaps */}
                    {previewData.data.gaps && Array.isArray(previewData.data.gaps) && previewData.data.gaps.length > 0 && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Compliance Gaps</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {previewData.data.gaps.slice(0, 5).map((gap: any, idx: number) => (
                            <div key={idx} style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                                <span className={severityChipClass(gap.severity)}>
                                  {gap.severity?.toUpperCase() || "MEDIUM"}
                                </span>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{gap.controlId}</span>
                              </div>
                              <p style={{ fontSize: 11, color: "var(--falcon-t3)" }}>{gap.gapDescription}</p>
                              {gap.remediationGuidance && (
                                <p style={{ fontSize: 11, marginTop: 8, color: "var(--falcon-t3)" }}>
                                  <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>Remediation:</span> {gap.remediationGuidance}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Audit Readiness */}
                    {previewData.data.auditReadiness && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Audit Readiness</div>
                        <div style={{ background: "var(--falcon-panel-2)", padding: 16, borderRadius: 6 }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 12 }}>
                            <div>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Readiness Score</div>
                              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.auditReadiness.score || 0}%</div>
                            </div>
                            <div>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Compliant Controls</div>
                              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--falcon-t1)" }}>
                                {previewData.data.auditReadiness.readyControls || 0} / {previewData.data.auditReadiness.totalControls || 0}
                              </div>
                            </div>
                          </div>
                          {previewData.data.auditReadiness.priorityActions && Array.isArray(previewData.data.auditReadiness.priorityActions) && (
                            <div>
                              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Priority Actions:</div>
                              <ol style={{ paddingLeft: 20, display: "flex", flexDirection: "column", gap: 4 }}>
                                {previewData.data.auditReadiness.priorityActions.slice(0, 3).map((action: string, idx: number) => (
                                  <li key={idx} style={{ fontSize: 11, color: "var(--falcon-t3)" }}>{action}</li>
                                ))}
                              </ol>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Breach Chain specific preview sections */}
                    {previewData.data.reportType === "breach_chain" && previewData.data.phases && Array.isArray(previewData.data.phases) && previewData.data.phases.length > 0 && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Breach Chain Phase Execution</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                          {previewData.data.phases.map((phase: any, idx: number) => (
                            <div key={idx} style={{
                              background: "var(--falcon-panel-2)", padding: "10px 12px", borderRadius: 6,
                              display: "flex", alignItems: "center", justifyContent: "space-between",
                            }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                <span style={{
                                  fontSize: 10, fontFamily: "var(--font-mono)",
                                  background: "var(--falcon-panel)", padding: "2px 8px", borderRadius: 3,
                                  color: "var(--falcon-t3)",
                                }}>{idx + 1}</span>
                                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{phase.name}</span>
                              </div>
                              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                <span className={
                                  phase.status === "completed" ? "f-chip f-chip-low" :
                                  phase.status === "failed" ? "f-chip f-chip-crit" :
                                  "f-chip f-chip-gray"
                                }>
                                  {phase.status?.toUpperCase() || "UNKNOWN"}
                                </span>
                                <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>{phase.findingCount || 0} findings</span>
                                {phase.durationMs > 0 && (
                                  <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>{Math.round(phase.durationMs / 1000)}s</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Breach Impact Summary */}
                    {previewData.data.reportType === "breach_chain" && previewData.data.overallRiskScore !== undefined && (
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Breach Impact Summary</div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                          <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                            <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Risk Score</div>
                            <div style={{
                              fontSize: 22, fontWeight: 700,
                              color: previewData.data.overallRiskScore >= 80 ? "var(--falcon-red)" :
                                     previewData.data.overallRiskScore >= 60 ? "var(--falcon-orange)" :
                                     previewData.data.overallRiskScore >= 40 ? "var(--falcon-yellow)" : "var(--falcon-green)",
                            }}>{previewData.data.overallRiskScore}/100</div>
                            <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>{previewData.data.riskTier}</div>
                          </div>
                          {previewData.data.assetsCompromised !== undefined && (
                            <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Assets Compromised</div>
                              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.assetsCompromised}</div>
                            </div>
                          )}
                          {previewData.data.credentialsHarvested !== undefined && (
                            <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Credentials Harvested</div>
                              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.credentialsHarvested}</div>
                            </div>
                          )}
                          {previewData.data.maxPrivilegeAchieved && previewData.data.maxPrivilegeAchieved !== "none" && (
                            <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Max Privilege</div>
                              <div style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.maxPrivilegeAchieved.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</div>
                            </div>
                          )}
                          {previewData.data.domainsBreached && previewData.data.domainsBreached.length > 0 && (
                            <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Domains Breached</div>
                              <div style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.domainsBreached.length}</div>
                            </div>
                          )}
                          {previewData.data.executionMode && (
                            <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Execution Mode</div>
                              <div style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-t1)" }}>{previewData.data.executionMode.replace(/\b\w/g, (c: string) => c.toUpperCase())}</div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Fallback raw JSON */}
                    {!previewData.data.executiveSummary && !previewData.data.recommendations && !previewData.data.findings && (
                      <pre style={{
                        fontSize: 11, fontFamily: "var(--font-mono)",
                        background: "var(--falcon-panel-2)", padding: 16, borderRadius: 6,
                        overflowX: "auto", color: "var(--falcon-t3)",
                      }}>
                        {JSON.stringify(previewData.data, null, 2)}
                      </pre>
                    )}
                  </div>
                </div>
              </div>
            </div>
      )}
    </div>
  );
}
