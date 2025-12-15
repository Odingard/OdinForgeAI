import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
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
} from "lucide-react";
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
  { value: "json", label: "JSON", icon: FileJson },
  { value: "csv", label: "CSV", icon: FileSpreadsheet },
];

export default function Reports() {
  const { toast } = useToast();
  const [isGenerateOpen, setIsGenerateOpen] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("executive_summary");
  const [selectedFormat, setSelectedFormat] = useState<string>("json");
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

  const handleDownload = (report: Report) => {
    const content = JSON.stringify(report.content, null, 2);
    const blob = new Blob([content], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.title.replace(/\s+/g, "_")}.json`;
    a.click();
    URL.revokeObjectURL(url);
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
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleDownload(report)}
                          data-testid={`btn-download-${report.id}`}
                        >
                          <Download className="w-4 h-4" />
                        </Button>
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
                  <pre className="text-sm font-mono bg-muted p-4 rounded-md overflow-x-auto">
                    {JSON.stringify(previewData.data, null, 2)}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
