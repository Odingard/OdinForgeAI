import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description?: string;
  controlCount: number;
}

export interface ComplianceControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "not_started" | "in_progress" | "completed" | "not_applicable";
  evidenceCount: number;
  lastAudit?: string;
}

export interface ComplianceCoverage {
  framework: string;
  totalControls: number;
  compliantControls: number;
  nonCompliantControls: number;
  notApplicableControls: number;
  coveragePercentage: number;
}

export interface ComplianceGap {
  controlId: string;
  title: string;
  framework: string;
  severity: string;
  recommendation: string;
  estimatedEffort: string;
}

export function useComplianceFrameworks() {
  return useQuery<ComplianceFramework[]>({
    queryKey: ["/api/compliance/frameworks"],
    refetchInterval: false,
  });
}

export function useComplianceControls(framework: string | null) {
  return useQuery<ComplianceControl[]>({
    queryKey: [`/api/compliance/controls/${framework}`],
    enabled: !!framework,
  });
}

export function useComplianceCoverage(framework?: string) {
  const queryKey = framework
    ? [`/api/compliance/coverage?framework=${framework}`]
    : ["/api/compliance/coverage"];

  return useQuery<ComplianceCoverage[]>({
    queryKey,
    refetchInterval: 300000, // 5 minutes
  });
}

export function useComplianceGaps(framework?: string) {
  const queryKey = framework
    ? [`/api/compliance/gaps?framework=${framework}`]
    : ["/api/compliance/gaps"];

  return useQuery<ComplianceGap[]>({
    queryKey,
    refetchInterval: 300000,
  });
}

export function useMapFindingToControl() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      findingId: string;
      controlId: string;
      framework: string;
    }) => {
      const response = await apiRequest("POST", "/api/compliance/map-finding", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Mapping Created",
        description: "Finding mapped to compliance control",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/coverage"] });
      queryClient.invalidateQueries({ queryKey: ["/api/compliance/controls"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Mapping Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useGenerateGapReport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      framework: string;
      startDate?: string;
      endDate?: string;
    }) => {
      const response = await apiRequest("POST", "/api/compliance/gap-report", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Report Generated",
        description: "Compliance gap report has been created",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useGenerateComplianceReport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      framework: string;
      format: "pdf" | "json" | "csv";
      includeEvidence?: boolean;
    }) => {
      const response = await apiRequest("POST", "/api/compliance/reports/generate", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Report Generated",
        description: "Compliance report is ready for download",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Generation Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
