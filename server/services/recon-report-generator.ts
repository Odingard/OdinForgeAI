import { storage } from "../storage";
import type { ReconScan, WebAppReconScan } from "@shared/schema";

export interface DomainScanReportData {
  reportMetadata: {
    generatedAt: string;
    reportType: "domain_scan";
    target: string;
    scanId: string;
  };
  executiveSummary: {
    target: string;
    scanTime: string;
    riskLevel: string;
    overallScore: number;
    summary: string;
  };
  networkExposure: {
    openPorts: number;
    highRiskPorts: number;
    services: Array<{ port: number; service: string; version?: string }>;
    findings: Array<{ protocol: string; finding: string; severity: string }>;
  } | null;
  transportSecurity: {
    tlsVersion: string;
    cipherSuite: string;
    forwardSecrecy: boolean;
    hstsEnabled: boolean;
    gradeEstimate: string;
    risks: Array<{ type: string; description: string; severity: string }>;
  } | null;
  applicationIdentity: {
    frameworks: string[];
    cms?: string;
    webServer?: string;
    language?: string;
    libraries: string[];
    wafDetected?: string;
  } | null;
  authenticationSurface: {
    loginPages: Array<{ path: string; riskLevel: string }>;
    adminPanels: Array<{ path: string; protected: boolean }>;
    vulnerabilities: string[];
  } | null;
  dnsInfrastructure: {
    ipAddresses: string[];
    mailServers: string[];
    nameServers: string[];
    subdomains: string[];
    mailSecurityIssues: string[];
  } | null;
  attackReadiness: {
    overallScore: number;
    riskLevel: string;
    categoryScores: Record<string, number>;
    attackVectors: Array<{ vector: string; feasibility: string; mitreAttackId?: string }>;
    prioritizedRemediations: Array<{ priority: number; finding: string; remediation: string; effort: string }>;
  } | null;
  exposures: Array<{
    type: string;
    severity: string;
    description: string;
    evidence: string;
  }>;
}

export interface WebAppScanReportData {
  reportMetadata: {
    generatedAt: string;
    reportType: "web_app_scan";
    targetUrl: string;
    scanId: string;
  };
  executiveSummary: {
    targetUrl: string;
    scanDuration: number;
    totalEndpoints: number;
    validatedVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    summary: string;
  };
  reconnaissance: {
    targetUrl: string;
    durationMs: number;
    applicationInfo?: {
      technologies: string[];
      frameworks: string[];
      server?: string;
    };
    attackSurface: {
      totalEndpoints: number;
      highRiskEndpoints: number;
      authenticatedEndpoints: number;
      parameterizedEndpoints: number;
    };
    endpoints: Array<{
      path: string;
      method: string;
      parameters: string[];
      riskLevel: string;
    }>;
  } | null;
  validatedFindings: Array<{
    id: string;
    vulnerabilityType: string;
    severity: string;
    confidence: number;
    endpointUrl: string;
    endpointPath: string;
    parameter?: string;
    evidence?: string;
    recommendations?: string[];
    reproductionSteps?: string[];
    cvssEstimate?: number;
    mitreAttackId?: string;
    llmValidation?: {
      isValid: boolean;
      confidence: number;
      reasoning: string;
    };
  }>;
  agentDispatchSummary: {
    totalTasks: number;
    completedTasks: number;
    failedTasks: number;
    falsePositivesFiltered: number;
    executionTimeMs: number;
    tasksByType: Record<string, number>;
  } | null;
  remediationPlan: Array<{
    priority: number;
    vulnerability: string;
    recommendation: string;
    effort: string;
    impact: string;
  }>;
}

export class ReconReportGenerator {
  async generateDomainScanReport(scanId: string): Promise<DomainScanReportData | null> {
    const scan = await storage.getReconScan(scanId);
    if (!scan) {
      return null;
    }

    const attackReadiness = scan.attackReadiness as any;
    const networkExposure = scan.networkExposure as any;
    const transportSecurity = scan.transportSecurity as any;
    const applicationIdentity = scan.applicationIdentity as any;
    const authSurface = scan.authenticationSurface as any;
    const dnsEnum = scan.dnsEnum as any;
    const infrastructure = scan.infrastructure as any;

    const riskLevel = attackReadiness?.riskLevel || "unknown";
    const overallScore = attackReadiness?.overallScore || 0;

    const exposures: DomainScanReportData["exposures"] = [];
    
    if (transportSecurity?.downgradeRisks) {
      for (const risk of transportSecurity.downgradeRisks) {
        exposures.push({
          type: "transport_security",
          severity: risk.severity || "medium",
          description: risk.description,
          evidence: risk.type,
        });
      }
    }

    if (authSurface?.vulnerabilities) {
      for (const vuln of authSurface.vulnerabilities) {
        exposures.push({
          type: "authentication",
          severity: "medium",
          description: vuln,
          evidence: "Authentication surface analysis",
        });
      }
    }

    if (infrastructure?.mailSecurityIssues) {
      for (const issue of infrastructure.mailSecurityIssues) {
        exposures.push({
          type: "email_security",
          severity: "low",
          description: issue,
          evidence: "DNS/Email configuration",
        });
      }
    }

    return {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        reportType: "domain_scan",
        target: scan.target,
        scanId,
      },
      executiveSummary: {
        target: scan.target,
        scanTime: scan.scanTime?.toISOString() || new Date().toISOString(),
        riskLevel,
        overallScore,
        summary: attackReadiness?.executiveSummary || 
          `External reconnaissance scan of ${scan.target} identified ${exposures.length} potential security concerns. Risk level: ${riskLevel.toUpperCase()}.`,
      },
      networkExposure: networkExposure ? {
        openPorts: networkExposure.openPorts || 0,
        highRiskPorts: networkExposure.highRiskPorts || 0,
        services: networkExposure.serviceVersions || [],
        findings: networkExposure.protocolFindings || [],
      } : null,
      transportSecurity: transportSecurity ? {
        tlsVersion: transportSecurity.tlsVersion || "Unknown",
        cipherSuite: transportSecurity.cipherSuite || "Unknown",
        forwardSecrecy: transportSecurity.forwardSecrecy || false,
        hstsEnabled: transportSecurity.hstsEnabled || false,
        gradeEstimate: transportSecurity.gradeEstimate || "Unknown",
        risks: (transportSecurity.downgradeRisks || []).map((r: any) => ({
          type: r.type,
          description: r.description,
          severity: r.severity,
        })),
      } : null,
      applicationIdentity: applicationIdentity ? {
        frameworks: applicationIdentity.frameworks || [],
        cms: applicationIdentity.cms,
        webServer: applicationIdentity.webServer,
        language: applicationIdentity.language,
        libraries: applicationIdentity.libraries || [],
        wafDetected: applicationIdentity.wafDetected,
      } : null,
      authenticationSurface: authSurface ? {
        loginPages: (authSurface.loginPages || []).map((p: any) => ({
          path: p.path,
          riskLevel: p.riskLevel,
        })),
        adminPanels: (authSurface.adminPanels || []).map((p: any) => ({
          path: p.path,
          protected: p.protected,
        })),
        vulnerabilities: authSurface.vulnerabilities || [],
      } : null,
      dnsInfrastructure: (dnsEnum || infrastructure) ? {
        ipAddresses: [...(dnsEnum?.ipv4 || []), ...(dnsEnum?.ipv6 || [])],
        mailServers: (dnsEnum?.mx || []).map((m: any) => m.exchange || m),
        nameServers: dnsEnum?.ns || [],
        subdomains: infrastructure?.subdomains || [],
        mailSecurityIssues: infrastructure?.mailSecurityIssues || [],
      } : null,
      attackReadiness: attackReadiness ? {
        overallScore: attackReadiness.overallScore,
        riskLevel: attackReadiness.riskLevel,
        categoryScores: attackReadiness.categoryScores || {},
        attackVectors: (attackReadiness.attackVectors || []).map((v: any) => ({
          vector: v.vector,
          feasibility: v.feasibility,
          mitreAttackId: v.mitreAttackId,
        })),
        prioritizedRemediations: (attackReadiness.prioritizedRemediations || []).map((r: any) => ({
          priority: r.priority,
          finding: r.finding,
          remediation: r.remediation,
          effort: r.effort,
        })),
      } : null,
      exposures,
    };
  }

  async generateWebAppScanReport(scanId: string): Promise<WebAppScanReportData | null> {
    const scan = await storage.getWebAppReconScan(scanId);
    if (!scan) {
      return null;
    }

    const reconResult = scan.reconResult as any;
    const validatedFindings = (scan.validatedFindings as any[]) || [];
    const agentResult = scan.agentDispatchResult as any;

    const criticalCount = validatedFindings.filter(f => f.severity === "critical").length;
    const highCount = validatedFindings.filter(f => f.severity === "high").length;
    const mediumCount = validatedFindings.filter(f => f.severity === "medium").length;
    const lowCount = validatedFindings.filter(f => f.severity === "low").length;

    const remediationPlan: WebAppScanReportData["remediationPlan"] = [];
    const seenVulnTypes = new Set<string>();
    
    for (const finding of validatedFindings.sort((a, b) => {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
    })) {
      if (!seenVulnTypes.has(finding.vulnerabilityType)) {
        seenVulnTypes.add(finding.vulnerabilityType);
        remediationPlan.push({
          priority: remediationPlan.length + 1,
          vulnerability: finding.vulnerabilityType,
          recommendation: finding.recommendations?.[0] || `Address ${finding.vulnerabilityType} vulnerability`,
          effort: finding.severity === "critical" || finding.severity === "high" ? "quick" : "moderate",
          impact: finding.severity === "critical" || finding.severity === "high" ? "high" : "medium",
        });
      }
    }

    return {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        reportType: "web_app_scan",
        targetUrl: scan.targetUrl,
        scanId,
      },
      executiveSummary: {
        targetUrl: scan.targetUrl,
        scanDuration: reconResult?.durationMs || 0,
        totalEndpoints: reconResult?.attackSurface?.totalEndpoints || reconResult?.endpoints?.length || 0,
        validatedVulnerabilities: validatedFindings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        summary: validatedFindings.length > 0
          ? `Web application security scan of ${scan.targetUrl} identified ${validatedFindings.length} validated vulnerabilities. ${criticalCount} critical, ${highCount} high, ${mediumCount} medium, and ${lowCount} low severity findings require attention.`
          : `Web application security scan of ${scan.targetUrl} completed. No validated vulnerabilities were identified.`,
      },
      reconnaissance: reconResult ? {
        targetUrl: reconResult.targetUrl || scan.targetUrl,
        durationMs: reconResult.durationMs || 0,
        applicationInfo: reconResult.applicationInfo ? {
          technologies: reconResult.applicationInfo.technologies || [],
          frameworks: reconResult.applicationInfo.frameworks || [],
          server: reconResult.applicationInfo.server,
        } : undefined,
        attackSurface: {
          totalEndpoints: reconResult.attackSurface?.totalEndpoints || reconResult.endpoints?.length || 0,
          highRiskEndpoints: reconResult.attackSurface?.highRiskEndpoints || 0,
          authenticatedEndpoints: reconResult.attackSurface?.authenticatedEndpoints || 0,
          parameterizedEndpoints: reconResult.attackSurface?.parameterizedEndpoints || 0,
        },
        endpoints: (reconResult.endpoints || []).slice(0, 50).map((e: any) => ({
          path: e.path || e.url,
          method: e.method || "GET",
          parameters: e.parameters || [],
          riskLevel: e.riskLevel || "low",
        })),
      } : null,
      validatedFindings: validatedFindings.map(f => ({
        id: f.id,
        vulnerabilityType: f.vulnerabilityType,
        severity: f.severity,
        confidence: f.confidence,
        endpointUrl: f.endpointUrl,
        endpointPath: f.endpointPath,
        parameter: f.parameter,
        evidence: f.evidence,
        recommendations: f.recommendations,
        reproductionSteps: f.reproductionSteps,
        cvssEstimate: f.cvssEstimate,
        mitreAttackId: f.mitreAttackId,
        llmValidation: f.llmValidation,
      })),
      agentDispatchSummary: agentResult ? {
        totalTasks: agentResult.totalTasks || 0,
        completedTasks: agentResult.completedTasks || 0,
        failedTasks: agentResult.failedTasks || 0,
        falsePositivesFiltered: agentResult.falsePositivesFiltered || 0,
        executionTimeMs: agentResult.executionTimeMs || 0,
        tasksByType: agentResult.tasksByVulnerabilityType || {},
      } : null,
      remediationPlan,
    };
  }

  exportToJSON(data: DomainScanReportData | WebAppScanReportData): string {
    return JSON.stringify(data, null, 2);
  }

  exportToCSV(data: DomainScanReportData | WebAppScanReportData): string {
    if (data.reportMetadata.reportType === "domain_scan") {
      const domainData = data as DomainScanReportData;
      const rows = [
        ["Category", "Type", "Severity", "Description", "Evidence"],
        ...domainData.exposures.map(e => [
          e.type,
          e.type,
          e.severity,
          e.description,
          e.evidence
        ])
      ];
      return rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
    } else {
      const webAppData = data as WebAppScanReportData;
      const rows = [
        ["Vulnerability Type", "Severity", "Confidence", "Endpoint", "Parameter", "CVSS", "Recommendations"],
        ...webAppData.validatedFindings.map(f => [
          f.vulnerabilityType,
          f.severity,
          String(f.confidence),
          f.endpointUrl,
          f.parameter || "",
          String(f.cvssEstimate || ""),
          (f.recommendations || []).join("; ")
        ])
      ];
      return rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
    }
  }
}

export const reconReportGenerator = new ReconReportGenerator();
