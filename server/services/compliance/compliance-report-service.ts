import { randomUUID } from "crypto";
import {
  COMPLIANCE_FRAMEWORKS,
  VULNERABILITY_TO_CONTROL_MAPPINGS,
  ComplianceControl,
  ComplianceFramework,
} from "./compliance-templates";

export type ReportFormat = "json" | "html" | "pdf" | "csv";
export type FrameworkId = "nist-800-53" | "pci-dss" | "soc2" | "hipaa";

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  affectedAssets: string[];
  evidence?: string;
  remediation: string;
  mitreId?: string;
  cvssScore?: number;
}

export interface ComplianceReportRequest {
  frameworkId: FrameworkId;
  organizationName: string;
  findings: Finding[];
  assessmentDate?: Date;
  assessmentScope?: string;
  assessor?: string;
  includePassingControls?: boolean;
  includeRemediationPlan?: boolean;
}

export interface ControlMapping {
  controlId: string;
  controlTitle: string;
  controlFamily: string;
  status: "pass" | "fail" | "partial" | "not-tested";
  findings: Finding[];
  gaps: string[];
  recommendations: string[];
}

export interface ComplianceReport {
  id: string;
  frameworkId: string;
  frameworkName: string;
  frameworkVersion: string;
  organizationName: string;
  assessmentDate: Date;
  assessmentScope?: string;
  assessor?: string;
  executiveSummary: ExecutiveSummary;
  controlMappings: ControlMapping[];
  findings: Finding[];
  remediationPlan?: RemediationPlan;
  appendices: ReportAppendix[];
  generatedAt: Date;
}

export interface ExecutiveSummary {
  overallScore: number;
  totalControls: number;
  passingControls: number;
  failingControls: number;
  partialControls: number;
  notTestedControls: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  topRisks: string[];
  complianceGaps: string[];
  keyRecommendations: string[];
}

export interface RemediationPlan {
  prioritizedActions: RemediationAction[];
  estimatedEffort: string;
  timelineRecommendation: string;
  resourceRequirements: string[];
}

export interface RemediationAction {
  priority: number;
  controlId: string;
  action: string;
  effort: "low" | "medium" | "high";
  impact: "low" | "medium" | "high";
  deadline?: string;
  owner?: string;
}

export interface ReportAppendix {
  title: string;
  content: string;
}

class ComplianceReportService {
  generateReport(request: ComplianceReportRequest): ComplianceReport {
    const framework = COMPLIANCE_FRAMEWORKS[request.frameworkId];
    if (!framework) {
      throw new Error(`Unknown framework: ${request.frameworkId}`);
    }

    const controlMappings = this.mapFindingsToControls(
      framework,
      request.findings,
      request.frameworkId
    );

    const executiveSummary = this.generateExecutiveSummary(
      controlMappings,
      request.findings
    );

    const remediationPlan = request.includeRemediationPlan
      ? this.generateRemediationPlan(controlMappings, request.findings)
      : undefined;

    const appendices = this.generateAppendices(framework, request.findings);

    return {
      id: `compliance-report-${randomUUID().slice(0, 8)}`,
      frameworkId: framework.id,
      frameworkName: framework.name,
      frameworkVersion: framework.version,
      organizationName: request.organizationName,
      assessmentDate: request.assessmentDate || new Date(),
      assessmentScope: request.assessmentScope,
      assessor: request.assessor,
      executiveSummary,
      controlMappings: request.includePassingControls
        ? controlMappings
        : controlMappings.filter(cm => cm.status !== "pass" && cm.status !== "not-tested"),
      findings: request.findings,
      remediationPlan,
      appendices,
      generatedAt: new Date(),
    };
  }

  private mapFindingsToControls(
    framework: ComplianceFramework,
    findings: Finding[],
    frameworkId: FrameworkId
  ): ControlMapping[] {
    const mappings: ControlMapping[] = [];
    const vulnMappings = VULNERABILITY_TO_CONTROL_MAPPINGS[frameworkId] || {};

    for (const control of framework.controls) {
      const relatedFindings: Finding[] = [];
      const gaps: string[] = [];
      const recommendations: string[] = [];

      for (const finding of findings) {
        const mappedControls = vulnMappings[finding.category] || [];
        if (mappedControls.includes(control.id)) {
          relatedFindings.push(finding);
        }
      }

      let status: "pass" | "fail" | "partial" | "not-tested" = "not-tested";
      
      if (relatedFindings.length > 0) {
        const hasCriticalOrHigh = relatedFindings.some(
          f => f.severity === "critical" || f.severity === "high"
        );
        status = hasCriticalOrHigh ? "fail" : "partial";

        for (const finding of relatedFindings) {
          gaps.push(`${finding.title} affects compliance with ${control.id}`);
        }

        recommendations.push(
          `Address ${relatedFindings.length} finding(s) related to ${control.title}`
        );

        if (hasCriticalOrHigh) {
          recommendations.push(
            `Priority: Remediate critical/high severity findings immediately`
          );
        }
      } else if (findings.length > 0) {
        status = "pass";
      }

      mappings.push({
        controlId: control.id,
        controlTitle: control.title,
        controlFamily: control.family,
        status,
        findings: relatedFindings,
        gaps,
        recommendations,
      });
    }

    return mappings;
  }

  private generateExecutiveSummary(
    controlMappings: ControlMapping[],
    findings: Finding[]
  ): ExecutiveSummary {
    const passingControls = controlMappings.filter(c => c.status === "pass").length;
    const failingControls = controlMappings.filter(c => c.status === "fail").length;
    const partialControls = controlMappings.filter(c => c.status === "partial").length;
    const notTestedControls = controlMappings.filter(c => c.status === "not-tested").length;
    
    const totalControls = controlMappings.length;
    const testedControls = totalControls - notTestedControls;
    const overallScore = testedControls > 0
      ? Math.round((passingControls / testedControls) * 100)
      : 0;

    const criticalFindings = findings.filter(f => f.severity === "critical").length;
    const highFindings = findings.filter(f => f.severity === "high").length;
    const mediumFindings = findings.filter(f => f.severity === "medium").length;
    const lowFindings = findings.filter(f => f.severity === "low").length;

    const topRisks = findings
      .filter(f => f.severity === "critical" || f.severity === "high")
      .slice(0, 5)
      .map(f => f.title);

    const failingFamilies = Array.from(new Set(
      controlMappings
        .filter(c => c.status === "fail")
        .map(c => c.controlFamily)
    ));

    const complianceGaps = failingFamilies.map(
      family => `Gaps identified in ${family} controls`
    );

    const keyRecommendations: string[] = [];
    if (criticalFindings > 0) {
      keyRecommendations.push(
        `Immediately address ${criticalFindings} critical finding(s)`
      );
    }
    if (highFindings > 0) {
      keyRecommendations.push(
        `Remediate ${highFindings} high severity finding(s) within 30 days`
      );
    }
    if (failingControls > 0) {
      keyRecommendations.push(
        `Review and remediate ${failingControls} failing control(s)`
      );
    }
    if (overallScore < 70) {
      keyRecommendations.push(
        `Improve overall compliance score from ${overallScore}% to target 85%+`
      );
    }

    return {
      overallScore,
      totalControls,
      passingControls,
      failingControls,
      partialControls,
      notTestedControls,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      topRisks,
      complianceGaps,
      keyRecommendations,
    };
  }

  private generateRemediationPlan(
    controlMappings: ControlMapping[],
    findings: Finding[]
  ): RemediationPlan {
    const prioritizedActions: RemediationAction[] = [];
    let priority = 1;

    const criticalFindings = findings.filter(f => f.severity === "critical");
    for (const finding of criticalFindings) {
      prioritizedActions.push({
        priority: priority++,
        controlId: this.findPrimaryControl(finding, controlMappings),
        action: finding.remediation,
        effort: this.estimateEffort(finding),
        impact: "high",
        deadline: "Immediate",
      });
    }

    const highFindings = findings.filter(f => f.severity === "high");
    for (const finding of highFindings) {
      prioritizedActions.push({
        priority: priority++,
        controlId: this.findPrimaryControl(finding, controlMappings),
        action: finding.remediation,
        effort: this.estimateEffort(finding),
        impact: "high",
        deadline: "30 days",
      });
    }

    const mediumFindings = findings.filter(f => f.severity === "medium");
    for (const finding of mediumFindings) {
      prioritizedActions.push({
        priority: priority++,
        controlId: this.findPrimaryControl(finding, controlMappings),
        action: finding.remediation,
        effort: this.estimateEffort(finding),
        impact: "medium",
        deadline: "90 days",
      });
    }

    const totalActions = prioritizedActions.length;
    const highEffortCount = prioritizedActions.filter(a => a.effort === "high").length;
    
    let estimatedEffort = "Low";
    if (totalActions > 10 || highEffortCount > 3) {
      estimatedEffort = "High";
    } else if (totalActions > 5 || highEffortCount > 1) {
      estimatedEffort = "Medium";
    }

    let timelineRecommendation = "1-2 months";
    if (criticalFindings.length > 0) {
      timelineRecommendation = "Immediate action required, full remediation in 3-6 months";
    } else if (highFindings.length > 3) {
      timelineRecommendation = "3-4 months";
    }

    const resourceRequirements: string[] = [];
    if (findings.some(f => f.category.includes("Authentication"))) {
      resourceRequirements.push("Identity and Access Management team");
    }
    if (findings.some(f => f.category.includes("Network"))) {
      resourceRequirements.push("Network Security team");
    }
    if (findings.some(f => f.category.includes("Application") || f.category.includes("Injection"))) {
      resourceRequirements.push("Application Security team");
    }
    if (findings.some(f => f.category.includes("Cloud") || f.category.includes("IAM"))) {
      resourceRequirements.push("Cloud Security team");
    }
    if (resourceRequirements.length === 0) {
      resourceRequirements.push("Security Operations team");
    }

    return {
      prioritizedActions,
      estimatedEffort,
      timelineRecommendation,
      resourceRequirements,
    };
  }

  private findPrimaryControl(finding: Finding, mappings: ControlMapping[]): string {
    const relatedMapping = mappings.find(m => 
      m.findings.some(f => f.id === finding.id)
    );
    return relatedMapping?.controlId || "N/A";
  }

  private estimateEffort(finding: Finding): "low" | "medium" | "high" {
    if (finding.category.includes("Configuration") || finding.category.includes("Insecure")) {
      return "low";
    }
    if (finding.category.includes("Injection") || finding.category.includes("RCE")) {
      return "high";
    }
    return "medium";
  }

  private generateAppendices(
    framework: ComplianceFramework,
    findings: Finding[]
  ): ReportAppendix[] {
    const appendices: ReportAppendix[] = [];

    appendices.push({
      title: "Methodology",
      content: `This compliance assessment was conducted using OdinForge AI automated security validation platform. 
The assessment evaluated ${findings.length} security findings against ${framework.controls.length} controls 
from the ${framework.name} ${framework.version} framework. Findings were mapped to applicable controls 
using industry-standard vulnerability-to-control mappings and MITRE ATT&CK framework correlations.`,
    });

    const mitreIds = Array.from(new Set(findings.filter(f => f.mitreId).map(f => f.mitreId)));
    if (mitreIds.length > 0) {
      appendices.push({
        title: "MITRE ATT&CK Mapping",
        content: `The following MITRE ATT&CK techniques were identified:\n\n${
          mitreIds.map(id => `- ${id}`).join("\n")
        }`,
      });
    }

    appendices.push({
      title: "Control Reference",
      content: `${framework.name} ${framework.version} - ${framework.description}\n\n` +
        `Total Controls: ${framework.controls.length}\n` +
        `Control Families: ${Array.from(new Set(framework.controls.map(c => c.family))).join(", ")}`,
    });

    return appendices;
  }

  exportToHTML(report: ComplianceReport): string {
    const severityColors: Record<string, string> = {
      critical: "#dc3545",
      high: "#fd7e14",
      medium: "#ffc107",
      low: "#28a745",
      info: "#17a2b8",
    };

    const statusColors: Record<string, string> = {
      pass: "#28a745",
      fail: "#dc3545",
      partial: "#ffc107",
      "not-tested": "#6c757d",
    };

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${report.frameworkName} Compliance Report - ${report.organizationName}</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 24px; }
    .header h1 { margin: 0 0 10px 0; font-size: 28px; }
    .header .subtitle { opacity: 0.8; font-size: 16px; }
    .card { background: white; border-radius: 8px; padding: 24px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .card h2 { margin-top: 0; color: #1a1a2e; border-bottom: 2px solid #e9ecef; padding-bottom: 12px; }
    .score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: bold; margin: 0 auto 20px; }
    .score-high { background: #d4edda; color: #155724; border: 4px solid #28a745; }
    .score-medium { background: #fff3cd; color: #856404; border: 4px solid #ffc107; }
    .score-low { background: #f8d7da; color: #721c24; border: 4px solid #dc3545; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }
    .stat-item { text-align: center; padding: 16px; background: #f8f9fa; border-radius: 6px; }
    .stat-value { font-size: 24px; font-weight: bold; color: #1a1a2e; }
    .stat-label { font-size: 12px; color: #6c757d; text-transform: uppercase; }
    .finding { border-left: 4px solid; padding: 12px 16px; margin: 12px 0; background: #f8f9fa; border-radius: 0 6px 6px 0; }
    .control-row { display: flex; align-items: center; padding: 12px; border-bottom: 1px solid #e9ecef; }
    .control-row:last-child { border-bottom: none; }
    .status-badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 500; color: white; text-transform: uppercase; }
    .remediation-item { padding: 16px; border: 1px solid #e9ecef; border-radius: 6px; margin: 12px 0; }
    .priority-badge { display: inline-block; width: 28px; height: 28px; border-radius: 50%; background: #1a1a2e; color: white; text-align: center; line-height: 28px; margin-right: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }
    th { background: #f8f9fa; font-weight: 600; }
    .footer { text-align: center; padding: 20px; color: #6c757d; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${report.frameworkName} ${report.frameworkVersion} Compliance Report</h1>
      <div class="subtitle">
        ${report.organizationName} | Assessment Date: ${report.assessmentDate.toLocaleDateString()}
        ${report.assessor ? ` | Assessor: ${report.assessor}` : ""}
      </div>
    </div>

    <div class="card">
      <h2>Executive Summary</h2>
      <div class="score-circle ${report.executiveSummary.overallScore >= 80 ? 'score-high' : report.executiveSummary.overallScore >= 50 ? 'score-medium' : 'score-low'}">
        ${report.executiveSummary.overallScore}%
      </div>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-value">${report.executiveSummary.totalControls}</div>
          <div class="stat-label">Total Controls</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: #28a745">${report.executiveSummary.passingControls}</div>
          <div class="stat-label">Passing</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: #dc3545">${report.executiveSummary.failingControls}</div>
          <div class="stat-label">Failing</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: #ffc107">${report.executiveSummary.partialControls}</div>
          <div class="stat-label">Partial</div>
        </div>
      </div>
      
      <h3>Key Findings Summary</h3>
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-value" style="color: ${severityColors.critical}">${report.executiveSummary.criticalFindings}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: ${severityColors.high}">${report.executiveSummary.highFindings}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: ${severityColors.medium}">${report.executiveSummary.mediumFindings}</div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-item">
          <div class="stat-value" style="color: ${severityColors.low}">${report.executiveSummary.lowFindings}</div>
          <div class="stat-label">Low</div>
        </div>
      </div>

      ${report.executiveSummary.keyRecommendations.length > 0 ? `
        <h3>Key Recommendations</h3>
        <ul>
          ${report.executiveSummary.keyRecommendations.map(r => `<li>${r}</li>`).join("")}
        </ul>
      ` : ""}
    </div>

    <div class="card">
      <h2>Control Assessment Results</h2>
      <table>
        <thead>
          <tr>
            <th>Control ID</th>
            <th>Title</th>
            <th>Family</th>
            <th>Status</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          ${report.controlMappings.map(cm => `
            <tr>
              <td><strong>${cm.controlId}</strong></td>
              <td>${cm.controlTitle}</td>
              <td>${cm.controlFamily}</td>
              <td><span class="status-badge" style="background: ${statusColors[cm.status]}">${cm.status}</span></td>
              <td>${cm.findings.length}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Security Findings</h2>
      ${report.findings.map(f => `
        <div class="finding" style="border-color: ${severityColors[f.severity]}">
          <strong>${f.title}</strong>
          <span class="status-badge" style="background: ${severityColors[f.severity]}; margin-left: 12px">${f.severity}</span>
          ${f.mitreId ? `<span style="margin-left: 8px; font-size: 12px; color: #6c757d">${f.mitreId}</span>` : ""}
          <p style="margin: 8px 0">${f.description}</p>
          <p style="margin: 8px 0; color: #6c757d"><strong>Remediation:</strong> ${f.remediation}</p>
        </div>
      `).join("")}
    </div>

    ${report.remediationPlan ? `
      <div class="card">
        <h2>Remediation Plan</h2>
        <p><strong>Estimated Effort:</strong> ${report.remediationPlan.estimatedEffort}</p>
        <p><strong>Timeline:</strong> ${report.remediationPlan.timelineRecommendation}</p>
        <p><strong>Resources Required:</strong> ${report.remediationPlan.resourceRequirements.join(", ")}</p>
        
        <h3>Prioritized Actions</h3>
        ${report.remediationPlan.prioritizedActions.slice(0, 10).map(action => `
          <div class="remediation-item">
            <span class="priority-badge">${action.priority}</span>
            <strong>${action.controlId}</strong> - ${action.action}
            <div style="margin-top: 8px; font-size: 13px; color: #6c757d">
              Effort: ${action.effort} | Impact: ${action.impact} | Deadline: ${action.deadline || "TBD"}
            </div>
          </div>
        `).join("")}
      </div>
    ` : ""}

    <div class="footer">
      Generated by OdinForge AI Platform | Report ID: ${report.id} | ${report.generatedAt.toISOString()}
    </div>
  </div>
</body>
</html>`;
  }

  exportToCSV(report: ComplianceReport): string {
    const headers = [
      "Control ID",
      "Control Title",
      "Control Family",
      "Status",
      "Finding Count",
      "Gaps",
      "Recommendations",
    ];

    const rows = report.controlMappings.map(cm => [
      cm.controlId,
      `"${cm.controlTitle.replace(/"/g, '""')}"`,
      `"${cm.controlFamily}"`,
      cm.status,
      cm.findings.length.toString(),
      `"${cm.gaps.join("; ").replace(/"/g, '""')}"`,
      `"${cm.recommendations.join("; ").replace(/"/g, '""')}"`,
    ]);

    return [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
  }

  getAvailableFrameworks(): ComplianceFramework[] {
    return Object.values(COMPLIANCE_FRAMEWORKS);
  }

  getFramework(frameworkId: string): ComplianceFramework | undefined {
    return COMPLIANCE_FRAMEWORKS[frameworkId];
  }

  getControlsByFamily(frameworkId: string, family: string): ComplianceControl[] {
    const framework = COMPLIANCE_FRAMEWORKS[frameworkId];
    if (!framework) return [];
    return framework.controls.filter(c => c.family === family);
  }
}

export const complianceReportService = new ComplianceReportService();
