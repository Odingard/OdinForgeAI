export type ComplianceFramework = "soc2" | "iso27001" | "nist_csf" | "pci_dss";

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  framework: ComplianceFramework;
  category: string;
}

export interface ComplianceMapping {
  findingType: string;
  controls: {
    framework: ComplianceFramework;
    controlId: string;
    controlName: string;
    relevance: "direct" | "supporting" | "related";
  }[];
}

export interface ComplianceGapReport {
  framework: ComplianceFramework;
  generatedAt: Date;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  partialControls: number;
  notTestedControls: number;
  overallScore: number;
  controlResults: ControlResult[];
  recommendations: string[];
}

export interface ControlResult {
  controlId: string;
  controlName: string;
  category: string;
  status: "passed" | "failed" | "partial" | "not_tested";
  findings: string[];
  evidence: string[];
}

const SOC2_CONTROLS: ComplianceControl[] = [
  { id: "CC1.1", name: "Control Environment", description: "Management demonstrates commitment to integrity and ethical values", framework: "soc2", category: "Common Criteria" },
  { id: "CC5.1", name: "Control Activities", description: "Selects and develops control activities that contribute to mitigation of risks", framework: "soc2", category: "Common Criteria" },
  { id: "CC5.2", name: "Logical Access Controls", description: "Logical access security software and infrastructure is implemented", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.1", name: "Logical and Physical Access", description: "Entity implements logical access security measures", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.2", name: "Authentication", description: "Prior to granting access, the entity validates user identity", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.3", name: "Authorization", description: "Entity authorizes, modifies, or removes access based on roles", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.6", name: "System Boundaries", description: "Entity implements security measures to protect against threats from outside system boundaries", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.7", name: "Transmission Protection", description: "Entity protects data during transmission", framework: "soc2", category: "Common Criteria" },
  { id: "CC6.8", name: "Software Development", description: "Entity implements controls over software development and changes", framework: "soc2", category: "Common Criteria" },
  { id: "CC7.1", name: "Detection", description: "Entity detects and identifies security events", framework: "soc2", category: "Common Criteria" },
  { id: "CC7.2", name: "Monitoring", description: "Entity monitors security configuration and vulnerabilities", framework: "soc2", category: "Common Criteria" },
  { id: "CC7.3", name: "Event Analysis", description: "Entity evaluates security events to determine impact", framework: "soc2", category: "Common Criteria" },
  { id: "CC7.4", name: "Incident Response", description: "Entity responds to identified security incidents", framework: "soc2", category: "Common Criteria" },
  { id: "CC8.1", name: "Change Management", description: "Entity authorizes, designs, develops, and implements changes", framework: "soc2", category: "Common Criteria" },
];

const ISO27001_CONTROLS: ComplianceControl[] = [
  { id: "A.5.1", name: "Information Security Policies", description: "Policies for information security", framework: "iso27001", category: "Organizational Controls" },
  { id: "A.5.15", name: "Access Control", description: "Rules and procedures for controlling access to information", framework: "iso27001", category: "Organizational Controls" },
  { id: "A.5.17", name: "Authentication Information", description: "Management of authentication information", framework: "iso27001", category: "Organizational Controls" },
  { id: "A.8.3", name: "Information Access Restriction", description: "Access to information and application functions shall be restricted", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.5", name: "Secure Authentication", description: "Secure authentication technologies and procedures", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.6", name: "Capacity Management", description: "Use of resources shall be monitored and adjusted", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.9", name: "Configuration Management", description: "Configurations shall be established, documented, implemented, monitored and reviewed", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.12", name: "Data Leakage Prevention", description: "Data leakage prevention measures shall be applied", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.16", name: "Monitoring Activities", description: "Networks, systems and applications shall be monitored", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.20", name: "Network Security", description: "Networks and network devices shall be secured", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.24", name: "Use of Cryptography", description: "Rules for effective use of cryptography shall be defined", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.25", name: "Secure Development Life Cycle", description: "Rules for secure development of software and systems", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.26", name: "Application Security Requirements", description: "Information security requirements shall be identified", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.28", name: "Secure Coding", description: "Secure coding principles shall be applied to software development", framework: "iso27001", category: "Technological Controls" },
  { id: "A.8.29", name: "Security Testing in Development", description: "Security testing shall be defined and performed", framework: "iso27001", category: "Technological Controls" },
];

const NIST_CSF_CONTROLS: ComplianceControl[] = [
  { id: "ID.AM-1", name: "Asset Inventory", description: "Physical devices and systems are inventoried", framework: "nist_csf", category: "Identify" },
  { id: "ID.AM-2", name: "Software Inventory", description: "Software platforms and applications are inventoried", framework: "nist_csf", category: "Identify" },
  { id: "ID.RA-1", name: "Vulnerability Identification", description: "Asset vulnerabilities are identified and documented", framework: "nist_csf", category: "Identify" },
  { id: "ID.RA-5", name: "Risk Response", description: "Threats, vulnerabilities, and likelihoods are used to determine risk", framework: "nist_csf", category: "Identify" },
  { id: "PR.AC-1", name: "Identity Management", description: "Identities and credentials are managed", framework: "nist_csf", category: "Protect" },
  { id: "PR.AC-3", name: "Remote Access", description: "Remote access is managed", framework: "nist_csf", category: "Protect" },
  { id: "PR.AC-4", name: "Access Permissions", description: "Access permissions are managed using least privilege", framework: "nist_csf", category: "Protect" },
  { id: "PR.AC-5", name: "Network Integrity", description: "Network integrity is protected", framework: "nist_csf", category: "Protect" },
  { id: "PR.DS-1", name: "Data-at-rest", description: "Data-at-rest is protected", framework: "nist_csf", category: "Protect" },
  { id: "PR.DS-2", name: "Data-in-transit", description: "Data-in-transit is protected", framework: "nist_csf", category: "Protect" },
  { id: "PR.DS-5", name: "Data Leakage", description: "Protections against data leaks are implemented", framework: "nist_csf", category: "Protect" },
  { id: "PR.IP-12", name: "Vulnerability Management", description: "A vulnerability management plan is developed and implemented", framework: "nist_csf", category: "Protect" },
  { id: "DE.AE-1", name: "Network Operations", description: "A baseline of network operations is established", framework: "nist_csf", category: "Detect" },
  { id: "DE.CM-1", name: "Network Monitoring", description: "The network is monitored to detect potential cybersecurity events", framework: "nist_csf", category: "Detect" },
  { id: "DE.CM-4", name: "Malicious Code", description: "Malicious code is detected", framework: "nist_csf", category: "Detect" },
  { id: "DE.CM-7", name: "Unauthorized Monitoring", description: "Monitoring for unauthorized personnel and connections", framework: "nist_csf", category: "Detect" },
  { id: "DE.CM-8", name: "Vulnerability Scans", description: "Vulnerability scans are performed", framework: "nist_csf", category: "Detect" },
];

const PCI_DSS_CONTROLS: ComplianceControl[] = [
  { id: "1.1", name: "Network Security Controls", description: "Network security controls are defined and understood", framework: "pci_dss", category: "Network Security" },
  { id: "1.2", name: "Network Segmentation", description: "Network connections and traffic are restricted", framework: "pci_dss", category: "Network Security" },
  { id: "2.1", name: "Vendor Defaults", description: "Vendor-supplied defaults are changed before installation", framework: "pci_dss", category: "Secure Configurations" },
  { id: "2.2", name: "System Hardening", description: "System components are hardened", framework: "pci_dss", category: "Secure Configurations" },
  { id: "3.1", name: "Data Storage", description: "Processes for protecting stored account data are defined", framework: "pci_dss", category: "Protect Account Data" },
  { id: "3.4", name: "PAN Protection", description: "PAN is secured wherever it is stored", framework: "pci_dss", category: "Protect Account Data" },
  { id: "4.1", name: "Transmission Encryption", description: "Strong cryptography protects transmission over public networks", framework: "pci_dss", category: "Encrypt Transmissions" },
  { id: "5.1", name: "Anti-Malware", description: "Anti-malware solutions protect systems", framework: "pci_dss", category: "Anti-Malware" },
  { id: "5.2", name: "Malware Prevention", description: "Malware is prevented or detected and addressed", framework: "pci_dss", category: "Anti-Malware" },
  { id: "6.1", name: "Secure Development", description: "Secure development processes and standards are defined", framework: "pci_dss", category: "Secure Development" },
  { id: "6.2", name: "Software Security", description: "Bespoke and custom software is developed securely", framework: "pci_dss", category: "Secure Development" },
  { id: "6.3", name: "Vulnerability Management", description: "Security vulnerabilities are identified and addressed", framework: "pci_dss", category: "Secure Development" },
  { id: "6.4", name: "Web Application Security", description: "Public-facing web applications are protected", framework: "pci_dss", category: "Secure Development" },
  { id: "7.1", name: "Access Control", description: "Processes to restrict access are defined and understood", framework: "pci_dss", category: "Access Control" },
  { id: "7.2", name: "Least Privilege", description: "Access is appropriately assigned", framework: "pci_dss", category: "Access Control" },
  { id: "8.1", name: "User Identification", description: "Processes to identify users and authenticate access are defined", framework: "pci_dss", category: "User Identification" },
  { id: "8.2", name: "Authentication", description: "User identification and authentication are managed", framework: "pci_dss", category: "User Identification" },
  { id: "8.3", name: "Strong Authentication", description: "Strong authentication is established for users and admins", framework: "pci_dss", category: "User Identification" },
  { id: "10.1", name: "Logging", description: "Logging and monitoring is defined and understood", framework: "pci_dss", category: "Logging and Monitoring" },
  { id: "11.3", name: "Penetration Testing", description: "External and internal penetration testing is regularly performed", framework: "pci_dss", category: "Testing" },
  { id: "11.4", name: "Vulnerability Scanning", description: "External and internal vulnerability scans are regularly performed", framework: "pci_dss", category: "Testing" },
];

const FINDING_TYPE_MAPPINGS: Record<string, { framework: ComplianceFramework; controlId: string; relevance: "direct" | "supporting" | "related" }[]> = {
  sqli: [
    { framework: "soc2", controlId: "CC6.1", relevance: "direct" },
    { framework: "soc2", controlId: "CC6.6", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.28", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.26", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-5", relevance: "direct" },
    { framework: "nist_csf", controlId: "ID.RA-1", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.2", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.4", relevance: "direct" },
  ],
  xss: [
    { framework: "soc2", controlId: "CC6.6", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.28", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-5", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.2", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.4", relevance: "direct" },
  ],
  auth_bypass: [
    { framework: "soc2", controlId: "CC6.1", relevance: "direct" },
    { framework: "soc2", controlId: "CC6.2", relevance: "direct" },
    { framework: "soc2", controlId: "CC6.3", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.5", relevance: "direct" },
    { framework: "iso27001", controlId: "A.5.17", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-1", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-4", relevance: "direct" },
    { framework: "pci_dss", controlId: "7.1", relevance: "direct" },
    { framework: "pci_dss", controlId: "8.2", relevance: "direct" },
    { framework: "pci_dss", controlId: "8.3", relevance: "direct" },
  ],
  idor: [
    { framework: "soc2", controlId: "CC6.3", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.3", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-4", relevance: "direct" },
    { framework: "pci_dss", controlId: "7.2", relevance: "direct" },
  ],
  ssrf: [
    { framework: "soc2", controlId: "CC6.6", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.20", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-5", relevance: "direct" },
    { framework: "pci_dss", controlId: "1.2", relevance: "direct" },
  ],
  command_injection: [
    { framework: "soc2", controlId: "CC6.1", relevance: "direct" },
    { framework: "soc2", controlId: "CC6.6", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.28", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-5", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.2", relevance: "direct" },
  ],
  path_traversal: [
    { framework: "soc2", controlId: "CC6.1", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.3", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-5", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.2", relevance: "direct" },
  ],
  default_credentials: [
    { framework: "soc2", controlId: "CC6.2", relevance: "direct" },
    { framework: "iso27001", controlId: "A.5.17", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-1", relevance: "direct" },
    { framework: "pci_dss", controlId: "2.1", relevance: "direct" },
    { framework: "pci_dss", controlId: "8.3", relevance: "direct" },
  ],
  weak_encryption: [
    { framework: "soc2", controlId: "CC6.7", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.24", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-1", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.DS-2", relevance: "direct" },
    { framework: "pci_dss", controlId: "3.4", relevance: "direct" },
    { framework: "pci_dss", controlId: "4.1", relevance: "direct" },
  ],
  missing_security_headers: [
    { framework: "soc2", controlId: "CC6.6", relevance: "supporting" },
    { framework: "iso27001", controlId: "A.8.9", relevance: "supporting" },
    { framework: "nist_csf", controlId: "PR.AC-5", relevance: "supporting" },
    { framework: "pci_dss", controlId: "6.4", relevance: "supporting" },
  ],
  open_relay: [
    { framework: "soc2", controlId: "CC6.6", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.20", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-5", relevance: "direct" },
    { framework: "pci_dss", controlId: "1.2", relevance: "direct" },
  ],
  ldap_injection: [
    { framework: "soc2", controlId: "CC6.1", relevance: "direct" },
    { framework: "iso27001", controlId: "A.8.28", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-1", relevance: "direct" },
    { framework: "pci_dss", controlId: "6.2", relevance: "direct" },
  ],
  iam_excessive_permissions: [
    { framework: "soc2", controlId: "CC6.3", relevance: "direct" },
    { framework: "iso27001", controlId: "A.5.15", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-4", relevance: "direct" },
    { framework: "pci_dss", controlId: "7.2", relevance: "direct" },
  ],
  iam_stale_credentials: [
    { framework: "soc2", controlId: "CC6.2", relevance: "direct" },
    { framework: "iso27001", controlId: "A.5.17", relevance: "direct" },
    { framework: "nist_csf", controlId: "PR.AC-1", relevance: "direct" },
    { framework: "pci_dss", controlId: "8.2", relevance: "direct" },
  ],
};

export function getAllControls(framework?: ComplianceFramework): ComplianceControl[] {
  if (framework) {
    switch (framework) {
      case "soc2": return SOC2_CONTROLS;
      case "iso27001": return ISO27001_CONTROLS;
      case "nist_csf": return NIST_CSF_CONTROLS;
      case "pci_dss": return PCI_DSS_CONTROLS;
    }
  }
  return [...SOC2_CONTROLS, ...ISO27001_CONTROLS, ...NIST_CSF_CONTROLS, ...PCI_DSS_CONTROLS];
}

export function getControlById(framework: ComplianceFramework, controlId: string): ComplianceControl | undefined {
  const controls = getAllControls(framework);
  return controls.find(c => c.id === controlId);
}

export function mapFindingToControls(findingType: string): ComplianceMapping {
  const mappings = FINDING_TYPE_MAPPINGS[findingType] || [];
  
  return {
    findingType,
    controls: mappings.map(m => {
      const control = getControlById(m.framework, m.controlId);
      return {
        framework: m.framework,
        controlId: m.controlId,
        controlName: control?.name || m.controlId,
        relevance: m.relevance,
      };
    }),
  };
}

export interface Finding {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  evidence?: string;
}

export function generateComplianceGapReport(
  framework: ComplianceFramework,
  findings: Finding[]
): ComplianceGapReport {
  const controls = getAllControls(framework);
  const controlResults: ControlResult[] = [];
  
  const failedControlIds = new Set<string>();
  const controlFindings: Record<string, string[]> = {};
  const controlEvidence: Record<string, string[]> = {};
  
  for (const finding of findings) {
    const mappings = FINDING_TYPE_MAPPINGS[finding.type] || [];
    
    for (const mapping of mappings) {
      if (mapping.framework !== framework) continue;
      
      failedControlIds.add(mapping.controlId);
      
      if (!controlFindings[mapping.controlId]) {
        controlFindings[mapping.controlId] = [];
      }
      controlFindings[mapping.controlId].push(finding.title);
      
      if (finding.evidence && !controlEvidence[mapping.controlId]) {
        controlEvidence[mapping.controlId] = [];
      }
      if (finding.evidence) {
        controlEvidence[mapping.controlId].push(finding.evidence);
      }
    }
  }
  
  let passed = 0, failed = 0, partial = 0, notTested = 0;
  
  for (const control of controls) {
    const hasFinding = failedControlIds.has(control.id);
    const status = hasFinding ? "failed" : "not_tested";
    
    if (status === "failed") failed++;
    else if (status === "not_tested") notTested++;
    else if (status === "passed") passed++;
    else partial++;
    
    controlResults.push({
      controlId: control.id,
      controlName: control.name,
      category: control.category,
      status,
      findings: controlFindings[control.id] || [],
      evidence: controlEvidence[control.id] || [],
    });
  }
  
  const testedControls = passed + failed + partial;
  const overallScore = testedControls > 0 
    ? Math.round((passed / testedControls) * 100) 
    : 0;
  
  const recommendations: string[] = [];
  
  const criticalFindings = findings.filter(f => f.severity === "critical");
  if (criticalFindings.length > 0) {
    recommendations.push(`Address ${criticalFindings.length} critical vulnerabilities immediately`);
  }
  
  if (failedControlIds.size > 0) {
    recommendations.push(`Review and remediate ${failedControlIds.size} failed controls`);
  }
  
  recommendations.push("Implement continuous vulnerability scanning");
  recommendations.push("Establish regular security assessments schedule");
  recommendations.push("Document compensating controls where gaps exist");
  
  return {
    framework,
    generatedAt: new Date(),
    totalControls: controls.length,
    passedControls: passed,
    failedControls: failed,
    partialControls: partial,
    notTestedControls: notTested,
    overallScore,
    controlResults,
    recommendations,
  };
}

export function generateComplianceReportMarkdown(report: ComplianceGapReport): string {
  const frameworkNames: Record<ComplianceFramework, string> = {
    soc2: "SOC 2",
    iso27001: "ISO 27001:2022",
    nist_csf: "NIST Cybersecurity Framework",
    pci_dss: "PCI DSS v4.0",
  };
  
  const lines: string[] = [
    `# ${frameworkNames[report.framework]} Compliance Gap Report`,
    "",
    `**Generated:** ${report.generatedAt.toISOString()}`,
    "",
    "## Executive Summary",
    "",
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total Controls | ${report.totalControls} |`,
    `| Failed Controls | ${report.failedControls} |`,
    `| Not Tested | ${report.notTestedControls} |`,
    `| Compliance Score | ${report.overallScore}% |`,
    "",
  ];
  
  if (report.failedControls > 0) {
    lines.push("## Failed Controls");
    lines.push("");
    
    const failedResults = report.controlResults.filter(r => r.status === "failed");
    
    for (const result of failedResults) {
      lines.push(`### ${result.controlId}: ${result.controlName}`);
      lines.push("");
      lines.push(`**Category:** ${result.category}`);
      lines.push("");
      lines.push("**Findings:**");
      for (const finding of result.findings) {
        lines.push(`- ${finding}`);
      }
      lines.push("");
    }
  }
  
  lines.push("## Recommendations");
  lines.push("");
  for (const rec of report.recommendations) {
    lines.push(`- ${rec}`);
  }
  lines.push("");
  
  lines.push("## All Controls Status");
  lines.push("");
  lines.push("| Control ID | Name | Category | Status |");
  lines.push("|------------|------|----------|--------|");
  
  for (const result of report.controlResults) {
    const statusIcon = {
      passed: "PASS",
      failed: "FAIL",
      partial: "PARTIAL",
      not_tested: "N/A",
    }[result.status];
    lines.push(`| ${result.controlId} | ${result.controlName} | ${result.category} | ${statusIcon} |`);
  }
  
  return lines.join("\n");
}

export const complianceService = {
  getAllControls,
  getControlById,
  mapFindingToControls,
  generateComplianceGapReport,
  generateComplianceReportMarkdown,
  frameworks: ["soc2", "iso27001", "nist_csf", "pci_dss"] as ComplianceFramework[],
};
