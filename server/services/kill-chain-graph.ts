import type { AttackPathStep, KillChainTactic } from "@shared/schema";

export interface KillChainPhase {
  id: KillChainTactic;
  name: string;
  shortName: string;
  description: string;
  order: number;
}

export const killChainPhases: KillChainPhase[] = [
  { id: "reconnaissance", name: "Reconnaissance", shortName: "Recon", description: "Gathering information about the target", order: 1 },
  { id: "resource-development", name: "Resource Development", shortName: "Resources", description: "Establishing resources for operations", order: 2 },
  { id: "initial-access", name: "Initial Access", shortName: "Access", description: "Gaining entry to the target environment", order: 3 },
  { id: "execution", name: "Execution", shortName: "Execute", description: "Running malicious code", order: 4 },
  { id: "persistence", name: "Persistence", shortName: "Persist", description: "Maintaining access over time", order: 5 },
  { id: "privilege-escalation", name: "Privilege Escalation", shortName: "Priv Esc", description: "Gaining higher-level permissions", order: 6 },
  { id: "defense-evasion", name: "Defense Evasion", shortName: "Evasion", description: "Avoiding detection", order: 7 },
  { id: "credential-access", name: "Credential Access", shortName: "Creds", description: "Stealing credentials", order: 8 },
  { id: "discovery", name: "Discovery", shortName: "Discover", description: "Exploring the environment", order: 9 },
  { id: "lateral-movement", name: "Lateral Movement", shortName: "Lateral", description: "Moving through the network", order: 10 },
  { id: "collection", name: "Collection", shortName: "Collect", description: "Gathering target data", order: 11 },
  { id: "command-and-control", name: "Command and Control", shortName: "C2", description: "Communicating with compromised systems", order: 12 },
  { id: "exfiltration", name: "Exfiltration", shortName: "Exfil", description: "Stealing data from the target", order: 13 },
  { id: "impact", name: "Impact", shortName: "Impact", description: "Causing damage or disruption", order: 14 }
];

export interface KillChainVisualization {
  phases: Array<{
    phase: KillChainPhase;
    isActive: boolean;
    steps: AttackPathStep[];
    severity: "critical" | "high" | "medium" | "low" | "none";
  }>;
  attackPathSummary: string;
  totalPhasesCovered: number;
  criticalPath: string[];
  timeToCompromise: string;
  complexityScore: number;
}

export function mapTechniqueToPhase(technique: string): KillChainTactic {
  const techniquePhaseMap: Record<string, KillChainTactic> = {
    "T1595": "reconnaissance",
    "T1592": "reconnaissance",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1591": "reconnaissance",
    "T1587": "resource-development",
    "T1588": "resource-development",
    "T1583": "resource-development",
    "T1584": "resource-development",
    "T1190": "initial-access",
    "T1133": "initial-access",
    "T1078": "initial-access",
    "T1566": "initial-access",
    "T1199": "initial-access",
    "T1059": "execution",
    "T1106": "execution",
    "T1053": "execution",
    "T1569": "execution",
    "T1547": "persistence",
    "T1136": "persistence",
    "T1098": "persistence",
    "T1543": "persistence",
    "T1068": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1134": "privilege-escalation",
    "T1574": "privilege-escalation",
    "T1070": "defense-evasion",
    "T1036": "defense-evasion",
    "T1027": "defense-evasion",
    "T1562": "defense-evasion",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1552": "credential-access",
    "T1555": "credential-access",
    "T1087": "discovery",
    "T1082": "discovery",
    "T1046": "discovery",
    "T1135": "discovery",
    "T1021": "lateral-movement",
    "T1550": "lateral-movement",
    "T1072": "lateral-movement",
    "T1210": "lateral-movement",
    "T1560": "collection",
    "T1039": "collection",
    "T1005": "collection",
    "T1114": "collection",
    "T1071": "command-and-control",
    "T1105": "command-and-control",
    "T1572": "command-and-control",
    "T1573": "command-and-control",
    "T1048": "exfiltration",
    "T1041": "exfiltration",
    "T1567": "exfiltration",
    "T1020": "exfiltration",
    "T1485": "impact",
    "T1486": "impact",
    "T1565": "impact",
    "T1499": "impact",
    "T1657": "impact"
  };
  
  const baseId = technique?.split(".")[0] || "";
  return techniquePhaseMap[baseId] || "execution";
}

export function buildKillChainVisualization(
  attackPath: AttackPathStep[],
  attackGraph?: {
    complexityScore?: number;
    timeToCompromise?: { expected: number; unit: string };
    criticalPath?: string[];
  }
): KillChainVisualization {
  const phaseStepMap = new Map<KillChainTactic, AttackPathStep[]>();
  
  killChainPhases.forEach(phase => {
    phaseStepMap.set(phase.id, []);
  });
  
  attackPath.forEach(step => {
    const phaseId = mapTechniqueToPhase(step.technique || "");
    const steps = phaseStepMap.get(phaseId) || [];
    steps.push(step);
    phaseStepMap.set(phaseId, steps);
  });
  
  const phases = killChainPhases.map(phase => {
    const steps = phaseStepMap.get(phase.id) || [];
    const isActive = steps.length > 0;
    
    let severity: "critical" | "high" | "medium" | "low" | "none" = "none";
    if (isActive) {
      const severities = steps.map(s => s.severity);
      if (severities.includes("critical")) severity = "critical";
      else if (severities.includes("high")) severity = "high";
      else if (severities.includes("medium")) severity = "medium";
      else if (severities.includes("low")) severity = "low";
    }
    
    return {
      phase,
      isActive,
      steps,
      severity
    };
  });
  
  const activePhases = phases.filter(p => p.isActive);
  const totalPhasesCovered = activePhases.length;
  
  const phaseNames = activePhases.map(p => p.phase.shortName);
  const attackPathSummary = phaseNames.length > 0 
    ? `Attack chain spans ${totalPhasesCovered} phases: ${phaseNames.join(" → ")}`
    : "No attack chain identified";
  
  return {
    phases,
    attackPathSummary,
    totalPhasesCovered,
    criticalPath: attackGraph?.criticalPath || attackPath.map(s => s.title),
    timeToCompromise: attackGraph?.timeToCompromise 
      ? `${attackGraph.timeToCompromise.expected} ${attackGraph.timeToCompromise.unit}`
      : "Unknown",
    complexityScore: attackGraph?.complexityScore || 50
  };
}

export interface KillChainReportSection {
  title: string;
  summary: string;
  phaseTable: Array<{
    phase: string;
    status: string;
    severity: string;
    stepsCount: number;
    techniques: string[];
    description: string;
  }>;
  attackFlow: string[];
  metrics: {
    totalPhases: number;
    activePhases: number;
    coverage: number;
    criticalPhases: number;
    highPhases: number;
    timeToCompromise: string;
    complexityScore: number;
    complexityLevel: string;
  };
  detailedSteps: Array<{
    order: number;
    phase: string;
    title: string;
    description: string;
    technique: string;
    severity: string;
  }>;
}

export function generateKillChainReportSection(
  visualization: KillChainVisualization
): KillChainReportSection {
  const phaseTable = visualization.phases.map(p => ({
    phase: p.phase.name,
    status: p.isActive ? "ACTIVE" : "Not Observed",
    severity: p.severity.toUpperCase(),
    stepsCount: p.steps.length,
    techniques: p.steps.map(s => s.technique || "N/A"),
    description: p.isActive 
      ? p.steps.map(s => s.title).join("; ")
      : p.phase.description
  }));
  
  const activePhases = visualization.phases.filter(p => p.isActive);
  const attackFlow = activePhases.map((p, i) => {
    const arrow = i < activePhases.length - 1 ? " → " : "";
    return `${p.phase.shortName}${arrow}`;
  });
  
  const criticalPhases = activePhases.filter(p => p.severity === "critical").length;
  const highPhases = activePhases.filter(p => p.severity === "high").length;
  const coverage = Math.round((visualization.totalPhasesCovered / killChainPhases.length) * 100);
  
  let complexityLevel = "Low";
  if (visualization.complexityScore >= 80) complexityLevel = "Expert";
  else if (visualization.complexityScore >= 60) complexityLevel = "High";
  else if (visualization.complexityScore >= 40) complexityLevel = "Medium";
  
  let stepOrder = 0;
  const detailedSteps: KillChainReportSection["detailedSteps"] = [];
  visualization.phases.forEach(p => {
    p.steps.forEach(step => {
      stepOrder++;
      detailedSteps.push({
        order: stepOrder,
        phase: p.phase.name,
        title: step.title,
        description: step.description,
        technique: step.technique || "N/A",
        severity: step.severity.toUpperCase()
      });
    });
  });
  
  return {
    title: "Kill Chain Analysis",
    summary: visualization.attackPathSummary,
    phaseTable,
    attackFlow: attackFlow.length > 0 ? attackFlow : ["No attack path identified"],
    metrics: {
      totalPhases: killChainPhases.length,
      activePhases: visualization.totalPhasesCovered,
      coverage,
      criticalPhases,
      highPhases,
      timeToCompromise: visualization.timeToCompromise,
      complexityScore: visualization.complexityScore,
      complexityLevel
    },
    detailedSteps
  };
}

export function generateTextualKillChainDiagram(visualization: KillChainVisualization): string {
  const lines: string[] = [];
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│                           MITRE ATT&CK KILL CHAIN                          │");
  lines.push("├─────────────────────────────────────────────────────────────────────────────┤");
  
  const activePhases = visualization.phases.filter(p => p.isActive);
  
  if (activePhases.length === 0) {
    lines.push("│                        No Attack Path Identified                            │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    return lines.join("\n");
  }
  
  const flowLine = activePhases.map(p => {
    const severityIcon = p.severity === "critical" ? "[!!!]" : 
                         p.severity === "high" ? "[!!]" : 
                         p.severity === "medium" ? "[!]" : "[*]";
    return `${p.phase.shortName}${severityIcon}`;
  }).join(" → ");
  
  const paddedFlow = flowLine.padStart((79 + flowLine.length) / 2).padEnd(79);
  lines.push(`│${paddedFlow.substring(0, 79)}│`);
  lines.push("├─────────────────────────────────────────────────────────────────────────────┤");
  
  activePhases.forEach(p => {
    const phaseName = p.phase.name.padEnd(25);
    const severity = p.severity.toUpperCase().padEnd(10);
    const stepCount = `${p.steps.length} step(s)`.padEnd(12);
    const techniques = p.steps.map(s => s.technique || "").filter(t => t).slice(0, 3).join(", ").substring(0, 25).padEnd(25);
    lines.push(`│ ${phaseName}│ ${severity}│ ${stepCount}│ ${techniques}│`);
  });
  
  lines.push("├─────────────────────────────────────────────────────────────────────────────┤");
  
  const metricsLine1 = `Coverage: ${visualization.totalPhasesCovered}/${killChainPhases.length} phases (${Math.round((visualization.totalPhasesCovered / killChainPhases.length) * 100)}%)`;
  const metricsLine2 = `Time to Compromise: ${visualization.timeToCompromise} | Complexity: ${visualization.complexityScore}/100`;
  
  lines.push(`│ ${metricsLine1.padEnd(77)}│`);
  lines.push(`│ ${metricsLine2.padEnd(77)}│`);
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  
  return lines.join("\n");
}

export interface PdfKillChainContent {
  header: any;
  flowDiagram: any;
  phaseTable: any;
  metricsPanel: any;
  detailedSteps: any;
}

export function generatePdfKillChainContent(
  visualization: KillChainVisualization,
  options: { includeDetails?: boolean; compact?: boolean } = {}
): PdfKillChainContent {
  const reportSection = generateKillChainReportSection(visualization);
  
  const header = {
    text: "Attack Kill Chain Analysis",
    style: "sectionHeader",
    margin: [0, 20, 0, 10]
  };
  
  const activePhases = visualization.phases.filter(p => p.isActive);
  const flowItems = activePhases.map((p, i) => {
    const color = p.severity === "critical" ? "#ef4444" :
                  p.severity === "high" ? "#f97316" :
                  p.severity === "medium" ? "#eab308" : "#22c55e";
    
    return {
      columns: [
        {
          width: "auto",
          stack: [
            {
              text: p.phase.shortName,
              style: "phaseLabel",
              color: color,
              bold: true
            },
            {
              text: p.severity.toUpperCase(),
              style: "phaseSeverity",
              fontSize: 7,
              color: color
            }
          ],
          margin: [0, 0, 5, 0]
        },
        i < activePhases.length - 1 ? {
          width: "auto",
          text: "→",
          style: "arrow",
          margin: [5, 5, 5, 0]
        } : { text: "", width: 0 }
      ],
      columnGap: 2
    };
  });
  
  const flowDiagram = {
    stack: [
      { text: "Attack Flow", style: "subHeader", margin: [0, 10, 0, 5] },
      activePhases.length > 0 ? {
        columns: flowItems.slice(0, 7),
        margin: [0, 5, 0, 10]
      } : {
        text: "No attack path identified",
        style: "note",
        italics: true,
        margin: [0, 5, 0, 10]
      }
    ]
  };
  
  const phaseTableBody: any[][] = [
    [
      { text: "Phase", style: "tableHeader" },
      { text: "Status", style: "tableHeader" },
      { text: "Severity", style: "tableHeader" },
      { text: "Techniques", style: "tableHeader" }
    ]
  ];
  
  const phasesToShow = options.compact 
    ? visualization.phases.filter(p => p.isActive)
    : visualization.phases;
  
  phasesToShow.forEach(p => {
    const statusColor = p.isActive ? "#22c55e" : "#6b7280";
    const severityColor = p.severity === "critical" ? "#ef4444" :
                          p.severity === "high" ? "#f97316" :
                          p.severity === "medium" ? "#eab308" :
                          p.severity === "low" ? "#22c55e" : "#6b7280";
    
    phaseTableBody.push([
      { text: p.phase.name, style: "tableCell" },
      { text: p.isActive ? "ACTIVE" : "Not Observed", color: statusColor, style: "tableCell" },
      { text: p.severity.toUpperCase(), color: severityColor, style: "tableCell" },
      { text: p.steps.map(s => s.technique || "").filter(t => t).join(", ") || "-", style: "tableCell" }
    ]);
  });
  
  const phaseTable = {
    stack: [
      { text: "Kill Chain Phase Coverage", style: "subHeader", margin: [0, 15, 0, 5] },
      {
        table: {
          headerRows: 1,
          widths: ["30%", "20%", "15%", "35%"],
          body: phaseTableBody
        },
        layout: {
          hLineWidth: () => 0.5,
          vLineWidth: () => 0.5,
          hLineColor: () => "#e5e7eb",
          vLineColor: () => "#e5e7eb"
        }
      }
    ]
  };
  
  const coverage = Math.round((reportSection.metrics.activePhases / reportSection.metrics.totalPhases) * 100);
  
  const metricsPanel = {
    stack: [
      { text: "Attack Metrics", style: "subHeader", margin: [0, 15, 0, 5] },
      {
        columns: [
          {
            width: "25%",
            stack: [
              { text: `${reportSection.metrics.activePhases}/${reportSection.metrics.totalPhases}`, style: "metricValue" },
              { text: "Phases Covered", style: "metricLabel" }
            ]
          },
          {
            width: "25%",
            stack: [
              { text: `${coverage}%`, style: "metricValue" },
              { text: "Coverage", style: "metricLabel" }
            ]
          },
          {
            width: "25%",
            stack: [
              { text: reportSection.metrics.timeToCompromise, style: "metricValue" },
              { text: "Time to Compromise", style: "metricLabel" }
            ]
          },
          {
            width: "25%",
            stack: [
              { text: `${reportSection.metrics.complexityScore}/100`, style: "metricValue" },
              { text: `Complexity (${reportSection.metrics.complexityLevel})`, style: "metricLabel" }
            ]
          }
        ]
      }
    ]
  };
  
  let detailedSteps: any = { text: "" };
  if (options.includeDetails && reportSection.detailedSteps.length > 0) {
    const stepsTableBody: any[][] = [
      [
        { text: "#", style: "tableHeader" },
        { text: "Phase", style: "tableHeader" },
        { text: "Step", style: "tableHeader" },
        { text: "Technique", style: "tableHeader" },
        { text: "Severity", style: "tableHeader" }
      ]
    ];
    
    reportSection.detailedSteps.forEach(step => {
      const severityColor = step.severity === "CRITICAL" ? "#ef4444" :
                            step.severity === "HIGH" ? "#f97316" :
                            step.severity === "MEDIUM" ? "#eab308" : "#22c55e";
      
      stepsTableBody.push([
        { text: String(step.order), style: "tableCell" },
        { text: step.phase, style: "tableCell" },
        { text: step.title, style: "tableCell" },
        { text: step.technique, style: "tableCell" },
        { text: step.severity, color: severityColor, style: "tableCell" }
      ]);
    });
    
    detailedSteps = {
      stack: [
        { text: "Detailed Attack Steps", style: "subHeader", margin: [0, 15, 0, 5] },
        {
          table: {
            headerRows: 1,
            widths: ["5%", "20%", "40%", "15%", "10%"],
            body: stepsTableBody
          },
          layout: {
            hLineWidth: () => 0.5,
            vLineWidth: () => 0.5,
            hLineColor: () => "#e5e7eb",
            vLineColor: () => "#e5e7eb"
          }
        }
      ]
    };
  }
  
  return {
    header,
    flowDiagram,
    phaseTable,
    metricsPanel,
    detailedSteps
  };
}
