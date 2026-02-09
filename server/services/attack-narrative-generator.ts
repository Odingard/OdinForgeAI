/**
 * Attack Narrative Generator
 * 
 * Generates consulting-style "story mode" narratives that describe 
 * the attacker's journey through the kill chain with specific 
 * asset/vulnerability references.
 */

import type { AttackNarrative, ExposureType } from "@shared/schema";
import { formatVulnerabilityName, getVulnerabilityInfo } from "@shared/vulnerability-catalog";
import OpenAI from "openai";

let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  if (openaiClient) return openaiClient;
  
  const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.warn("[AttackNarrative] OpenAI API key not configured - using template narratives");
    return null;
  }

  openaiClient = new OpenAI({
    apiKey,
    baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
    timeout: 90000, // 90 second timeout to prevent hanging
    maxRetries: 2,
  });
  
  return openaiClient;
}

// Extended attack path step with MITRE technique info
interface NarrativeAttackStep {
  id: number;
  title: string;
  description: string;
  technique?: string;
  techniqueId?: string; // MITRE ATT&CK ID (e.g., T1190)
  severity: "critical" | "high" | "medium" | "low";
  discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
}

interface AttackPathData {
  evaluationId: string;
  assetId: string;
  exposureType: ExposureType;
  priority: string;
  description: string;
  steps: NarrativeAttackStep[];
  exploitable: boolean;
  score: number;
  impact?: string;
}

interface NarrativeContext {
  organizationName?: string;
  assessmentPeriod?: { startDate: string; endDate: string };
  methodology?: string;
}

/**
 * Maps MITRE ATT&CK techniques to kill chain phases
 */
function getTechniquePhase(techniqueId: string): AttackNarrative["milestones"][0]["phase"] {
  const phaseMap: Record<string, AttackNarrative["milestones"][0]["phase"]> = {
    // Reconnaissance
    "T1595": "reconnaissance", "T1592": "reconnaissance", "T1589": "reconnaissance",
    // Initial Access
    "T1190": "initial_access", "T1133": "initial_access", "T1078": "initial_access",
    "T1566": "initial_access", "T1195": "initial_access",
    // Execution
    "T1059": "execution", "T1203": "execution", "T1204": "execution",
    // Persistence
    "T1098": "persistence", "T1136": "persistence", "T1078.001": "persistence",
    // Privilege Escalation
    "T1068": "privilege_escalation", "T1548": "privilege_escalation", "T1134": "privilege_escalation",
    // Defense Evasion
    "T1070": "defense_evasion", "T1027": "defense_evasion", "T1562": "defense_evasion",
    // Credential Access
    "T1003": "credential_access", "T1110": "credential_access", "T1552": "credential_access",
    // Discovery
    "T1087": "discovery", "T1083": "discovery", "T1046": "discovery",
    // Lateral Movement
    "T1021": "lateral_movement", "T1210": "lateral_movement", "T1550": "lateral_movement",
    // Collection
    "T1005": "collection", "T1039": "collection", "T1114": "collection",
    // Exfiltration
    "T1041": "exfiltration", "T1567": "exfiltration",
    // Impact
    "T1486": "impact", "T1490": "impact", "T1489": "impact",
  };
  
  return phaseMap[techniqueId] || "execution";
}

/**
 * Convert priority to access level
 */
function priorityToAccessLevel(priority: string, exploitable: boolean): AttackNarrative["finalImpact"]["accessLevel"] {
  if (!exploitable) return "none";
  
  switch (priority) {
    case "critical": return "root";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "low";
  }
}

/**
 * Generates a templated narrative when AI is not available
 */
function generateTemplatedNarrative(
  attackPaths: AttackPathData[],
  context: NarrativeContext
): AttackNarrative {
  const primaryPath = attackPaths[0];
  if (!primaryPath) {
    return {
      title: "Security Assessment Narrative",
      overview: "No exploitable attack paths were identified during this assessment.",
      narrative: "During the security assessment, the testing team conducted comprehensive analysis of the target environment. No viable attack chains were discovered that could lead to significant compromise.",
      milestones: [],
      finalImpact: {
        accessLevel: "none",
        businessImpact: "No exploitable vulnerabilities were identified.",
      },
    };
  }

  const vulnInfo = getVulnerabilityInfo(primaryPath.exposureType);
  const vulnName = formatVulnerabilityName(primaryPath.exposureType);
  
  // Build milestones from attack path steps
  const milestones: AttackNarrative["milestones"] = primaryPath.steps.map((step) => ({
    phase: getTechniquePhase(step.techniqueId || ""),
    description: step.description,
    technique: step.technique || "Unknown Technique",
    techniqueId: step.techniqueId,
    targetAsset: primaryPath.assetId,
  }));

  // Calculate impact
  const compromisedAssets = Array.from(new Set(attackPaths.map(p => p.assetId)));
  const accessLevel = priorityToAccessLevel(primaryPath.priority, primaryPath.exploitable);

  // Build narrative prose
  const orgName = context.organizationName || "the target organization";
  const narrative = buildTemplatedProse(primaryPath, attackPaths, vulnName, orgName, compromisedAssets);

  return {
    title: `Attack Path Analysis: ${vulnName} Exploitation Chain`,
    overview: `During the assessment period, the testing team identified a ${primaryPath.priority}-severity attack chain leveraging ${vulnName} on ${primaryPath.assetId}. ${primaryPath.exploitable ? "This vulnerability was confirmed exploitable with a confidence score of " + primaryPath.score + "." : "Exploitation was not successful but the vulnerability presents significant risk."}`,
    narrative,
    milestones,
    finalImpact: {
      accessLevel,
      systemsCompromised: compromisedAssets,
      businessImpact: vulnInfo.businessImpact,
    },
    timeMetrics: {
      totalTime: estimateTimeToCompromise(attackPaths),
    },
  };
}

/**
 * Build narrative prose in consulting report style
 */
function buildTemplatedProse(
  primaryPath: AttackPathData,
  allPaths: AttackPathData[],
  vulnName: string,
  orgName: string,
  compromisedAssets: string[]
): string {
  const sections: string[] = [];
  
  // Opening
  sections.push(
    `The security assessment of ${orgName} revealed a significant attack path that could be leveraged by a malicious actor to gain unauthorized access to critical systems.`
  );
  
  // Initial Access
  sections.push(
    `**Initial Access**: The attack chain begins with ${vulnName} affecting ${primaryPath.assetId}. ${primaryPath.description || "This vulnerability provides an initial foothold into the environment."}`
  );
  
  // Attack Chain Steps
  if (primaryPath.steps.length > 0) {
    sections.push(`**Attack Chain Execution**: From the initial access point, the following attack progression was identified:`);
    primaryPath.steps.forEach((step, i) => {
      const techniqueRef = step.techniqueId ? ` (${step.techniqueId})` : "";
      sections.push(`${i + 1}. **${step.technique}**${techniqueRef}: ${step.description}`);
    });
  }
  
  // Impact Assessment
  if (primaryPath.exploitable) {
    sections.push(
      `**Impact Assessment**: Successful exploitation of this attack chain would result in compromise of ${compromisedAssets.length} system(s): ${compromisedAssets.join(", ")}. The exploitability score of ${primaryPath.score.toFixed(1)} indicates a ${primaryPath.score >= 8 ? "high" : primaryPath.score >= 5 ? "moderate" : "lower"} likelihood of successful real-world exploitation.`
    );
  } else {
    sections.push(
      `**Impact Assessment**: While exploitation was not fully successful during testing, the identified vulnerabilities represent significant risk and should be remediated promptly.`
    );
  }
  
  // Additional Paths
  if (allPaths.length > 1) {
    sections.push(
      `**Additional Attack Vectors**: ${allPaths.length - 1} additional attack path(s) were identified that could provide alternative routes to compromise. These should be addressed as part of a comprehensive remediation effort.`
    );
  }
  
  // Conclusion
  sections.push(
    `**Conclusion**: The identified attack chain represents a ${primaryPath.priority}-priority security risk requiring immediate attention. Remediation should focus on addressing the root cause vulnerability while implementing compensating controls to reduce exposure.`
  );
  
  return sections.join("\n\n");
}

/**
 * Estimate time to compromise based on attack path complexity
 */
function estimateTimeToCompromise(paths: AttackPathData[]): string {
  const totalSteps = paths.reduce((sum, p) => sum + (p.steps?.length || 0), 0);
  const avgScore = paths.reduce((sum, p) => sum + p.score, 0) / paths.length;
  
  // Higher score = easier = faster
  // More steps = slower
  let minutes = 30 + (totalSteps * 15) - (avgScore * 5);
  minutes = Math.max(10, Math.min(480, minutes));
  
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours} hour${hours > 1 ? "s" : ""} ${mins} minutes` : `${hours} hour${hours > 1 ? "s" : ""}`;
  }
  return `${Math.round(minutes)} minutes`;
}

/**
 * Generate AI-powered narrative using OpenAI
 */
async function generateAINarrative(
  attackPaths: AttackPathData[],
  context: NarrativeContext
): Promise<AttackNarrative> {
  const client = getOpenAIClient();
  if (!client) {
    return generateTemplatedNarrative(attackPaths, context);
  }
  
  try {
    const prompt = buildAIPrompt(attackPaths, context);
    
    const response = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [
        {
          role: "system",
          content: `You are a senior penetration tester writing the narrative section of a professional security assessment report. Your writing should be:
- Technical but accessible to security managers
- Written in past tense, describing actions taken during the assessment
- Structured with clear progression through the attack chain
- Reference specific systems, vulnerabilities, and MITRE ATT&CK techniques
- Professional and objective, avoiding sensationalism
- Similar in style to Big 4 consulting firm deliverables`
        },
        {
          role: "user",
          content: prompt
        }
      ],
      response_format: { type: "json_object" },
      temperature: 0.7,
    });
    
    const content = response.choices[0]?.message?.content;
    if (!content) {
      return generateTemplatedNarrative(attackPaths, context);
    }
    
    const parsed = JSON.parse(content);
    return validateAndEnrichNarrative(parsed, attackPaths, context);
    
  } catch (error) {
    console.warn("[AttackNarrative] AI generation failed, falling back to template:", error);
    return generateTemplatedNarrative(attackPaths, context);
  }
}

/**
 * Build the prompt for AI narrative generation
 */
function buildAIPrompt(paths: AttackPathData[], context: NarrativeContext): string {
  const pathDescriptions = paths.map((p, i) => {
    const vulnName = formatVulnerabilityName(p.exposureType);
    return `
Attack Path ${i + 1}:
- Target Asset: ${p.assetId}
- Vulnerability Type: ${vulnName}
- Priority: ${p.priority}
- Exploitable: ${p.exploitable}
- Score: ${p.score}
- Description: ${p.description}
- Attack Steps: ${JSON.stringify(p.steps, null, 2)}
${p.impact ? `- Impact: ${p.impact}` : ""}`;
  }).join("\n");
  
  return `Generate a professional penetration test narrative report section based on the following attack path data:

${pathDescriptions}

Context:
- Organization: ${context.organizationName || "Target Organization"}
- Assessment Period: ${context.assessmentPeriod?.startDate || "Recent"} to ${context.assessmentPeriod?.endDate || "Present"}
- Methodology: ${context.methodology || "Industry standard penetration testing"}

Respond with a JSON object matching this structure:
{
  "title": "Attack Path Analysis: [Descriptive Title]",
  "overview": "A 2-3 sentence summary suitable for executives",
  "narrative": "A detailed multi-paragraph narrative in markdown format describing the attack chain as a story. Use **bold** for emphasis. Include specific technical details but remain accessible.",
  "milestones": [
    {
      "phase": "initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact",
      "description": "What happened in this phase",
      "technique": "MITRE ATT&CK Technique Name",
      "techniqueId": "TXXXX",
      "targetAsset": "Asset identifier"
    }
  ],
  "finalImpact": {
    "accessLevel": "none|low|medium|high|domain_admin|root",
    "businessImpact": "Description of business impact"
  },
  "timeMetrics": {
    "totalTime": "Estimated time to compromise"
  }
}`;
}

/**
 * Validate and enrich the AI-generated narrative
 */
function validateAndEnrichNarrative(
  aiResponse: any,
  paths: AttackPathData[],
  context: NarrativeContext
): AttackNarrative {
  const compromisedAssets = Array.from(new Set(paths.map(p => p.assetId)));
  
  return {
    title: aiResponse.title || "Security Assessment Attack Narrative",
    overview: aiResponse.overview || generateTemplatedNarrative(paths, context).overview,
    narrative: aiResponse.narrative || generateTemplatedNarrative(paths, context).narrative,
    milestones: (aiResponse.milestones || []).map((m: any) => ({
      phase: m.phase || "execution",
      description: m.description || "",
      technique: m.technique || "Unknown Technique",
      techniqueId: m.techniqueId,
      targetAsset: m.targetAsset || paths[0]?.assetId || "Unknown",
    })),
    finalImpact: {
      accessLevel: aiResponse.finalImpact?.accessLevel || priorityToAccessLevel(paths[0]?.priority || "low", paths[0]?.exploitable || false),
      systemsCompromised: compromisedAssets,
      dataAccessed: aiResponse.finalImpact?.dataAccessed,
      businessImpact: aiResponse.finalImpact?.businessImpact || paths[0]?.impact || "Potential unauthorized access to systems",
    },
    timeMetrics: aiResponse.timeMetrics || {
      totalTime: estimateTimeToCompromise(paths),
    },
  };
}

/**
 * Main export: Generate attack narrative from evaluation data
 */
export async function generateAttackNarrative(
  attackPaths: AttackPathData[],
  context: NarrativeContext = {},
  useAI: boolean = true
): Promise<AttackNarrative> {
  if (!attackPaths || attackPaths.length === 0) {
    return {
      title: "Security Assessment Summary",
      overview: "No exploitable attack paths were identified during this assessment period.",
      narrative: "During the security assessment, comprehensive testing was conducted against the target environment. The assessment did not identify any exploitable attack chains that could lead to significant system compromise. This indicates a favorable security posture, though continued monitoring and periodic reassessment is recommended.",
      milestones: [],
      finalImpact: {
        accessLevel: "none",
        businessImpact: "No immediate risk identified. Continue security monitoring.",
      },
    };
  }
  
  if (useAI) {
    return generateAINarrative(attackPaths, context);
  }
  
  return generateTemplatedNarrative(attackPaths, context);
}

/**
 * Generate a brief attack summary for executive reports
 */
export function generateExecutiveAttackSummary(narrative: AttackNarrative): string {
  const accessLevelDescriptions: Record<string, string> = {
    "none": "No successful compromise was achieved",
    "low": "Limited access was obtained",
    "medium": "Moderate system access was achieved",
    "high": "Significant system access was achieved",
    "domain_admin": "Domain administrator access was achieved",
    "root": "Root/system-level access was achieved",
  };
  
  const accessDesc = accessLevelDescriptions[narrative.finalImpact.accessLevel] || "System access was evaluated";
  const systemCount = narrative.finalImpact.systemsCompromised?.length || 0;
  const timeEstimate = narrative.timeMetrics?.totalTime || "a short period";
  
  let summary = `${accessDesc}`;
  if (systemCount > 0) {
    summary += ` affecting ${systemCount} system${systemCount > 1 ? "s" : ""}`;
  }
  summary += `. The attack chain could be executed in approximately ${timeEstimate}.`;
  
  if (narrative.milestones.length > 0) {
    const phases = Array.from(new Set(narrative.milestones.map(m => m.phase)));
    summary += ` The attack progression included ${phases.length} distinct phase${phases.length > 1 ? "s" : ""}.`;
  }
  
  return summary;
}

export const attackNarrativeGenerator = {
  generateAttackNarrative,
  generateExecutiveAttackSummary,
};
