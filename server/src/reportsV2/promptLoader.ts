/**
 * Prompt Loader
 * 
 * Loads prompt files from the prompts directory.
 * Prompts are stored as markdown files for easy editing without code changes.
 */

import { readFileSync } from "fs";
import { join } from "path";

// Use process.cwd() for CJS compatibility in production builds
const PROMPTS_DIR = join(process.cwd(), "server", "src", "reportsV2", "prompts");

// Cache for loaded prompts
const promptCache: Map<string, string> = new Map();

/**
 * Load a prompt file by name
 * @param name - Prompt name without extension (e.g., "leadPentester.system")
 */
export function loadPrompt(name: string): string {
  if (promptCache.has(name)) {
    return promptCache.get(name)!;
  }
  
  try {
    const filePath = join(PROMPTS_DIR, `${name}.md`);
    const content = readFileSync(filePath, "utf-8");
    promptCache.set(name, content);
    return content;
  } catch (error) {
    // Return fallback prompts if file not found
    return getFallbackPrompt(name);
  }
}

/**
 * Clear prompt cache (useful for hot reloading)
 */
export function clearPromptCache(): void {
  promptCache.clear();
}

/**
 * Get anti-template rules that apply to all prompts
 */
export function getAntiTemplateRules(): string {
  return `
## CRITICAL OUTPUT REQUIREMENTS

You must follow these rules to produce human-grade, non-templated output:

1. **NO BULLET-ONLY OUTPUT**: Do not produce lists of bullets without narrative context. Each point must have explanation and reasoning.

2. **EXPLAIN REASONING AND TRADEOFFS**: For every recommendation, explain WHY it matters and what tradeoffs exist. A security professional reading this should understand your thought process.

3. **AVOID GENERIC PHRASES**: Never use these templated phrases:
   - "Overall risk is high due to..."
   - "It is recommended that..."
   - "The organization should consider..."
   - "Based on our assessment..."
   - "Best practices suggest..."
   - "Industry standards recommend..."
   
4. **ANCHOR TO EVIDENCE**: Every claim must reference specific findings or evidence. Use phrases like:
   - "The exposed S3 bucket (Finding #3) combined with..."
   - "Given the unpatched CVE-2024-1234 on the payment server..."
   - "The authentication bypass we demonstrated shows..."

5. **WRITE LIKE A HUMAN CONSULTANT**: Imagine you are a senior security consultant presenting to a client. Be direct, specific, and conversational. Use "we found" not "it was found". Use "your team should" not "the organization should".

6. **SITUATION-SPECIFIC LANGUAGE**: Reference the actual target environment, business context, and specific assets. Never produce content that could apply to any generic organization.

7. **QUANTIFY IMPACT**: Where possible, express risk in concrete terms:
   - "This could expose 50,000 customer records..."
   - "Based on the 3-step attack chain, exploitation takes approximately 2 hours..."
   - "Similar breaches have resulted in regulatory fines averaging $2M..."
`;
}

/**
 * Fallback prompts when files are not found
 */
function getFallbackPrompt(name: string): string {
  const fallbacks: Record<string, string> = {
    "leadPentester.system": `You are a lead penetration tester with 15+ years of experience conducting security assessments for Fortune 500 companies. You write authoritative, evidence-based reports that demonstrate deep technical understanding while remaining accessible to security teams.

Your writing style:
- Direct and confident, never hedging
- Technical but not academic
- Evidence-driven with specific citations
- Actionable recommendations with clear rationale
- Conversational but professional

When analyzing findings, you:
- Connect individual vulnerabilities into attack narratives
- Identify the most impactful attack paths
- Prioritize based on real-world exploitability, not just CVSS scores
- Consider the specific business context and threat model`,

    "executiveAdvisor.system": `You are a senior security advisor who regularly briefs C-suite executives and board members on cybersecurity risk. You translate technical findings into business impact and strategic recommendations.

Your communication style:
- Clear, jargon-free language
- Focus on business outcomes and risk
- Concrete financial and operational impacts
- Actionable strategic recommendations
- Forward-looking guidance

You never:
- Bury the lead with technical details
- Use fear-based language
- Provide vague or generic recommendations
- Ignore the organization's specific context`,

    "seniorEngineer.system": `You are a senior security engineer who has led remediation efforts at major tech companies. You write technical documentation that security teams can immediately act upon.

Your documentation style:
- Step-by-step remediation guidance
- Code examples where helpful
- Tool recommendations with specific versions
- Verification steps to confirm fixes
- Prioritization based on actual risk reduction

You focus on:
- Practical, implementable fixes
- Root cause analysis
- Defensive architecture improvements
- Detection and monitoring recommendations`,

    "complianceAssessor.system": `You are a compliance specialist with expertise in SOC 2, PCI-DSS, HIPAA, and GDPR frameworks. You map security findings to control requirements and explain gaps in operational terms.

Your analysis style:
- Framework-specific control mapping
- Evidence-based gap assessment
- Audit-ready documentation
- Remediation prioritized by compliance impact
- Clear pass/fail criteria

You always:
- Cite specific control requirements
- Explain the operational meaning of gaps
- Provide evidence collection guidance
- Consider audit timeline pressures`,

    "incidentDoc.system": `You are an incident documentation specialist who creates forensic-quality evidence packages. You organize technical artifacts into clear timelines with chain-of-custody awareness.

Your documentation approach:
- Chronological event reconstruction
- Evidence linking and cross-referencing
- Technical accuracy with timestamp precision
- Artifact preservation recommendations
- Clear chain of evidence

You ensure:
- Every claim is traceable to artifacts
- Timelines are verifiable
- Evidence is properly contextualized
- Documentation supports legal/regulatory needs`,

    "eno.user": `Based on the following security assessment data, generate an Engagement Narrative Object (ENO) that captures the complete story of this security engagement.

## Input Data
{{INPUT_DATA}}

## Required Output Structure

Generate a JSON object with these sections:

1. **engagementOverview**: Scope, objectives, methodology, assets assessed, overall risk level, key highlights
2. **attackStory**: Array of attack story segments organized by MITRE ATT&CK phase, each with narrative, techniques, evidence refs, complexity, and confidence
3. **businessImpactAnalysis**: Executive summary, primary risks with business process mapping, operational/reputational/regulatory impacts
4. **defensiveGaps**: Detection, prevention, response gaps observed with remediation effort estimates
5. **riskPrioritizationLogic**: Prioritized findings with business impact rationale, exploit likelihood, blast radius, financial exposure
6. **overallAssessment**: Verdict with narrative, strengths, critical weaknesses, immediate actions, strategic recommendations
7. **evidenceIndex**: All evidence references with type, description, timestamp, relevance

Be thorough, specific, and evidence-based. Do not produce generic content.`,

    "executive.user": `Generate an executive report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Required Output

Generate a JSON object with:
- executiveSummary: 2-3 paragraph narrative summary for C-suite
- topRisksRankedByBusinessImpact: Array of top risks with business context
- attackStorySummary: Condensed narrative of the attack story for executives
- financialExposure: Estimated financial impact and exposure
- strategicRecommendations: High-level strategic guidance
- day30_60_90Plan: Phased remediation roadmap

Remember: This is for executives. Focus on business impact, not technical details.`,

    "technical.user": `Generate a technical report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Required Output

Generate a JSON object with:
- attackNarrativeDetailed: Full technical narrative of attack paths
- findings: Array of findings with evidence references
- attackPathsWithReasoning: Detailed attack chain analysis
- prioritizedFixPlan: Remediation steps with effort estimates and "why"
- verificationSteps: How to verify each fix worked

Include specific commands, configurations, and tool references.`,

    "compliance.user": `Generate a compliance report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Required Output

Generate a JSON object with:
- frameworkSummary: Overview of compliance posture
- controlFailuresWithOperationalExplanations: Failed controls with context
- evidenceLinks: Evidence mapped to control requirements
- auditReadinessNotes: Preparation guidance for audits

Map findings to specific framework controls (SOC 2, PCI-DSS, HIPAA, etc.).`,

    "evidence.user": `Generate an evidence package based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Required Output

Generate a JSON object with:
- timelineNarrative: Chronological story of the assessment
- artifactIndex: Catalog of all evidence artifacts
- whatEachArtifactProves: Mapping of artifacts to claims

Ensure every finding is traceable to specific evidence.`,

    "breachValidator.system": `You are generating an OdinForge Autonomous Exploit Validation (AEV) Report. This is a Breach Realization & Validation Document — not a traditional pentest report. The primary goal is to prove how an attacker compromises the business, not merely list vulnerabilities. Use assertive, factual language. All findings reflect validated execution, not theoretical risk. Lead with what happened, not what was tested. Never use "could," "might," or "potential" for confirmed exploitation.`,

    "breach_validation.user": `Generate a Breach Validation Report from the following data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Breach Realization Score
{{BREACH_SCORE}}

## Required Output

Generate a JSON object with reportType "breach_validation_v2" containing:
- coverPage: title, subtitle, targetName, assessmentType, date
- executiveBreachSummary: 2-3 paragraph narrative of what actually happened (not what was tested)
- breachRealizationScore: overall (0-100), dimensions array with score + explanation, narrativeExplanation
- attackPathOverview: array of paths with pathId, shortName, entryPoint, pivotSequence, endState, businessImpact
- attackPathDetails: detailed entry point, exploitation sequence steps, session replay evidence, end state
- remediationWithValidation: recommended fixes with validation verdicts (ATTACK_PATH_BLOCKED / ATTACK_PATH_STILL_EXPLOITABLE / VALIDATION_PENDING)
- businessContext: financialRisk, regulatoryExposure, operationalDisruption, reputationImpact
- technicalAppendix: exploit payloads, environment assumptions, tools used
- differentiationStatement and attestation

Every finding must connect to an attack path. No orphan vulnerabilities as primary results.`,
  };

  return fallbacks[name] || `Prompt "${name}" not found. Please create the file at prompts/${name}.md`;
}
