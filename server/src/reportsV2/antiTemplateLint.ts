/**
 * Anti-Template Linting
 * 
 * Quality checks to ensure AI-generated content reads like authored
 * pentest reports, not templated output.
 */

import { ENO } from "./eno.schema";

export interface LintResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  score: number; // 0-100 quality score
}

// Forbidden generic phrases
const FORBIDDEN_PHRASES = [
  "overall risk is high due to",
  "it is recommended that",
  "the organization should consider",
  "based on our assessment",
  "best practices suggest",
  "industry standards recommend",
  "it was found that",
  "it should be noted that",
  "moving forward",
  "at this time",
  "in order to",
  "due diligence",
  "synergies",
  "leverage",
  "holistic approach",
  "robust security",
  "comprehensive solution",
  "mission critical",
];

// Minimum narrative lengths for quality
const MIN_NARRATIVE_LENGTH = 100;
const MIN_RATIONALE_LENGTH = 50;

/**
 * Run anti-template linting on ENO
 */
export function antiTemplateLint(eno: ENO): LintResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let qualityScore = 100;
  
  // Check 1: Forbidden phrases
  const allText = extractAllText(eno);
  for (const phrase of FORBIDDEN_PHRASES) {
    const regex = new RegExp(phrase, "gi");
    const matches = allText.match(regex);
    if (matches && matches.length > 0) {
      if (matches.length >= 3) {
        errors.push(`Overused templated phrase: "${phrase}" appears ${matches.length} times`);
        qualityScore -= 15;
      } else {
        warnings.push(`Templated phrase detected: "${phrase}"`);
        qualityScore -= 5;
      }
    }
  }
  
  // Check 2: Repetition detection
  const repetitionScore = detectRepetition(allText);
  if (repetitionScore > 0.3) {
    errors.push(`High repetition detected (${(repetitionScore * 100).toFixed(1)}%). Content feels templated.`);
    qualityScore -= 20;
  } else if (repetitionScore > 0.15) {
    warnings.push(`Moderate repetition detected (${(repetitionScore * 100).toFixed(1)}%)`);
    qualityScore -= 10;
  }
  
  // Check 3: Evidence references exist for critical findings
  const highPriorityFindings = eno.riskPrioritizationLogic.filter(
    r => r.exploitLikelihood === "certain" || r.exploitLikelihood === "highly_likely"
  );
  
  for (const finding of highPriorityFindings) {
    const hasEvidenceRef = eno.attackStory.some(
      segment => segment.evidenceRefs.length > 0
    );
    if (!hasEvidenceRef) {
      errors.push(`High-priority finding "${finding.findingId}" lacks evidence references`);
      qualityScore -= 10;
    }
  }
  
  // Check 4: Narrative quality - check minimum lengths
  if (eno.businessImpactAnalysis.executiveSummary.length < MIN_NARRATIVE_LENGTH) {
    errors.push(`Executive summary too short (${eno.businessImpactAnalysis.executiveSummary.length} chars, minimum ${MIN_NARRATIVE_LENGTH})`);
    qualityScore -= 15;
  }
  
  if (eno.overallAssessment.verdictNarrative.length < MIN_NARRATIVE_LENGTH) {
    errors.push(`Verdict narrative too short (${eno.overallAssessment.verdictNarrative.length} chars, minimum ${MIN_NARRATIVE_LENGTH})`);
    qualityScore -= 15;
  }
  
  // Check 5: Attack story has reasoning
  for (const segment of eno.attackStory) {
    if (segment.narrative.length < MIN_RATIONALE_LENGTH) {
      warnings.push(`Attack story segment "${segment.phase}" has thin narrative (${segment.narrative.length} chars)`);
      qualityScore -= 5;
    }
  }
  
  // Check 6: Risk prioritization has reasoning
  for (const risk of eno.riskPrioritizationLogic) {
    if (risk.rationale.length < MIN_RATIONALE_LENGTH) {
      warnings.push(`Risk "${risk.findingId}" has insufficient rationale (${risk.rationale.length} chars)`);
      qualityScore -= 5;
    }
  }
  
  // Check 7: Verify evidence index is populated
  if (eno.evidenceIndex.length === 0) {
    errors.push("No evidence artifacts in evidence index");
    qualityScore -= 20;
  }
  
  // Check 8: Confidence scores are reasonable (not all 1.0)
  const confidences = [
    eno.engagementOverview.confidence,
    eno.businessImpactAnalysis.confidence,
    eno.overallAssessment.confidence,
    ...eno.attackStory.map(s => s.confidence),
    ...eno.defensiveGaps.map(g => g.confidence),
  ];
  
  const allMaxConfidence = confidences.every(c => c === 1.0);
  if (allMaxConfidence) {
    warnings.push("All confidence scores are 1.0 - seems unrealistic");
    qualityScore -= 5;
  }
  
  // Ensure score doesn't go below 0
  qualityScore = Math.max(0, qualityScore);
  
  return {
    passed: errors.length === 0,
    errors,
    warnings,
    score: qualityScore,
  };
}

/**
 * Extract all text content from ENO for analysis
 */
function extractAllText(eno: ENO): string {
  const texts: string[] = [];
  
  // Engagement overview
  texts.push(eno.engagementOverview.scope);
  texts.push(...eno.engagementOverview.objectives);
  texts.push(eno.engagementOverview.methodology);
  texts.push(...eno.engagementOverview.keyHighlights);
  
  // Attack story
  for (const segment of eno.attackStory) {
    texts.push(segment.narrative);
  }
  
  // Business impact
  texts.push(eno.businessImpactAnalysis.executiveSummary);
  texts.push(eno.businessImpactAnalysis.operationalImpact);
  texts.push(eno.businessImpactAnalysis.reputationalImpact);
  if (eno.businessImpactAnalysis.regulatoryImpact) {
    texts.push(eno.businessImpactAnalysis.regulatoryImpact);
  }
  for (const risk of eno.businessImpactAnalysis.primaryRisks) {
    texts.push(risk.description);
  }
  
  // Defensive gaps
  for (const gap of eno.defensiveGaps) {
    texts.push(gap.description);
  }
  
  // Risk prioritization
  for (const risk of eno.riskPrioritizationLogic) {
    texts.push(risk.businessImpact);
    texts.push(risk.rationale);
  }
  
  // Overall assessment
  texts.push(eno.overallAssessment.verdictNarrative);
  texts.push(...eno.overallAssessment.strengthsObserved);
  texts.push(...eno.overallAssessment.criticalWeaknesses);
  for (const action of eno.overallAssessment.immediateActions) {
    texts.push(action.action);
    texts.push(action.expectedImpact);
  }
  for (const rec of eno.overallAssessment.strategicRecommendations) {
    texts.push(rec.recommendation);
    texts.push(rec.rationale);
  }
  
  return texts.join(" ").toLowerCase();
}

/**
 * Detect repetition in text using n-gram analysis
 */
function detectRepetition(text: string): number {
  const words = text.split(/\s+/).filter(w => w.length > 3);
  if (words.length < 20) return 0;
  
  // Create 3-grams
  const ngrams: Map<string, number> = new Map();
  for (let i = 0; i < words.length - 2; i++) {
    const ngram = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
    ngrams.set(ngram, (ngrams.get(ngram) || 0) + 1);
  }
  
  // Count repeated n-grams
  let repeatedCount = 0;
  let totalNgrams = 0;
  
  ngrams.forEach((count) => {
    totalNgrams += count;
    if (count > 1) {
      repeatedCount += count - 1;
    }
  });
  
  return totalNgrams > 0 ? repeatedCount / totalNgrams : 0;
}

/**
 * Lint a report section (for use with generated reports, not just ENO)
 */
export function lintReportSection(content: string, sectionName: string): LintResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let qualityScore = 100;
  
  const lowerContent = content.toLowerCase();
  
  // Check forbidden phrases
  for (const phrase of FORBIDDEN_PHRASES) {
    if (lowerContent.includes(phrase)) {
      warnings.push(`${sectionName}: Contains templated phrase "${phrase}"`);
      qualityScore -= 5;
    }
  }
  
  // Check minimum length
  if (content.length < MIN_NARRATIVE_LENGTH) {
    errors.push(`${sectionName}: Content too short (${content.length} chars, minimum ${MIN_NARRATIVE_LENGTH})`);
    qualityScore -= 15;
  }
  
  // Check for bullet-only content
  const bulletLines = content.split("\n").filter(line => line.trim().match(/^[-*•]\s/));
  const totalLines = content.split("\n").filter(line => line.trim().length > 0);
  
  if (bulletLines.length > 0 && bulletLines.length / totalLines.length > 0.8) {
    warnings.push(`${sectionName}: Mostly bullet points (${Math.round(bulletLines.length / totalLines.length * 100)}%). Consider adding narrative.`);
    qualityScore -= 10;
  }
  
  return {
    passed: errors.length === 0,
    errors,
    warnings,
    score: Math.max(0, qualityScore),
  };
}
