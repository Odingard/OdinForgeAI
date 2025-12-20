# ENO Generation Task

Based on the following security assessment data, generate an Engagement Narrative Object (ENO) that captures the complete story of this security engagement.

## Input Data

```json
{{INPUT_DATA}}
```

## Your Task

Analyze the assessment data and generate a comprehensive ENO that tells the story of what was found, why it matters, and what should be done about it.

## Required Output Structure

Generate a valid JSON object with these sections:

### 1. engagementOverview
- `scope`: Describe what was assessed (50+ chars)
- `objectives`: Array of assessment objectives
- `methodology`: Describe the testing approach used
- `timeframe`: Object with `start` and `end` ISO dates
- `assetsAssessed`: Array of assets with id, name, type, criticality
- `overallRiskLevel`: "critical" | "high" | "medium" | "low"
- `keyHighlights`: Array of 3-5 key findings/observations
- `confidence`: 0-1 confidence score

### 2. attackStory
Array of attack story segments, each with:
- `phase`: MITRE ATT&CK phase (initial_access, execution, persistence, etc.)
- `narrative`: Detailed narrative of what happened in this phase (50+ chars)
- `techniques`: Array of technique names used
- `evidenceRefs`: Array of evidence IDs that support this
- `complexity`: "trivial" | "moderate" | "complex" | "expert"
- `confidence`: 0-1 confidence score

### 3. businessImpactAnalysis
- `executiveSummary`: 2-3 paragraph summary for executives (100+ chars)
- `primaryRisks`: Array of risks with title, description, affectedBusinessProcess, potentialConsequences, estimatedFinancialImpact
- `operationalImpact`: Description of operational impact
- `reputationalImpact`: Description of reputational impact
- `regulatoryImpact`: (optional) Regulatory impact
- `confidence`: 0-1 confidence score

### 4. defensiveGaps
Array of gaps with:
- `category`: "detection" | "prevention" | "response" | "recovery" | "visibility" | "process" | "training"
- `title`: Short title
- `description`: What the gap is (30+ chars)
- `affectedAssets`: Array of affected asset IDs
- `exploitedInAttack`: Boolean - was this gap exploited?
- `remediationEffort`: "low" | "medium" | "high"
- `confidence`: 0-1 confidence score

### 5. riskPrioritizationLogic
Array of prioritized findings:
- `findingId`: Reference to finding
- `priority`: Numeric priority (1 = highest)
- `businessImpact`: Description of business impact (20+ chars)
- `exploitLikelihood`: "certain" | "highly_likely" | "likely" | "possible" | "unlikely"
- `blastRadius`: Description of what could be affected
- `financialExposure`: (optional) Estimated financial exposure
- `rationale`: Why this priority was assigned (50+ chars)
- `confidence`: 0-1 confidence score

### 6. overallAssessment
- `verdict`: "critical" | "high" | "medium" | "low"
- `verdictNarrative`: Explanation of the overall verdict (100+ chars)
- `strengthsObserved`: Array of security strengths observed
- `criticalWeaknesses`: Array of critical weaknesses
- `immediateActions`: Array with action, priority ("immediate" | "short_term" | "medium_term"), effort, expectedImpact
- `strategicRecommendations`: Array with recommendation, rationale, timeframe
- `confidence`: 0-1 confidence score

### 7. evidenceIndex
Array of evidence references:
- `id`: Unique evidence ID
- `type`: "http_capture" | "log_entry" | "screenshot" | "config_file" | "network_trace" | "command_output"
- `description`: What this evidence shows
- `timestamp`: (optional) When it was captured
- `relevance`: Why this evidence matters

## Quality Requirements

1. **Be specific**: Reference actual assets, findings, and data from the input
2. **Tell a story**: Attack phases should flow logically
3. **Quantify impact**: Use numbers where possible
4. **Anchor to evidence**: Every major claim should reference evidence
5. **Vary confidence**: Not everything is 1.0 confidence - be honest about uncertainty
