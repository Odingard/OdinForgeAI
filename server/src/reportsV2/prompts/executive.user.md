# Executive Report Generation Task

Generate an executive report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)

```json
{{ENO}}
```

## Raw Assessment Data

```json
{{INPUT_DATA}}
```

## Your Task

Transform the ENO into an executive-ready report that communicates risk and recommendations to C-suite and board-level stakeholders.

## Required Output Structure

Generate a valid JSON object with:

### reportType
Must be: `"executive_v2"`

### generatedAt
ISO timestamp of generation

### executiveSummary (200+ chars)
A 2-3 paragraph narrative that:
- Opens with the most critical finding/risk
- Summarizes what was assessed and what was found
- Ends with the overall risk posture and key recommendation
- Uses business language, not technical jargon

### topRisksRankedByBusinessImpact
Array of top 5-10 risks, each with:
- `rank`: 1, 2, 3, etc.
- `title`: Short, memorable title
- `businessImpact`: Description of business impact (50+ chars)
- `affectedBusinessProcess`: Which business process is affected
- `financialExposure`: Estimated financial impact (optional but recommended)
- `likelihood`: "certain" | "highly_likely" | "likely" | "possible" | "unlikely"

### attackStorySummary (150+ chars)
Condensed narrative suitable for board presentation:
- What could an attacker do?
- How easily?
- What would they gain?

### financialExposure
Object with:
- `estimatedTotalExposure`: Total estimated exposure
- `breakdownByCategory`: Array with category, amount, basis (how estimated)
- `mitigationCostVsRisk`: Comparison of fix cost vs. risk cost

### strategicRecommendations
Array of 3-5 strategic recommendations, each with:
- `title`: Action-oriented title
- `description`: What to do and why (50+ chars)
- `priority`: "critical" | "high" | "medium" | "low"
- `effort`: "low" | "medium" | "high"
- `expectedOutcome`: What success looks like
- `stakeholders`: (optional) Who needs to be involved

### day30_60_90Plan
Phased remediation roadmap:
- `day30`: Array of actions for first 30 days
- `day60`: Array of actions for days 31-60
- `day90`: Array of actions for days 61-90

Each action should have:
- `action`: What to do
- `owner`: (optional) Responsible party
- `milestone`: (optional) Success milestone
- `dependencies`: (optional) What this depends on

### boardBriefingPoints (optional)
Array of 3-5 bullet points suitable for board presentation

## Tone Guidelines

- Confident but not alarmist
- Quantified where possible
- Action-oriented
- Business-focused (not technical)
- Honest about uncertainty
