# Technical Report Generation Task

Generate a technical report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)

```json
{{ENO}}
```

## Raw Assessment Data

```json
{{INPUT_DATA}}
```

## Your Task

Create a detailed technical report that security engineers can use to understand and remediate the identified issues.

## Required Output Structure

Generate a valid JSON object with:

### reportType
Must be: `"technical_v2"`

### generatedAt
ISO timestamp of generation

### attackNarrativeDetailed (300+ chars)
Full technical narrative of the attack paths discovered. Include:
- Initial access methods attempted and successful
- Privilege escalation techniques
- Lateral movement possibilities
- Data access or exfiltration potential
- Technical specifics (ports, protocols, commands)

### findings
Array of findings, each with:
- `id`: Unique identifier
- `title`: Descriptive title
- `severity`: "critical" | "high" | "medium" | "low" | "informational"
- `description`: What the issue is (50+ chars)
- `technicalDetails`: Technical specifics of the vulnerability
- `affectedComponents`: Array of affected components
- `evidenceReferences`: Array of evidence IDs
- `cweId`: (optional) CWE ID if applicable
- `cveId`: (optional) CVE ID if applicable
- `cvssScore`: (optional) CVSS score if applicable

### attackPathsWithReasoning
Array of attack paths, each with:
- `pathId`: Unique identifier
- `title`: Descriptive title for the attack path
- `narrative`: Explanation of the attack chain (100+ chars)
- `steps`: Array of steps, each with order, technique, mitreId (optional), description, prerequisites (optional), outcome
- `complexity`: "trivial" | "moderate" | "complex" | "expert"
- `timeToCompromise`: Estimated time (e.g., "2 hours", "several days")
- `businessImpact`: What this attack path achieves
- `evidenceReferences`: Array of evidence IDs

### prioritizedFixPlan
Array of remediation steps, ordered by priority:
- `priority`: Numeric priority (1 = highest)
- `findingIds`: Array of finding IDs this addresses
- `action`: What to do
- `rationale`: Why this is important (30+ chars)
- `effort`: "low" | "medium" | "high"
- `commands`: (optional) Array of specific commands to run
- `configChanges`: (optional) Configuration changes needed
- `toolsRequired`: (optional) Array of tools needed
- `verificationSteps`: Array of steps to verify the fix

### verificationSteps
Array of verification guidance:
- `findingId`: Which finding this verifies
- `steps`: Array of verification steps
- `expectedResult`: What success looks like
- `tools`: (optional) Array of tools for verification

### architectureRecommendations (optional)
Array of architecture improvements:
- `area`: Security area (e.g., "Network Segmentation")
- `currentState`: Current architecture state
- `recommendedState`: Target architecture state
- `rationale`: Why this change is recommended
- `implementationNotes`: (optional) Implementation guidance

## Quality Requirements

1. Commands should be copy-paste ready
2. Include specific versions where tools are mentioned
3. Explain the "why" for each remediation step
4. Verification steps should be actionable
5. Reference evidence for all claims
