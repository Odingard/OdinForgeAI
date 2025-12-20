# Compliance Report Generation Task

Generate a compliance report based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)

```json
{{ENO}}
```

## Raw Assessment Data

```json
{{INPUT_DATA}}
```

## Your Task

Map the security findings to compliance framework requirements and provide audit-ready documentation.

## Required Output Structure

Generate a valid JSON object with:

### reportType
Must be: `"compliance_v2"`

### generatedAt
ISO timestamp of generation

### frameworkSummary
Overview of compliance posture:
- `primaryFramework`: Main framework assessed (e.g., "SOC 2 Type II", "PCI-DSS v4.0")
- `additionalFrameworks`: Array of other applicable frameworks
- `overallComplianceScore`: 0-100 score
- `criticalGaps`: Count of critical control gaps
- `partialCompliance`: Count of partially compliant controls
- `fullCompliance`: Count of fully compliant controls

### controlFailuresWithOperationalExplanations
Array of failed controls, each with:
- `controlId`: Control identifier (e.g., "CC6.1", "PCI-DSS 6.2.4")
- `controlName`: Human-readable control name
- `framework`: Framework this control belongs to
- `operationalExplanation`: What this means in practice (50+ chars)
- `findingIds`: Array of finding IDs that caused failure
- `evidenceIds`: Array of evidence IDs demonstrating the gap
- `remediationGuidance`: How to achieve compliance
- `compensatingControls`: (optional) Alternative controls if direct fix isn't possible

### evidenceLinks
Array mapping evidence to controls:
- `evidenceId`: Evidence identifier
- `controlIds`: Array of controls this evidence relates to
- `purpose`: What this evidence proves or disproves

### auditReadinessNotes
Audit preparation guidance:
- `currentReadiness`: "not_ready" | "partially_ready" | "mostly_ready" | "audit_ready"
- `keyGaps`: Array of gaps that would fail an audit
- `recommendedActions`: Array with action, timeline, impact
- `documentationNeeded`: Array of documentation to prepare

### frameworkSpecificAnalysis (optional)
Object keyed by framework name, each containing:
- `requirements`: Array with requirementId, description, status ("met" | "not_met" | "partially_met" | "not_applicable"), notes (optional)

## Framework Mapping Guidelines

### SOC 2 Trust Service Criteria
- CC1.x: Control Environment
- CC2.x: Communication and Information
- CC3.x: Risk Assessment
- CC4.x: Monitoring Activities
- CC5.x: Control Activities
- CC6.x: Logical and Physical Access
- CC7.x: System Operations
- CC8.x: Change Management
- CC9.x: Risk Mitigation

### PCI-DSS v4.0 Requirements
- Req 1-2: Network Security
- Req 3-4: Data Protection
- Req 5-6: Vulnerability Management
- Req 7-8: Access Control
- Req 9-10: Physical/Monitoring
- Req 11-12: Testing/Policies

### HIPAA Safeguards
- Administrative Safeguards
- Physical Safeguards
- Technical Safeguards

## Quality Requirements

1. Cite specific control requirements, not general categories
2. Explain gaps in operational terms
3. Provide actionable remediation guidance
4. Consider audit timelines in recommendations
5. Include compensating controls where appropriate
