# Evidence Package Generation Task

Generate an evidence package based on the following ENO and assessment data.

## ENO (Engagement Narrative Object)

```json
{{ENO}}
```

## Raw Assessment Data

```json
{{INPUT_DATA}}
```

## Your Task

Create a forensic-quality evidence package that documents all artifacts and their significance.

## Required Output Structure

Generate a valid JSON object with:

### reportType
Must be: `"evidence_v2"`

### generatedAt
ISO timestamp of generation

### timelineNarrative (200+ chars)
Chronological story of the assessment:
- When did testing begin?
- What sequence of discoveries occurred?
- How did findings build upon each other?
- When were critical issues identified?

### timeline
Array of timeline events:
- `timestamp`: ISO timestamp
- `event`: What happened
- `significance`: Why this matters
- `artifactIds`: Array of related artifact IDs

### artifactIndex
Catalog of all evidence artifacts:
- `id`: Unique artifact identifier
- `type`: "http_capture" | "log_entry" | "screenshot" | "config_file" | "network_trace" | "command_output" | "code_snippet"
- `title`: Descriptive title
- `description`: What this artifact shows
- `timestamp`: (optional) When captured
- `sourceSystem`: (optional) Where it came from
- `contentPreview`: (optional) Preview of content
- `fullContentRef`: (optional) Reference to full content
- `chainOfCustody`: (optional) Object with collectedAt, collectedBy, hash

### whatEachArtifactProves
Array mapping artifacts to claims:
- `artifactId`: Artifact identifier
- `proves`: Array of claims this artifact supports
- `relatedFindings`: Array of finding IDs
- `significance`: "critical" | "supporting" | "contextual"

### evidenceSummary
Statistics about the evidence:
- `totalArtifacts`: Count of artifacts
- `byType`: Object mapping type to count
- `timespan`: (optional) Object with earliest and latest timestamps

## Evidence Organization Guidelines

### Artifact Types

**http_capture**
- HTTP requests and responses
- Include method, URL, headers, body
- Note authentication tokens (redacted if sensitive)

**log_entry**
- Application, system, or security logs
- Include timestamps, source, message
- Context around the relevant entry

**screenshot**
- Visual evidence of states or configurations
- Annotate key elements
- Include timestamp if relevant

**config_file**
- Configuration demonstrating vulnerabilities
- Before/after comparisons
- Highlight problematic settings

**network_trace**
- PCAP data or flow information
- Protocol analysis results
- Notable traffic patterns

**command_output**
- Terminal session outputs
- Tool results (nmap, etc.)
- Include full command used

**code_snippet**
- Vulnerable code sections
- Exploit payloads used
- Remediation code samples

## Quality Requirements

1. Every artifact should trace to at least one finding
2. Timestamps should be in ISO 8601 format (UTC)
3. Sensitive data should be noted for redaction
4. Chain of custody should be preserved
5. Organization should support both quick review and detailed analysis
