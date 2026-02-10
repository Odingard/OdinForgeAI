# Generate Breach Validation Report

You are generating an OdinForge AEV Breach Validation Report from the following assessment data.

## ENO (Engagement Narrative Object)
{{ENO}}

## Raw Assessment Data
{{INPUT_DATA}}

## Breach Realization Score (Pre-Computed)
{{BREACH_SCORE}}

## Required Output Structure

Generate a JSON object matching this exact structure. Every field is required unless marked optional.

```json
{
  "reportType": "breach_validation_v2",
  "generatedAt": "<ISO timestamp>",

  "coverPage": {
    "title": "OdinForge Autonomous Exploit Validation Report",
    "subtitle": "Validated Breach Paths & Remediation Confirmation",
    "targetName": "<company/application name from assessment data>",
    "assessmentType": "Autonomous Exploit Validation (AEV)",
    "date": "<assessment date>"
  },

  "executiveBreachSummary": "<2-3 paragraph narrative of WHAT ACTUALLY HAPPENED. Include: total time to first impact, highest privilege achieved, business-critical assets accessed, number of completed attack paths, whether remediation was validated. Do NOT list OWASP categories. Write as if briefing a CEO.>",

  "breachRealizationScore": {
    "overall": <0-100 from pre-computed score>,
    "dimensions": [
      {
        "dimension": "<dimension name>",
        "score": <0-100>,
        "explanation": "<1-2 sentence plain-language explanation>"
      }
    ],
    "narrativeExplanation": "<2-3 sentences explaining WHY the score is what it is, in non-technical language>"
  },

  "attackPathOverview": [
    {
      "pathId": "<unique ID>",
      "shortName": "<e.g., External -> Application -> Cloud IAM -> Production Data>",
      "entryPoint": "<how access was obtained>",
      "pivotSequence": "<brief chain description>",
      "endState": "<what the attacker could now do>",
      "businessImpact": "<concrete business consequence>"
    }
  ],

  "attackPathDetails": [
    {
      "pathId": "<matching pathId from overview>",
      "title": "<descriptive name>",
      "entryPoint": {
        "description": "<how access was obtained>",
        "preconditions": "<any preconditions or 'None - unauthenticated access'>",
        "whyExploitable": "<root cause explanation>"
      },
      "exploitationSequence": [
        {
          "step": <order number>,
          "action": "<what was done>",
          "technique": "<MITRE ATT&CK technique if applicable>",
          "outcome": "<what was gained>",
          "evidenceRef": "<evidence ID>"
        }
      ],
      "sessionReplayEvidence": {
        "timestamps": ["<key timestamps>"],
        "stateChanges": ["<identity transitions, access level changes>"],
        "attestation": "This sequence was autonomously executed and recorded by OdinForge AEV."
      },
      "endState": {
        "accessAchieved": "<what the attacker can now do>",
        "dataAccessible": "<what data/systems are accessible>",
        "businessSignificance": "<why this matters to the business>"
      }
    }
  ],

  "remediationWithValidation": [
    {
      "attackPathId": "<which attack path this fixes>",
      "recommendedFix": {
        "description": "<exact remediation steps>",
        "implementation": "<IaC snippet, config diff, or policy change>",
        "effort": "<low|medium|high>",
        "timeline": "<recommended timeline>"
      },
      "validationResult": {
        "replayAttempted": <true|false>,
        "blocked": <true|false|null>,
        "blockedAtStep": "<which step in the chain was blocked, or null>",
        "verdict": "<ATTACK_PATH_BLOCKED | ATTACK_PATH_STILL_EXPLOITABLE | VALIDATION_PENDING>",
        "explanation": "<what happened when replay was attempted>"
      }
    }
  ],

  "businessContext": {
    "financialRisk": "<concrete financial exposure estimate with basis>",
    "regulatoryExposure": "<which regulations are implicated and why>",
    "operationalDisruption": "<what business operations are at risk>",
    "reputationImpact": "<customer/market impact assessment>"
  },

  "technicalAppendix": {
    "exploitPayloads": [
      {
        "attackPathId": "<reference>",
        "step": <step number>,
        "payload": "<the actual exploit payload or command>",
        "requestResponse": "<summarized HTTP request/response or command output>"
      }
    ],
    "environmentAssumptions": ["<list of assumptions about the target environment>"],
    "toolsUsed": ["OdinForge AEV Engine", "<other tools>"]
  },

  "differentiationStatement": "This report validates complete attack paths rather than isolated vulnerabilities. Findings represent confirmed exploitation sequences that demonstrate how application compromise transitions into full environment breach. Every finding in this report was autonomously validated through live execution.",

  "attestation": "This assessment was performed autonomously by OdinForge AEV. All findings represent validated execution paths observed during live testing. No theoretical or unconfirmed risks are included in the primary findings."
}
```

## CRITICAL RULES

1. **Breach-first storytelling**: The Executive Breach Summary must read like an incident report, not a vulnerability scan summary.
2. **No orphan findings**: Every finding MUST connect to an attack path. If a finding does not result in privilege escalation, lateral movement, or business impact, it belongs in the technical appendix only — NOT as a primary result.
3. **Validation results are mandatory**: Every remediation recommendation must state whether the fix was validated. Use VALIDATION_PENDING if replay was not performed.
4. **Evidence anchoring**: Every claim in the attack path details must reference a specific evidence artifact.
5. **Quantify everything**: Financial risk in dollars, time to impact in minutes, blast radius in asset counts.
6. **Use the pre-computed Breach Realization Score**: Map its dimensions into the narrativeExplanation. Do not recalculate.
