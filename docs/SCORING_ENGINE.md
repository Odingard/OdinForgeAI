# Scoring Engine & Threat Intelligence

**Version:** 3.0 (Deterministic)
**Last Updated:** February 20, 2026

---

## Overview

OdinForge uses a **deterministic, reproducible scoring formula** to prioritize vulnerabilities — replacing LLM-based estimation with real threat intelligence signals. This is the same approach used by enterprise platforms like Qualys TruRisk, Tenable VPR, and CrowdStrike Falcon Spotlight.

Every score includes an audit-friendly methodology string showing exactly which signals drove the result:

```
OdinForge Deterministic v3.0 | EPSS 97.2% (P100) | CVSS 3.1 9.8 | CISA KEV [Ransomware] | Asset: critical
```

---

## Scoring Formula

### Exploitability Score (0-100)

The exploitability score combines three weighted signals:

| Signal | Weight | Range | Source |
|--------|--------|-------|--------|
| EPSS probability | 45% | 0.0-1.0 (×100) | FIRST.org API |
| CVSS base score | 35% | 0.0-10.0 (×10) | Parsed CVSS vector |
| Agent exploitability | 20% | 0 or 100 | Exploit agent tool results |

When signals are missing, weights **automatically redistribute** to available data:

| Available Signals | EPSS | CVSS | Agent |
|-------------------|------|------|-------|
| All three | 45% | 35% | 20% |
| EPSS + CVSS only | 55% | 45% | — |
| EPSS + Agent only | 65% | — | 35% |
| CVSS + Agent only | — | 70% | 30% |
| EPSS only | 100% | — | — |
| CVSS only | — | 100% | — |
| Agent only | — | — | 100% |
| None | Falls back to severity heuristic |

### Override Rules

1. **CISA KEV Floor**: If CVE is on the CISA Known Exploited Vulnerabilities catalog, exploitability is floored at **85**.
2. **Ransomware Amplifier**: If CVE has known ransomware campaign use, exploitability gets **+10** bonus.
3. **Finding Severity Boost**: +5 per critical finding, +2 per high finding from the agent.

### Business Impact Score (0-100)

```
businessImpact = exploitabilityScore × priorityWeight × criticalityWeight
```

| Finding Severity | Priority Weight |
|-----------------|----------------|
| Critical | 1.0 |
| High | 0.8 |
| Medium | 0.6 |
| Low | 0.4 |

| Asset Criticality | Criticality Weight |
|-------------------|-------------------|
| Critical | 1.3 |
| High | 1.1 |
| Medium | 1.0 |
| Low | 0.7 |

**KEV Compliance Floor**: If CVE is on CISA KEV, business impact is floored at **70** (regulatory risk).

### Overall Risk Score

```
overallScore = exploitability × 0.60 + businessImpact × 0.40
```

| Score Range | Risk Level | Action |
|-------------|-----------|--------|
| >= 90 | Emergency | Fix immediately |
| >= 75 | Critical | Fix within 24 hours |
| >= 55 | High | Fix within 7 days |
| >= 35 | Medium | Fix within 30 days |
| >= 15 | Low | Fix within 90 days |
| < 15 | Info | Acceptable risk |

### Exploit Maturity Mapping

The scoring engine deterministically maps exploit maturity based on available signals:

| Condition | Availability | Skill Required | Score |
|-----------|-------------|---------------|-------|
| CISA KEV listed | `in_the_wild` | `script_kiddie` or `intermediate` | 95 |
| EPSS >= 0.5 | `weaponized` | `intermediate` | 80 |
| EPSS >= 0.1 | `poc` | `intermediate` | 60 |
| Agent confirmed exploit | `poc` | `advanced` | 50 |
| None of above | `theoretical` | `advanced` | 20 |

### Confidence Score

Confidence tracks data richness (max 100):

| Signal Present | Confidence Added |
|---------------|-----------------|
| EPSS score | +30 |
| CVSS vector/score | +25 |
| CISA KEV status | +15 |
| Agent exploitation result | +20 |
| Finding severity data | +10 |

---

## Threat Intelligence Sources

### EPSS (Exploit Prediction Scoring System)

**Source:** [FIRST.org](https://www.first.org/epss/)
**Update Frequency:** Daily
**Coverage:** 200,000+ CVEs
**Cost:** Free, no authentication required

EPSS provides the probability that a CVE will be exploited in the wild within the next 30 days. It uses machine learning trained on real-world exploitation data from IDS/IPS sensors, honeypots, and threat intelligence feeds.

**Integration Details:**
- Batch queries: up to 100 CVEs per API call
- Rate limit: 1,000 requests/minute
- In-memory cache: 24h TTL (matches daily update frequency)
- Graceful degradation: scoring works without EPSS if API is unreachable
- Response values are strings — automatically parsed to float

**API Endpoint:**
```
GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-1234
```

**OdinForge API:**
```
GET /api/threat-intel/epss?cve=CVE-2021-44228,CVE-2024-1234
```
Requires authentication (`evaluations:read` permission). Max 100 CVEs per request.

### CVSS Vector Parsing

**Supported Versions:** CVSS v2.0, v3.0, v3.1
**Source:** Vulnerability scanner imports, NVD data

The CVSS parser handles all three vector formats with automatic version detection:

```
CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8
CVSS v3.0: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8
CVSS v2:   AV:N/AC:L/Au:N/C:C/I:C/A:C                       → 10.0
```

**Extracted Metrics:**
- Attack Vector (network, adjacent, local, physical)
- Attack Complexity (low, high)
- Privileges Required (none, low, high)
- User Interaction (none, required)
- Scope (unchanged, changed — v3 only)
- Confidentiality/Integrity/Availability Impact

**Derived Fields (for scoring context):**
- Network exposure: internet | dmz | internal | isolated
- Auth required: none | single | multi-factor | privileged

### CISA KEV (Known Exploited Vulnerabilities)

**Source:** CISA Known Exploited Vulnerabilities Catalog
**Purpose:** Binary override signal for confirmed active exploitation

When a CVE appears in the CISA KEV catalog:
- Exploitability score is floored at **85** regardless of other signals
- Business impact is floored at **70** (regulatory compliance risk)
- Exploit maturity is set to `in_the_wild`
- If ransomware use is confirmed, exploitability gets an additional **+10** bonus

KEV status is checked against locally stored threat intelligence indicators via `storage.getThreatIntelIndicatorByValue()`.

---

## Data Flow

```
Vulnerability Import / Agent Finding
         │
         ▼
┌─────────────────────┐
│  Collect CVE IDs    │ ← From vulnerability imports
│  from findings      │
└────────┬────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────────┐
│ EPSS   │ │ KEV Lookup │ ← Parallel enrichment
│ Batch  │ │ (local DB) │
│ Fetch  │ └─────┬──────┘
└───┬────┘       │
    │            │
    ▼            ▼
┌─────────────────────────────┐
│  ScoringContext             │
│  ├─ epssScore (0.0-1.0)    │
│  ├─ epssPercentile          │
│  ├─ cvssScore (0.0-10.0)   │
│  ├─ cvssVector              │
│  ├─ isKevListed             │
│  ├─ kevRansomwareUse        │
│  ├─ assetCriticality        │
│  ├─ findings[]              │
│  └─ agentExploitable        │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  generateDeterministicScore │
│  ├─ Weighted formula        │
│  ├─ KEV overrides           │
│  ├─ Exploit maturity map    │
│  ├─ Business impact calc    │
│  └─ Methodology string      │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  IntelligentScore           │
│  ├─ riskRank.overallScore   │
│  ├─ exploitability.score    │
│  ├─ businessImpact.score    │
│  ├─ methodology (audit str) │
│  └─ calculatedAt            │
└─────────────────────────────┘
```

Both EPSS and KEV enrichment are wrapped in try/catch — if either fails, scoring proceeds with available data.

---

## Database Schema

### vulnerability_imports table

| Column | Type | Description |
|--------|------|-------------|
| `epss_score` | real (nullable) | EPSS exploitation probability (0.0-1.0) |
| `epss_percentile` | real (nullable) | EPSS percentile rank (0.0-1.0) |
| `epss_updated_at` | timestamp (nullable) | When EPSS data was last fetched |
| `is_kev_listed` | boolean (default false) | Whether CVE is on CISA KEV |

### agent_findings table

| Column | Type | Description |
|--------|------|-------------|
| `epss_score` | real (nullable) | EPSS exploitation probability (0.0-1.0) |
| `epss_percentile` | real (nullable) | EPSS percentile rank (0.0-1.0) |
| `is_kev_listed` | boolean (default false) | Whether CVE is on CISA KEV |

All columns are nullable and additive — zero-downtime migration.

---

## Key Files

| File | Purpose |
|------|---------|
| `server/services/threat-intel/epss-client.ts` | EPSS API client with batch queries + 24h cache |
| `server/services/threat-intel/index.ts` | Threat intel module exports |
| `server/services/agents/scoring-engine.ts` | `generateDeterministicScore()` + scoring context |
| `server/services/agents/orchestrator.ts` | Wires EPSS + KEV enrichment into scoring |
| `server/services/cvss-parser.ts` | CVSS v2/v3.x vector parser |
| `client/src/components/IntelligentScorePanel.tsx` | UI panel showing scores + threat intel badges |

---

## UI: Threat Intelligence Signals

The `IntelligentScorePanel` component displays:

- **Overall risk score** with trend indicator (improving/stable/degrading)
- **Risk level badge** (emergency/critical/high/medium/low/info)
- **Fix priority** and recommended remediation timeframe
- **Exploitability tab** — attack complexity, auth requirements, detection likelihood, exploit maturity
- **Business Impact tab** — data sensitivity, financial exposure, compliance impact, blast radius, reputational risk
- **Threat Intel badges** — EPSS score (purple), CVSS version (blue), CISA KEV (red), Known Ransomware (dark red)
- **Methodology string** — audit trail showing exact signals and versions

---

## Comparison to Industry

| Feature | OdinForge v3.0 | Qualys TruRisk | Tenable VPR | CrowdStrike Spotlight |
|---------|---------------|----------------|-------------|----------------------|
| EPSS integration | Yes | Yes | Yes | Yes |
| CVSS base score | Yes | Yes | Yes | Yes |
| CISA KEV override | Yes | Yes | Yes | Yes |
| Asset criticality | Yes | Yes | Yes | Yes |
| Deterministic formula | Yes | Yes | Yes | Yes |
| Ransomware amplifier | Yes | Yes | No | Yes |
| Agent exploit confirmation | Yes | No | No | No |
| Audit methodology string | Yes | No | No | No |
| Transparent weights | Yes | No | No | No |

OdinForge's unique advantage: the exploit agent provides **tool-confirmed exploitability** as a scoring input, rather than relying solely on external threat intel signals.
