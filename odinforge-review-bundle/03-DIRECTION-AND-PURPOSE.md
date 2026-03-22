# OdinForge-AI — Direction & Purpose (2026-03-22)

## What OdinForge Is
**Autonomous Exploitation & Validation (AEV) platform** — not a scanner, not a pentest-as-a-service clone. OdinForge runs real exploit chains against real targets and proves exploitability with cryptographically verifiable evidence.

The core differentiator: findings are **evidence-backed** and architecturally cannot be synthetic. ADR-001 (EvidenceContract) makes it structurally impossible for the system to generate a finding without real HTTP evidence.

## Market Position
- **Target market**: $3.4B AEV market by 2027
- **Competitive gap**: No competitor ships evidence-backed findings with full breach chain replay
- **Target buyers**: Security Engineering Leads + CISOs

## Business Model (ADR-005)
- **One-and-done per-engagement pricing** — no subscriptions
- **Tiers**: Standard / Deep / MSSP White-Label — all per-assessment, not per-seat
- **Re-engagement**: Every sealed engagement includes a 90-day follow-on offer at 20% discount
- **API keys**: Per-engagement, automatically deactivated when package is sealed

## Current Strategic Direction: Managed Adversarial Assessment Service
Dre runs assessments remotely from his own OdinForge instance against customer environments:
- Customer never installs anything (no Go agent, no platform access)
- Delivers sealed Engagement Package with confirmed exploitable vulnerabilities, blast radius mapping, remediation priorities
- External-only assessment: Phases 1-2 are primary attack surface; Phases 3-6 require customer-provided cloud creds or credentials harvested from Phases 1-2
- Path to first revenue (Sprint 6 / Week 12 target)

## Foundation Principles

### 10 ADRs (Architectural Constitution)
| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| ADR-001 | EvidenceContract | Accepted | `RealFinding.create()` requires `RealHttpEvidence`. Synthetic findings architecturally impossible. |
| ADR-002 | LLM Boundary | Accepted | LLM is classifier/narrator only — never evidence generator. 5 permitted contexts: classify, vary payloads, narrate, suggest fixes, reason about chains. |
| ADR-005 | Engagement Model | Accepted | One-and-done. Per-engagement pricing. 90-day re-engagement. API keys expire on seal. |
| ADR-007 | Defender's Mirror | Accepted | Sigma rule per confirmed finding, mandatory in Engagement Package. |
| ADR-008 | Breach Chain Replay | Accepted | Standalone HTML export, mandatory in Engagement Package. |
| ADR-009 | Per-Engagement API Keys | Accepted | Scoped to engagement ID, deactivate on package seal. |
| ADR-010 | Mandatory Leave-Behinds | Accepted | Sigma rules + Replay are mandatory, not optional add-ons. |

### 6 Core Principles (Foundation Document)
1. Real evidence or nothing — no synthetic findings
2. LLM as tool, not authority — classifier/narrator only
3. One-and-done engagement model
4. Defender gets the mirror — every finding comes with detection rules
5. Breach chain replay — customer sees exactly what happened
6. Per-engagement isolation — keys, data, access scoped and sealed

### Kill Switches
1. Competitor ships evidence-backed findings before Week 8
2. Full breach chain fails by Week 6
3. EvidenceContract false positive rate > 5%
4. LLM inference cost per scan > $3.00
5. No paying customer by Week 16

## Engineering Timeline
- **6 sprints / 12 weeks**
- **Demo at Week 8**
- **First revenue at Week 12**

## Engagement Package (5 Mandatory Components)
1. CISO PDF (risk grade A-F, breach narrative, blast radius)
2. Security Engineer PDF (full finding detail, evidence, chain trace, remediation diff)
3. Evidence JSON (complete EvidenceContract data)
4. Defender's Mirror Sigma rules
5. Breach Chain Replay (self-contained HTML)

## Service Docs (Built)
- `docs/managed-service/service-description.md` — One-page service description for outreach
- `docs/managed-service/pricing-sheet.md` — Standard/Deep/MSSP tier pricing
- `docs/managed-service/scoping-questionnaire.md` — Pre-engagement scoping questionnaire

## Deployment
- **Production**: DigitalOcean `24.199.95.237`, domain `odinforgeai.com`
- **Staging**: `159.65.234.95`, domain `staging.odinforgeai.com`
- **6 containers**: App, Worker, PostgreSQL 15, Redis 7, MinIO, Caddy
- **Monitoring**: Prometheus + Grafana
- **CI/CD**: GitHub Actions → ghcr.io → SSH deploy
