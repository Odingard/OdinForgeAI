# OdinForge AEV — Competitive Threat Assessment

**Prepared for:** Odingard Security (Six Sense Enterprise Services)
**Date:** 2026-03-22
**Classification:** Internal — Not for distribution

---

## Executive Summary

OdinForge has genuine architectural strengths that neither Shannon nor Aikido can match today: real multi-phase breach chains with evidence-backed findings, sealed engagement packages with SHA-256 integrity, and a deterministic scoring engine that refuses to fabricate results. However, OdinForge is competing against a $2.5B AEV market where customers expect polished integrations, continuous validation, compliance-ready reporting, and sub-hour time-to-value. Shannon brings a 96% XBOW benchmark score and open-source momentum. Aikido brings 100,000+ teams, Deloitte partnership, enterprise logos (Visma, Revolut, SoundCloud), and a pricing model that starts free. Before Odingard takes money from a customer, the gaps in UI polish, integration ecosystem, scan breadth, and report presentation quality need honest assessment — because the architecture is defensible but the customer experience is not yet at a level where it can survive side-by-side comparison with either competitor.

---

## 1. Shannon (by Keygraph)

### What It Does

Shannon is an autonomous, white-box AI pentester for web applications and APIs. It ingests source code, maps data flows, identifies attack vectors, then uses browser automation and CLI tools to execute real exploits against the running application. It is powered by Anthropic's Claude models (Claude 3.5 Sonnet recommended). Shannon Lite is open source (AGPL-3.0). Shannon Pro adds SAST, SCA, secrets scanning, business logic testing, and CI/CD integration as a commercial platform.

### How It Discovers Attack Surface

- Ingests the application's source code and repository layout directly
- Runs external recon tools (Nmap, Subfinder, WhatWeb) to map the live environment
- Combines static code analysis with dynamic exploitation — identifies routes, parameters, auth flows, and data sinks from source before attacking them live
- Parallel agents target OWASP-critical vulnerability classes simultaneously

### How It Validates Exploitability

- **Proof-by-exploitation**: Every finding is backed by a real exploit attempt against the running application
- Handles 2FA/TOTP, SSO, browser navigation, and complex auth flows autonomously
- XBOW benchmark score: 96.15% (100/104 exploits) in hint-free, source-aware mode — this is the highest publicly reported score for any AI pentesting tool
- Covers SQL injection, XSS, SSRF, command injection, auth bypass, and business logic flaws

### Pricing Model

- **Shannon Lite**: Free (AGPL-3.0), but costs ~$40-55 per scan in Claude API credits for a medium-complexity app
- **Shannon Pro**: Contact sales; includes SAST, SCA, secrets scanning, CI/CD integration, compliance reporting (SOC 2, ISO 27001), and self-hosted runner option
- **Cost per engagement**: Extremely low marginal cost — a full scan is 1-1.5 hours and under $60 in compute

### Customers

- 10,000+ GitHub stars since early 2026 launch
- Enterprise adoption via self-hosted runner model (GitHub Actions architecture)
- No publicly disclosed enterprise logo customers yet — still early-stage
- Growing community fork ecosystem (e.g., shannon-uncontained for black-box testing)

### What Shannon Can Do That OdinForge Currently Cannot

1. **Source code analysis**: Shannon reads application source to find attack vectors with near-perfect accuracy; OdinForge operates black-box only
2. **96% XBOW benchmark score**: Publicly verifiable, reproducible benchmark result that OdinForge has no equivalent for
3. **Per-scan cost under $60**: Dramatically lower cost per assessment than any managed service engagement
4. **CI/CD integration (Pro)**: Runs in deployment pipelines, blocks vulnerable code before production
5. **Browser automation with 2FA/SSO**: Handles complex authentication flows that OdinForge's exploit agent may struggle with
6. **Open source transparency**: Security teams can audit Shannon's methodology; OdinForge is opaque

### Shannon's Weaknesses

1. **White-box only (Lite)**: Requires source code access — cannot test black-box targets, which is OdinForge's primary mode
2. **Web applications only**: No network infrastructure, cloud IAM, container/K8s, or lateral movement capabilities
3. **No multi-phase breach chains**: Tests individual vulnerabilities, not chained attack paths across domains
4. **No engagement delivery system**: No sealed packages, no CISO reports, no Defender's Mirror detection rules
5. **No managed service**: Shannon is a tool, not a service — customers must run it themselves
6. **Staging/dev only**: Ethical use policy prohibits production testing; OdinForge is designed for production-target assessments
7. **LLM context window limitations**: Acknowledged limitation for large codebases in Lite edition
8. **No continuous monitoring**: Point-in-time scans only, no always-on exposure tracking

### Threat Level to OdinForge: MODERATE-HIGH

Shannon's threat is not in direct competition (different operating model) but in **credibility**. When a prospect evaluates OdinForge, they will Google "AI pentesting" and find Shannon with a 96% benchmark score, open-source transparency, and $50/scan cost. If OdinForge cannot articulate why a managed black-box breach chain is worth 100x more per engagement, Shannon sets a price anchor that kills the deal. Shannon also validates the "proof-by-exploitation" approach that OdinForge claims — but Shannon has public, reproducible benchmark numbers and OdinForge does not.

---

## 2. Aikido (aikido.dev)

### What It Does

Aikido is a unified security platform covering the entire SDLC: SAST, DAST, SCA, IaC scanning, container scanning, secrets detection, CSPM, runtime protection, and (as of Feb 2026) autonomous AI pentesting via "Aikido Attack" and "Aikido Infinite." It positions itself as the developer-friendly alternative to enterprise security tool sprawl.

### How It Discovers Attack Surface

- Subdomain enumeration and DNS resolution for external surface mapping
- Repository scanning for code-level vulnerabilities (SAST)
- Container image scanning
- Cloud posture management (AWS, GCP, Azure)
- API discovery and scanning (authenticated and unauthenticated)
- Real-time monitoring of domain/subdomain changes

### How It Validates Exploitability

- **Aikido Attack**: Deploys hundreds of specialized AI agents to hunt vulnerabilities, claims to validate exploitability, and provides remediation. Has found real CVEs (CVE-2026-25545 in Astro, WebSocket hijacking in Storybook)
- **Aikido Infinite** (launched Feb 2026): Continuous AI pentesting that runs on every deployment, confirms exploitability, and auto-remediates
- **Standard DAST**: Uses OWASP ZAP-derived safe scans with de-noising. Critically: **standard DAST does NOT actually exploit vulnerabilities** — it performs "safe, non-destructive automated tests"
- **Reachability analysis**: Connects vulnerabilities into attack graphs across code, containers, and cloud to show chained exploitation paths

### Pricing Model

- **Free**: 2 users, 10 repos, 1 domain, 1 cloud, 250K monthly requests
- **Basic**: $300/month for 10 users, 100 repos, 3 clouds, 25 containers, full SAST/DAST
- **Pro**: $600/month for 10 users, adds API scanning, malware detection, IDE plugins, advanced cloud/VM
- **Enterprise**: Custom pricing
- **Startup discount**: Up to 50%
- **Aikido Attack/Infinite**: Separate pricing, likely premium tier

### Customers

- **100,000+ teams** using the platform
- **3,000+ organizations**, 300+ paying subscribers
- **Enterprise logos**: Visma (€2B revenue, 200 portfolio companies, 6,000 devs), Revolut, SoundCloud, Niantic, Premier League
- **Strategic partner**: Deloitte (bringing Aikido to enterprise clients)
- **Market recognition**: 2026 Frost & Sullivan Customer Value Leadership Award for ASPM

### What Aikido Can Do That OdinForge Currently Cannot

1. **Full SDLC coverage**: SAST + DAST + SCA + IaC + containers + secrets + CSPM + runtime in one platform
2. **CI/CD integration**: GitHub, GitLab, Bitbucket, IDE plugins — blocks vulnerabilities in the development workflow
3. **Auto-remediation**: Aikido Infinite fixes vulnerabilities automatically in the same workflow that found them
4. **Container and cloud scanning**: Deep container image analysis and cloud posture management
5. **Runtime protection**: In-application firewall with bot protection, injection blocking, API rate limiting
6. **Secrets detection**: Scans for leaked credentials, API keys, tokens across repos
7. **Free tier**: Prospects can try before buying with zero commitment
8. **Scale**: 100K+ teams means battle-tested at scale; OdinForge has no comparable production usage
9. **Compliance reporting**: SOC 2, ISO 27001, GDPR-ready reports out of the box
10. **Developer experience**: Polished UI, IDE extensions, Slack/Jira integrations, API-first design

### Aikido's Weaknesses

1. **Safe scanning, not real exploitation**: Standard DAST explicitly does NOT exploit vulnerabilities — "safe, non-destructive automated tests" only. Aikido Attack/Infinite are new (Feb 2026) and unproven at scale
2. **No breach chains**: Vulnerability-by-vulnerability findings, not multi-phase attack progression showing how an attacker chains access across domains
3. **Developer-focused, not security-analyst-focused**: Users complain reporting lacks depth for security engineering teams — "developer-focused rather than security-analyst-focused"
4. **Limited advanced reporting**: Dashboard filtering and customization feels limited for enterprise security teams
5. **No sealed engagement packages**: No concept of an immutable, SHA-256-sealed deliverable with audit trail
6. **No Defender's Mirror equivalent**: No automatic generation of Sigma/YARA/Splunk detection rules per finding
7. **No managed service model**: Self-service SaaS, not white-glove adversarial assessment
8. **Secret scanning tuning issues**: Limited visibility into underlying rules makes false positive management difficult at scale
9. **Pricing aggressive for small teams**: Users find even the Basic tier expensive for smaller developers
10. **No black-box network pentesting**: Cannot do what OdinForge does with its breach orchestrator against production infrastructure

### Threat Level to OdinForge: HIGH

Aikido is the most dangerous competitor because it solves the **adjacent problem** that OdinForge's customers also have. A CISO evaluating OdinForge for adversarial assessment will ask: "Can't Aikido do this for $600/month?" The answer is technically "no, Aikido doesn't do real breach chains," but Aikido's marketing, customer logos, Deloitte partnership, and free tier make it easy for a prospect to choose "good enough" over "architecturally superior but unproven." Aikido Infinite's launch in Feb 2026 directly targets the exploit-validation narrative that OdinForge is built on — even if Aikido's actual exploitation depth is shallow compared to OdinForge's breach orchestrator.

---

## 3. OdinForge: Honest Internal Assessment

### Current Strengths — What Sets OdinForge Apart

**These are real, defensible differentiators:**

1. **Evidence-backed findings (ADR-001)**: `RealFinding.fromHttpEvidence()` throws if there is zero confirmed evidence. Synthetic findings are architecturally impossible, not merely discouraged. Neither Shannon nor Aikido enforces this at the code level.

2. **Evidence quality classification**: Four-tier system (PROVEN / CORROBORATED / INFERRED / UNVERIFIABLE) with `ReportIntegrityFilter` that strips INFERRED and UNVERIFIABLE from customer output. This is more rigorous than either competitor's approach to false positive management.

3. **Multi-phase breach chains**: 6-phase orchestrator (Application Compromise, Credential Extraction, Cloud IAM Escalation, Container/K8s Breakout, Lateral Movement, Impact Assessment) with context passing between phases. Neither competitor chains attacks across domains this way.

4. **Sealed engagement packages (ADR-005)**: 5-component bundle (CISO PDF, Engineer PDF, Evidence JSON, Defender's Mirror, Breach Chain Replay) with SHA-256 integrity hashes. Immutable once sealed. This is a genuinely novel delivery mechanism for pentest results.

5. **Defender's Mirror**: Automatic generation of Sigma rules, YARA rules, and Splunk SPL queries for every technique used. Turns offensive findings into defensive content. No competitor does this.

6. **Deterministic scoring**: EPSS(45%) + CVSS(35%) + Agent(20%), KEV override at 85. No LLM involved in scoring. Reproducible results.

7. **Black-box production testing**: OdinForge tests actual production-facing infrastructure without requiring source code access. This is the real-world adversary model that Shannon explicitly cannot support.

8. **Continuous exposure engine**: Scheduled re-runs with risk snapshots, SLA tracking, and trend analysis. This is table stakes for AEV but OdinForge has it built.

9. **Multi-tenancy with RLS**: Row-level security, 67 permissions, 8 roles. Ready for multi-customer managed service from day one.

### Current Gaps — What Could Lose Deals

**These are the honest problems:**

1. **No public benchmark results**: Shannon has 96.15% on XBOW. OdinForge has no publicly verifiable benchmark score. In a market where Gartner says "demand consistent, continuous, and automated evidence," having no benchmark is a credibility gap. A prospect's security team will ask "what's your detection rate?" and OdinForge has no number to give.

2. **No CI/CD integration**: Both Shannon Pro and Aikido integrate into development pipelines. OdinForge operates as a standalone assessment tool. For continuous AEV (which Gartner defines as the category), this is a missing capability, not a nice-to-have.

3. **No SAST/SCA/secrets scanning**: Aikido covers the full SDLC. Shannon Pro covers SAST + SCA + secrets. OdinForge does black-box exploitation only. Customers buying AEV increasingly expect a platform, not a point tool.

4. **Limited ecosystem integrations**: OdinForge has SIEM connection stubs in the schema and Defender's Mirror output, but no production integrations with Splunk, Sentinel, Jira, GitHub Issues, Slack (beyond webhook stubs), PagerDuty, or any ticketing/workflow system. Aikido has all of these.

5. **No free tier or self-service trial**: Aikido starts free. Shannon Lite is AGPL. OdinForge requires a managed engagement. Prospects cannot evaluate OdinForge independently before committing budget.

6. **Report presentation quality**: The PDF renderer (`pdf-renderer.ts`) uses pdfmake with a basic color palette. Aikido's dashboard is polished SaaS. Shannon generates structured reports. OdinForge's PDFs need to look like they came from a premium security consultancy, not a developer tool. A CISO receiving a OdinForge CISO report will compare it against Mandiant, CrowdStrike, or Bishop Fox deliverables — not against other startups.

7. **Web application focus**: The active exploit engine covers web vulnerabilities (SQLi, XSS, SSRF, command injection, auth bypass, path traversal, BFLA). Cloud IAM, K8s breakout, and lateral movement phases exist in the orchestrator but are stubbed ("disabled" stubs per the code comments). If a customer pays for a 6-phase breach chain and gets results only from phases 1-2, that is a trust-destroying experience.

8. **Single deployment target**: DigitalOcean droplet with 6 containers. No multi-region, no SOC 2 attestation (that I can see), no uptime SLA. Enterprise customers will ask about data residency, disaster recovery, and compliance certifications.

9. **No customer base**: Zero paying customers vs. Aikido's 300+ and Shannon's 10K GitHub stars. Every sale is a cold start with no references, no case studies, no G2/Gartner reviews.

10. **CLI-first experience**: The `odinforge.ts` CLI is functional but the web UI is a React SPA with Shadcn components that has not been battle-tested with real customers. UI rough edges that are invisible to developers are immediately visible to CISOs and their teams.

### What Would Embarrass Odingard in Front of a Customer

**Be specific — these are the scenarios that kill deals and reputations:**

1. **Customer runs a breach chain and gets zero findings**: If the target is well-hardened, the exploit agent may return nothing. Unlike a traditional pentest where the human tester writes a "negative finding" report with methodology details, OdinForge's engagement package with zero proven findings looks like the tool failed, not like the customer's security is good. There is no "clean bill of health" report template.

2. **Phases 3-5 return "disabled" stubs**: The breach orchestrator imports cloud IAM, K8s, and lateral movement but the code comments say "executors return disabled stubs." If the CISO report says "6-phase breach chain" and the engagement only executed 2 real phases, that is misrepresentation.

3. **PDF looks amateur next to a Big 4 report**: The pdfmake renderer generates functional but basic PDFs. Customers paying $10K+ for a managed assessment expect Mandiant-quality deliverables. Font choices, whitespace, chart quality, and information hierarchy matter more than most engineers think.

4. **Scan takes hours with no progress visibility**: The exploit agent has a 110-second timeout per tool call and a 12-turn loop. A full breach chain across multiple domains could take significant time. If the customer is watching a dashboard with no real-time progress, a loading spinner for 45 minutes feels like the product is broken. (Note: WebSocket bridge exists, but UI polish of live progress is critical.)

5. **False positive in a PROVEN finding**: If the evidence quality gate misclassifies an INFERRED finding as PROVEN, and the customer tries to reproduce it and fails, OdinForge's core value proposition — "architecturally impossible to fabricate findings" — collapses. The 4-tier classification must be bulletproof.

6. **SARIF export is referenced but untested in production**: SARIF support appears in the codebase but without production validation. If a customer's security team tries to import findings into their toolchain via SARIF and it breaks, that is a first-impression failure.

7. **No SOC 2 / ISO 27001 compliance documentation**: Enterprise procurement will require security questionnaires, compliance attestations, and data handling documentation. If Odingard cannot produce these, the deal dies in procurement regardless of technical capability.

8. **Breach chain replay HTML has rendering issues**: The self-contained HTML replay is a differentiator, but if it does not render correctly in the customer's browser, or if it looks like a developer prototype rather than a polished visualization, it undermines the sealed package concept.

9. **Agent rate limiting or circuit breaker trips during a paid engagement**: The circuit breaker and rate limiter exist for safety, but if they halt a scan during a time-boxed paid engagement, the customer sees "we paid for 8 hours and the tool stopped itself at hour 3."

10. **No incident response if OdinForge accidentally causes issues**: Real exploitation against production carries real risk. There is no documented incident response playbook for "OdinForge knocked over a customer's production service." This is the kind of thing that generates lawsuits, not just bad reviews.

---

## 4. Market Context

### What Paying Customers Expect from AEV (Per Gartner, BreachLock, Pentera)

The AEV market has established baseline expectations:

| Capability | Shannon | Aikido | OdinForge | Market Expectation |
|---|---|---|---|---|
| Real exploitation / proof | Yes (96% XBOW) | Partial (Attack/Infinite only) | Yes (ADR-001) | Required |
| Continuous validation | No | Yes (Infinite) | Yes (exposure engine) | Required for AEV |
| MITRE ATT&CK mapping | Partial | Partial | Yes | Required |
| Multi-phase attack chains | No | Partial (attack graphs) | Yes (6-phase) | Expected |
| SIEM/EDR integration | No | Yes | Stubs only | Required for enterprise |
| CI/CD pipeline integration | Yes (Pro) | Yes | No | Expected |
| Compliance reporting | Yes (Pro) | Yes | Partial | Required for enterprise |
| Sealed/immutable reports | No | No | Yes (ADR-005) | Differentiator |
| Detection rule generation | No | No | Yes (Defender's Mirror) | Differentiator |
| Self-service trial | Yes (OSS) | Yes (free tier) | No | Expected |
| Public benchmarks | Yes (96% XBOW) | No | No | Increasingly expected |
| Production-safe testing | No (staging only) | Yes (safe scans) | Yes (governed) | Required |

### Pricing Context

- **Traditional pentest**: $15K-$100K per engagement
- **Pentera**: ~$50K/year subscription
- **NodeZero (Horizon3)**: Premium, claims $325K/year savings for customers
- **Aikido**: $300-$600/month SaaS
- **Shannon Lite**: $40-55/scan in API credits
- **OdinForge managed engagement**: TBD — must be priced to compete with both the $50K/year autonomous tools AND justify premium over $600/month SaaS

---

## 5. Recommendations: What to Fix Before First Paid Engagement

### Critical (Must-Have Before Taking Money)

1. **Honest scoping of breach chain phases**: If phases 3-5 are stubbed, do not sell "6-phase breach chain." Sell "Application Compromise + Credential Extraction with Exposure Monitoring" and expand phase coverage over time. Misrepresenting capability is worse than having limited capability.

2. **"Clean report" template**: Build a report for when the breach chain finds zero or minimal vulnerabilities. This is the most common outcome for well-secured targets and the current gap is unacceptable for a managed service.

3. **Report quality audit**: Have a CISO or security director (not a developer) review the PDF output and compare it against Mandiant/CrowdStrike/Bishop Fox report samples. Fix every visual and structural gap they identify. This is the single highest-ROI investment for credibility.

4. **Incident response playbook**: Document exactly what happens when OdinForge's exploitation causes unintended impact on a customer's production system. Include insurance, liability limits, communication templates, and rollback procedures. Put this in the engagement contract.

5. **Engagement contract and legal framework**: Rules of engagement, scope definition, liability limitations, data handling terms, and authorization documentation. No managed pentest service operates without these.

6. **Run OdinForge against deliberately vulnerable targets and document results**: DVWA, Juice Shop, WebGoat, HackTheBox machines. Publish the results (with methodology) as OdinForge's benchmark equivalent. This gives the sales team something concrete to show prospects.

### High Priority (Should Have Within 30 Days of First Engagement)

7. **Jira/GitHub Issues integration**: Findings must flow into the customer's existing ticketing system. Every competitor has this. Export to CSV/JSON is not sufficient.

8. **Slack/Teams notification integration**: Real-time alerts during breach chain execution. The webhook stubs need to become production features.

9. **SARIF export validation**: Test SARIF output against GitHub Advanced Security, Snyk, and DefectDojo imports. Fix any schema issues.

10. **Scan progress UI**: Real-time phase-by-phase progress in the web UI with estimated time remaining. The WebSocket bridge exists — make the frontend experience match what a paying customer expects to see.

11. **SOC 2 Type II readiness**: Begin the process. Enterprise customers with >$50M revenue will require this. At minimum, produce a security practices document and data handling policy.

### Medium Priority (Within 90 Days)

12. **CI/CD integration (GitHub Actions at minimum)**: Not to compete with Aikido as a DevSecOps platform, but to allow customers to trigger breach chain runs as part of their deployment process.

13. **SIEM integration (Splunk and Sentinel at minimum)**: The Defender's Mirror generates Sigma/YARA/SPL rules — push them directly into the customer's SIEM, not just as report artifacts.

14. **Public benchmark program**: Establish a reproducible benchmark methodology and publish results. The AEV market is moving toward verifiable claims.

15. **Customer reference program**: After the first 2-3 engagements, get permission to use sanitized case studies. Every subsequent sale gets easier.

### What NOT to Build (Avoid Scope Creep)

- **Do not build SAST/SCA/secrets scanning**: This is Aikido's territory and OdinForge cannot compete with a dedicated SDLC platform. Stay focused on adversarial assessment.
- **Do not build a free tier**: OdinForge is a managed service, not a self-service SaaS. The business model is high-touch, high-value engagements, not PLG volume.
- **Do not build CI/CD-native pentesting**: This is Shannon's territory. OdinForge's differentiator is the production breach chain with sealed evidence, not pipeline-stage scanning.
- **Do not chase Gartner MQ inclusion yet**: Build 5-10 customer references first. Analyst relations without customer evidence is wasted money.

---

## 6. Bottom Line

OdinForge has a defensible technical architecture that neither Shannon nor Aikido replicates. The evidence quality gate, sealed engagement packages, Defender's Mirror, and multi-phase breach chains are real differentiators that map to what enterprise security teams actually need.

But architecture does not close deals. Polished reports, integration ecosystem, benchmark credibility, customer references, and professional services packaging close deals.

**The risk is not that Shannon or Aikido will out-build OdinForge technically. The risk is that a CISO will compare a $600/month Aikido subscription with polished dashboards against a $25K OdinForge engagement with basic PDFs and choose "good enough" because Aikido looks like a real product and OdinForge looks like a promising prototype.**

Fix the presentation layer, be honest about phase coverage, get legal/compliance documentation in order, and run benchmark engagements that produce publishable results. Then OdinForge can compete on the grounds where it actually wins: proving real exploitability across real infrastructure with evidence that holds up to scrutiny.

---

## Sources

### Shannon / Keygraph
- [Shannon GitHub Repository](https://github.com/KeygraphHQ/shannon)
- [Shannon Pro Documentation](https://github.com/KeygraphHQ/shannon/blob/main/SHANNON-PRO.md)
- [Shannon XBOW Benchmark Results](https://github.com/KeygraphHQ/shannon/blob/main/xben-benchmark-results/README.md)
- [Shannon: The Autonomous AI Pentester (Medium)](https://lalatenduswain.medium.com/shannon-the-autonomous-ai-pentester-that-changes-web-security-in-2026-da9111be8357)
- [Shannon: Autonomous AI Tool with Nmap Integration (GBHackers)](https://gbhackers.com/shannon-autonomous-ai-tool-with-nmap-integration/)
- [Proof by Exploitation: Shannon's Approach (Medium)](https://medium.com/@parathan/proof-by-exploitation-shannons-approach-to-autonomous-penetration-testing-010eac3588d3)
- [Shannon AI Pentesting Alternative (Penligent)](https://www.penligent.ai/hackinglabs/shannon-ai-pentesting-tool-alternative-what-to-use-when-you-need-more-than-white-box-autonomy/)
- [Shannon AI Security Hacker 96.15% Success Rate (DecisionCrafters)](https://www.decisioncrafters.com/shannon-ai-security-hacker-96-percent-success-rate/)

### Aikido
- [Aikido Security Platform](https://www.aikido.dev/)
- [Aikido Pricing](https://www.aikido.dev/pricing)
- [Aikido Attack — AI Pentesting](https://www.aikido.dev/attack/aipentest)
- [Aikido Infinite Launch](https://www.aikido.dev/blog/introducing-aikido-infinite)
- [Aikido DAST Scanner](https://www.aikido.dev/scanners/surface-monitoring-dast)
- [Aikido for Enterprise](https://www.aikido.dev/industries/aikido-for-enterprise)
- [Aikido + Deloitte Partnership](https://www.aikido.dev/blog/how-aikido-and-deloitte-are-bringing-developer-first-security-to-enterprise)
- [Aikido Customer Stories](https://www.aikido.dev/customer-stories)
- [Aikido Frost & Sullivan 2026 Award](https://www.prnewswire.com/news-releases/aikido-receives-the-2026-global-application-security-posture-management-customer-value-leadership-recognition-for-excellence-in-developer-first-security-innovation-302712049.html)
- [Aikido G2 Reviews — Pros and Cons](https://www.g2.com/products/aikido-security/reviews?qs=pros-and-cons)
- [Aikido Review (The CTO Club)](https://thectoclub.com/tools/aikido-security-review/)
- [Aikido Infinite (Help Net Security)](https://www.helpnetsecurity.com/2026/02/24/aikido-infinite-introduces-continuous-self-remediating-ai-penetration-testing/)

### AEV Market
- [Gartner Peer Insights — AEV Market](https://www.gartner.com/reviews/market/adversarial-exposure-validation)
- [Gartner Market Guide for AEV](https://www.gartner.com/en/documents/6255151)
- [AEV Definitive Guide 2025-2026 (Cyber Strategy Institute)](https://cyberstrategyinstitute.com/adversarial-exposure-validation-aev-the-definitive-guide-to-2025-trends-challenges-innovations-and-2026-projections-in-cybersecurity/)
- [Why Security Validation Is Becoming Agentic (Hacker News)](https://thehackernews.com/2026/03/why-security-validation-is-becoming.html)
- [Beyond Simulation: Strategic Imperative of AEV (FRC)](https://fedresources.com/beyond-simulation-the-strategic-imperative-of-adversarial-exposure-validation-aev/)
- [Operationalizing CTEM with ASM, AEV, PTaaS (BreachLock)](https://www.breachlock.com/resources/blog/operationalizing-ctem-how-asm-aev-and-ptaas-form-a-ctem-aligned-tech-stack/)
- [AttackIQ — Driving AEV Across CTEM Stages (PDF)](https://www.attackiq.com/wp-content/uploads/2025/01/driving-adversarial-exposure-validation-across-ctem-stages.pdf)
- [AttackIQ 2025 Year in Review](https://www.attackiq.com/2026/01/15/2025-year-in-review/)
- [Pentera vs NodeZero Comparison (PeerSpot)](https://www.peerspot.com/products/comparisons/pentera_vs_the-nodezero-platform)
- [NodeZero Users Saved $325K+/Year (Brilliance Security)](https://brilliancesecuritymagazine.com/cybersecurity/horizon3-ai-nodezero-autonomous-pentesting-users-saved-325k-year-new-study-finds/)
- [Pentesting Deliverables (Lares Labs)](https://labs.lares.com/pentesting-101-pt4/)
