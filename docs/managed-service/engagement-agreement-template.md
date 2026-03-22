# Odingard Security -- Adversarial Exposure Validation Engagement Agreement

> **DISCLAIMER:** This document is a template only and does not constitute legal advice.
> It must be reviewed, customized, and approved by qualified legal counsel before use
> in any engagement. Odingard Security / Six Sense Enterprise Services accepts no
> liability for the use of this template without proper legal review.

---

**Agreement Number:** `[ENG-YYYY-####]`
**Effective Date:** `[DATE]`
**Client Organization:** `[CLIENT LEGAL NAME]`
**Client Contact:** `[NAME, TITLE, EMAIL]`
**Odingard Engagement Lead:** `[NAME, TITLE, EMAIL]`

---

## 1. Scope of Assessment

### 1.1 Engagement Overview

Odingard Security ("Provider") will conduct an Adversarial Exposure Validation (AEV)
assessment against the systems, applications, and infrastructure identified below
("Target Environment") on behalf of `[CLIENT LEGAL NAME]` ("Client").

The assessment uses OdinForge, an automated breach chain engine that executes
multi-phase adversarial testing including application compromise, credential extraction,
cloud IAM escalation, container/Kubernetes breakout, lateral movement, and impact
assessment.

### 1.2 In-Scope Assets

| Asset Identifier | Type | Environment | Notes |
|---|---|---|---|
| `[e.g., app.client.com]` | Web Application | Production / Staging | |
| `[e.g., api.client.com]` | API Endpoint | Production / Staging | |
| `[e.g., AWS Account 123456]` | Cloud Infrastructure | Production | |
| `[Additional rows as needed]` | | | |

### 1.3 Out-of-Scope Assets

The following assets, systems, and networks are explicitly excluded from this
engagement and will not be tested under any circumstances:

- `[List excluded systems, IP ranges, domains]`
- `[Third-party services not owned by Client]`
- `[Production databases containing PII unless explicitly authorized]`

### 1.4 Assessment Methodology

The engagement will follow the OdinForge 6-phase breach chain methodology:

1. **Application Compromise** -- Active exploitation of web application vulnerabilities
2. **Credential Extraction** -- Identification and extraction of exposed credentials
3. **Cloud IAM Escalation** -- Privilege escalation within cloud environments
4. **Container/K8s Breakout** -- Container escape and Kubernetes exploitation
5. **Lateral Movement** -- Cross-system pivoting using harvested credentials
6. **Impact Assessment** -- Business impact analysis and risk scoring

### 1.5 Execution Mode

- [ ] **Safe Mode** -- Non-destructive testing only; no data modification
- [ ] **Simulation Mode** -- Validates attack paths without full exploitation
- [ ] **Live Mode** -- Full adversarial simulation with real exploitation

The selected execution mode will be enforced by OdinForge governance controls
throughout the engagement.

### 1.6 Excluded Activities

Unless explicitly authorized in writing, the following activities are prohibited:

- Denial-of-service (DoS) or distributed denial-of-service (DDoS) attacks
- Social engineering of Client employees
- Physical access testing
- Modification or deletion of production data
- Exfiltration of personally identifiable information (PII) or protected health information (PHI)
- Testing of systems not listed in Section 1.2

---

## 2. Authorization and Legal Basis

### 2.1 Client Authorization

Client hereby authorizes Provider to conduct the assessment described in Section 1
against the Target Environment. Client represents and warrants that:

(a) Client has the legal authority to authorize testing of all in-scope assets;
(b) Client owns or has obtained written permission from the owners of all in-scope
    assets;
(c) Client has notified all relevant hosting providers, cloud service providers, and
    third parties as required by their terms of service;
(d) Client's authorization extends to the specific execution mode selected in
    Section 1.5.

### 2.2 Letter of Authorization

This agreement, when signed by both parties, constitutes a Letter of Authorization
for the purpose of the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act
(CMA), and equivalent legislation in the jurisdiction(s) where testing will occur.

### 2.3 Third-Party Notifications

Client is responsible for:

- Notifying cloud service providers (AWS, Azure, GCP) of pending penetration testing
  per their acceptable use policies
- Obtaining any required third-party authorizations
- Notifying internal security operations teams to prevent false incident responses

---

## 3. Liability Limitations

### 3.1 Provider Liability Cap

Provider's total aggregate liability for any and all claims arising from or related
to this engagement shall not exceed `[AMOUNT OR MULTIPLE OF ENGAGEMENT FEE]`.

### 3.2 Exclusion of Consequential Damages

In no event shall either party be liable for indirect, incidental, special,
consequential, or punitive damages, including but not limited to loss of revenue,
loss of data, business interruption, or loss of profits, regardless of the theory
of liability.

### 3.3 Client Responsibility

Client acknowledges that:

(a) Security testing inherently carries risk of service disruption;
(b) Provider will exercise reasonable care to minimize impact on production systems;
(c) Client is responsible for maintaining current backups of all in-scope systems
    prior to the engagement start date;
(d) Client assumes responsibility for any pre-existing vulnerabilities discovered
    during the assessment.

### 3.4 Insurance

Provider maintains professional liability (errors and omissions) insurance with
coverage of at least `[AMOUNT]` per occurrence. Certificate of insurance available
upon request.

---

## 4. Safe Harbor Clause

### 4.1 Good Faith Testing

All testing activities conducted by Provider under this agreement are performed in
good faith and within the scope authorized by Client. Provider shall not be held
liable for damages resulting from:

(a) The discovery or reporting of vulnerabilities in Client systems;
(b) Exploitation of vulnerabilities during authorized testing within the agreed
    execution mode;
(c) Temporary service degradation that occurs as a direct result of authorized
    testing activities;
(d) The identification and reporting of regulatory compliance gaps.

### 4.2 Vulnerability Disclosure

Provider agrees to disclose all discovered vulnerabilities exclusively to Client
and will not disclose findings to any third party without Client's prior written
consent, except as required by law.

### 4.3 No Prosecution

Client agrees not to initiate or support any legal action against Provider or its
personnel for activities conducted in good faith within the scope of this agreement.

---

## 5. Data Handling and Confidentiality

### 5.1 Confidential Information

All information obtained during the engagement, including but not limited to
vulnerability findings, credentials, system configurations, network architecture,
and business logic, shall be treated as Confidential Information.

### 5.2 Data Classification

| Data Type | Handling Requirement |
|---|---|
| Discovered credentials | Hashed immediately; plaintext never stored or transmitted |
| HTTP evidence (request/response) | Stored encrypted; included in sealed engagement package |
| System architecture details | Included in reports only; not retained after delivery |
| PII/PHI discovered incidentally | Reported to Client immediately; not retained by Provider |

### 5.3 Evidence Retention

- **During engagement:** All evidence stored in OdinForge encrypted storage
- **Engagement package delivery:** SHA-256 sealed package delivered to Client
- **Post-delivery retention:** Provider retains engagement metadata for `[30/60/90]`
  days, then permanently deletes all evidence
- **Client request:** Client may request immediate deletion at any time

### 5.4 Evidence Integrity

All findings delivered to Client are sealed with the OdinForge EvidenceContract
(ADR-001). Only PROVEN and CORROBORATED findings appear in customer deliverables.
INFERRED and UNVERIFIABLE findings are suppressed from customer output and logged
internally for engineering review only.

### 5.5 Non-Disclosure

Neither party shall disclose Confidential Information to any third party without
the prior written consent of the other party, except:

(a) To employees, contractors, or agents who need to know and are bound by
    equivalent confidentiality obligations;
(b) As required by law, regulation, or court order (with prompt notice to the
    other party where permitted);
(c) To legal counsel for the purpose of obtaining legal advice.

---

## 6. Rules of Engagement

### 6.1 Testing Windows

| Parameter | Value |
|---|---|
| Primary testing window | `[e.g., Monday-Friday 09:00-17:00 EST]` |
| Extended/off-hours testing | `[Authorized / Not Authorized]` |
| Blackout periods | `[e.g., month-end processing, release windows]` |
| Emergency halt contact | `[NAME, PHONE, EMAIL]` |

### 6.2 Traffic Identification

All testing traffic will originate from the following source IP addresses:

- `[Provider IP 1]`
- `[Provider IP 2]`

User-Agent strings will include `OdinForge-AEV/[version]` for identification.

### 6.3 Rate Limiting and Throttling

Provider will respect the following operational constraints:

- Maximum concurrent requests: `[NUMBER]`
- Maximum requests per second: `[NUMBER]`
- Payload size limits: `[SIZE]`
- Automatic throttling on HTTP 429/503 responses

### 6.4 Emergency Stop Procedure

Either party may invoke an emergency stop at any time:

1. Contact the designated emergency halt contact (Section 6.1)
2. Provider will cease all testing within **5 minutes** of receiving the halt request
3. Provider will provide a status report within **1 hour** of the halt
4. Testing resumes only upon mutual written agreement

### 6.5 Governance Controls

OdinForge enforces the following automated governance controls:

- Kill switch capability (immediate halt of all operations)
- Scope enforcement (prevents testing of out-of-scope assets)
- Execution mode enforcement (prevents escalation beyond authorized mode)
- Per-phase timeout controls
- Rate limiting per target

---

## 7. Incident Notification Procedures

### 7.1 Critical Finding Notification

If Provider discovers a critical vulnerability that poses an immediate risk to
Client's operations or data, Provider will:

1. Notify Client's designated security contact within **2 hours** of discovery
2. Provide a preliminary description of the vulnerability and its potential impact
3. Recommend immediate mitigation steps
4. Document the finding in the engagement package with full evidence

### 7.2 Incidental Discovery

If Provider incidentally discovers evidence of an active breach, compromise, or
unauthorized access by a third party, Provider will:

1. Immediately notify Client's designated security contact
2. Preserve all evidence of the third-party activity
3. Cease testing in the affected area until directed by Client
4. Provide a separate incident report if requested

### 7.3 Service Impact

If testing activities cause unintended service degradation or outage, Provider will:

1. Immediately halt testing on the affected system
2. Notify Client within **15 minutes**
3. Assist with service restoration if requested
4. Document the incident and root cause in the engagement report

### 7.4 Notification Contacts

| Role | Name | Phone | Email |
|---|---|---|---|
| Client Security Lead | `[NAME]` | `[PHONE]` | `[EMAIL]` |
| Client IT Operations | `[NAME]` | `[PHONE]` | `[EMAIL]` |
| Provider Engagement Lead | `[NAME]` | `[PHONE]` | `[EMAIL]` |
| Provider Emergency Contact | `[NAME]` | `[PHONE]` | `[EMAIL]` |

---

## 8. Deliverables

### 8.1 Engagement Package

Upon completion, Provider will deliver a sealed OdinForge Engagement Package
containing the following 5 components:

| # | Component | Description | Format |
|---|---|---|---|
| 1 | CISO Report | Executive risk assessment with Risk Grade A-F, breach narrative, business impact | PDF |
| 2 | Engineer Report | Technical chain trace, HTTP evidence, remediation diffs, MITRE ATT&CK mapping | PDF |
| 3 | Evidence JSON | Machine-readable findings with sealed evidence per ADR-001 | JSON |
| 4 | Defender's Mirror | Sigma, YARA, and Splunk detection rules per validated finding | JSON |
| 5 | Breach Chain Replay | Self-contained HTML step-by-step attack visualization | HTML |

### 8.2 Package Integrity

Each component is hashed with SHA-256. The overall package hash seals all components
into an immutable, tamper-evident bundle. Integrity can be verified independently.

### 8.3 Evidence Standard

All findings adhere to the OdinForge EvidenceContract (ADR-001):

- **PROVEN**: Real execution with confirmed server response (included in deliverables)
- **CORROBORATED**: Real attempt with target confirmation (included in deliverables)
- **INFERRED**: LLM reasoning without execution (suppressed from customer output)
- **UNVERIFIABLE**: Ambiguous results (suppressed from customer output)

### 8.4 Optional Deliverables

- [ ] Re-engagement assessment (available within 90-day window)
- [ ] Remediation verification testing
- [ ] Executive briefing presentation
- [ ] Compliance mapping report (PCI-DSS, SOC 2, ISO 27001, NIST CSF)

---

## 9. Timeline and Duration

### 9.1 Engagement Schedule

| Milestone | Target Date | Status |
|---|---|---|
| Agreement execution | `[DATE]` | |
| Pre-engagement scoping call | `[DATE]` | |
| Client environment preparation | `[DATE]` | |
| Testing window start | `[DATE]` | |
| Testing window end | `[DATE]` | |
| Draft report delivery | `[DATE]` | |
| Client review period | `[DATE - DATE]` | |
| Final report delivery | `[DATE]` | |
| Executive briefing (if applicable) | `[DATE]` | |
| Re-engagement window opens | `[DATE]` | |
| Re-engagement window closes | `[DATE + 90 days]` | |

### 9.2 Estimated Duration

- **Active testing:** `[NUMBER]` business days
- **Report generation:** 1-2 business days (automated via OdinForge)
- **Client review period:** `[NUMBER]` business days
- **Total engagement duration:** `[NUMBER]` business days

### 9.3 Delays and Extensions

If testing is delayed or interrupted due to Client actions (system unavailability,
scope changes, emergency halt), the timeline will be extended accordingly.
Additional fees may apply for extensions exceeding `[NUMBER]` business days.

---

## 10. Fees and Payment

### 10.1 Engagement Fee

| Item | Amount |
|---|---|
| Base assessment fee | `$[AMOUNT]` |
| Additional assets (per asset) | `$[AMOUNT]` |
| Executive briefing (optional) | `$[AMOUNT]` |
| Re-engagement assessment (20% discount) | `$[AMOUNT]` |
| **Total** | **`$[AMOUNT]`** |

### 10.2 Payment Terms

- `[PERCENTAGE]`% due upon agreement execution
- `[PERCENTAGE]`% due upon delivery of final engagement package
- Net `[30/45/60]` days from invoice date

---

## 11. General Provisions

### 11.1 Governing Law

This agreement shall be governed by and construed in accordance with the laws of
`[STATE/JURISDICTION]`, without regard to conflict of law principles.

### 11.2 Dispute Resolution

Any disputes arising from this agreement shall be resolved through:

1. Good faith negotiation between the parties (30 days)
2. Mediation by a mutually agreed mediator (30 days)
3. Binding arbitration in accordance with `[ARBITRATION RULES]`

### 11.3 Entire Agreement

This agreement constitutes the entire understanding between the parties with respect
to the subject matter hereof and supersedes all prior agreements, understandings,
negotiations, and discussions.

### 11.4 Amendments

This agreement may only be amended by written instrument signed by both parties.

### 11.5 Severability

If any provision of this agreement is found to be invalid or unenforceable, the
remaining provisions shall continue in full force and effect.

### 11.6 Assignment

Neither party may assign this agreement without the prior written consent of the
other party.

---

## Signatures

**Client Organization: `[CLIENT LEGAL NAME]`**

| | |
|---|---|
| Signature | _________________________________ |
| Printed Name | `[NAME]` |
| Title | `[TITLE]` |
| Date | `[DATE]` |

**Provider: Odingard Security / Six Sense Enterprise Services**

| | |
|---|---|
| Signature | _________________________________ |
| Printed Name | `[NAME]` |
| Title | `[TITLE]` |
| Date | `[DATE]` |

---

*This engagement agreement template was prepared for Odingard Security.
It must be reviewed and customized by qualified legal counsel before use.
Template version: 1.0 | Last updated: 2026-03-22*
