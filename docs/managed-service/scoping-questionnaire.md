# OdinForge AEV — Engagement Scoping Questionnaire

Complete this questionnaire before your managed adversarial assessment. This information determines scope, pricing tier, and execution configuration.

---

## 1. Organization Information

| Field | Response |
|-------|----------|
| Organization Name | |
| Primary Contact Name | |
| Primary Contact Email | |
| Primary Contact Role | |
| Assessment Sponsor (who approved this?) | |

---

## 2. Assessment Scope

### 2.1 Target Assets

List all domains, subdomains, IP ranges, and cloud environments in scope:

| # | Asset | Type | Notes |
|---|-------|------|-------|
| 1 | | Domain / IP / Cloud Account | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

### 2.2 Exclusions

List any assets, IP ranges, or environments that are **explicitly out of scope**:

| # | Excluded Asset | Reason |
|---|---------------|--------|
| 1 | | |
| 2 | | |

### 2.3 Testing Windows

| Field | Response |
|-------|----------|
| Preferred start date | |
| Blackout dates (no testing) | |
| Testing hours restriction? (e.g., business hours only) | |
| Timezone | |

---

## 3. Environment Details

### 3.1 External Infrastructure

| Question | Response |
|----------|----------|
| How many public-facing web applications? | |
| Primary web technology stack (e.g., Node.js, Java, .NET, Python) | |
| WAF or CDN in place? (CloudFlare, Akamai, AWS WAF, etc.) | |
| API gateway? (Kong, Apigee, AWS API Gateway, etc.) | |
| Authentication method (SSO, OAuth, SAML, local auth, etc.) | |

### 3.2 Cloud Infrastructure

| Question | Response |
|----------|----------|
| Cloud provider(s) (AWS, GCP, Azure, other) | |
| Will you provide read-only cloud credentials for testing? | Yes / No |
| If yes, which services should we test? (IAM, S3, Lambda, EC2, etc.) | |
| Multi-account architecture? | Yes / No |

### 3.3 Container / Kubernetes

| Question | Response |
|----------|----------|
| Running Kubernetes? | Yes / No / Unknown |
| If yes: managed (EKS, GKE, AKS) or self-hosted? | |
| Container registry (ECR, GCR, Docker Hub, etc.) | |
| Service mesh? (Istio, Linkerd, etc.) | |

### 3.4 Internal Network (Deep / MSSP tiers only)

| Question | Response |
|----------|----------|
| Internal network segments in scope? | Yes / No |
| Will you provide VPN access for internal testing? | Yes / No |
| Active Directory / LDAP in environment? | Yes / No |
| Network segmentation between environments? (prod/staging/dev) | |

---

## 4. Compliance & Regulatory Context

| Question | Response |
|----------|----------|
| Active compliance frameworks (SOC 2, PCI-DSS, ISO 27001, HIPAA, etc.) | |
| Upcoming audit date? | |
| Is this assessment for audit evidence purposes? | Yes / No |
| Any regulatory notification requirements if critical findings discovered? | |

---

## 5. Prior Assessment History

| Question | Response |
|----------|----------|
| Last external pentest date | |
| Last internal pentest date | |
| Known unresolved critical/high findings? | |
| Bug bounty program active? | Yes / No |
| Previous OdinForge engagement? | Yes / No |

---

## 6. Communication & Escalation

| Question | Response |
|----------|----------|
| Preferred communication channel (email, Slack, Teams) | |
| Emergency escalation contact (for critical findings during assessment) | |
| Emergency escalation phone number | |
| Should we pause on critical findings or continue assessment? | Pause / Continue |

---

## 7. Tier Selection

Based on your scope above, select your preferred tier:

- [ ] **Standard** ($5,000) — Single domain, external only, Phases 1-2
- [ ] **Deep** ($15,000) — Multi-domain + cloud, Phases 1-5
- [ ] **MSSP** ($30,000) — Full infrastructure, Phases 1-6, white-label option

Not sure which tier? We'll recommend one based on your answers above.

---

## 8. Authorization

**I confirm that I am authorized to commission adversarial security testing against the assets listed in Section 2, and that all necessary approvals have been obtained.**

| Field | Response |
|-------|----------|
| Authorized by (name) | |
| Title | |
| Date | |
| Signature | |

---

*Return this completed questionnaire to [assessment@odinforgeai.com](mailto:assessment@odinforgeai.com). We will respond within 1 business day with a confirmed scope, timeline, and engagement agreement.*
