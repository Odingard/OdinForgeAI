# OdinForge AEV — Pricing Sheet

## Per-Engagement Pricing (ADR-005)

One assessment. One price. No subscription.

---

### Standard — $5,000

**Best for:** Single-domain external validation, pre-audit readiness

- **Scope:** 1 primary domain + subdomains
- **Phases:** Application Compromise + Credential Extraction (Phases 1-2)
- **Execution:** Up to 50 concurrent agents
- **Delivery:** 48 hours from engagement start
- **Includes:**
  - Full 5-component Engagement Package
  - Risk Grade A-F with CISO-ready narrative
  - Remediation diffs for all confirmed findings
  - Sigma/YARA/Splunk detection rules (Defender's Mirror)
  - 90-day reengagement window at 20% off ($4,000)

---

### Deep — $15,000

**Best for:** Multi-domain assessments, cloud-inclusive validation, breach readiness

- **Scope:** Multiple domains + cloud environments (AWS, GCP, Azure)
- **Phases:** Full 5-phase chain (App + Creds + Cloud IAM + K8s + Lateral Movement)
- **Execution:** Up to 200 concurrent agents
- **Delivery:** 5 business days from engagement start
- **Includes:**
  - Everything in Standard, plus:
  - Cloud IAM privilege escalation testing
  - Container/Kubernetes breakout probing
  - Multi-hop lateral movement with credential reuse
  - Cross-domain attack graph visualization
  - 90-day reengagement window at 20% off ($12,000)

---

### MSSP — $30,000

**Best for:** Managed service providers, large enterprise, multi-tenant environments

- **Scope:** Full infrastructure — external, cloud, container, internal network
- **Phases:** Complete 6-phase breach chain including Impact Assessment
- **Execution:** Up to 300 concurrent agents
- **Delivery:** Custom timeline (typically 5-10 business days)
- **Includes:**
  - Everything in Deep, plus:
  - Impact Assessment phase with compliance mapping (SOC 2, PCI-DSS, ISO 27001, NIST CSF)
  - White-label Engagement Package (your branding)
  - Dedicated engagement manager
  - Custom scoping for multi-tenant isolation
  - 90-day reengagement window at 20% off ($24,000)

---

## Add-Ons

| Add-On | Price | Description |
|--------|-------|-------------|
| Remediation Verification | $2,000 | Re-run assessment after fixes to confirm findings are resolved |
| Continuous Monitoring | $3,000/mo | Recurring breach chain runs (weekly/monthly) with drift detection |
| Custom Adversary Profile | $2,500 | Tuned to specific threat actor TTPs (APT group simulation) |
| Extended Evidence Retention | $500/yr | Evidence packages retained beyond standard 90 days |

---

## Reengagement Window

All tiers include a **90-day reengagement window** after the initial Engagement Package is sealed. During this window, the customer can re-engage at **20% off** the original tier price. This is designed for post-remediation verification — prove that your fixes actually work.

After 90 days, reengagement is available at standard pricing.

---

## What's Included in Every Engagement

Regardless of tier, every customer receives:

1. **CISO Report** — Risk Grade A-F, breach narrative, business impact, compliance implications
2. **Engineer Report** — Full chain trace with HTTP evidence, remediation diffs, MITRE ATT&CK mapping
3. **Evidence JSON** — Machine-readable findings for SIEM ingestion and ticket automation
4. **Defender's Mirror** — Sigma, YARA, and Splunk SPL detection rules for every confirmed attack
5. **Breach Chain Replay** — Self-contained HTML visualization of the complete attack path

All findings are backed by the OdinForge EvidenceContract (ADR-001). INFERRED and UNVERIFIABLE findings are suppressed from customer reports — only PROVEN and CORROBORATED findings are delivered.

---

## Evidence Standard

OdinForge operates under a strict evidence quality standard:

- **PROVEN** — Direct HTTP evidence with request, response, and status code
- **CORROBORATED** — Real execution evidence from protocol probes or credential validation
- **INFERRED** — Synthesis of proven findings (internal use only, not in customer reports)
- **UNVERIFIABLE** — Insufficient evidence (suppressed entirely)

This means: if it's in your Engagement Package, it's real.
