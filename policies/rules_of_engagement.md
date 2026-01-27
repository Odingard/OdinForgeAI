# OdinForge Rules of Engagement

## 1. Purpose and Scope

This document defines the rules of engagement for OdinForge AI-powered security assessments. All automated and AI-driven security testing must comply with these rules to ensure safe, legal, and ethical operations.

## 2. Authorization Requirements

### 2.1 Written Authorization
All security assessments MUST have written authorization from the asset owner before any testing begins. This includes:
- Signed penetration testing agreement
- Defined scope boundaries
- Emergency contact information
- Escalation procedures

### 2.2 Scope Boundaries
Testing is ONLY permitted on explicitly authorized systems. The following are strictly prohibited without explicit authorization:
- Production databases containing customer data
- Payment processing systems during business hours
- Third-party integrations and APIs
- Systems outside the defined IP ranges

## 3. Testing Restrictions

### 3.1 Prohibited Activities
The following activities are NEVER permitted regardless of authorization level:
- Denial of Service (DoS) attacks
- Social engineering against employees
- Physical security testing
- Attacks on shared infrastructure (cloud providers, CDNs)
- Data exfiltration of real customer data
- Modification of production data

### 3.2 Safe Mode Restrictions
When operating in SAFE mode:
- Only passive reconnaissance is permitted
- No exploit execution
- No credential testing
- No fuzzing with payloads

### 3.3 Simulation Mode Restrictions
When operating in SIMULATION mode:
- Exploit validation without actual exploitation
- Rate-limited scanning only
- No persistence mechanisms
- Automatic rollback of any changes

### 3.4 Live Mode Requirements
LIVE mode requires:
- Explicit approval from Security Administrator or higher
- Active monitoring during testing
- Immediate notification of successful exploits
- Evidence collection for all actions

## 4. Sensitive Data Handling

### 4.1 Data Classification
- PII (Personally Identifiable Information) must never be extracted
- Financial data must be masked in all reports
- Healthcare data (PHI) requires additional authorization
- Credentials discovered must be immediately reported

### 4.2 Evidence Storage
- All evidence must be encrypted at rest
- Evidence retention: 90 days maximum
- Secure deletion after retention period
- No evidence stored on personal devices

## 5. Notification Requirements

### 5.1 Critical Findings
The following require immediate notification:
- Active breach indicators
- Critical vulnerabilities (CVSS 9.0+)
- Exposed credentials
- Data leakage discoveries
- Compliance violations

### 5.2 Notification Timeline
- Critical: Immediate (within 1 hour)
- High: Within 4 hours
- Medium: Within 24 hours
- Low: In regular report cycle

## 6. Business Hours and Rate Limiting

### 6.1 Testing Windows
- Aggressive scanning: Only during maintenance windows
- Standard scanning: Business hours with rate limiting
- Passive reconnaissance: Anytime

### 6.2 Rate Limits
- API testing: Maximum 100 requests per minute
- Network scanning: Maximum 1000 ports per hour
- Authentication testing: Maximum 10 attempts per account

## 7. Incident Response

### 7.1 If Unintended Impact Occurs
1. Immediately halt all testing activities
2. Document the incident with timestamps
3. Notify the Security Administrator
4. Preserve all logs and evidence
5. Do not attempt to "fix" the impact

### 7.2 Emergency Contacts
- Security Operations Center: Available 24/7
- Kill Switch: Can be activated by any team member
- Escalation path: SOC → Security Admin → CISO

## 8. Compliance Considerations

### 8.1 Regulatory Alignment
All testing must consider:
- PCI-DSS requirements for cardholder data environments
- HIPAA requirements for healthcare systems
- GDPR requirements for EU citizen data
- SOC 2 evidence collection requirements

### 8.2 Audit Trail
Every action must be logged including:
- Timestamp
- Actor (human or AI agent)
- Action performed
- Target system
- Result and findings

## 9. AI-Specific Guidelines

### 9.1 AI Agent Behavior
AI agents must:
- Respect all scope boundaries
- Stop immediately when kill switch is activated
- Not attempt to bypass governance controls
- Report all findings without filtering

### 9.2 Hallucination Prevention
- AI recommendations must be validated before action
- Critical decisions require human approval
- Exploit suggestions must match known CVE patterns

## 10. Version Control

- Document Version: 1.0
- Effective Date: January 2026
- Review Cycle: Quarterly
- Owner: Chief Information Security Officer
