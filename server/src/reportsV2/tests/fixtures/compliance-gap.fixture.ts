/**
 * Compliance Gap Test Fixture
 * 
 * Simulates PCI-DSS control failures in a payment processing environment.
 * Tests the narrative engine's ability to map findings to compliance frameworks
 * and generate appropriate remediation guidance.
 */

import type { TestEvaluation, TestResult, TestFixture } from "./test-data.types";

export const complianceGapEvaluation: TestEvaluation = {
  id: "eval-compliance-001",
  assetId: "asset-payment-gateway-001",
  assetName: "payment-gateway.merchant.com",
  assetType: "payment_system",
  exposureType: "compliance_violation",
  description: `Multiple PCI-DSS control failures identified in cardholder data environment (CDE).
    Scope: Payment gateway processing 50,000+ transactions monthly
    Findings: Unencrypted PAN storage, missing audit logs, weak access controls
    Discovery: QSA audit preparation assessment
    Compliance deadline: 90 days to remediate before annual assessment`,
  priority: "critical",
  status: "completed",
  organizationId: "test-org-001",
  createdAt: new Date("2024-12-12T11:00:00Z"),
  updatedAt: new Date("2024-12-13T09:00:00Z"),
};

export const complianceGapResult: TestResult = {
  id: "result-compliance-001",
  evaluationId: "eval-compliance-001",
  exploitable: true,
  confidence: 85,
  score: 75,
  
  attackPath: [
    {
      id: 1,
      title: "Shared Credential Access",
      description: "Use shared admin credentials (known to 15+ employees) for initial access",
      technique: "T1078",
      severity: "high",
      order: 1,
      targetAsset: "payment-gateway",
      tools: ["ssh", "browser"],
    },
    {
      id: 2,
      title: "Locate Unencrypted PAN Data",
      description: "Locate unencrypted PAN data in database and log files",
      technique: "T1083",
      severity: "critical",
      order: 2,
      targetAsset: "payment-db",
      tools: ["mysql-client", "grep"],
    },
    {
      id: 3,
      title: "Undetected Exfiltration",
      description: "Extract card data without detection (no logging enabled)",
      technique: "T1041",
      severity: "critical",
      order: 3,
      targetAsset: "external",
      tools: ["curl", "openssl"],
    },
  ],
  
  impact: `The compliance gaps create multiple exploitable weaknesses. Unencrypted PAN storage enables direct card data theft if database is breached. Missing audit logs prevent detection of unauthorized access. Shared admin credentials mean no accountability for access. Missing network segmentation allows lateral movement from compromised systems. PCI-DSS non-compliance fines up to $500,000/month. Card brand penalties. Potential loss of merchant account.`,
  
  recommendations: [
    {
      id: "rec-compliance-001",
      title: "Implement encryption for stored PAN",
      description: "Deploy AES-256 encryption for all stored cardholder data with proper key management (PCI-DSS Req 3.4)",
      priority: "critical",
      type: "remediation",
      effort: "high",
      timeline: "4 weeks",
    },
    {
      id: "rec-compliance-002",
      title: "Enable comprehensive audit logging",
      description: "Configure logging for all access to cardholder data with tamper-evident log storage (PCI-DSS Req 10.1-10.3)",
      priority: "critical",
      type: "remediation",
      effort: "medium",
      timeline: "2 weeks",
    },
    {
      id: "rec-compliance-003",
      title: "Implement individual user accounts",
      description: "Replace shared credentials with unique accounts per user with role-based access control (PCI-DSS Req 8.1)",
      priority: "high",
      type: "remediation",
      effort: "medium",
      timeline: "3 weeks",
    },
    {
      id: "rec-compliance-004",
      title: "Deploy network segmentation",
      description: "Isolate CDE from corporate network with firewall rules and network ACLs (PCI-DSS Req 1.3)",
      priority: "high",
      type: "preventive",
      effort: "high",
      timeline: "6 weeks",
    },
    {
      id: "rec-compliance-005",
      title: "Implement MFA for CDE access",
      description: "Require multi-factor authentication for all administrative access to payment systems (PCI-DSS Req 8.3.1)",
      priority: "high",
      type: "preventive",
      effort: "low",
      timeline: "1 week",
    },
  ],
  
  evidenceArtifacts: [
    {
      id: "ev-compliance-001",
      type: "database_query",
      title: "Unencrypted PAN Storage",
      description: "Unencrypted PAN data in transactions table",
      content: `mysql> SELECT id, card_number, expiry, cvv FROM transactions LIMIT 3;
+----+------------------+--------+-----+
| id | card_number      | expiry | cvv |
+----+------------------+--------+-----+
|  1 | 4111111111111111 | 12/26  | 123 |
|  2 | 5500000000000004 | 03/25  | 456 |
|  3 | 340000000000009  | 06/27  | 7890|
+----+------------------+--------+-----+
WARNING: Full PAN and CVV stored in plaintext - PCI-DSS 3.2 violation`,
    },
    {
      id: "ev-compliance-002",
      type: "configuration",
      title: "Shared Credentials in Config",
      description: "Shared credentials in configuration file",
      content: `# /opt/payment-gateway/config.yml
database:
  host: payment-db.internal
  user: pci_admin
  password: Payment2019!  # Shared by all 15 CDE admins
  
# Note: Same password used since 2019
# Access list: dev-team@, ops@, support@ (distribution lists)`,
    },
    {
      id: "ev-compliance-003",
      type: "log_sample",
      title: "Missing Audit Trail",
      description: "Missing audit trail - no access logs configured",
      content: `$ ls -la /var/log/payment-gateway/
total 0
drwxr-xr-x 2 root root 40 Dec 12 10:00 .
drwxr-xr-x 3 root root 60 Dec 12 10:00 ..

$ cat /etc/payment-gateway/logging.conf
# Logging disabled for performance
log_level: OFF
audit_trail: false`,
    },
    {
      id: "ev-compliance-004",
      type: "network_scan",
      title: "Missing Network Segmentation",
      description: "Missing network segmentation - CDE directly accessible",
      content: `Nmap scan from corporate workstation (192.168.1.50):
  
PORT     STATE SERVICE
22/tcp   open  ssh (payment-gateway.internal)
3306/tcp open  mysql (payment-db.internal)
443/tcp  open  https (payment-api.internal)

No firewall rules blocking corporate -> CDE traffic
All CDE hosts reachable from any corporate IP`,
    },
  ],
  
  completedAt: new Date("2024-12-13T09:00:00Z"),
};

export const complianceGapFixture: TestFixture = {
  evaluation: complianceGapEvaluation,
  result: complianceGapResult,
  expectedNarrativeElements: [
    "PCI-DSS",
    "cardholder data",
    "encryption",
    "audit logging",
    "network segmentation",
    "shared credentials",
    "compliance",
  ],
  complianceFrameworks: ["PCI-DSS 4.0"],
  affectedRequirements: ["3.4", "7.1", "8.1", "8.3.1", "10.1", "10.2", "10.3", "1.3"],
};
