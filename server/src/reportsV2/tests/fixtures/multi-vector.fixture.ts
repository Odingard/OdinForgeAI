/**
 * Multi-Vector Attack Test Fixture
 * 
 * Simulates a complex attack chain combining SQL injection, credential theft,
 * lateral movement, and data exfiltration. Tests the narrative engine's ability
 * to construct coherent stories from multi-stage attacks.
 */

import type { TestEvaluation, TestResult, TestFixture } from "./test-data.types";

export const multiVectorEvaluation: TestEvaluation = {
  id: "eval-multi-001",
  assetId: "asset-legacy-crm-001",
  assetName: "legacy-crm.internal.corp",
  assetType: "web_application",
  exposureType: "sql_injection",
  description: `SQL injection vulnerability in legacy CRM search functionality leading to full database compromise.
    Endpoint: GET /api/customers/search?q=
    Database: PostgreSQL 12.4 with customer PII and payment data
    Issue: Unsanitized user input directly concatenated into SQL query
    Compounding factors: Database user has DBA privileges, credentials stored in same database
    Discovery: Automated vulnerability scan flagged error-based SQLi`,
  priority: "critical",
  status: "completed",
  organizationId: "test-org-001",
  createdAt: new Date("2024-12-08T08:00:00Z"),
  updatedAt: new Date("2024-12-09T18:00:00Z"),
};

export const multiVectorResult: TestResult = {
  id: "result-multi-001",
  evaluationId: "eval-multi-001",
  exploitable: true,
  confidence: 95,
  score: 95,
  
  attackPath: [
    {
      id: 1,
      title: "SQL Injection Discovery",
      description: "Inject SQL payload in search parameter to extract database schema",
      technique: "T1190",
      severity: "high",
      order: 1,
      targetAsset: "legacy-crm",
      tools: ["sqlmap", "burp-suite"],
    },
    {
      id: 2,
      title: "Credential Extraction",
      description: "Extract admin credentials from users table via UNION-based injection",
      technique: "T1005",
      severity: "critical",
      order: 2,
      targetAsset: "postgres-db",
      tools: ["sqlmap"],
    },
    {
      id: 3,
      title: "Password Cracking",
      description: "Crack MD5 password hashes using rainbow tables",
      technique: "T1110.002",
      severity: "high",
      order: 3,
      targetAsset: "offline",
      tools: ["hashcat", "john"],
    },
    {
      id: 4,
      title: "Admin Panel Access",
      description: "Authenticate to internal admin panel with cracked credentials",
      technique: "T1078.003",
      severity: "critical",
      order: 4,
      targetAsset: "admin-panel",
      tools: ["browser"],
    },
    {
      id: 5,
      title: "Cloud Credentials Discovery",
      description: "Discover AWS credentials in admin panel configuration export",
      technique: "T1552.001",
      severity: "critical",
      order: 5,
      targetAsset: "admin-panel",
      tools: ["browser"],
    },
    {
      id: 6,
      title: "Data Exfiltration",
      description: "Access S3 buckets and exfiltrate customer database backups",
      technique: "T1537",
      severity: "critical",
      order: 6,
      targetAsset: "s3-customer-data",
      tools: ["aws-cli"],
    },
  ],
  
  impact: `The SQL injection vulnerability enables a complete attack chain from initial access to data exfiltration. Error-based SQLi reveals database structure and version. Union-based extraction of admin credentials from users table. Password hashes cracked offline (MD5 without salt). Admin credentials provide access to internal tools containing AWS keys enabling cloud pivot. S3 bucket access reveals 500,000+ customer records with PII and payment data. Estimated breach cost: $75M-100M total exposure.`,
  
  recommendations: [
    {
      id: "rec-multi-001",
      title: "Parameterize all SQL queries",
      description: "Replace string concatenation with parameterized queries or prepared statements throughout the application.",
      priority: "critical",
      type: "remediation",
      effort: "high",
      timeline: "1 week",
    },
    {
      id: "rec-multi-002",
      title: "Rotate all credentials",
      description: "Immediately rotate database credentials, admin passwords, and AWS keys. Assume all credentials in the database are compromised.",
      priority: "critical",
      type: "remediation",
      effort: "medium",
      timeline: "24 hours",
    },
    {
      id: "rec-multi-003",
      title: "Implement proper password hashing",
      description: "Replace MD5 with bcrypt or Argon2. Enforce password complexity and implement MFA for admin accounts.",
      priority: "high",
      type: "remediation",
      effort: "medium",
      timeline: "1 week",
    },
    {
      id: "rec-multi-004",
      title: "Apply least-privilege database access",
      description: "Remove DBA privileges from application database user. Create separate read-only and read-write database accounts.",
      priority: "high",
      type: "preventive",
      effort: "medium",
      timeline: "3 days",
    },
    {
      id: "rec-multi-005",
      title: "Deploy WAF with SQLi rules",
      description: "Implement Web Application Firewall with SQL injection detection rules as defense-in-depth.",
      priority: "medium",
      type: "compensating",
      effort: "low",
      timeline: "48 hours",
    },
  ],
  
  evidenceArtifacts: [
    {
      id: "ev-multi-001",
      type: "http_request",
      title: "SQL Injection Probe",
      description: "Initial SQLi probe revealing error-based injection",
      content: `GET /api/customers/search?q=test'+OR+1=1--+ HTTP/1.1
Host: legacy-crm.internal.corp

Response: 500 Internal Server Error
ERROR: syntax error at or near "+" at character 42
QUERY: SELECT * FROM customers WHERE name LIKE '%test'+OR+1=1--+'%'`,
    },
    {
      id: "ev-multi-002",
      type: "sql_output",
      title: "Extracted Admin Credentials",
      description: "Extracted admin credentials via UNION injection",
      content: `Username: admin@corp.internal
Password Hash: 5f4dcc3b5aa765d61d8327deb882cf99 (MD5: password)
Role: superadmin
Created: 2019-03-15`,
    },
    {
      id: "ev-multi-003",
      type: "configuration",
      title: "AWS Credentials in Config",
      description: "AWS credentials found in admin panel export",
      content: `[production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
s3_bucket = corp-customer-backups`,
    },
    {
      id: "ev-multi-004",
      type: "data_sample",
      title: "Exfiltrated Customer Records",
      description: "Sample of exfiltrated customer records from S3",
      content: `customer_id,name,email,ssn_last4,card_last4,card_expiry
100001,John Smith,jsmith@email.com,1234,4242,12/26
100002,Jane Doe,jdoe@email.com,5678,1111,03/25
[... 499,998 additional records ...]`,
    },
  ],
  
  completedAt: new Date("2024-12-09T18:00:00Z"),
};

export const multiVectorFixture: TestFixture = {
  evaluation: multiVectorEvaluation,
  result: multiVectorResult,
  expectedNarrativeElements: [
    "SQL injection",
    "credential theft",
    "lateral movement",
    "cloud pivot",
    "data exfiltration",
    "attack chain",
    "MD5",
    "parameterized queries",
  ],
};
