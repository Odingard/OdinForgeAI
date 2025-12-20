/**
 * IAM Abuse Test Fixture
 * 
 * Simulates a privilege escalation attack through misconfigured AWS IAM roles.
 * Tests the V2 narrative engine's ability to construct coherent attack stories
 * for identity-based vulnerabilities.
 */

import type { TestEvaluation, TestResult, TestFixture } from "./test-data.types";

export const iamAbuseEvaluation: TestEvaluation = {
  id: "eval-iam-001",
  assetId: "asset-aws-lambda-001",
  assetName: "aws-iam-role-lambda-executor",
  assetType: "cloud_iam",
  exposureType: "iam_misconfiguration",
  description: `AWS Lambda execution role with overly permissive IAM policy allowing sts:AssumeRole on wildcard resources. 
    Role ARN: arn:aws:iam::123456789012:role/LambdaExecutorRole
    Attached Policy: arn:aws:iam::123456789012:policy/LambdaFullAccess
    Issue: Policy grants iam:PassRole and sts:AssumeRole with Resource: "*"
    Discovery: Automated IAM policy analyzer flagged during routine audit`,
  priority: "critical",
  status: "completed",
  organizationId: "test-org-001",
  createdAt: new Date("2024-12-15T10:30:00Z"),
  updatedAt: new Date("2024-12-15T14:45:00Z"),
};

export const iamAbuseResult: TestResult = {
  id: "result-iam-001",
  evaluationId: "eval-iam-001",
  exploitable: true,
  confidence: 92,
  score: 92,
  
  attackPath: [
    {
      id: 1,
      title: "Initial Lambda Access",
      description: "Attacker invokes Lambda function via public API Gateway endpoint",
      technique: "T1078.004",
      severity: "high",
      order: 1,
      targetAsset: "api-gateway-prod",
      tools: ["curl", "aws-cli"],
    },
    {
      id: 2,
      title: "Role Assumption",
      description: "Lambda execution role has sts:AssumeRole with Resource: '*'",
      technique: "T1548.005",
      severity: "critical",
      order: 2,
      targetAsset: "LambdaExecutorRole",
      tools: ["aws-cli"],
    },
    {
      id: 3,
      title: "Admin Privilege Escalation",
      description: "Attacker assumes OrganizationAccountAccessRole for full admin access",
      technique: "T1098.001",
      severity: "critical",
      order: 3,
      targetAsset: "OrganizationAccountAccessRole",
      tools: ["aws-cli", "pacu"],
    },
    {
      id: 4,
      title: "Account Enumeration",
      description: "Enumerate all IAM users, roles, and policies in the account",
      technique: "T1087.004",
      severity: "high",
      order: 4,
      targetAsset: "aws-iam",
      tools: ["aws-cli", "enumerate-iam"],
    },
  ],
  
  impact: `The IAM misconfiguration is highly exploitable due to wildcard resource permissions allowing role assumption to any role in the account. An attacker with initial access to the Lambda function can escalate to AdministratorAccess by assuming the OrganizationAccountAccessRole. This represents a complete cloud account compromise enabling data exfiltration, resource abuse, and potential ransomware deployment.`,
  
  recommendations: [
    {
      id: "rec-iam-001",
      title: "Implement least-privilege IAM policies",
      description: "Replace wildcard Resource permissions with specific ARNs. Remove sts:AssumeRole unless explicitly required.",
      priority: "critical",
      type: "remediation",
      effort: "medium",
      timeline: "48 hours",
    },
    {
      id: "rec-iam-002",
      title: "Add IAM permission boundaries",
      description: "Create and attach permission boundaries to all Lambda execution roles to prevent privilege escalation.",
      priority: "high",
      type: "preventive",
      effort: "medium",
      timeline: "1 week",
    },
    {
      id: "rec-iam-003",
      title: "Enable AWS CloudTrail with alerting",
      description: "Configure real-time alerts for sts:AssumeRole events targeting high-privilege roles.",
      priority: "medium",
      type: "compensating",
      effort: "low",
      timeline: "24 hours",
    },
    {
      id: "rec-iam-004",
      title: "Implement SCP guardrails",
      description: "Deploy Service Control Policies at the organization level to prevent role assumption outside trusted boundaries.",
      priority: "high",
      type: "preventive",
      effort: "high",
      timeline: "2 weeks",
    },
  ],
  
  evidenceArtifacts: [
    {
      id: "ev-iam-001",
      type: "policy_document",
      title: "Overpermissive IAM Policy",
      description: "IAM policy JSON showing wildcard permissions",
      content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole",
        "iam:PassRole"
      ],
      "Resource": "*"
    }
  ]
}`,
    },
    {
      id: "ev-iam-002",
      type: "cloudtrail_log",
      title: "Role Assumption Event",
      description: "CloudTrail event showing successful role assumption",
      content: `{
  "eventName": "AssumeRole",
  "eventSource": "sts.amazonaws.com",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/LambdaExecutorRole/lambda-function"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIAXXX..."
    }
  }
}`,
    },
  ],
  
  completedAt: new Date("2024-12-15T14:45:00Z"),
};

export const iamAbuseFixture: TestFixture = {
  evaluation: iamAbuseEvaluation,
  result: iamAbuseResult,
  expectedNarrativeElements: [
    "privilege escalation",
    "Lambda execution role",
    "wildcard permissions",
    "OrganizationAccountAccessRole",
    "sts:AssumeRole",
  ],
};
