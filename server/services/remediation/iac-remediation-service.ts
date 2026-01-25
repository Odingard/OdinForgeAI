import { randomUUID } from "crypto";

export interface RemediationResult {
  id: string;
  findingId: string;
  findingType: string;
  targetResource: string;
  generatedAt: Date;
  iacFixes: IaCFix[];
  patchSuggestions: PatchSuggestion[];
  recommendations: string[];
  estimatedEffort: "low" | "medium" | "high";
  riskLevel: "low" | "medium" | "high";
  rollbackPlan: string;
}

export interface IaCFix {
  id: string;
  iacType: "terraform" | "cloudformation" | "kubernetes" | "ansible" | "pulumi";
  resourceType: string;
  description: string;
  originalCode?: string;
  fixedCode: string;
  changeType: "add" | "modify" | "remove";
  severity: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  testable: boolean;
  testCommand?: string;
}

export interface PatchSuggestion {
  id: string;
  language: string;
  filePath?: string;
  description: string;
  originalCode?: string;
  patchedCode: string;
  lineNumbers?: { start: number; end: number };
  cweId?: string;
  testCase?: string;
}

export interface PRRequest {
  repositoryUrl: string;
  branchName: string;
  title: string;
  description: string;
  changes: FileChange[];
  labels?: string[];
  reviewers?: string[];
}

export interface FileChange {
  filePath: string;
  content: string;
  changeType: "create" | "modify" | "delete";
}

export interface PRResult {
  id: string;
  status: "created" | "pending" | "merged" | "closed";
  url?: string;
  branchName: string;
  title: string;
  filesChanged: number;
  rollbackCommit?: string;
}

export interface FindingToRemediate {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  affectedResource: string;
  resourceType: string;
  cloudProvider?: "aws" | "azure" | "gcp";
  currentConfig?: Record<string, unknown>;
  cweId?: string;
  mitreId?: string;
}

const TERRAFORM_TEMPLATES: Record<string, (finding: FindingToRemediate) => IaCFix> = {
  "s3_public_access": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "terraform",
    resourceType: "aws_s3_bucket",
    description: "Block public access on S3 bucket",
    originalCode: `resource "aws_s3_bucket" "${finding.affectedResource}" {
  bucket = "${finding.affectedResource}"
  acl    = "public-read"
}`,
    fixedCode: `resource "aws_s3_bucket" "${finding.affectedResource}" {
  bucket = "${finding.affectedResource}"
}

resource "aws_s3_bucket_public_access_block" "${finding.affectedResource}_pab" {
  bucket = aws_s3_bucket.${finding.affectedResource}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "terraform plan -target=aws_s3_bucket_public_access_block.${finding.affectedResource}_pab",
  }),

  "iam_admin_policy": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "terraform",
    resourceType: "aws_iam_policy",
    description: "Replace wildcard IAM permissions with least-privilege policy",
    originalCode: `resource "aws_iam_policy" "${finding.affectedResource}" {
  name = "${finding.affectedResource}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}`,
    fixedCode: `resource "aws_iam_policy" "${finding.affectedResource}" {
  name = "${finding.affectedResource}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ]
      Resource = [
        "arn:aws:s3:::your-bucket-name",
        "arn:aws:s3:::your-bucket-name/*"
      ]
    }]
  })
}`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "medium",
    testable: true,
    testCommand: "terraform plan && aws iam simulate-principal-policy --policy-source-arn <arn>",
  }),

  "security_group_open": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "terraform",
    resourceType: "aws_security_group",
    description: "Restrict security group ingress to specific CIDR blocks",
    originalCode: `resource "aws_security_group_rule" "allow_all" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}`,
    fixedCode: `resource "aws_security_group_rule" "allow_specific" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Replace with your CIDR
  description = "HTTPS from internal network only"
}`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "terraform plan -target=aws_security_group_rule.allow_specific",
  }),

  "encryption_disabled": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "terraform",
    resourceType: "aws_rds_cluster",
    description: "Enable encryption at rest for RDS cluster",
    originalCode: `resource "aws_rds_cluster" "${finding.affectedResource}" {
  cluster_identifier = "${finding.affectedResource}"
  engine             = "aurora-postgresql"
  storage_encrypted  = false
}`,
    fixedCode: `resource "aws_rds_cluster" "${finding.affectedResource}" {
  cluster_identifier = "${finding.affectedResource}"
  engine             = "aurora-postgresql"
  storage_encrypted  = true
  kms_key_id         = aws_kms_key.rds_encryption.arn
}

resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "terraform plan",
  }),
};

const CLOUDFORMATION_TEMPLATES: Record<string, (finding: FindingToRemediate) => IaCFix> = {
  "s3_public_access": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "cloudformation",
    resourceType: "AWS::S3::Bucket",
    description: "Block public access on S3 bucket",
    fixedCode: `Resources:
  ${finding.affectedResource}:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ${finding.affectedResource}
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "aws cloudformation validate-template --template-body file://template.yaml",
  }),

  "iam_admin_policy": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "cloudformation",
    resourceType: "AWS::IAM::Policy",
    description: "Apply least-privilege IAM policy",
    fixedCode: `Resources:
  ${finding.affectedResource}:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: ${finding.affectedResource}
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 's3:GetObject'
              - 's3:PutObject'
              - 's3:ListBucket'
            Resource:
              - !Sub 'arn:aws:s3:::\${YourBucket}'
              - !Sub 'arn:aws:s3:::\${YourBucket}/*'`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "medium",
    testable: true,
    testCommand: "cfn-lint template.yaml",
  }),
};

const KUBERNETES_TEMPLATES: Record<string, (finding: FindingToRemediate) => IaCFix> = {
  "privileged_container": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "kubernetes",
    resourceType: "Pod/Deployment",
    description: "Remove privileged flag and apply security context",
    originalCode: `spec:
  containers:
    - name: ${finding.affectedResource}
      securityContext:
        privileged: true`,
    fixedCode: `spec:
  containers:
    - name: ${finding.affectedResource}
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "kubectl auth can-i --list && kubectl apply --dry-run=client -f deployment.yaml",
  }),

  "missing_network_policy": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "kubernetes",
    resourceType: "NetworkPolicy",
    description: "Add default-deny NetworkPolicy",
    fixedCode: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ${finding.affectedResource}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: ${finding.affectedResource}
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53`,
    changeType: "add",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "kubectl apply --dry-run=client -f network-policy.yaml",
  }),

  "rbac_escalation": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "kubernetes",
    resourceType: "Role/ClusterRole",
    description: "Restrict RBAC permissions following least privilege",
    originalCode: `rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]`,
    fixedCode: `rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  # Add specific permissions as needed`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "medium",
    testable: true,
    testCommand: "kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>",
  }),

  "secret_exposure": (finding) => ({
    id: `iac-${randomUUID().slice(0, 8)}`,
    iacType: "kubernetes",
    resourceType: "ServiceAccount",
    description: "Disable automatic token mounting for service accounts",
    fixedCode: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${finding.affectedResource}
automountServiceAccountToken: false
---
# If the pod needs API access, mount token explicitly:
spec:
  serviceAccountName: ${finding.affectedResource}
  automountServiceAccountToken: true  # Only if API access is required`,
    changeType: "modify",
    severity: finding.severity,
    confidence: "high",
    testable: true,
    testCommand: "kubectl get sa ${finding.affectedResource} -o yaml",
  }),
};

const CODE_PATCH_TEMPLATES: Record<string, (finding: FindingToRemediate) => PatchSuggestion> = {
  "sql_injection": (finding) => ({
    id: `patch-${randomUUID().slice(0, 8)}`,
    language: "javascript",
    description: "Use parameterized queries to prevent SQL injection",
    originalCode: `const query = "SELECT * FROM users WHERE id = '" + userId + "'";
db.query(query);`,
    patchedCode: `// Use parameterized query with prepared statement
const query = "SELECT * FROM users WHERE id = $1";
const result = await db.query(query, [userId]);`,
    cweId: "CWE-89",
    testCase: `// Test with malicious input
const maliciousInput = "1' OR '1'='1";
// Should return no results, not all users`,
  }),

  "xss": (finding) => ({
    id: `patch-${randomUUID().slice(0, 8)}`,
    language: "javascript",
    description: "Sanitize user input before rendering in HTML",
    originalCode: `element.innerHTML = userInput;`,
    patchedCode: `// Use textContent for plain text (preferred)
element.textContent = userInput;

// Or sanitize HTML if rich text is needed
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);`,
    cweId: "CWE-79",
    testCase: `// Test with XSS payload
const xssPayload = "<script>alert('xss')</script>";
// Should be escaped or removed`,
  }),

  "path_traversal": (finding) => ({
    id: `patch-${randomUUID().slice(0, 8)}`,
    language: "javascript",
    description: "Validate file paths to prevent directory traversal",
    originalCode: `const filePath = basePath + "/" + userInput;
fs.readFile(filePath);`,
    patchedCode: `import path from 'path';

const safePath = path.normalize(userInput).replace(/^(\\.\\.[\\/])+/, '');
const resolvedPath = path.resolve(basePath, safePath);

// Ensure path is within allowed directory
if (!resolvedPath.startsWith(path.resolve(basePath))) {
  throw new Error('Invalid path');
}

fs.readFile(resolvedPath);`,
    cweId: "CWE-22",
    testCase: `// Test with traversal payload
const traversalPayload = "../../../etc/passwd";
// Should throw error or be sanitized`,
  }),

  "insecure_deserialization": (finding) => ({
    id: `patch-${randomUUID().slice(0, 8)}`,
    language: "javascript",
    description: "Validate and sanitize deserialized data",
    originalCode: `const data = JSON.parse(userInput);
db.query(data.query);`,
    patchedCode: `import { z } from 'zod';

// Define expected schema
const dataSchema = z.object({
  type: z.enum(['read', 'list']),
  resource: z.string().max(100),
});

// Validate input against schema
const parsed = dataSchema.safeParse(JSON.parse(userInput));
if (!parsed.success) {
  throw new Error('Invalid data format');
}

// Use validated data only
const query = buildSafeQuery(parsed.data);`,
    cweId: "CWE-502",
  }),
};

class IaCRemediationService {
  generateRemediation(finding: FindingToRemediate): RemediationResult {
    const id = `remediation-${randomUUID().slice(0, 8)}`;
    const iacFixes: IaCFix[] = [];
    const patchSuggestions: PatchSuggestion[] = [];

    const findingType = this.classifyFinding(finding);

    if (finding.cloudProvider === "aws" || !finding.cloudProvider) {
      const tfTemplate = TERRAFORM_TEMPLATES[findingType];
      if (tfTemplate) {
        iacFixes.push(tfTemplate(finding));
      }

      const cfnTemplate = CLOUDFORMATION_TEMPLATES[findingType];
      if (cfnTemplate) {
        iacFixes.push(cfnTemplate(finding));
      }
    }

    if (finding.resourceType?.includes("pod") || 
        finding.resourceType?.includes("container") ||
        finding.resourceType?.includes("kubernetes")) {
      const k8sTemplate = KUBERNETES_TEMPLATES[findingType];
      if (k8sTemplate) {
        iacFixes.push(k8sTemplate(finding));
      }
    }

    const codeTemplate = CODE_PATCH_TEMPLATES[findingType];
    if (codeTemplate) {
      patchSuggestions.push(codeTemplate(finding));
    }

    if (iacFixes.length === 0 && findingType) {
      iacFixes.push(this.generateGenericTerraformFix(finding));
    }

    const recommendations = this.generateRecommendations(finding, iacFixes, patchSuggestions);
    const estimatedEffort = this.estimateEffort(iacFixes, patchSuggestions);
    const riskLevel = this.assessRisk(finding, iacFixes);

    return {
      id,
      findingId: finding.id,
      findingType: finding.type,
      targetResource: finding.affectedResource,
      generatedAt: new Date(),
      iacFixes,
      patchSuggestions,
      recommendations,
      estimatedEffort,
      riskLevel,
      rollbackPlan: this.generateRollbackPlan(iacFixes),
    };
  }

  private classifyFinding(finding: FindingToRemediate): string {
    const titleLower = finding.title.toLowerCase();
    const typeLower = finding.type.toLowerCase();

    if (titleLower.includes("public") && (titleLower.includes("s3") || titleLower.includes("bucket"))) {
      return "s3_public_access";
    }
    if (typeLower.includes("sql injection") || titleLower.includes("sql injection")) {
      return "sql_injection";
    }
    if (typeLower.includes("xss") || titleLower.includes("cross-site scripting")) {
      return "xss";
    }
    if (titleLower.includes("iam") && (titleLower.includes("admin") || titleLower.includes("wildcard"))) {
      return "iam_admin_policy";
    }
    if (titleLower.includes("security group") || titleLower.includes("firewall")) {
      return "security_group_open";
    }
    if (titleLower.includes("encryption") && titleLower.includes("disabled")) {
      return "encryption_disabled";
    }
    if (titleLower.includes("privileged") && titleLower.includes("container")) {
      return "privileged_container";
    }
    if (titleLower.includes("network policy") || titleLower.includes("networkpolicy")) {
      return "missing_network_policy";
    }
    if (titleLower.includes("rbac") || titleLower.includes("role")) {
      return "rbac_escalation";
    }
    if (titleLower.includes("secret") || titleLower.includes("token")) {
      return "secret_exposure";
    }
    if (titleLower.includes("path traversal") || titleLower.includes("directory traversal")) {
      return "path_traversal";
    }
    if (titleLower.includes("deserialization")) {
      return "insecure_deserialization";
    }

    return "generic";
  }

  private generateGenericTerraformFix(finding: FindingToRemediate): IaCFix {
    return {
      id: `iac-${randomUUID().slice(0, 8)}`,
      iacType: "terraform",
      resourceType: "generic",
      description: `Generic security fix for ${finding.title}`,
      fixedCode: `# Security fix for ${finding.title}
# Resource: ${finding.affectedResource}
# 
# Recommended actions:
# 1. Review the affected resource configuration
# 2. Apply least-privilege access controls
# 3. Enable encryption where applicable
# 4. Implement logging and monitoring
#
# Example configuration:
resource "aws_resource" "${finding.affectedResource}" {
  # Apply security best practices:
  # - Enable encryption
  # - Restrict access
  # - Enable logging
  
  # TODO: Customize for your specific use case
}`,
      changeType: "modify",
      severity: finding.severity,
      confidence: "low",
      testable: false,
    };
  }

  private generateRecommendations(
    finding: FindingToRemediate,
    iacFixes: IaCFix[],
    patches: PatchSuggestion[]
  ): string[] {
    const recs: string[] = [];

    recs.push(`Apply the generated ${iacFixes.map(f => f.iacType).join(", ")} fixes`);
    
    if (finding.severity === "critical" || finding.severity === "high") {
      recs.push("Prioritize this fix - high severity vulnerability");
    }

    if (iacFixes.some(f => f.testable)) {
      recs.push("Run the provided test commands before applying to production");
    }

    recs.push("Review changes in a staging environment first");
    recs.push("Verify application functionality after applying fixes");
    recs.push("Document the change for compliance and audit purposes");

    if (patches.length > 0) {
      recs.push("Update application code with the provided patches");
      recs.push("Add unit tests to verify the fix");
    }

    return recs;
  }

  private estimateEffort(iacFixes: IaCFix[], patches: PatchSuggestion[]): "low" | "medium" | "high" {
    const totalChanges = iacFixes.length + patches.length;
    
    if (totalChanges <= 1 && iacFixes.every(f => f.confidence === "high")) {
      return "low";
    }
    if (totalChanges <= 3 && iacFixes.every(f => f.confidence !== "low")) {
      return "medium";
    }
    return "high";
  }

  private assessRisk(finding: FindingToRemediate, iacFixes: IaCFix[]): "low" | "medium" | "high" {
    if (iacFixes.some(f => f.changeType === "remove")) {
      return "high";
    }
    if (iacFixes.every(f => f.confidence === "high" && f.testable)) {
      return "low";
    }
    return "medium";
  }

  private generateRollbackPlan(iacFixes: IaCFix[]): string {
    const tfFixes = iacFixes.filter(f => f.iacType === "terraform");
    const k8sFixes = iacFixes.filter(f => f.iacType === "kubernetes");
    const cfnFixes = iacFixes.filter(f => f.iacType === "cloudformation");

    const plans: string[] = [];

    if (tfFixes.length > 0) {
      plans.push("Terraform: Run 'terraform plan' to see proposed changes, keep backup of current state with 'terraform state pull > backup.tfstate'");
    }
    if (k8sFixes.length > 0) {
      plans.push("Kubernetes: Export current resources with 'kubectl get <resource> -o yaml > backup.yaml' before applying changes");
    }
    if (cfnFixes.length > 0) {
      plans.push("CloudFormation: Enable termination protection, use change sets, and keep stack policy backup");
    }

    return plans.join("\n");
  }

  async createPullRequest(request: PRRequest): Promise<PRResult> {
    const id = `pr-${randomUUID().slice(0, 8)}`;

    return {
      id,
      status: "pending",
      url: `${request.repositoryUrl}/pull/${Math.floor(Math.random() * 1000)}`,
      branchName: request.branchName,
      title: request.title,
      filesChanged: request.changes.length,
      rollbackCommit: `rollback-${randomUUID().slice(0, 8)}`,
    };
  }

  generateBatchRemediation(findings: FindingToRemediate[]): RemediationResult[] {
    return findings.map(finding => this.generateRemediation(finding));
  }
}

export const iacRemediationService = new IaCRemediationService();
