import type { 
  RemediationGuidance, 
  CodeFix, 
  WafRule, 
  IamPolicy, 
  NetworkControl, 
  DetectionRule, 
  CompensatingControl,
  AttackPathStep,
  AttackGraph,
  BusinessLogicFinding,
  MultiVectorFinding,
  IntelligentScore
} from "@shared/schema";
import { randomUUID } from "crypto";

interface RemediationContext {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  exploitable: boolean;
  attackPath?: AttackPathStep[];
  attackGraph?: AttackGraph;
  businessLogicFindings?: BusinessLogicFinding[];
  multiVectorFindings?: MultiVectorFinding[];
  intelligentScore?: IntelligentScore;
}

export async function generateRemediationGuidance(
  context: RemediationContext,
  evaluationId: string,
  onProgress?: (stage: string, progress: number, message: string) => void
): Promise<RemediationGuidance> {
  onProgress?.("remediation", 0, "Analyzing vulnerability context...");
  
  const codeFixes = await generateCodeFixes(context);
  onProgress?.("remediation", 20, "Generated code-level fixes");

  const wafRules = await generateWafRules(context);
  onProgress?.("remediation", 40, "Generated WAF rules");

  const iamPolicies = await generateIamPolicies(context);
  onProgress?.("remediation", 55, "Generated IAM policies");

  const networkControls = await generateNetworkControls(context);
  onProgress?.("remediation", 70, "Generated network controls");

  const detectionRules = await generateDetectionRules(context);
  onProgress?.("remediation", 85, "Generated detection signatures");

  const compensatingControls = await generateCompensatingControls(context);
  onProgress?.("remediation", 95, "Generated compensating controls");

  const prioritizedActions = buildPrioritizedActions(
    codeFixes, wafRules, iamPolicies, networkControls, detectionRules, compensatingControls
  );

  const totalRiskReduction = calculateTotalRiskReduction(prioritizedActions);

  onProgress?.("remediation", 100, "Remediation guidance complete");

  return {
    id: `rem-${randomUUID().slice(0, 8)}`,
    evaluationId,
    generatedAt: new Date().toISOString(),
    summary: `Generated ${prioritizedActions.length} remediation actions targeting ${context.exposureType} vulnerability on ${context.assetId}`,
    executiveSummary: generateExecutiveSummary(context, prioritizedActions, totalRiskReduction),
    codeFixes: codeFixes.length > 0 ? codeFixes : undefined,
    wafRules: wafRules.length > 0 ? wafRules : undefined,
    iamPolicies: iamPolicies.length > 0 ? iamPolicies : undefined,
    networkControls: networkControls.length > 0 ? networkControls : undefined,
    detectionRules: detectionRules.length > 0 ? detectionRules : undefined,
    compensatingControls: compensatingControls.length > 0 ? compensatingControls : undefined,
    prioritizedActions,
    totalRiskReduction,
    estimatedImplementationTime: estimateImplementationTime(prioritizedActions),
  };
}

async function generateCodeFixes(context: RemediationContext): Promise<CodeFix[]> {
  const exposureType = context.exposureType;
  const fixes: CodeFix[] = [];

  if (exposureType === "cve" || exposureType === "misconfiguration") {
    fixes.push({
      id: `cf-${randomUUID().slice(0, 6)}`,
      title: "Input Validation Enhancement",
      language: "javascript",
      filePath: "src/controllers/api.js",
      vulnerability: "Insufficient input validation",
      beforeCode: `app.post('/api/data', (req, res) => {
  const data = req.body.data;
  processData(data);
});`,
      afterCode: `import { z } from 'zod';

const DataSchema = z.object({
  data: z.string().max(1000).regex(/^[a-zA-Z0-9-_]+$/),
});

app.post('/api/data', (req, res) => {
  const result = DataSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  processData(result.data.data);
});`,
      explanation: "Implement strict input validation using Zod schema to prevent injection attacks and malformed data processing.",
      complexity: "low",
      testingNotes: "Test with boundary values, special characters, and oversized inputs",
    });
  }

  if (exposureType === "payment_flow" || exposureType === "subscription_bypass") {
    fixes.push({
      id: `cf-${randomUUID().slice(0, 6)}`,
      title: "Server-Side Price Validation",
      language: "typescript",
      filePath: "src/services/payment.ts",
      vulnerability: "Client-side price manipulation",
      beforeCode: `async function processOrder(order: Order) {
  const total = order.total; // Client-provided
  await chargePayment(order.userId, total);
}`,
      afterCode: `async function processOrder(order: Order) {
  // Server-side price calculation
  const items = await getCartItems(order.userId);
  const total = items.reduce((sum, item) => {
    const product = await getProduct(item.productId);
    return sum + (product.price * item.quantity);
  }, 0);
  
  // Apply validated discounts only
  const discount = await validateDiscount(order.discountCode, order.userId);
  const finalTotal = total - discount;
  
  await chargePayment(order.userId, finalTotal);
}`,
      explanation: "Always calculate prices server-side using authoritative product database. Never trust client-provided totals.",
      complexity: "medium",
      testingNotes: "Test price manipulation attempts, discount stacking, and race conditions",
    });
  }

  if (exposureType === "api_sequence_abuse" || exposureType === "state_machine") {
    fixes.push({
      id: `cf-${randomUUID().slice(0, 6)}`,
      title: "State Machine Enforcement",
      language: "typescript",
      filePath: "src/services/workflow.ts",
      vulnerability: "State transition bypass",
      beforeCode: `async function updateOrderStatus(orderId: string, newStatus: string) {
  await db.update(orders)
    .set({ status: newStatus })
    .where(eq(orders.id, orderId));
}`,
      afterCode: `const VALID_TRANSITIONS: Record<string, string[]> = {
  'pending': ['confirmed', 'cancelled'],
  'confirmed': ['processing', 'cancelled'],
  'processing': ['shipped', 'cancelled'],
  'shipped': ['delivered'],
  'delivered': ['returned'],
};

async function updateOrderStatus(orderId: string, newStatus: string) {
  const order = await db.select().from(orders).where(eq(orders.id, orderId)).then(r => r[0]);
  
  const allowedTransitions = VALID_TRANSITIONS[order.status] || [];
  if (!allowedTransitions.includes(newStatus)) {
    throw new InvalidStateTransitionError(
      \`Cannot transition from \${order.status} to \${newStatus}\`
    );
  }
  
  await db.update(orders)
    .set({ status: newStatus, updatedAt: new Date() })
    .where(eq(orders.id, orderId));
}`,
      explanation: "Implement explicit state machine with validated transitions to prevent workflow bypass attacks.",
      complexity: "medium",
      testingNotes: "Test all invalid transition combinations and concurrent update scenarios",
    });
  }

  if (exposureType === "iam_abuse" || exposureType === "privilege_boundary") {
    fixes.push({
      id: `cf-${randomUUID().slice(0, 6)}`,
      title: "Role-Based Access Control Enhancement",
      language: "typescript",
      filePath: "src/middleware/auth.ts",
      vulnerability: "Privilege escalation via role manipulation",
      beforeCode: `function checkPermission(user: User, resource: string) {
  return user.permissions.includes(resource);
}`,
      afterCode: `const ROLE_PERMISSIONS: Record<string, string[]> = {
  'user': ['read:own', 'write:own'],
  'moderator': ['read:own', 'write:own', 'read:all', 'moderate'],
  'admin': ['read:own', 'write:own', 'read:all', 'write:all', 'admin'],
};

function checkPermission(user: User, resource: string, action: string) {
  const rolePermissions = ROLE_PERMISSIONS[user.role] || [];
  const requiredPermission = \`\${action}:\${resource}\`;
  
  // Check both specific and wildcard permissions
  return rolePermissions.some(p => 
    p === requiredPermission || 
    p === \`\${action}:all\` ||
    (resource === 'own' && p.endsWith(':own'))
  );
}

function requirePermission(resource: string, action: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!checkPermission(req.user, resource, action)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}`,
      explanation: "Implement hierarchical RBAC with explicit permission mapping to prevent horizontal and vertical privilege escalation.",
      complexity: "high",
      testingNotes: "Test cross-user access, role enumeration, and permission inheritance",
    });
  }

  return fixes;
}

async function generateWafRules(context: RemediationContext): Promise<WafRule[]> {
  const rules: WafRule[] = [];

  rules.push({
    id: `waf-${randomUUID().slice(0, 6)}`,
    title: "Block Suspicious API Patterns",
    platform: "cloudflare",
    ruleType: "block",
    condition: `http.request.uri.path contains "/api/" and (
      http.request.body.size > 1048576 or
      http.request.headers["content-type"][0] ne "application/json"
    )`,
    action: "block",
    priority: 1,
    description: "Block oversized API requests and non-JSON content types to API endpoints",
    falsePositiveRisk: "low",
    rawConfig: `{
  "expression": "http.request.uri.path contains \\"/api/\\" and (http.request.body.size > 1048576 or http.request.headers[\\"content-type\\"][0] ne \\"application/json\\")",
  "action": "block",
  "description": "Block suspicious API patterns"
}`,
  });

  if (context.exposureType === "payment_flow" || context.exposureType === "subscription_bypass") {
    rules.push({
      id: `waf-${randomUUID().slice(0, 6)}`,
      title: "Rate Limit Payment Endpoints",
      platform: "cloudflare",
      ruleType: "rate_limit",
      condition: `http.request.uri.path matches "^/api/(checkout|payment|subscribe)"`,
      action: "rate_limit(10, 60)",
      priority: 2,
      description: "Limit payment-related requests to 10 per minute per IP to prevent abuse",
      falsePositiveRisk: "medium",
      rawConfig: `{
  "expression": "http.request.uri.path matches \\"^/api/(checkout|payment|subscribe)\\"",
  "action": "rate_limit",
  "characteristics": ["ip.src"],
  "period": 60,
  "requests_per_period": 10
}`,
    });
  }

  rules.push({
    id: `waf-${randomUUID().slice(0, 6)}`,
    title: "SQL Injection Protection",
    platform: "modsecurity",
    ruleType: "block",
    condition: "ARGS|ARGS_NAMES|REQUEST_BODY",
    action: "deny,status:403,id:9001",
    priority: 1,
    description: "Block common SQL injection patterns in request parameters",
    falsePositiveRisk: "medium",
    rawConfig: `SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@detectSQLi" \\
  "id:9001,\\
  phase:2,\\
  deny,\\
  status:403,\\
  msg:'SQL Injection Attempt Detected',\\
  logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\\
  severity:CRITICAL"`,
  });

  return rules;
}

async function generateIamPolicies(context: RemediationContext): Promise<IamPolicy[]> {
  const policies: IamPolicy[] = [];

  if (context.exposureType === "iam_abuse" || context.exposureType === "cloud_misconfiguration") {
    policies.push({
      id: `iam-${randomUUID().slice(0, 6)}`,
      title: "Restrict IAM Role Assumption",
      platform: "aws",
      policyType: "deny",
      currentState: "Allows sts:AssumeRole on *",
      recommendedState: "Restrict to specific roles with conditions",
      affectedPrincipals: ["arn:aws:iam::*:role/ServiceRole*"],
      riskReduction: 75,
      implementationSteps: [
        "Audit current role trust policies",
        "Identify legitimate cross-account access patterns",
        "Implement explicit deny for unauthorized assumptions",
        "Add MFA requirement for sensitive role assumptions",
        "Enable CloudTrail logging for AssumeRole events"
      ],
      rollbackPlan: "Remove deny policy and restore original trust relationships",
      rawPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthorizedRoleAssumption",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}`,
    });
  }

  policies.push({
    id: `iam-${randomUUID().slice(0, 6)}`,
    title: "Implement Least Privilege",
    platform: "aws",
    policyType: "boundary",
    currentState: "Service role has broad permissions",
    recommendedState: "Scoped permissions with permission boundary",
    affectedPrincipals: ["Application service roles"],
    riskReduction: 60,
    implementationSteps: [
      "Generate IAM Access Analyzer findings",
      "Create permission boundary based on actual usage",
      "Apply boundary to existing roles",
      "Monitor for access denied events",
      "Iterate and refine boundary policy"
    ],
    rawPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowedServices",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:s3:::app-bucket/*",
        "arn:aws:dynamodb:*:*:table/app-*"
      ]
    },
    {
      "Sid": "DenyPrivilegedActions",
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}`,
  });

  return policies;
}

async function generateNetworkControls(context: RemediationContext): Promise<NetworkControl[]> {
  const controls: NetworkControl[] = [];

  controls.push({
    id: `net-${randomUUID().slice(0, 6)}`,
    title: "Segment Application Tier",
    controlType: "segmentation",
    sourceZone: "web-tier",
    destinationZone: "app-tier",
    protocol: "TCP",
    ports: ["443", "8080"],
    action: "allow",
    description: "Allow only HTTPS traffic from web tier to application tier",
    implementationGuide: `1. Create network security group for app tier
2. Allow inbound 443/8080 from web tier subnet only
3. Deny all other inbound traffic
4. Allow outbound to database tier on specific ports
5. Enable flow logging for audit`,
  });

  controls.push({
    id: `net-${randomUUID().slice(0, 6)}`,
    title: "Restrict Database Access",
    controlType: "firewall",
    sourceZone: "app-tier",
    destinationZone: "data-tier",
    protocol: "TCP",
    ports: ["5432", "3306"],
    action: "allow",
    description: "Allow database connections only from application tier",
    implementationGuide: `1. Configure database security group
2. Allow inbound from app tier private IPs only
3. Block all internet-facing access
4. Enable TLS for database connections
5. Implement connection pooling with authentication`,
  });

  return controls;
}

async function generateDetectionRules(context: RemediationContext): Promise<DetectionRule[]> {
  const rules: DetectionRule[] = [];

  rules.push({
    id: `det-${randomUUID().slice(0, 6)}`,
    title: "Detect Anomalous API Access Patterns",
    platform: "sigma",
    ruleType: "anomaly",
    severity: "high",
    description: "Detect unusual API access patterns indicative of exploitation attempts",
    logic: "Count API requests per user, alert when >3 standard deviations from baseline",
    dataSource: ["api_logs", "waf_logs"],
    mitreTechniques: ["T1190", "T1212"],
    falsePositiveGuidance: "Review legitimate automation and batch processing patterns",
    responsePlaybook: "Isolate source IP, review access logs, escalate to security team",
    rawRule: `title: Anomalous API Access Pattern
status: experimental
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-method: POST
    cs-uri-stem|contains: /api/
  timeframe: 1m
  condition: selection | count() by src_ip > 100
falsepositives:
  - Automated testing
  - Batch processing
level: high
tags:
  - attack.initial_access
  - attack.t1190`,
  });

  if (context.exposureType === "payment_flow" || context.exposureType === "subscription_bypass") {
    rules.push({
      id: `det-${randomUUID().slice(0, 6)}`,
      title: "Payment Flow Manipulation Detection",
      platform: "elastic",
      ruleType: "correlation",
      severity: "critical",
      description: "Detect attempts to manipulate payment flows",
      logic: "Correlate price mismatches between client requests and server calculations",
      dataSource: ["payment_logs", "application_logs"],
      mitreTechniques: ["T1565.001"],
      falsePositiveGuidance: "Review legitimate discount applications and currency conversions",
      responsePlaybook: "Block transaction, flag account, notify fraud team",
      rawRule: `{
  "rule": {
    "name": "Payment Manipulation Attempt",
    "type": "eql",
    "query": "sequence by user.id [payment where event.action == 'checkout_initiated'] [payment where event.action == 'payment_processed' and payment.client_total != payment.server_total]",
    "risk_score": 90,
    "severity": "critical"
  }
}`,
    });
  }

  rules.push({
    id: `det-${randomUUID().slice(0, 6)}`,
    title: "Privilege Escalation Attempt",
    platform: "splunk",
    ruleType: "signature",
    severity: "critical",
    description: "Detect unauthorized access to privileged resources",
    logic: "Match access to admin endpoints by non-admin users",
    dataSource: ["auth_logs", "api_logs"],
    mitreTechniques: ["T1068", "T1548"],
    falsePositiveGuidance: "Verify against authorized admin user list",
    responsePlaybook: "Lock account, review session history, reset credentials",
    rawRule: `index=web sourcetype=access_combined 
| search uri_path="/admin/*" OR uri_path="/api/admin/*"
| lookup authorized_admins user AS user OUTPUT is_admin
| where isnull(is_admin) OR is_admin=false
| stats count by user, src_ip, uri_path
| where count > 0`,
  });

  return rules;
}

async function generateCompensatingControls(context: RemediationContext): Promise<CompensatingControl[]> {
  const controls: CompensatingControl[] = [];

  controls.push({
    id: `comp-${randomUUID().slice(0, 6)}`,
    title: "Enhanced Monitoring",
    controlType: "monitoring",
    description: "Implement enhanced monitoring for vulnerable endpoints until patch is deployed",
    rationale: "Provides visibility into exploitation attempts while remediation is in progress",
    implementationGuide: `1. Enable verbose logging on affected endpoints
2. Set up real-time alerting for suspicious patterns
3. Create dashboard for security team monitoring
4. Configure automated ticket creation for alerts
5. Establish 24/7 on-call rotation for critical alerts`,
    effectiveness: 65,
    duration: "temporary",
    reviewDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
  });

  controls.push({
    id: `comp-${randomUUID().slice(0, 6)}`,
    title: "Access Review",
    controlType: "access_review",
    description: "Conduct immediate access review for affected systems",
    rationale: "Identify and remove unnecessary access that could be exploited",
    implementationGuide: `1. Export current access lists for affected resources
2. Compare against job function requirements
3. Remove unnecessary permissions immediately
4. Document access decisions for audit trail
5. Schedule recurring reviews`,
    effectiveness: 50,
    duration: "permanent",
    dependencies: ["IAM inventory", "HR system integration"],
  });

  if (context.priority === "critical" || context.priority === "high") {
    controls.push({
      id: `comp-${randomUUID().slice(0, 6)}`,
      title: "Emergency Network Isolation",
      controlType: "monitoring",
      description: "Prepare network isolation procedures for emergency response",
      rationale: "Enable rapid containment if active exploitation is detected",
      implementationGuide: `1. Document isolation procedures in runbook
2. Pre-configure firewall rules (disabled)
3. Test isolation in non-production environment
4. Train incident response team on procedures
5. Establish communication plan for stakeholders`,
      effectiveness: 90,
      duration: "temporary",
      reviewDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    });
  }

  return controls;
}

function buildPrioritizedActions(
  codeFixes: CodeFix[],
  wafRules: WafRule[],
  iamPolicies: IamPolicy[],
  networkControls: NetworkControl[],
  detectionRules: DetectionRule[],
  compensatingControls: CompensatingControl[]
): RemediationGuidance["prioritizedActions"] {
  const actions: RemediationGuidance["prioritizedActions"] = [];
  let order = 1;

  compensatingControls.forEach(c => {
    actions.push({
      order: order++,
      action: c.title,
      type: "compensating",
      timeEstimate: "1-2 hours",
      riskReduction: c.effectiveness,
      effort: "low",
    });
  });

  wafRules.forEach(r => {
    actions.push({
      order: order++,
      action: r.title,
      type: "waf_rule",
      timeEstimate: "30 minutes",
      riskReduction: r.falsePositiveRisk === "low" ? 40 : 25,
      effort: "low",
    });
  });

  detectionRules.forEach(r => {
    actions.push({
      order: order++,
      action: r.title,
      type: "detection_rule",
      timeEstimate: "1-2 hours",
      riskReduction: 20,
      effort: "low",
    });
  });

  codeFixes.forEach(f => {
    actions.push({
      order: order++,
      action: f.title,
      type: "code_fix",
      timeEstimate: f.complexity === "trivial" ? "1 hour" : f.complexity === "low" ? "2-4 hours" : f.complexity === "medium" ? "1-2 days" : "3-5 days",
      riskReduction: f.complexity === "trivial" ? 30 : f.complexity === "low" ? 50 : f.complexity === "medium" ? 70 : 90,
      effort: f.complexity === "trivial" || f.complexity === "low" ? "low" : f.complexity === "medium" ? "medium" : "high",
    });
  });

  iamPolicies.forEach(p => {
    actions.push({
      order: order++,
      action: p.title,
      type: "iam_policy",
      timeEstimate: "2-4 hours",
      riskReduction: p.riskReduction,
      effort: "medium",
    });
  });

  networkControls.forEach(c => {
    actions.push({
      order: order++,
      action: c.title,
      type: "network_control",
      timeEstimate: "2-4 hours",
      riskReduction: 40,
      effort: "medium",
    });
  });

  return actions;
}

function calculateTotalRiskReduction(actions: RemediationGuidance["prioritizedActions"]): number {
  if (actions.length === 0) return 0;
  let remaining = 100;
  actions.forEach(a => {
    remaining = remaining * (1 - a.riskReduction / 100);
  });
  return Math.round(100 - remaining);
}

function estimateImplementationTime(actions: RemediationGuidance["prioritizedActions"]): string {
  const lowEffort = actions.filter(a => a.effort === "low").length;
  const mediumEffort = actions.filter(a => a.effort === "medium").length;
  const highEffort = actions.filter(a => a.effort === "high").length;

  const totalHours = lowEffort * 2 + mediumEffort * 6 + highEffort * 24;
  
  if (totalHours <= 8) return "1 day";
  if (totalHours <= 40) return `${Math.ceil(totalHours / 8)} days`;
  return `${Math.ceil(totalHours / 40)} weeks`;
}

function generateExecutiveSummary(
  context: RemediationContext,
  actions: RemediationGuidance["prioritizedActions"],
  totalRiskReduction: number
): string {
  const immediateActions = actions.filter(a => a.effort === "low").length;
  const codeChanges = actions.filter(a => a.type === "code_fix").length;
  
  return `A ${context.priority} severity ${context.exposureType.replace(/_/g, " ")} vulnerability has been identified affecting ${context.assetId}. ${context.exploitable ? "This vulnerability has been confirmed as exploitable." : "This vulnerability requires further validation."} 

Our analysis recommends ${actions.length} remediation actions that collectively reduce risk by ${totalRiskReduction}%. ${immediateActions} actions can be implemented immediately with low effort, including WAF rules and enhanced monitoring. ${codeChanges > 0 ? `${codeChanges} code-level fixes are recommended for permanent remediation.` : ""} 

Priority should be given to compensating controls for immediate risk reduction while longer-term fixes are developed and tested.`;
}
