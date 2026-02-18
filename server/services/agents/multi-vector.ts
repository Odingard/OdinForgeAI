import type {
  AgentMemory,
  AgentResult,
  MultiVectorFindings,
  CloudFinding,
  IAMFinding,
  SaaSFinding,
  ShadowAdminIndicator,
  ChainedAttackPath
} from "./types";
import type { MultiVectorFinding, CloudVectorType } from "@shared/schema";
import { cloudVectorTypes } from "@shared/schema";
import { openai } from "./openai-client";
import { buildCloudGroundTruth } from "./scan-data-loader";

type ProgressCallback = (stage: string, progress: number, message: string) => void;

const MULTI_VECTOR_EXPOSURE_TYPES = [
  "cloud_misconfiguration",
  "iam_abuse",
  "saas_permission",
  "shadow_admin"
];

export function shouldRunMultiVectorAnalysis(exposureType: string): boolean {
  return MULTI_VECTOR_EXPOSURE_TYPES.includes(exposureType);
}

export async function runMultiVectorAnalysisAgent(
  memory: AgentMemory,
  onProgress?: ProgressCallback
): Promise<AgentResult<MultiVectorFindings>> {
  const startTime = Date.now();
  
  onProgress?.("multi_vector", 60, "Initializing multi-vector analysis...");

  onProgress?.("multi_vector", 63, "Analyzing cloud misconfigurations...");
  const cloudFindings = await analyzeCloudVectors(memory);
  
  onProgress?.("multi_vector", 68, "Analyzing IAM abuse paths...");
  const iamFindings = await analyzeIAMAbuse(memory);
  
  onProgress?.("multi_vector", 73, "Analyzing SaaS permissions...");
  const saasFindings = await analyzeSaaSPermissions(memory);
  
  onProgress?.("multi_vector", 78, "Discovering shadow admins...");
  const shadowAdminIndicators = await discoverShadowAdmins(memory, iamFindings, saasFindings);
  
  onProgress?.("multi_vector", 83, "Building chained attack paths...");
  const chainedAttackPaths = await buildChainedAttackPaths(
    memory, 
    cloudFindings, 
    iamFindings, 
    saasFindings
  );
  
  onProgress?.("multi_vector", 88, "Generating multi-vector findings...");
  const findings = generateMultiVectorFindings(
    cloudFindings,
    iamFindings,
    saasFindings,
    shadowAdminIndicators
  );

  const multiVectorFindings: MultiVectorFindings = {
    findings,
    cloudFindings,
    iamFindings,
    saasFindings,
    shadowAdminIndicators,
    chainedAttackPaths,
  };

  return {
    success: true,
    findings: multiVectorFindings,
    agentName: "Multi-Vector Analysis Agent",
    processingTime: Date.now() - startTime,
  };
}

async function analyzeCloudVectors(memory: AgentMemory): Promise<CloudFinding[]> {
  const isCloudRelated = [
    "cloud_misconfiguration",
    "iam_abuse"
  ].includes(memory.context.exposureType);

  if (!isCloudRelated) {
    return [];
  }

  const systemPrompt = `You are a CLOUD SECURITY ANALYZER for OdinForge AI.

Your task is to identify cloud misconfigurations and abuse paths across AWS, GCP, and Azure:
1. S3/Storage bucket exposures
2. IAM role chaining opportunities
3. Cross-account access vectors
4. Metadata service abuse (IMDS)
5. Lambda/Function privilege escalation
6. Service account abuse
7. Permission boundary bypasses
8. Resource policy misconfigurations

For each finding, provide exploitation path and remediation steps.`;

  // Inject verified cloud infrastructure data
  const cloudGroundTruth = memory.groundTruth ? buildCloudGroundTruth(memory.groundTruth) : "";

  const userPrompt = `Analyze cloud security vectors for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${memory.recon ? `Technologies: ${memory.recon.technologies.join(", ")}
Entry Points: ${memory.recon.entryPoints.join(", ")}` : ""}
${cloudGroundTruth ? `\n${cloudGroundTruth}\n` : ""}
Return a JSON object with this structure:
{
  "findings": [
    {
      "id": "cloud_finding_id",
      "vectorType": "${cloudVectorTypes.join("|")}",
      "provider": "aws|gcp|azure|multi-cloud",
      "service": "service name (e.g., S3, IAM, Lambda)",
      "resource": "affected resource identifier",
      "title": "Finding title",
      "description": "Detailed description",
      "severity": "critical|high|medium|low",
      "exploitPath": ["step1", "step2", "step3"],
      "remediationSteps": ["fix1", "fix2"]
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.findings) ? result.findings : [];
  } catch (error) {
    console.error("Cloud vector analysis error:", error);
    return [];
  }
}

async function analyzeIAMAbuse(memory: AgentMemory): Promise<IAMFinding[]> {
  const isIAMRelated = [
    "iam_abuse",
    "cloud_misconfiguration",
    "privilege_boundary"
  ].includes(memory.context.exposureType);

  if (!isIAMRelated) {
    return [];
  }

  const systemPrompt = `You are an IAM ABUSE PATH ANALYZER for OdinForge AI.

Your task is to identify IAM misconfigurations and privilege escalation paths:
1. Overly permissive IAM policies
2. Role assumption chains
3. Cross-account trust relationships
4. Service-linked role abuse
5. Permission boundary bypasses
6. Policy wildcard abuse
7. Condition key bypasses

For each finding, map the privilege escalation path from initial access to objective.`;

  // Inject verified cloud infrastructure data for IAM context
  const iamGroundTruth = memory.groundTruth ? buildCloudGroundTruth(memory.groundTruth) : "";

  const userPrompt = `Analyze IAM abuse paths for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${memory.lateral ? `Privilege Escalation Paths: ${memory.lateral.privilegeEscalation.map(p =>
  `${p.target} via ${p.method}`
).join(", ")}` : ""}
${iamGroundTruth ? `\n${iamGroundTruth}\n` : ""}
Return a JSON object with this structure:
{
  "findings": [
    {
      "id": "iam_finding_id",
      "principal": "arn:aws:iam::...",
      "assumableRoles": ["role1", "role2"],
      "effectivePermissions": ["permission1", "permission2"],
      "privilegeEscalationPath": "description of escalation path or null",
      "severity": "critical|high|medium|low",
      "title": "Finding title",
      "description": "Detailed description"
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.findings) ? result.findings : [];
  } catch (error) {
    console.error("IAM abuse analysis error:", error);
    return [];
  }
}

async function analyzeSaaSPermissions(memory: AgentMemory): Promise<SaaSFinding[]> {
  const isSaaSRelated = [
    "saas_permission",
    "shadow_admin"
  ].includes(memory.context.exposureType);

  if (!isSaaSRelated) {
    return [];
  }

  const systemPrompt = `You are a SAAS PERMISSION ANALYZER for OdinForge AI.

Your task is to identify SaaS permission misconfigurations and abuse paths:
1. Overly permissive OAuth scopes
2. Delegated admin abuse
3. API key scope creep
4. Cross-tenant access
5. Third-party app permissions
6. SSO/SAML misconfiguration
7. Service account over-provisioning

Focus on identifying shadow admin indicators - users with admin-equivalent permissions who shouldn't have them.`;

  const userPrompt = `Analyze SaaS permissions for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${memory.recon ? `Auth Mechanisms: ${memory.recon.authMechanisms.join(", ")}
Technologies: ${memory.recon.technologies.join(", ")}` : ""}

Return a JSON object with this structure:
{
  "findings": [
    {
      "id": "saas_finding_id",
      "platform": "Google Workspace|Microsoft 365|Salesforce|etc",
      "permissionLevel": "admin|elevated|standard",
      "title": "Finding title",
      "description": "Detailed description",
      "severity": "critical|high|medium|low",
      "shadowAdminIndicators": ["indicator1", "indicator2"],
      "exploitPath": ["step1", "step2"]
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.findings) ? result.findings : [];
  } catch (error) {
    console.error("SaaS permission analysis error:", error);
    return [];
  }
}

async function discoverShadowAdmins(
  memory: AgentMemory,
  iamFindings: IAMFinding[],
  saasFindings: SaaSFinding[]
): Promise<ShadowAdminIndicator[]> {
  if (memory.context.exposureType !== "shadow_admin" && 
      !iamFindings.some(f => f.privilegeEscalationPath) &&
      !saasFindings.some(f => f.shadowAdminIndicators.length > 0)) {
    return [];
  }

  const systemPrompt = `You are a SHADOW ADMIN DISCOVERY ENGINE for OdinForge AI.

Shadow admins are users or service accounts with admin-equivalent permissions who:
1. Don't appear in official admin groups
2. Have accumulated permissions over time
3. Use delegated or inherited permissions
4. Control critical resources without proper oversight
5. Can perform admin actions through indirect paths

Identify shadow admin indicators from the provided IAM and SaaS findings.`;

  const iamContext = iamFindings.length > 0 
    ? `IAM Findings:\n${iamFindings.map(f => 
        `- ${f.principal}: ${f.effectivePermissions.slice(0, 5).join(", ")}`
      ).join("\n")}`
    : "";

  const saasContext = saasFindings.length > 0
    ? `SaaS Findings:\n${saasFindings.map(f => 
        `- ${f.platform} (${f.permissionLevel}): ${f.shadowAdminIndicators.join(", ")}`
      ).join("\n")}`
    : "";

  const userPrompt = `Discover shadow admins for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

${iamContext}
${saasContext}

Return a JSON object with this structure:
{
  "indicators": [
    {
      "id": "shadow_admin_id",
      "principal": "user/service account identifier",
      "platform": "AWS|GCP|Azure|Google Workspace|etc",
      "indicatorType": "excessive_permissions|dormant_admin|service_account_abuse|delegated_admin|hidden_role",
      "evidence": ["evidence1", "evidence2"],
      "riskLevel": "critical|high|medium|low"
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.indicators) ? result.indicators : [];
  } catch (error) {
    console.error("Shadow admin discovery error:", error);
    return [];
  }
}

async function buildChainedAttackPaths(
  memory: AgentMemory,
  cloudFindings: CloudFinding[],
  iamFindings: IAMFinding[],
  saasFindings: SaaSFinding[]
): Promise<ChainedAttackPath[]> {
  const totalFindings = cloudFindings.length + iamFindings.length + saasFindings.length;
  if (totalFindings < 2) {
    return [];
  }

  const systemPrompt = `You are a CHAINED ATTACK PATH BUILDER for OdinForge AI.

Your task is to identify how multiple vectors can be chained together for greater impact:
1. Cloud misconfiguration -> IAM escalation -> data exfiltration
2. SaaS compromise -> lateral movement -> admin access
3. Initial access -> privilege escalation -> persistence

Chain findings together to show realistic attack scenarios.`;

  const findingsContext = `
Cloud Findings: ${cloudFindings.map(f => f.title).join(", ") || "none"}
IAM Findings: ${iamFindings.map(f => f.title).join(", ") || "none"}
SaaS Findings: ${saasFindings.map(f => f.title).join(", ") || "none"}
`;

  const userPrompt = `Build chained attack paths for:

Asset ID: ${memory.context.assetId}
Exposure Type: ${memory.context.exposureType}
Description: ${memory.context.description}

Available Vectors:
${findingsContext}

Return a JSON object with this structure:
{
  "chainedPaths": [
    {
      "id": "chain_id",
      "name": "Attack chain name",
      "vectors": ["vector_type1", "vector_type2"],
      "steps": [
        {
          "step": 1,
          "action": "action description",
          "target": "target resource",
          "technique": "MITRE technique if applicable"
        }
      ],
      "combinedImpact": "description of combined impact",
      "difficulty": "trivial|low|medium|high|expert"
    }
  ]
}`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 2048,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) return [];

    const result = JSON.parse(content);
    return Array.isArray(result.chainedPaths) ? result.chainedPaths : [];
  } catch (error) {
    console.error("Chained attack path building error:", error);
    return [];
  }
}

function generateMultiVectorFindings(
  cloudFindings: CloudFinding[],
  iamFindings: IAMFinding[],
  saasFindings: SaaSFinding[],
  shadowAdmins: ShadowAdminIndicator[]
): MultiVectorFinding[] {
  const findings: MultiVectorFinding[] = [];
  let findingId = 1;

  for (const cloud of cloudFindings) {
    findings.push({
      id: `mv-${findingId++}`,
      vectorType: "cloud_misconfiguration",
      cloudVector: cloud.vectorType as CloudVectorType,
      title: cloud.title,
      description: cloud.description,
      severity: cloud.severity,
      affectedResources: [cloud.resource],
      exploitPath: cloud.exploitPath.map((step, i) => ({
        step: i + 1,
        action: step,
        target: cloud.resource,
        technique: cloud.vectorType,
      })),
      cloudContext: {
        provider: cloud.provider,
        service: cloud.service,
        resourceArn: cloud.resource,
      },
    });
  }

  for (const iam of iamFindings) {
    findings.push({
      id: `mv-${findingId++}`,
      vectorType: "iam_abuse",
      title: iam.title,
      description: iam.description,
      severity: iam.severity,
      affectedResources: [iam.principal, ...iam.assumableRoles],
      exploitPath: [{
        step: 1,
        action: "Assume initial role",
        target: iam.principal,
        technique: "AssumeRole",
      }],
      iamContext: {
        principal: iam.principal,
        assumableRoles: iam.assumableRoles,
        effectivePermissions: iam.effectivePermissions,
        privilegeEscalationPath: iam.privilegeEscalationPath || undefined,
      },
    });
  }

  for (const saas of saasFindings) {
    findings.push({
      id: `mv-${findingId++}`,
      vectorType: "saas_permission",
      title: saas.title,
      description: saas.description,
      severity: saas.severity,
      affectedResources: [saas.platform],
      exploitPath: saas.exploitPath.map((step, i) => ({
        step: i + 1,
        action: step,
        target: saas.platform,
      })),
      saasContext: {
        platform: saas.platform,
        permissionLevel: saas.permissionLevel,
        shadowAdminIndicators: saas.shadowAdminIndicators,
      },
    });
  }

  for (const shadow of shadowAdmins) {
    findings.push({
      id: `mv-${findingId++}`,
      vectorType: "shadow_admin",
      title: `Shadow Admin: ${shadow.principal}`,
      description: `Discovered shadow admin via ${shadow.indicatorType}`,
      severity: shadow.riskLevel,
      affectedResources: [shadow.principal],
      exploitPath: [{
        step: 1,
        action: `Identify shadow admin: ${shadow.indicatorType}`,
        target: shadow.principal,
        technique: "Shadow Admin Discovery",
      }],
      saasContext: {
        platform: shadow.platform,
        shadowAdminIndicators: shadow.evidence,
      },
    });
  }

  return findings;
}
