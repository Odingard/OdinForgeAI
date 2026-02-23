import { z } from "zod";

export const jobTypes = [
  "evaluation",
  "full_assessment", 
  "ai_simulation",
  "network_scan",
  "cloud_discovery",
  "external_recon",
  "report_generation",
  "agent_deployment",
  "remediation",
  "exploit_validation",
  "api_scan",
  "auth_scan",
  "protocol_probe",
  "recon_scan",
  "mimir_triggered_evaluation",
  "cloud_scan",
  "endpoint_scan",
] as const;

export type JobType = typeof jobTypes[number];

export const jobStatuses = [
  "pending",
  "queued",
  "processing",
  "completed",
  "failed",
  "cancelled",
  "stalled",
  "retrying",
] as const;

export type JobStatus = typeof jobStatuses[number];

export const jobPriorities = {
  critical: 1,
  high: 2,
  normal: 3,
  low: 4,
  background: 5,
} as const;

export type JobPriority = keyof typeof jobPriorities;

export const baseJobDataSchema = z.object({
  tenantId: z.string(),
  organizationId: z.string(),
  userId: z.string().optional(),
  correlationId: z.string().optional(),
});

export const evaluationJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("evaluation"),
  evaluationId: z.string(),
  executionMode: z.enum(["safe", "simulation", "live"]),
  assetId: z.string().optional(),
  exposureData: z.any().optional(),
});

export const fullAssessmentJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("full_assessment"),
  assessmentId: z.string(),
  targetSystems: z.array(z.string()),
  phases: z.array(z.string()).optional(),
});

export const networkScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("network_scan"),
  scanId: z.string(),
  targets: z.array(z.string()),
  portRange: z.string().optional(),
  scanType: z.enum(["quick", "full", "stealth"]).optional(),
});

export const cloudDiscoveryJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("cloud_discovery"),
  connectionId: z.string(),
  provider: z.enum(["aws", "azure", "gcp"]),
  regions: z.array(z.string()).optional(),
});

export const externalReconJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("external_recon"),
  reconId: z.string(),
  target: z.string(),
  modules: z.array(z.string()).optional(),
});

export const reportGenerationJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("report_generation"),
  reportId: z.string(),
  evaluationIds: z.array(z.string()),
  format: z.enum(["pdf", "html", "json"]).optional(),
  reportType: z.enum(["executive", "technical", "compliance"]).optional(),
});

export const aiSimulationJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("ai_simulation"),
  simulationId: z.string(),
  scenario: z.string(),
  rounds: z.number().optional(),
});

export const exploitValidationJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("exploit_validation"),
  validationId: z.string(),
  findingId: z.string(),
  exploitType: z.string(),
  safeMode: z.boolean().default(true),
  evaluationId: z.string().optional(),
  targetUrl: z.string().optional(),
  httpMethod: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).optional(),
  parameterName: z.string().optional(),
  parameterLocation: z.enum(["url_param", "body_param", "header", "cookie", "path"]).optional(),
});

export const apiScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("api_scan"),
  scanId: z.string(),
  specUrl: z.string().optional(),
  specContent: z.string().optional(),
  baseUrl: z.string(),
});

export const authScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("auth_scan"),
  scanId: z.string(),
  targetUrl: z.string(),
  authType: z.enum(["basic", "bearer", "oauth", "oauth2", "session", "jwt", "api_key"]),
  credentials: z.any().optional(),
});

export const remediationJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("remediation"),
  remediationId: z.string(),
  findingIds: z.array(z.string()),
  actions: z.array(z.object({
    type: z.string(),
    target: z.string(),
    parameters: z.record(z.any()).optional(),
  })),
  evaluationId: z.string().optional(),
  dryRun: z.boolean().default(true),
});

export const agentDeploymentJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("agent_deployment"),
  deploymentId: z.string(),
  provider: z.enum(["aws", "azure", "gcp", "ssh"]),
  instanceIds: z.array(z.string()),
  deploymentMethod: z.enum(["cloud_api", "ssh"]).optional(), // cloud_api uses provider APIs, ssh uses direct SSH
  serverUrl: z.string().optional(), // OdinForge server URL for agent registration
  sshCredentialId: z.string().optional(), // Reference to SSH credential for SSH deployment
});

export const protocolProbeJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("protocol_probe"),
  targetHost: z.string(),
  probeTypes: z.array(z.enum(["smtp", "dns", "ldap", "credential"])),
  credentialServices: z.array(z.enum(["ssh", "ftp", "mysql", "postgresql", "redis", "mongodb", "telnet"])).optional(),
  domain: z.string().optional(),
  evaluationId: z.string().optional(),
  timeout: z.number().optional(),
});

export const reconScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("recon_scan"),
  scanId: z.string(),
  evaluationId: z.string().optional(),
  target: z.string(),
  options: z.object({
    skipSubdomains: z.boolean().optional(),
    skipPorts: z.boolean().optional(),
    endpointCheckConcurrency: z.number().optional(),
    maxEndpointsToCheck: z.number().optional(),
    agentConcurrency: z.number().optional(),
    agentMaxFindings: z.number().optional(),
    priorityFilter: z.array(z.enum(["critical", "high", "medium", "low"])).optional(),
  }).optional(),
});

// Mimir-triggered evaluation — cross-product job from Redis Stream
export const mimirFindingSchema = z.object({
  finding_id:    z.string(),
  title:         z.string(),
  category:      z.string(),
  severity:      z.enum(["critical", "high", "medium", "low", "info"]),
  risk_score:    z.number().nullable(),
  cve_id:        z.string().nullable(),
  is_kev_listed: z.boolean(),
  entity_id:     z.string().nullable(),
});

export const mimirTriggeredEvaluationSchema = baseJobDataSchema.extend({
  type: z.literal("mimir_triggered_evaluation"),
  stream_event_id:      z.string(),
  mimir_event_id:       z.string(),
  mimir_assessment_id:  z.string(),
  target_domain:        z.string(),
  entity_id:            z.string(),
  risk_grade:           z.enum(["A", "B", "C", "D", "F"]),
  risk_score:           z.number().min(0).max(100),
  kev_count:            z.number().int().min(0),
  critical_count:       z.number().int().min(0),
  top_risk_findings:    z.array(mimirFindingSchema).max(10),
  industry:             z.string().nullable(),
  company_name:         z.string().nullable(),
  execution_mode:       z.enum(["safe", "aggressive"]).default("safe"),
});

export type MimirTriggeredEvaluationJobData = z.infer<typeof mimirTriggeredEvaluationSchema>;

export const cloudScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("cloud_scan"),
  evaluationId: z.string(),
  provider: z.enum(["aws", "azure", "gcp", "k8s"]),
  credentials: z.any(),
});

export const endpointScanJobDataSchema = baseJobDataSchema.extend({
  type: z.literal("endpoint_scan"),
  evaluationId: z.string(),
  os: z.enum(["linux", "macos", "windows"]),
  hostname: z.string().optional(),
});

export type EvaluationJobData = z.infer<typeof evaluationJobDataSchema>;
export type FullAssessmentJobData = z.infer<typeof fullAssessmentJobDataSchema>;
export type NetworkScanJobData = z.infer<typeof networkScanJobDataSchema>;
export type CloudDiscoveryJobData = z.infer<typeof cloudDiscoveryJobDataSchema>;
export type ExternalReconJobData = z.infer<typeof externalReconJobDataSchema>;
export type ReportGenerationJobData = z.infer<typeof reportGenerationJobDataSchema>;
export type AiSimulationJobData = z.infer<typeof aiSimulationJobDataSchema>;
export type ExploitValidationJobData = z.infer<typeof exploitValidationJobDataSchema>;
export type ApiScanJobData = z.infer<typeof apiScanJobDataSchema>;
export type AuthScanJobData = z.infer<typeof authScanJobDataSchema>;
export type RemediationJobData = z.infer<typeof remediationJobDataSchema>;
export type AgentDeploymentJobData = z.infer<typeof agentDeploymentJobDataSchema>;
export type ProtocolProbeJobData = z.infer<typeof protocolProbeJobDataSchema>;
export type ReconScanJobData = z.infer<typeof reconScanJobDataSchema>;
export type CloudScanJobData = z.infer<typeof cloudScanJobDataSchema>;
export type EndpointScanJobData = z.infer<typeof endpointScanJobDataSchema>;

export type AnyJobData =
  | EvaluationJobData
  | FullAssessmentJobData
  | NetworkScanJobData
  | CloudDiscoveryJobData
  | ExternalReconJobData
  | ReportGenerationJobData
  | AiSimulationJobData
  | ExploitValidationJobData
  | ApiScanJobData
  | AuthScanJobData
  | RemediationJobData
  | AgentDeploymentJobData
  | ProtocolProbeJobData
  | ReconScanJobData
  | MimirTriggeredEvaluationJobData
  | CloudScanJobData
  | EndpointScanJobData;

export interface JobResult {
  success: boolean;
  data?: any;
  error?: string;
  duration?: number;
  metrics?: Record<string, number>;
  metadata?: Record<string, any>;
}

export interface JobProgress {
  percent: number;
  stage: string;
  message?: string;
  details?: Record<string, any>;
}
