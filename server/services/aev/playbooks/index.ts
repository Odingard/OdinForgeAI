/**
 * AEV Exploit Chain Playbooks
 * 
 * Pre-defined playbooks for common attack chains that demonstrate
 * true AEV capabilities with multi-step exploit validation.
 */

import type { Playbook } from "../chain-orchestrator";

// ============================================================================
// SQLi TO DATA EXFILTRATION CHAIN
// ============================================================================

export const sqliExfilPlaybook: Playbook = {
  id: "sqli-exfil-chain",
  name: "SQLi to Data Exfiltration",
  description: "Validates SQL injection and attempts to prove data exfiltration capability",
  version: "1.0.0",
  category: "sqli",
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1190", "T1005", "T1213"],
  riskLevel: "critical",
  
  minimumMode: "simulation",
  estimatedDuration: 60000,
  
  steps: [
    {
      id: "sqli-detect",
      name: "SQL Injection Detection",
      description: "Detect SQL injection vulnerability using error-based and time-based techniques",
      type: "validate",
      category: "sqli",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: {
        technique: "all",
      },
    },
    {
      id: "sqli-fingerprint",
      name: "Database Fingerprinting",
      description: "Identify database type and version via SQL injection",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["sqli-detect"],
      requiredConfidence: 70,
      config: {
        queries: ["@@version", "version()"],
      },
    },
    {
      id: "sqli-schema-enum",
      name: "Schema Enumeration",
      description: "Extract table and column names from information_schema",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["sqli-fingerprint"],
      requiredConfidence: 60,
      config: {
        maxTables: 10,
        sensitivePatterns: ["user", "password", "credential", "session", "token"],
      },
    },
    {
      id: "sqli-data-sample",
      name: "Data Sample Extraction",
      description: "Extract limited sample data to prove exfiltration capability",
      type: "exfiltrate",
      category: "sqli",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["sqli-schema-enum"],
      requiredConfidence: 80,
      requiredEvidence: ["sqli_validation", "schema_enumeration"],
      safeMode: {
        enabled: true,
        maxPayloads: 5,
      },
      config: {
        maxRows: 3,
        redactSensitive: true,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 2,
    confidenceBelow: 40,
  },
};

// ============================================================================
// PATH TRAVERSAL TO FILE READ PROOF
// ============================================================================

export const pathTraversalProofPlaybook: Playbook = {
  id: "path-traversal-proof",
  name: "Path Traversal File Read Proof",
  description: "Validates path traversal and proves file read capability",
  version: "1.0.0",
  category: "path_traversal",
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1083", "T1005"],
  riskLevel: "high",
  
  minimumMode: "simulation",
  estimatedDuration: 45000,
  
  steps: [
    {
      id: "pt-detect",
      name: "Path Traversal Detection",
      description: "Detect path traversal vulnerability using common patterns",
      type: "validate",
      category: "path_traversal",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "pt-os-detect",
      name: "OS Detection",
      description: "Determine target operating system via file signatures",
      type: "exploit",
      category: "path_traversal",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["pt-detect"],
      requiredConfidence: 60,
      config: {
        unixFiles: ["/etc/passwd", "/etc/hosts"],
        windowsFiles: ["C:\\Windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts"],
      },
    },
    {
      id: "pt-file-proof",
      name: "File Content Proof",
      description: "Extract and hash file content to prove read access",
      type: "exfiltrate",
      category: "path_traversal",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["pt-os-detect"],
      requiredConfidence: 70,
      safeMode: {
        enabled: true,
        allowedTargets: ["/etc/passwd", "/etc/hosts"],
      },
      config: {
        hashOnly: false,
        maxBytes: 1024,
        targetFiles: ["safe_system_files"],
      },
    },
  ],
  
  abortOn: {
    stepFailures: 2,
  },
};

// ============================================================================
// COMMAND INJECTION TO RCE PROOF
// ============================================================================

export const commandInjectionRcePlaybook: Playbook = {
  id: "cmd-injection-rce",
  name: "Command Injection to RCE Proof",
  description: "Validates command injection and proves remote code execution",
  version: "1.0.0",
  category: "command_injection",
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1059", "T1106"],
  riskLevel: "critical",
  
  minimumMode: "simulation",
  estimatedDuration: 50000,
  
  steps: [
    {
      id: "cmdi-detect",
      name: "Command Injection Detection",
      description: "Detect command injection via time-based and error-based techniques",
      type: "validate",
      category: "command_injection",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "cmdi-os-enum",
      name: "OS Enumeration via RCE",
      description: "Execute benign commands to identify OS type",
      type: "exploit",
      category: "command_injection",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["cmdi-detect"],
      requiredConfidence: 70,
      config: {
        commands: ["id", "whoami", "hostname"],
        windowsCommands: ["whoami", "hostname"],
      },
    },
    {
      id: "cmdi-rce-proof",
      name: "RCE Capability Proof",
      description: "Execute proof command and capture output",
      type: "exploit",
      category: "command_injection",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["cmdi-os-enum"],
      requiredConfidence: 80,
      safeMode: {
        enabled: true,
      },
      config: {
        proofCommands: ["echo OdinForge-$(date +%s)", "date"],
        captureOutput: true,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 1,
    confidenceBelow: 50,
  },
};

// ============================================================================
// AUTH BYPASS TO PRIVILEGE ESCALATION
// ============================================================================

export const authBypassEscalationPlaybook: Playbook = {
  id: "auth-bypass-escalation",
  name: "Auth Bypass to Privilege Escalation",
  description: "Validates authentication bypass and attempts privilege escalation",
  version: "1.0.0",
  category: "auth_bypass",
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1548", "T1078"],
  riskLevel: "critical",
  
  minimumMode: "simulation",
  estimatedDuration: 60000,
  
  steps: [
    {
      id: "auth-detect",
      name: "Authentication Bypass Detection",
      description: "Detect authentication bypass vulnerabilities",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "auth-session-capture",
      name: "Session Token Analysis",
      description: "Analyze and capture session tokens",
      type: "exploit",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["auth-detect"],
      requiredConfidence: 60,
      config: {
        analyzeJwt: true,
        analyzeCookies: true,
      },
    },
    {
      id: "auth-privesc-attempt",
      name: "Privilege Escalation Attempt",
      description: "Attempt to access higher-privilege resources",
      type: "escalate",
      category: "auth_bypass",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["auth-session-capture"],
      requiredConfidence: 70,
      config: {
        targetRoles: ["admin", "root", "superuser"],
        testEndpoints: ["/admin", "/api/admin", "/dashboard"],
      },
    },
  ],
  
  abortOn: {
    stepFailures: 1,
  },
};

// ============================================================================
// SSRF TO INTERNAL NETWORK PIVOT
// ============================================================================

export const ssrfPivotPlaybook: Playbook = {
  id: "ssrf-internal-pivot",
  name: "SSRF to Internal Network Pivot",
  description: "Validates SSRF and attempts internal network reconnaissance",
  version: "1.0.0",
  category: "ssrf",
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1090", "T1046"],
  riskLevel: "high",
  
  minimumMode: "simulation",
  estimatedDuration: 60000,
  
  steps: [
    {
      id: "ssrf-detect",
      name: "SSRF Detection",
      description: "Detect SSRF vulnerability via cloud metadata and localhost probes",
      type: "validate",
      category: "ssrf",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "ssrf-cloud-meta",
      name: "Cloud Metadata Access",
      description: "Attempt to access cloud provider metadata endpoints",
      type: "exploit",
      category: "ssrf",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["ssrf-detect"],
      requiredConfidence: 70,
      config: {
        providers: ["aws", "azure", "gcp"],
      },
    },
    {
      id: "ssrf-internal-scan",
      name: "Internal Network Discovery",
      description: "Probe internal network endpoints via SSRF",
      type: "pivot",
      category: "ssrf",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["ssrf-cloud-meta"],
      requiredConfidence: 60,
      config: {
        internalRanges: ["10.0.0.0/24", "172.16.0.0/24", "192.168.0.0/24"],
        commonPorts: [22, 80, 443, 3306, 5432, 6379],
        maxTargets: 10,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 1,
  },
};

// ============================================================================
// MULTI-VECTOR ATTACK CHAIN
// ============================================================================

export const multiVectorChainPlaybook: Playbook = {
  id: "multi-vector-chain",
  name: "Multi-Vector Attack Chain",
  description: "Comprehensive attack chain testing multiple vulnerability classes",
  version: "1.0.0",
  category: "sqli", // Primary category
  
  author: "OdinForge AEV",
  mitreAttackIds: ["T1190", "T1059", "T1548"],
  riskLevel: "critical",
  
  minimumMode: "simulation",
  estimatedDuration: 120000,
  
  steps: [
    {
      id: "recon-sqli",
      name: "SQLi Reconnaissance",
      description: "Test for SQL injection vulnerabilities",
      type: "validate",
      category: "sqli",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "recon-xss",
      name: "XSS Reconnaissance",
      description: "Test for XSS vulnerabilities",
      type: "validate",
      category: "xss",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "recon-cmdi",
      name: "Command Injection Reconnaissance",
      description: "Test for command injection vulnerabilities",
      type: "validate",
      category: "command_injection",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "recon-ssrf",
      name: "SSRF Reconnaissance",
      description: "Test for SSRF vulnerabilities",
      type: "validate",
      category: "ssrf",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "exploit-primary",
      name: "Primary Exploit Execution",
      description: "Execute highest-confidence exploit",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["recon-sqli", "recon-xss", "recon-cmdi", "recon-ssrf"],
      config: {
        selectHighestConfidence: true,
      },
    },
    {
      id: "chain-escalation",
      name: "Attack Chain Escalation",
      description: "Attempt to chain vulnerabilities for impact",
      type: "escalate",
      category: "auth_bypass",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["exploit-primary"],
      requiredConfidence: 70,
      config: {
        chainFromPrevious: true,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 3,
    confidenceBelow: 30,
  },
};

// ============================================================================
// IDOR ESCALATION CHAIN
// ============================================================================

export const idorEscalationPlaybook: Playbook = {
  id: "idor-escalation-chain",
  name: "IDOR to Privilege Escalation",
  description: "Tests for IDOR vulnerabilities and attempts vertical privilege escalation",
  version: "1.0.0",
  category: "idor",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1078", "T1548"],
  riskLevel: "high",

  minimumMode: "simulation",
  estimatedDuration: 45000,

  steps: [
    {
      id: "idor-validate",
      name: "IDOR Detection",
      description: "Test common endpoints for insecure direct object references",
      type: "validate",
      category: "idor",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "idor-horizontal",
      name: "Horizontal IDOR Exploitation",
      description: "Enumerate object IDs to access other users' data",
      type: "exploit",
      category: "idor",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["idor-validate"],
      requiredConfidence: 50,
      config: {},
    },
    {
      id: "idor-vertical",
      name: "Vertical Privilege Escalation",
      description: "Attempt to access admin endpoints with regular user credentials",
      type: "escalate",
      category: "idor",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["idor-horizontal"],
      requiredConfidence: 60,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 2,
    confidenceBelow: 30,
  },
};

// ============================================================================
// RACE CONDITION CHAIN
// ============================================================================

export const raceConditionPlaybook: Playbook = {
  id: "race-condition-chain",
  name: "Race Condition to Double-Spend",
  description: "Tests for race conditions including double-spend and limit bypass",
  version: "1.0.0",
  category: "race_condition",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1499"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 30000,

  steps: [
    {
      id: "race-validate",
      name: "Race Condition Detection",
      description: "Run concurrent requests to detect timing-based vulnerabilities",
      type: "validate",
      category: "race_condition",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: { concurrentRequests: 10 },
    },
    {
      id: "race-double-spend",
      name: "Double-Spend Exploitation",
      description: "Attempt double-spend via concurrent transaction requests",
      type: "exploit",
      category: "race_condition",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["race-validate"],
      requiredConfidence: 50,
      config: { concurrentRequests: 10 },
    },
  ],

  abortOn: {
    stepFailures: 1,
  },
};

// ============================================================================
// WORKFLOW BYPASS CHAIN
// ============================================================================

export const workflowBypassPlaybook: Playbook = {
  id: "workflow-bypass-chain",
  name: "Workflow Bypass to Unauthorized Action",
  description: "Tests whether business workflow steps can be skipped or state can be manipulated",
  version: "1.0.0",
  category: "workflow_bypass",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1548", "T1068"],
  riskLevel: "high",

  minimumMode: "simulation",
  estimatedDuration: 40000,

  steps: [
    {
      id: "wf-validate",
      name: "Workflow Bypass Detection",
      description: "Test default workflows for direct access, step skip, and state manipulation",
      type: "validate",
      category: "workflow_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "wf-exploit",
      name: "Workflow Exploitation",
      description: "Exploit confirmed workflow bypasses via step-skip and state manipulation",
      type: "exploit",
      category: "workflow_bypass",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["wf-validate"],
      requiredConfidence: 50,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 1,
  },
};

// ============================================================================
// CLOUD SECURITY PLAYBOOKS
// ============================================================================

export const iamEscalationPlaybook: Playbook = {
  id: "iam-escalation-chain",
  name: "IAM Privilege Escalation Chain",
  description: "Validates IAM permission analysis, tests privilege escalation paths, and proves impact",
  version: "1.0.0",
  category: "iam_escalation",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1098.001", "T1098.003", "T1548.005"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 45000,

  steps: [
    {
      id: "iam-permission-audit",
      name: "IAM Permission Analysis",
      description: "Enumerate current IAM permissions and identify dangerous capabilities",
      type: "validate",
      category: "iam_escalation",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "iam-escalation-test",
      name: "Privilege Escalation Path Testing",
      description: "Test identified escalation paths (CreateAccessKey, AttachPolicy, PassRole)",
      type: "escalate",
      category: "iam_escalation",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["iam-permission-audit"],
      requiredConfidence: 60,
      config: {},
    },
    {
      id: "iam-impact-proof",
      name: "Escalation Impact Proof",
      description: "Demonstrate the scope of access achievable through escalation",
      type: "exploit",
      category: "iam_escalation",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["iam-escalation-test"],
      requiredConfidence: 70,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 1,
    confidenceBelow: 40,
  },
};

export const cloudStorageExposurePlaybook: Playbook = {
  id: "cloud-storage-exposure",
  name: "Cloud Storage Exposure Chain",
  description: "S3/blob scan, public access test, sensitive data exposure proof",
  version: "1.0.0",
  category: "cloud_storage_exposure",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1530", "T1537"],
  riskLevel: "high",

  minimumMode: "safe",
  estimatedDuration: 40000,

  steps: [
    {
      id: "storage-enum",
      name: "Storage Bucket Enumeration",
      description: "Enumerate cloud storage buckets and check public access configuration",
      type: "validate",
      category: "cloud_storage_exposure",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: {},
    },
    {
      id: "storage-access-test",
      name: "Public Access Verification",
      description: "Test for public read/write access and misconfigured ACLs",
      type: "exploit",
      category: "cloud_storage_exposure",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["storage-enum"],
      requiredConfidence: 50,
      config: {},
    },
    {
      id: "storage-data-exposure",
      name: "Sensitive Data Exposure Proof",
      description: "Identify sensitive file patterns in exposed buckets",
      type: "exfiltrate",
      category: "cloud_storage_exposure",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["storage-access-test"],
      requiredConfidence: 60,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 2,
  },
};

// ============================================================================
// PLAYBOOK REGISTRY
// ============================================================================

export const playbookRegistry: Map<string, Playbook> = new Map([
  [sqliExfilPlaybook.id, sqliExfilPlaybook],
  [pathTraversalProofPlaybook.id, pathTraversalProofPlaybook],
  [commandInjectionRcePlaybook.id, commandInjectionRcePlaybook],
  [authBypassEscalationPlaybook.id, authBypassEscalationPlaybook],
  [ssrfPivotPlaybook.id, ssrfPivotPlaybook],
  [multiVectorChainPlaybook.id, multiVectorChainPlaybook],
  [idorEscalationPlaybook.id, idorEscalationPlaybook],
  [raceConditionPlaybook.id, raceConditionPlaybook],
  [workflowBypassPlaybook.id, workflowBypassPlaybook],
  [iamEscalationPlaybook.id, iamEscalationPlaybook],
  [cloudStorageExposurePlaybook.id, cloudStorageExposurePlaybook],
]);

export function getPlaybook(id: string): Playbook | undefined {
  return playbookRegistry.get(id);
}

export function listPlaybooks(): Playbook[] {
  return Array.from(playbookRegistry.values());
}

export function getPlaybooksByCategory(category: string): Playbook[] {
  return Array.from(playbookRegistry.values())
    .filter(p => p.category === category);
}

export function getPlaybooksByRiskLevel(riskLevel: Playbook["riskLevel"]): Playbook[] {
  return Array.from(playbookRegistry.values())
    .filter(p => p.riskLevel === riskLevel);
}
