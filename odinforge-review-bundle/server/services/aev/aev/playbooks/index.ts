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
      requiredConfidence: 50,
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
      requiredConfidence: 45,
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
    stepFailures: 3,
    confidenceBelow: 20,
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
      requiredConfidence: 30,
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
      dependsOn: ["pt-detect"],
      requiredConfidence: 40,
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
      requiredConfidence: 30,
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
    stepFailures: 2,
    confidenceBelow: 15,
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
      requiredConfidence: 25,
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
    stepFailures: 2,
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
      requiredConfidence: 30,
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
      dependsOn: ["ssrf-detect"],
      requiredConfidence: 40,
      config: {
        internalRanges: ["10.0.0.0/24", "172.16.0.0/24", "192.168.0.0/24"],
        commonPorts: [22, 80, 443, 3306, 5432, 6379],
        maxTargets: 10,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 2,
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
      dependsOn: ["recon-sqli"],
      requiredConfidence: 40,
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
      requiredConfidence: 50,
      config: {
        chainFromPrevious: true,
      },
    },
  ],
  
  abortOn: {
    stepFailures: 5,
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
// IDOR CHAIN ESCALATION (FULL 4-STEP)
// ============================================================================

export const idorChainEscalationPlaybook: Playbook = {
  id: "idor-chain-escalation",
  name: "IDOR Chain Escalation",
  description: "Chains IDOR detection through user enumeration, data harvesting, and privilege escalation",
  version: "1.0.0",
  category: "idor",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1078", "T1087", "T1005", "T1548"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 180000,

  steps: [
    {
      id: "idor-detect",
      name: "IDOR Detection",
      description: "Detect IDOR by testing ID parameter manipulation",
      type: "validate",
      category: "idor",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      requiredConfidence: 0,
      config: {},
    },
    {
      id: "idor-enumerate-users",
      name: "User/Resource ID Enumeration",
      description: "Enumerate valid user/resource IDs by incrementing/iterating",
      type: "exploit",
      category: "idor",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 45000,
      maxRetries: 1,
      dependsOn: ["idor-detect"],
      requiredConfidence: 40,
      config: {
        maxIds: 50,
        patterns: ["increment", "uuid_swap"],
      },
    },
    {
      id: "idor-harvest-data",
      name: "Data Harvesting via IDOR",
      description: "Access other users' data using discovered IDs",
      type: "exfiltrate",
      category: "idor",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 60000,
      maxRetries: 1,
      dependsOn: ["idor-enumerate-users"],
      requiredConfidence: 50,
      config: {
        sensitiveFields: ["email", "phone", "ssn", "address", "credit_card", "password", "token"],
      },
    },
    {
      id: "idor-privesc-attempt",
      name: "Privilege Escalation via IDOR",
      description: "Attempt to modify other users' data or escalate to admin",
      type: "escalate",
      category: "idor",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 45000,
      maxRetries: 1,
      dependsOn: ["idor-harvest-data"],
      requiredConfidence: 60,
      config: {
        targetRoles: ["admin", "superuser", "moderator"],
        testMethods: ["PUT", "PATCH", "DELETE"],
      },
    },
  ],

  abortOn: {
    stepFailures: 2,
    confidenceBelow: 20,
  },
};

// ============================================================================
// LATERAL MOVEMENT CHAIN
// ============================================================================

export const lateralMovementChainPlaybook: Playbook = {
  id: "lateral-movement-chain",
  name: "Credential-Based Lateral Movement",
  description: "Uses harvested credentials to move laterally across the network via SSH, RDP, SMB, and service APIs",
  version: "1.0.0",
  category: "lateral_movement",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1550.002", "T1021.002", "T1563.002", "T1018"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 45 * 60 * 1000,

  steps: [
    {
      id: "credential-reuse-scan",
      name: "Credential Reuse Scan",
      description: "Test harvested credentials against other services on the network: SSH, RDP, SMB, API auth endpoints, admin panels",
      type: "validate",
      category: "credential_attack",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "pass-the-hash",
      name: "Pass-the-Hash Attack",
      description: "Attempt pass-the-hash attacks using NTLM hashes extracted from previous compromise",
      type: "exploit",
      category: "credential_attack",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["credential-reuse-scan"],
      requiredConfidence: 40,
      config: {},
    },
    {
      id: "session-hijacking",
      name: "Session Hijacking",
      description: "Steal active sessions via cookie theft, token replay, or SSO abuse",
      type: "exploit",
      category: "session_attack",
      requiredMode: "live",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["pass-the-hash"],
      requiredConfidence: 40,
      config: {},
    },
    {
      id: "pivot-discovery",
      name: "Pivot Point Discovery",
      description: "Map reachable internal hosts from pivot point, enumerate services on 192.168/10.0 ranges",
      type: "exfiltrate",
      category: "lateral_movement",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 45000,
      maxRetries: 1,
      dependsOn: ["credential-reuse-scan"],
      requiredConfidence: 30,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 3,
    confidenceBelow: 20,
  },
};

// ============================================================================
// PRIVILEGE ESCALATION CHAIN
// ============================================================================

export const privilegeEscalationChainPlaybook: Playbook = {
  id: "privilege-escalation-chain",
  name: "Local to Domain Admin Escalation",
  description: "Systematic privilege escalation from unprivileged foothold to domain admin via sudo abuse, SUID binaries, service exploitation, and token impersonation",
  version: "1.0.0",
  category: "privilege_escalation",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1548.003", "T1548.001", "T1574.005", "T1134.001", "T1558.003"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 60 * 60 * 1000,

  steps: [
    {
      id: "sudo-abuse-check",
      name: "Sudo Misconfiguration Check",
      description: "Check sudo permissions, NOPASSWD entries, sudoers misconfigurations",
      type: "validate",
      category: "privilege_escalation",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "suid-sgid-enum",
      name: "SUID/SGID Binary Enumeration",
      description: "Find SUID/SGID binaries exploitable for privilege escalation (GTFOBins)",
      type: "exploit",
      category: "privilege_escalation",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 1,
      dependsOn: ["sudo-abuse-check"],
      requiredConfidence: 30,
      config: {},
    },
    {
      id: "service-exploitation",
      name: "Weak Service Permission Exploitation",
      description: "Target weak service permissions, unquoted service paths, writable service binaries",
      type: "exploit",
      category: "privilege_escalation",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["sudo-abuse-check"],
      requiredConfidence: 30,
      config: {},
    },
    {
      id: "token-impersonation",
      name: "Token Impersonation",
      description: "Impersonate high-privilege tokens via SeImpersonatePrivilege (Potato attacks)",
      type: "exploit",
      category: "privilege_escalation",
      requiredMode: "live",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["service-exploitation"],
      requiredConfidence: 50,
      config: {},
    },
    {
      id: "domain-escalation",
      name: "Domain Admin Escalation",
      description: "Attempt Kerberoasting, AS-REP Roasting, DCSync if domain credentials available",
      type: "escalate",
      category: "privilege_escalation",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 60000,
      maxRetries: 1,
      dependsOn: ["token-impersonation"],
      requiredConfidence: 60,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 3,
    confidenceBelow: 20,
  },
};

// ============================================================================
// PERSISTENCE IMPLANT CHAIN
// ============================================================================

export const persistenceImplantChainPlaybook: Playbook = {
  id: "persistence-implant-chain",
  name: "Persistence and C2 Foothold",
  description: "Establishes persistent access via cron backdoors, startup modifications, webshell upload, and C2 beacon simulation",
  version: "1.0.0",
  category: "persistence",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1053.003", "T1546.004", "T1505.003", "T1071.001"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 30 * 60 * 1000,

  steps: [
    {
      id: "cron-backdoor",
      name: "Cron Backdoor Installation Test",
      description: "Attempt to install cron job backdoor in /etc/cron.d or user crontab",
      type: "exploit",
      category: "persistence",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "startup-persistence",
      name: "Startup Persistence Test",
      description: "Test .bashrc/.profile modification, systemd service installation, rc.local",
      type: "exploit",
      category: "persistence",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["cron-backdoor"],
      requiredConfidence: 30,
      config: {},
    },
    {
      id: "webshell-upload",
      name: "Webshell Upload Attempt",
      description: "Attempt webshell upload to writable web directories",
      type: "exploit",
      category: "persistence",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["cron-backdoor"],
      requiredConfidence: 40,
      config: {},
    },
    {
      id: "c2-beacon-simulate",
      name: "C2 Beacon Simulation",
      description: "Simulate C2 beacon: outbound connection to external host, test egress filtering",
      type: "persist",
      category: "persistence",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["cron-backdoor"],
      requiredConfidence: 20,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 3,
  },
};

// ============================================================================
// DATA EXFILTRATION CHAIN
// ============================================================================

export const dataExfiltrationChainPlaybook: Playbook = {
  id: "data-exfiltration-chain",
  name: "Staged Data Exfiltration",
  description: "Discovers sensitive data, dumps databases, tests cloud storage exfiltration, and validates egress paths",
  version: "1.0.0",
  category: "data_exfiltration",

  author: "OdinForge AEV",
  mitreAttackIds: ["T1083", "T1005", "T1537", "T1048"],
  riskLevel: "critical",

  minimumMode: "simulation",
  estimatedDuration: 35 * 60 * 1000,

  steps: [
    {
      id: "data-discovery",
      name: "Sensitive Data Discovery",
      description: "Find sensitive data: .env files, config files, database dumps, SSH keys, API credentials in common paths",
      type: "exfiltrate",
      category: "data_exfiltration",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      config: {},
    },
    {
      id: "database-dump-attempt",
      name: "Database Dump Attempt",
      description: "Attempt to dump database schema and sample records via SQLi or direct DB access",
      type: "exfiltrate",
      category: "data_exfiltration",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 45000,
      maxRetries: 1,
      dependsOn: ["data-discovery"],
      requiredConfidence: 40,
      config: {},
    },
    {
      id: "cloud-storage-exfil",
      name: "Cloud Storage Exfiltration Test",
      description: "Test S3/GCS/Azure Blob exfiltration paths using any discovered cloud credentials",
      type: "exfiltrate",
      category: "data_exfiltration",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["data-discovery"],
      requiredConfidence: 30,
      config: {},
    },
    {
      id: "egress-validation",
      name: "Egress Path Validation",
      description: "Validate data can leave the network: test DNS exfiltration, HTTP POST to external, FTP",
      type: "exfiltrate",
      category: "data_exfiltration",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["data-discovery"],
      requiredConfidence: 20,
      config: {},
    },
  ],

  abortOn: {
    stepFailures: 3,
    confidenceBelow: 20,
  },
};

// ============================================================================
// PLAYBOOK REGISTRY
// ============================================================================

// ============================================================================
// OAUTH TOKEN THEFT CHAIN
// ============================================================================

export const oauthTokenTheftPlaybook: Playbook = {
  id: "oauth-token-theft-chain",
  name: "OAuth Token Theft Chain",
  description: "Tests OAuth 2.0 flows for open redirect, CSRF bypass, PKCE absence, and token exfiltration",
  version: "1.0.0",
  category: "auth_bypass",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1550", "T1606", "T1539"],
  riskLevel: "critical",
  minimumMode: "simulation",
  estimatedDuration: 60000,
  steps: [
    {
      id: "oauth-fingerprint",
      name: "OAuth Endpoint Discovery",
      description: "Fingerprint target for OAuth/OIDC endpoints and client IDs",
      type: "recon",
      category: "auth_bypass",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: { technique: "oauth_discovery" },
    },
    {
      id: "oauth-open-redirect",
      name: "Open Redirect in redirect_uri",
      description: "Test if redirect_uri accepts external hosts — enables authorization code theft",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["oauth-fingerprint"],
      requiredConfidence: 30,
      config: { technique: "open_redirect" },
    },
    {
      id: "oauth-state-csrf",
      name: "State Parameter CSRF Bypass",
      description: "Test if state parameter is required and validated to prevent CSRF",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 15000,
      maxRetries: 1,
      dependsOn: ["oauth-fingerprint"],
      requiredConfidence: 30,
      config: { technique: "state_csrf" },
    },
    {
      id: "oauth-pkce-bypass",
      name: "PKCE Enforcement Check",
      description: "Verify PKCE (code_challenge) is enforced to prevent authorization code interception",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 15000,
      maxRetries: 1,
      dependsOn: ["oauth-fingerprint"],
      requiredConfidence: 30,
      config: { technique: "pkce_bypass" },
    },
  ],
};

// ============================================================================
// GRAPHQL EXFILTRATION CHAIN
// ============================================================================

export const graphqlExfilPlaybook: Playbook = {
  id: "graphql-exfil-chain",
  name: "GraphQL Schema Exfiltration",
  description: "Discovers GraphQL endpoint, dumps schema via introspection, and tests for authorization bypass and data exfiltration",
  version: "1.0.0",
  category: "sqli",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1190", "T1213", "T1005"],
  riskLevel: "high",
  minimumMode: "simulation",
  estimatedDuration: 60000,
  steps: [
    {
      id: "graphql-discover",
      name: "GraphQL Endpoint Discovery",
      description: "Find GraphQL endpoint via common paths and JS source analysis",
      type: "recon",
      category: "sqli",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: { paths: ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"] },
    },
    {
      id: "graphql-introspect",
      name: "Schema Introspection",
      description: "Dump full GraphQL schema to identify sensitive types and queries",
      type: "validate",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["graphql-discover"],
      requiredConfidence: 40,
      config: { technique: "introspection" },
    },
    {
      id: "graphql-authz-bypass",
      name: "Authorization Bypass Test",
      description: "Query sensitive fields without authentication based on discovered schema",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 1,
      dependsOn: ["graphql-introspect"],
      requiredConfidence: 50,
      config: { technique: "authorization_bypass" },
    },
    {
      id: "graphql-batch-abuse",
      name: "Batching Attack",
      description: "Test if GraphQL batching can be used to brute-force or enumerate data",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["graphql-discover"],
      requiredConfidence: 30,
      config: { technique: "batching", batchSize: 50 },
    },
  ],
};

// ============================================================================
// CI/CD PIPELINE POISONING CHAIN
// ============================================================================

export const cicdPoisoningPlaybook: Playbook = {
  id: "cicd-poisoning-chain",
  name: "CI/CD Pipeline Poisoning",
  description: "Tests for exposed CI/CD interfaces, secret leakage in build artifacts, and pipeline injection vectors",
  version: "1.0.0",
  category: "cicd",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1195", "T1552.001", "T1059"],
  riskLevel: "critical",
  minimumMode: "simulation",
  estimatedDuration: 75000,
  steps: [
    {
      id: "cicd-panel-discovery",
      name: "CI/CD Panel Discovery",
      description: "Detect exposed Jenkins, GitHub Actions, GitLab CI, CircleCI, and similar panels",
      type: "validate",
      category: "cicd",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 2,
      config: {
        paths: ["/jenkins", "/jenkins/", "/:8080", "/gitlab-ci", "/api/v4/projects", "/.github", "/circleci"],
      },
    },
    {
      id: "cicd-secret-scan",
      name: "Build Artifact Secret Scan",
      description: "Scan accessible build logs, artifacts, and configuration files for embedded secrets",
      type: "validate",
      category: "cicd",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["cicd-panel-discovery"],
      requiredConfidence: 30,
      config: { patterns: ["AWS_SECRET", "GITHUB_TOKEN", "DOCKER_PASSWORD", "DATABASE_URL", "API_KEY"] },
    },
    {
      id: "cicd-unauth-access",
      name: "Unauthenticated Pipeline Access",
      description: "Test if CI/CD APIs accept unauthenticated requests or use default credentials",
      type: "exploit",
      category: "cicd",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 1,
      dependsOn: ["cicd-panel-discovery"],
      requiredConfidence: 40,
      config: { defaultCreds: [["admin", "admin"], ["admin", "password"], ["admin", ""]] },
    },
  ],
};

// ============================================================================
// SERVERLESS PRIVILEGE ESCALATION CHAIN
// ============================================================================

export const serverlessPrivescPlaybook: Playbook = {
  id: "serverless-privesc-chain",
  name: "Serverless Privilege Escalation",
  description: "Tests serverless functions (Lambda, Cloud Functions) for over-permissive IAM roles, environment variable leakage, and event injection",
  version: "1.0.0",
  category: "serverless",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1098", "T1552.005", "T1190"],
  riskLevel: "critical",
  minimumMode: "simulation",
  estimatedDuration: 75000,
  steps: [
    {
      id: "lambda-discovery",
      name: "Lambda/Function URL Discovery",
      description: "Discover exposed serverless function endpoints via DNS, headers, and JS source",
      type: "validate",
      category: "serverless",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 2,
      config: { indicators: ["x-amzn-requestid", "x-cloud-trace-id", "x-powered-by: aws"] },
    },
    {
      id: "lambda-env-leak",
      name: "Environment Variable Leakage",
      description: "Test for lambda function returning environment variables via error messages or debug endpoints",
      type: "validate",
      category: "serverless",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["lambda-discovery"],
      requiredConfidence: 35,
      config: { patterns: ["AWS_ACCESS_KEY", "AWS_SECRET", "DATABASE_URL", "process.env"] },
    },
    {
      id: "lambda-iam-test",
      name: "IAM Role Escalation via SSRF",
      description: "Use SSRF in serverless function to reach EC2 metadata and steal IAM role credentials",
      type: "exploit",
      category: "serverless",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["lambda-discovery"],
      requiredConfidence: 50,
      config: { target: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
    },
  ],
};

// ============================================================================
// KUBERNETES ETCD EXPOSURE CHAIN
// ============================================================================

export const k8sEtcdPlaybook: Playbook = {
  id: "k8s-etcd-exposure-chain",
  name: "Kubernetes etcd Exposure",
  description: "Tests for exposed Kubernetes API server, etcd, and kubelet endpoints that could expose cluster secrets and configuration",
  version: "1.0.0",
  category: "k8s",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1613", "T1552.005", "T1190"],
  riskLevel: "critical",
  minimumMode: "safe",
  estimatedDuration: 60000,
  steps: [
    {
      id: "k8s-api-discovery",
      name: "Kubernetes API Discovery",
      description: "Detect exposed Kubernetes API server (6443), etcd (2379/2380), and kubelet (10250/10255)",
      type: "validate",
      category: "k8s",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: { ports: [6443, 2379, 2380, 10250, 10255, 8080] },
    },
    {
      id: "k8s-unauth-api",
      name: "Unauthenticated API Access",
      description: "Test if Kubernetes API server allows anonymous access to secrets or pod listings",
      type: "validate",
      category: "k8s",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["k8s-api-discovery"],
      requiredConfidence: 40,
      config: { endpoints: ["/api/v1/secrets", "/api/v1/namespaces/default/secrets", "/api/v1/pods"] },
    },
    {
      id: "k8s-etcd-dump",
      name: "etcd Secret Enumeration",
      description: "If etcd is directly accessible, attempt to read Kubernetes secrets from etcd",
      type: "exploit",
      category: "k8s",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 25000,
      maxRetries: 1,
      dependsOn: ["k8s-api-discovery"],
      requiredConfidence: 60,
      config: { etcdPaths: ["/registry/secrets/", "/registry/serviceaccounts/"] },
    },
  ],
};

// ============================================================================
// BUSINESS LOGIC EXPLOITATION CHAIN
// ============================================================================

export const businessLogicChainPlaybook: Playbook = {
  id: "business-logic-chain",
  name: "Business Logic Exploitation Chain",
  description: "Systematically tests for negative value abuse, coupon stacking, race conditions, and workflow bypass in e-commerce and financial applications",
  version: "1.0.0",
  category: "business_logic",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1190", "T1574", "T1565"],
  riskLevel: "high",
  minimumMode: "simulation",
  estimatedDuration: 90000,
  steps: [
    {
      id: "bl-fingerprint",
      name: "Application Flow Mapping",
      description: "Map cart, checkout, pricing, and coupon endpoints for logic testing",
      type: "validate",
      category: "business_logic",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 2,
      config: { scanPaths: ["/api/cart", "/api/basket", "/api/orders", "/api/checkout", "/api/discount", "/api/coupon"] },
    },
    {
      id: "bl-negative-values",
      name: "Negative Value Injection",
      description: "Test if negative quantities or prices are accepted, enabling free or negative-cost orders",
      type: "validate",
      category: "business_logic",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["bl-fingerprint"],
      requiredConfidence: 30,
      config: { technique: "negative_values" },
    },
    {
      id: "bl-coupon-abuse",
      name: "Coupon Stacking Attack",
      description: "Test if the same discount coupon can be applied multiple times",
      type: "validate",
      category: "business_logic",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["bl-fingerprint"],
      requiredConfidence: 30,
      config: { technique: "coupon_abuse", couponCodes: ["SAVE10", "DISCOUNT20", "FREE"] },
    },
    {
      id: "bl-race-condition",
      name: "Race Condition Exploit",
      description: "Send simultaneous requests to checkout/redeem endpoint to exploit TOCTOU race conditions",
      type: "exploit",
      category: "business_logic",
      requiredMode: "live",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["bl-fingerprint"],
      requiredConfidence: 50,
      config: { technique: "race_condition", concurrentRequests: 5 },
    },
  ],
};

// ============================================================================
// WEBSOCKET HIJACKING CHAIN
// ============================================================================

export const websocketHijackingPlaybook: Playbook = {
  id: "websocket-hijacking-chain",
  name: "WebSocket Hijacking Chain",
  description: "Discovers WebSocket endpoints and tests for cross-site WebSocket hijacking (CSWSH), authentication bypass, and message injection",
  version: "1.0.0",
  category: "auth_bypass",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1557", "T1190", "T1539"],
  riskLevel: "high",
  minimumMode: "simulation",
  estimatedDuration: 60000,
  steps: [
    {
      id: "ws-discovery",
      name: "WebSocket Endpoint Discovery",
      description: "Find WebSocket endpoints from page source, JS bundles, and common paths",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: { paths: ["/ws", "/socket.io", "/websocket", "/chat", "/live", "/realtime"] },
    },
    {
      id: "ws-origin-bypass",
      name: "Cross-Site WebSocket Hijacking",
      description: "Test if WebSocket server validates Origin header to prevent CSWSH attacks",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["ws-discovery"],
      requiredConfidence: 40,
      config: { technique: "origin_bypass" },
    },
    {
      id: "ws-auth-bypass",
      name: "Unauthenticated WebSocket Access",
      description: "Test if WebSocket connections can be established without valid authentication tokens",
      type: "validate",
      category: "auth_bypass",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 15000,
      maxRetries: 1,
      dependsOn: ["ws-discovery"],
      requiredConfidence: 40,
      config: { technique: "auth_bypass" },
    },
  ],
};

// ============================================================================
// NOSQL INJECTION EXFILTRATION CHAIN
// ============================================================================

export const nosqlExfilPlaybook: Playbook = {
  id: "nosql-exfil-chain",
  name: "NoSQL Injection to Data Exfiltration",
  description: "Tests for MongoDB/Redis operator injection enabling authentication bypass and user data exfiltration",
  version: "1.0.0",
  category: "sqli",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1190", "T1213", "T1005"],
  riskLevel: "critical",
  minimumMode: "simulation",
  estimatedDuration: 60000,
  steps: [
    {
      id: "nosql-detect",
      name: "NoSQL Stack Detection",
      description: "Detect MongoDB, Redis, or CouchDB usage via headers, error messages, and response patterns",
      type: "validate",
      category: "sqli",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: { indicators: ["mongodb", "mongoose", "ObjectId", "BSON", "redis"] },
    },
    {
      id: "nosql-auth-bypass",
      name: "NoSQL Authentication Bypass",
      description: "Inject MongoDB $ne/$gt operators into login parameters to bypass authentication",
      type: "validate",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 2,
      dependsOn: ["nosql-detect"],
      requiredConfidence: 40,
      config: { payloads: ["$ne", "$gt", "$regex", "$where", "$in"] },
    },
    {
      id: "nosql-data-exfil",
      name: "Regex-Based Data Exfiltration",
      description: "Use $regex operator to enumerate user passwords character by character",
      type: "exploit",
      category: "sqli",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["nosql-auth-bypass"],
      requiredConfidence: 60,
      config: { technique: "regex_exfil", targetField: "password", charset: "abcdefghijklmnopqrstuvwxyz0123456789" },
    },
  ],
};

// ============================================================================
// SUPPLY CHAIN ATTACK CHAIN
// ============================================================================

export const supplyChainPlaybook: Playbook = {
  id: "supply-chain-attack-chain",
  name: "Supply Chain Attack Surface",
  description: "Tests for exposed package management endpoints, dependency confusion vectors, and third-party script injection risks",
  version: "1.0.0",
  category: "supply_chain",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1195.001", "T1195.002", "T1059.007"],
  riskLevel: "high",
  minimumMode: "safe",
  estimatedDuration: 60000,
  steps: [
    {
      id: "sc-dependency-scan",
      name: "Dependency Manifest Scan",
      description: "Access exposed package.json, requirements.txt, Gemfile, or pom.xml to identify known-vulnerable dependencies",
      type: "validate",
      category: "supply_chain",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 2,
      config: { paths: ["/package.json", "/requirements.txt", "/Gemfile.lock", "/.npmrc", "/composer.json"] },
    },
    {
      id: "sc-third-party-scripts",
      name: "Third-Party Script Analysis",
      description: "Identify third-party scripts loaded without SRI hashes that could be poisoned via supply chain",
      type: "validate",
      category: "supply_chain",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 20000,
      maxRetries: 1,
      dependsOn: ["sc-dependency-scan"],
      requiredConfidence: 20,
      config: { checkSRI: true, externalDomains: ["cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"] },
    },
    {
      id: "sc-npm-confusion",
      name: "Dependency Confusion Test",
      description: "Check if private package names are predictable and could be targeted via dependency confusion attacks",
      type: "validate",
      category: "supply_chain",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 15000,
      maxRetries: 1,
      dependsOn: ["sc-dependency-scan"],
      requiredConfidence: 30,
      config: { technique: "dependency_confusion" },
    },
  ],
};

// ============================================================================
// API KEY REUSE CHAIN
// ============================================================================

export const apiKeyReusePlaybook: Playbook = {
  id: "api-key-reuse-chain",
  name: "API Key Reuse & Leakage Chain",
  description: "Discovers exposed API keys in JS bundles, HTML, and public endpoints, then tests their scope and reusability across services",
  version: "1.0.0",
  category: "supply_chain",
  author: "OdinForge AEV",
  mitreAttackIds: ["T1552.001", "T1078", "T1213"],
  riskLevel: "high",
  minimumMode: "safe",
  estimatedDuration: 75000,
  steps: [
    {
      id: "apikey-extract",
      name: "API Key Extraction",
      description: "Extract API keys, tokens, and credentials from page source, JS bundles, and debug endpoints",
      type: "validate",
      category: "supply_chain",
      requiredMode: "safe",
      requiresApproval: false,
      timeout: 30000,
      maxRetries: 2,
      config: {
        patterns: ["AKIA", "sk_live_", "ghp_", "xoxb-", "AIza", "Bearer ", "apikey=", "api_key="],
        crawlDepth: 2,
      },
    },
    {
      id: "apikey-scope-test",
      name: "Key Scope Validation",
      description: "Test discovered keys to determine their access level and what resources they can reach",
      type: "validate",
      category: "supply_chain",
      requiredMode: "simulation",
      requiresApproval: false,
      timeout: 25000,
      maxRetries: 1,
      dependsOn: ["apikey-extract"],
      requiredConfidence: 50,
      config: { services: ["aws", "github", "stripe", "sendgrid", "twilio", "google_maps"] },
    },
    {
      id: "apikey-lateral-move",
      name: "Lateral Movement via Key Reuse",
      description: "Test if keys found in one application work across other services in the same organization",
      type: "exploit",
      category: "supply_chain",
      requiredMode: "simulation",
      requiresApproval: true,
      timeout: 30000,
      maxRetries: 1,
      dependsOn: ["apikey-scope-test"],
      requiredConfidence: 60,
      config: { technique: "key_reuse_lateral" },
    },
  ],
};

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
  [idorChainEscalationPlaybook.id, idorChainEscalationPlaybook],
  [lateralMovementChainPlaybook.id, lateralMovementChainPlaybook],
  [privilegeEscalationChainPlaybook.id, privilegeEscalationChainPlaybook],
  [persistenceImplantChainPlaybook.id, persistenceImplantChainPlaybook],
  [dataExfiltrationChainPlaybook.id, dataExfiltrationChainPlaybook],
  [oauthTokenTheftPlaybook.id, oauthTokenTheftPlaybook],
  [graphqlExfilPlaybook.id, graphqlExfilPlaybook],
  [cicdPoisoningPlaybook.id, cicdPoisoningPlaybook],
  [serverlessPrivescPlaybook.id, serverlessPrivescPlaybook],
  [k8sEtcdPlaybook.id, k8sEtcdPlaybook],
  [businessLogicChainPlaybook.id, businessLogicChainPlaybook],
  [websocketHijackingPlaybook.id, websocketHijackingPlaybook],
  [nosqlExfilPlaybook.id, nosqlExfilPlaybook],
  [supplyChainPlaybook.id, supplyChainPlaybook],
  [apiKeyReusePlaybook.id, apiKeyReusePlaybook],
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
