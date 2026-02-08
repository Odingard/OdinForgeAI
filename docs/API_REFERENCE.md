# OdinForge-AI API Reference

**Version:** 1.0
**Last Updated:** February 7, 2026
**Base URL:** `http://your-server:5000/api`

---

## Table of Contents

1. [Lateral Movement API](#1-lateral-movement-api)
2. [Container Security API](#2-container-security-api)
3. [Sandbox Operations API](#3-sandbox-operations-api)
4. [API Fuzzing](#4-api-fuzzing)
5. [Compliance Mapping API](#5-compliance-mapping-api)
6. [Tool Integration API](#6-tool-integration-api)
7. [Cloud Pentesting API](#7-cloud-pentesting-api)
8. [Protocol Probes API](#8-protocol-probes-api)
9. [Session Management API](#9-session-management-api)
10. [Business Logic Testing API](#10-business-logic-testing-api)
11. [Forensic Analysis API](#11-forensic-analysis-api)

---

## Authentication

All API endpoints require authentication. Include the access token in the Authorization header:

```bash
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### Getting an Access Token

```bash
POST /ui/api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response:**
```json
{
  "success": true,
  "user": { ... },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 1. Lateral Movement API

Test and analyze lateral movement capabilities across your infrastructure.

### 1.1 Get Available Techniques

```bash
GET /api/lateral-movement/techniques
```

**Response:**
```json
[
  {
    "id": "psexec",
    "name": "PsExec",
    "description": "Execute commands remotely using PsExec",
    "protocols": ["SMB"],
    "requiresCredentials": true,
    "stealthLevel": "medium"
  },
  {
    "id": "winrm",
    "name": "Windows Remote Management",
    "description": "Execute commands via WinRM",
    "protocols": ["HTTP", "HTTPS"],
    "requiresCredentials": true,
    "stealthLevel": "low"
  }
]
```

### 1.2 Test Credential Reuse

Test if discovered credentials work on other hosts.

```bash
POST /api/lateral-movement/test-reuse
Content-Type: application/json

{
  "credentialType": "password",
  "username": "admin",
  "domain": "CONTOSO",
  "credentialValue": "hashed_password_here",
  "targetHosts": ["192.168.1.10", "192.168.1.20"],
  "techniques": ["winrm", "psexec"]
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "host": "192.168.1.10",
      "accessible": true,
      "successfulTechniques": ["winrm"],
      "failedTechniques": ["psexec"]
    },
    {
      "host": "192.168.1.20",
      "accessible": false,
      "successfulTechniques": [],
      "failedTechniques": ["winrm", "psexec"],
      "error": "Connection timeout"
    }
  ]
}
```

### 1.3 Discover Pivot Points

Find hosts that can access multiple systems.

```bash
POST /api/lateral-movement/discover-pivots
Content-Type: application/json

{
  "startingHost": "192.168.1.10",
  "scanDepth": 2,
  "techniques": ["winrm", "ssh"],
  "excludeHosts": ["192.168.1.1"]
}
```

**Response:**
```json
{
  "success": true,
  "pivotPoints": [
    {
      "hostname": "server01",
      "ipAddress": "192.168.1.10",
      "accessibleHosts": 15,
      "techniques": ["winrm", "ssh"],
      "risk": "high"
    }
  ],
  "attackPaths": [
    {
      "source": "192.168.1.10",
      "target": "192.168.1.20",
      "hops": 1,
      "techniques": ["winrm"],
      "feasibility": "high"
    }
  ]
}
```

### 1.4 Pass-the-Hash Simulation

Simulate pass-the-hash attacks (simulation mode only).

```bash
POST /api/lateral-movement/pass-the-hash
Content-Type: application/json

{
  "ntlmHash": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
  "username": "administrator",
  "domain": "CONTOSO",
  "targetHost": "192.168.1.20"
}
```

**Response:**
```json
{
  "success": true,
  "simulated": true,
  "result": "would_succeed",
  "message": "Pass-the-hash attack would succeed with these credentials"
}
```

---

## 2. Container Security API

Scan and assess Kubernetes and Docker environments.

### 2.1 Scan Kubernetes Cluster

```bash
POST /api/container-security/kubernetes/scan
Content-Type: application/json

{
  "kubeconfig": "path/to/kubeconfig",
  "namespace": "default",
  "scanType": "comprehensive"
}
```

**Response:**
```json
{
  "success": true,
  "scanId": "k8s-scan-abc123",
  "findings": [
    {
      "severity": "high",
      "type": "privileged_container",
      "pod": "nginx-deployment-abc",
      "namespace": "default",
      "description": "Container running in privileged mode"
    }
  ],
  "summary": {
    "totalPods": 15,
    "vulnerablePods": 3,
    "critical": 1,
    "high": 5,
    "medium": 10
  }
}
```

### 2.2 Test Kubernetes Escape

Test container escape scenarios (simulation mode).

```bash
POST /api/container-security/kubernetes/test-escape
Content-Type: application/json

{
  "pod": "nginx-deployment-abc",
  "namespace": "default",
  "technique": "hostPath_mount"
}
```

**Response:**
```json
{
  "success": true,
  "escapePossible": true,
  "technique": "hostPath_mount",
  "severity": "critical",
  "recommendations": [
    "Remove hostPath mounts",
    "Enable Pod Security Standards",
    "Use restrictive securityContext"
  ]
}
```

### 2.3 Scan Docker Images

```bash
POST /api/container-security/docker/scan-image
Content-Type: application/json

{
  "image": "nginx:latest",
  "registryUrl": "https://registry.hub.docker.com",
  "credentials": {
    "username": "user",
    "password": "pass"
  }
}
```

**Response:**
```json
{
  "success": true,
  "image": "nginx:latest",
  "vulnerabilities": [
    {
      "cve": "CVE-2023-1234",
      "severity": "high",
      "package": "libssl1.1",
      "fixedVersion": "1.1.1k-1"
    }
  ],
  "secrets": [
    {
      "type": "api_key",
      "location": "/app/.env",
      "severity": "critical"
    }
  ]
}
```

---

## 3. Sandbox Operations API

Manage and control security testing sandbox environments.

### 3.1 Get Sandbox Configuration

```bash
GET /api/aev/sandbox/config
```

**Response:**
```json
{
  "maxExecutionTime": 300,
  "maxConcurrentOperations": 5,
  "networkIsolation": true,
  "snapshotting": true,
  "rollbackOnFailure": true
}
```

### 3.2 Update Sandbox Configuration

```bash
PUT /api/aev/sandbox/config
Content-Type: application/json

{
  "maxExecutionTime": 600,
  "maxConcurrentOperations": 10
}
```

### 3.3 Abort Operation

```bash
POST /api/aev/sandbox/abort/:operationId
```

**Response:**
```json
{
  "success": true,
  "operationId": "op-abc123",
  "status": "aborted",
  "message": "Operation terminated successfully"
}
```

### 3.4 Engage Kill Switch

Emergency stop all sandbox operations.

```bash
POST /api/aev/sandbox/kill-switch/engage
Content-Type: application/json

{
  "reason": "Security incident detected",
  "duration": 3600
}
```

**Response:**
```json
{
  "success": true,
  "killSwitchActive": true,
  "expiresAt": "2026-02-07T13:00:00Z",
  "operationsTerminated": 5
}
```

---

## 4. API Fuzzing

Fuzz test APIs for vulnerabilities.

### 4.1 Start API Fuzzing

```bash
POST /api/fuzz/api/start
Content-Type: application/json

{
  "targetUrl": "https://api.example.com",
  "openApiSpec": "https://api.example.com/swagger.json",
  "authToken": "Bearer token",
  "testCases": ["sql_injection", "xss", "auth_bypass"],
  "intensity": "medium"
}
```

**Response:**
```json
{
  "success": true,
  "fuzzJobId": "fuzz-abc123",
  "status": "running",
  "estimatedDuration": 1800
}
```

### 4.2 Get Fuzzing Results

```bash
GET /api/fuzz/api/:jobId/results
```

**Response:**
```json
{
  "jobId": "fuzz-abc123",
  "status": "completed",
  "findings": [
    {
      "severity": "high",
      "type": "sql_injection",
      "endpoint": "POST /api/users",
      "payload": "' OR '1'='1",
      "response": "200 OK",
      "evidence": "SQL error in response body"
    }
  ],
  "summary": {
    "requestsSent": 1500,
    "anomalies": 12,
    "critical": 1,
    "high": 3
  }
}
```

---

## 5. Compliance Mapping API

Map findings to compliance frameworks.

### 5.1 Get Supported Frameworks

```bash
GET /api/compliance/frameworks
```

**Response:**
```json
[
  {
    "id": "pci-dss-4.0",
    "name": "PCI DSS 4.0",
    "version": "4.0",
    "categories": 12
  },
  {
    "id": "nist-csf-2.0",
    "name": "NIST Cybersecurity Framework",
    "version": "2.0",
    "categories": 23
  }
]
```

### 5.2 Map Findings to Framework

```bash
POST /api/compliance/map
Content-Type: application/json

{
  "framework": "pci-dss-4.0",
  "findingIds": ["finding-123", "finding-456"]
}
```

**Response:**
```json
{
  "success": true,
  "mappings": [
    {
      "findingId": "finding-123",
      "requirements": [
        {
          "id": "6.5.1",
          "title": "Injection flaws",
          "category": "Develop and maintain secure systems"
        }
      ]
    }
  ]
}
```

---

## 6. Tool Integration API

Integrate with security tools like Metasploit and Nuclei.

### 6.1 Metasploit Integration

#### List Modules
```bash
GET /api/tools/metasploit/modules
```

#### Execute Module
```bash
POST /api/tools/metasploit/execute
Content-Type: application/json

{
  "module": "exploit/multi/http/apache_struts_rce",
  "targetHost": "192.168.1.10",
  "targetPort": 8080,
  "options": {
    "RHOST": "192.168.1.10",
    "RPORT": 8080
  },
  "payloadType": "reverse_tcp"
}
```

**Response:**
```json
{
  "success": true,
  "sessionId": "msf-session-123",
  "result": "simulated",
  "exploitWouldSucceed": true
}
```

### 6.2 Nuclei Integration

#### Run Templates
```bash
POST /api/tools/nuclei/scan
Content-Type: application/json

{
  "targets": ["https://example.com"],
  "templates": ["cves/", "vulnerabilities/"],
  "severity": ["critical", "high"]
}
```

**Response:**
```json
{
  "success": true,
  "scanId": "nuclei-abc123",
  "findings": [
    {
      "templateId": "CVE-2021-44228",
      "severity": "critical",
      "target": "https://example.com",
      "matched": true
    }
  ]
}
```

---

## 7. Cloud Pentesting API

Test cloud infrastructure security.

### 7.1 AWS IAM Testing

```bash
POST /api/cloud-pentest/aws/test-iam
Content-Type: application/json

{
  "accessKeyId": "AKIA...",
  "secretAccessKey": "secret",
  "region": "us-east-1",
  "tests": ["privilege_escalation", "resource_exposure"]
}
```

**Response:**
```json
{
  "success": true,
  "findings": [
    {
      "severity": "high",
      "type": "privilege_escalation",
      "description": "User can assume administrative role",
      "path": "user -> AssumeRole -> AdminRole"
    }
  ]
}
```

### 7.2 Azure RBAC Testing

```bash
POST /api/cloud-pentest/azure/test-rbac
Content-Type: application/json

{
  "tenantId": "tenant-id",
  "clientId": "client-id",
  "clientSecret": "secret",
  "subscriptionId": "sub-id"
}
```

### 7.3 GCP IAM Testing

```bash
POST /api/cloud-pentest/gcp/test-iam
Content-Type: application/json

{
  "projectId": "my-project",
  "credentialsPath": "/path/to/credentials.json"
}
```

---

## 8. Protocol Probes API

Test various network protocols.

### 8.1 LDAP Enumeration

```bash
POST /api/probes/ldap/enumerate
Content-Type: application/json

{
  "host": "ldap.example.com",
  "port": 389,
  "baseDn": "dc=example,dc=com",
  "username": "user",
  "password": "pass"
}
```

**Response:**
```json
{
  "success": true,
  "users": [
    {
      "dn": "cn=admin,dc=example,dc=com",
      "attributes": {
        "memberOf": ["CN=Administrators,DC=example,DC=com"]
      }
    }
  ],
  "groups": 15,
  "computers": 50
}
```

### 8.2 SMTP Testing

```bash
POST /api/probes/smtp/test
Content-Type: application/json

{
  "host": "smtp.example.com",
  "port": 25,
  "tests": ["open_relay", "user_enumeration"]
}
```

### 8.3 Credential Testing

```bash
POST /api/probes/test-credentials
Content-Type: application/json

{
  "protocol": "ssh",
  "host": "192.168.1.10",
  "port": 22,
  "username": "admin",
  "password": "password123"
}
```

---

## 9. Session Management API

Manage testing sessions and replay attacks.

### 9.1 Create Session

```bash
POST /api/sessions/create
Content-Type: application/json

{
  "targetUrl": "https://app.example.com",
  "sessionType": "authenticated",
  "credentials": {
    "username": "test",
    "password": "test123"
  }
}
```

**Response:**
```json
{
  "success": true,
  "sessionId": "sess-abc123",
  "cookies": ["sessionid=xyz", "csrftoken=abc"],
  "expiresAt": "2026-02-07T13:00:00Z"
}
```

### 9.2 Replay Session

```bash
POST /api/sessions/:sessionId/replay
Content-Type: application/json

{
  "actions": [
    {
      "type": "navigate",
      "url": "/dashboard"
    },
    {
      "type": "click",
      "selector": "#submit-button"
    }
  ]
}
```

---

## 10. Business Logic Testing API

Test application business logic for flaws.

### 10.1 Test Workflow

```bash
POST /api/business-logic/test-workflow
Content-Type: application/json

{
  "baseUrl": "https://app.example.com",
  "workflow": "checkout",
  "steps": [
    {
      "action": "add_to_cart",
      "itemId": "item-123",
      "quantity": 1
    },
    {
      "action": "apply_discount",
      "code": "DISCOUNT50"
    },
    {
      "action": "submit_order"
    }
  ],
  "anomalyTests": ["price_manipulation", "quantity_bypass"]
}
```

**Response:**
```json
{
  "success": true,
  "findings": [
    {
      "severity": "high",
      "type": "price_manipulation",
      "description": "Able to modify price by changing request parameter",
      "evidence": "Original price: $100, Modified price: $0.01"
    }
  ]
}
```

### 10.2 Fuzz Parameters

```bash
POST /api/business-logic/fuzz-parameters
Content-Type: application/json

{
  "endpoint": "https://api.example.com/orders",
  "parameters": {
    "quantity": "integer",
    "price": "decimal",
    "userId": "string"
  },
  "tests": ["boundary_values", "negative_numbers", "type_confusion"]
}
```

---

## 11. Forensic Analysis API

Export and analyze security testing evidence.

### 11.1 Create Forensic Export

```bash
POST /api/evidence/:evaluationId/export
Content-Type: application/json

{
  "format": "zip",
  "includeArtifacts": true,
  "includeTimeline": true,
  "password": "secure123"
}
```

**Response:**
```json
{
  "success": true,
  "exportId": "export-abc123",
  "downloadUrl": "/api/evidence/download/export-abc123",
  "expiresAt": "2026-02-08T12:00:00Z",
  "size": "15.2 MB"
}
```

### 11.2 Get Evidence Timeline

```bash
GET /api/evidence/:evaluationId/timeline
```

**Response:**
```json
{
  "evaluationId": "eval-123",
  "events": [
    {
      "timestamp": "2026-02-07T10:00:00Z",
      "type": "scan_started",
      "user": "admin",
      "details": "Full assessment initiated"
    },
    {
      "timestamp": "2026-02-07T10:05:00Z",
      "type": "vulnerability_found",
      "severity": "high",
      "details": "SQL injection in /api/users"
    }
  ]
}
```

### 11.3 Verify Evidence Integrity

```bash
GET /api/evidence/:id/verify
```

**Response:**
```json
{
  "evidenceId": "evidence-123",
  "verified": true,
  "checksumMatch": true,
  "chainOfCustody": [
    {
      "timestamp": "2026-02-07T10:00:00Z",
      "action": "created",
      "user": "admin"
    },
    {
      "timestamp": "2026-02-07T10:30:00Z",
      "action": "accessed",
      "user": "security-team"
    }
  ]
}
```

---

## Error Responses

All endpoints follow a consistent error format:

```json
{
  "error": "Error type",
  "message": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional context"
  }
}
```

### Common HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

---

## Rate Limiting

| Endpoint Type | Limit | Window |
|---|---|---|
| API requests | 100 requests | 1 minute |
| Evaluations | 10 requests | 1 minute |
| Reports | 5 requests | 1 minute |
| Simulations | 3 requests | 1 minute |

**Rate Limit Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1675774800
```

---

## Webhooks

Configure webhooks to receive real-time notifications.

### Configure Webhook

```bash
POST /api/webhooks/configure
Content-Type: application/json

{
  "url": "https://your-server.com/webhook",
  "events": ["evaluation_completed", "finding_critical"],
  "secret": "webhook-secret-key"
}
```

### Webhook Payload Example

```json
{
  "event": "evaluation_completed",
  "timestamp": "2026-02-07T12:00:00Z",
  "data": {
    "evaluationId": "eval-123",
    "status": "completed",
    "findings": 15,
    "severity": {
      "critical": 2,
      "high": 5,
      "medium": 8
    }
  },
  "signature": "sha256=abc123..."
}
```

---

## SDK Examples

### Python

```python
import requests

# Authentication
response = requests.post(
    "http://localhost:5000/ui/api/auth/login",
    json={"email": "user@example.com", "password": "password"}
)
access_token = response.json()["accessToken"]

# Make authenticated request
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(
    "http://localhost:5000/api/lateral-movement/techniques",
    headers=headers
)
techniques = response.json()
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

// Authentication
const auth = await axios.post('http://localhost:5000/ui/api/auth/login', {
  email: 'user@example.com',
  password: 'password'
});

const accessToken = auth.data.accessToken;

// Make authenticated request
const response = await axios.get(
  'http://localhost:5000/api/lateral-movement/techniques',
  {
    headers: { Authorization: `Bearer ${accessToken}` }
  }
);
```

### cURL

```bash
# Get access token
ACCESS_TOKEN=$(curl -s -X POST http://localhost:5000/ui/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' \
  | jq -r '.accessToken')

# Use access token
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:5000/api/lateral-movement/techniques
```

---

## Support & Resources

- **GitHub:** https://github.com/Odingard/OdinForgeAI
- **Documentation:** https://docs.odinforge.ai
- **Issues:** https://github.com/Odingard/OdinForgeAI/issues

---

**Last Updated:** February 7, 2026
**Version:** 1.0
**Status:** ✅ Production Ready
