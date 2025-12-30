# API Reference

This document provides a reference for the OdinForge REST API. For complete endpoint details, refer to the server source code in `server/routes.ts`.

## Table of Contents

- [Authentication](#authentication)
- [Evaluations](#evaluations)
- [Agents](#agents)
- [Simulations](#simulations)
- [Reports](#reports)
- [Infrastructure](#infrastructure)
- [Governance](#governance)

---

## Authentication

OdinForge uses multiple authentication methods depending on the endpoint:

### Agent Registration Token

Used for initial agent registration:

```bash
curl -H "Authorization: Bearer <registration-token>" \
  -X POST https://odinforge.example.com/api/agents/register
```

### Agent API Key

Used for agent telemetry and heartbeat after registration:

```bash
curl -H "X-API-Key: <agent-api-key>" \
  -X POST https://odinforge.example.com/api/agents/telemetry
```

### Admin API Key

Used for administrative operations:

```bash
curl -H "X-Admin-Key: <admin-api-key>" \
  https://odinforge.example.com/api/agents/registration-token
```

---

## Evaluations

### Create Evaluation

```http
POST /api/aev/evaluate
```

Starts a new AI-powered security evaluation.

**Request Body:**

```json
{
  "name": "CVE-2024-1234 Assessment",
  "exposureType": "cve_exploitation",
  "targetAsset": "web-server-01",
  "priority": "high",
  "description": "Evaluate potential CVE exploitation path",
  "adversaryProfile": "organized_crime"
}
```

### List Evaluations

```http
GET /api/aev/evaluations
```

### Get Evaluation

```http
GET /api/aev/evaluations/:id
```

### Archive/Unarchive Evaluation

```http
PATCH /api/aev/evaluations/:id/archive
PATCH /api/aev/evaluations/:id/unarchive
```

### Delete Evaluation

```http
DELETE /api/aev/evaluations/:id
```

### Get Statistics

```http
GET /api/aev/stats
```

---

## Agents

### Get Registration Token

```http
GET /api/agents/registration-token
```

Requires admin authentication.

### Register Agent

```http
POST /api/agents/register
Authorization: Bearer <registration-token>
```

**Request Body:**

```json
{
  "agentName": "web-server-01",
  "hostname": "web-server-01.example.com",
  "platform": "linux",
  "architecture": "amd64",
  "version": "1.0.0"
}
```

### Auto-Register Agent

```http
POST /api/agents/auto-register
Authorization: Bearer <registration-token>
```

Registers a new agent or returns existing if already registered.

### Agent Heartbeat

```http
POST /api/agents/heartbeat
X-API-Key: <agent-api-key>
```

### Submit Telemetry

```http
POST /api/agents/telemetry
X-API-Key: <agent-api-key>
```

**Request Body:**

```json
{
  "systemInfo": { ... },
  "metrics": { ... },
  "services": [ ... ],
  "ports": [ ... ],
  "connections": [ ... ],
  "packages": [ ... ],
  "containerInfo": { ... },
  "findings": [ ... ]
}
```

### Submit Events

```http
POST /api/agents/events
X-API-Key: <agent-api-key>
```

### Download Agent Binary

```http
GET /api/agents/download/:platform
```

Platforms: `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`

### Installation Scripts

```http
GET /api/agents/install.sh
GET /api/agents/install.ps1
GET /api/agents/kubernetes/daemonset.yaml
```

### Agent Build Status

```http
GET /api/agents/build-status
```

### Agent Releases

```http
GET /api/agent-releases/latest
```

---

## Simulations

AI vs AI purple team simulations.

### Create Simulation

```http
POST /api/simulations
```

**Request Body:**

```json
{
  "targetAssetId": "asset-id",
  "exposureType": "network_vulnerability",
  "priority": "high",
  "rounds": 5,
  "scenario": "Simulate APT attack"
}
```

### List Simulations

```http
GET /api/simulations
```

### Get Simulation

```http
GET /api/simulations/:id
```

### Delete Simulation

```http
DELETE /api/simulations/:id
```

---

## Reports

### Generate Report

```http
POST /api/reports/generate
```

**Request Body:**

```json
{
  "evaluationId": 1,
  "reportType": "executive"
}
```

Report types: `executive`, `technical`, `compliance`

### List Reports

```http
GET /api/reports
```

### Get Report

```http
GET /api/reports/:id
```

### Download Report

```http
GET /api/reports/:id/download
```

### Delete Report

```http
DELETE /api/reports/:id
```

### Enhanced Reports

```http
GET /api/reports/enhanced/:evaluationId
POST /api/reports/enhanced/date-range
```

---

## Infrastructure

### Assets

```http
GET /api/assets
GET /api/assets/:id
PATCH /api/assets/:id
DELETE /api/assets/:id
GET /api/assets/:id/vulnerabilities
```

### Vulnerabilities

```http
GET /api/vulnerabilities
GET /api/vulnerabilities/:id
PATCH /api/vulnerabilities/:id
POST /api/vulnerabilities/:id/evaluate
```

### Cloud Connections

```http
GET /api/cloud-connections
POST /api/cloud-connections
GET /api/cloud-connections/:id
PATCH /api/cloud-connections/:id
DELETE /api/cloud-connections/:id
POST /api/cloud-connections/:id/test
```

### Imports

```http
GET /api/imports
POST /api/imports/upload
GET /api/imports/:id
DELETE /api/imports/:id
GET /api/imports/:id/vulnerabilities
```

### Statistics

```http
GET /api/infrastructure/stats
```

---

## Governance

### Settings

```http
GET /api/governance/:organizationId
PATCH /api/governance/:organizationId
```

### Kill Switch

```http
POST /api/governance/:organizationId/kill-switch
```

### Rate Limits

```http
GET /api/governance/rate-limits
```

### Authorization Logs

```http
GET /api/authorization-logs/:organizationId
```

### Scope Rules

```http
GET /api/scope-rules/:organizationId
POST /api/scope-rules
DELETE /api/scope-rules/:id
```

---

## Batch Jobs

```http
GET /api/batch-jobs
POST /api/batch-jobs
GET /api/batch-jobs/:id
PATCH /api/batch-jobs/:id
DELETE /api/batch-jobs/:id
```

---

## Scheduled Scans

```http
GET /api/scheduled-scans
POST /api/scheduled-scans
GET /api/scheduled-scans/:id
PATCH /api/scheduled-scans/:id
DELETE /api/scheduled-scans/:id
```

---

## Adversary Profiles

```http
GET /api/adversary-profiles
GET /api/adversary-profiles/:id
POST /api/adversary-profiles
```

---

## Error Responses

```json
{
  "error": "Error message"
}
```

**HTTP Status Codes:**

| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Server Error |

---

## Rate Limiting

Endpoints are rate limited by type:

| Endpoint Type | Limit |
|--------------|-------|
| Evaluations | 10/minute |
| Simulations | 5/minute |
| Reports | 10/minute |
| Agent telemetry | 60/minute |
| Authentication | 5/minute |
