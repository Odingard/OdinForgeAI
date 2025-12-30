# Configuration Reference

This document describes all configuration options for the OdinForge server.

## Table of Contents

- [Environment Variables](#environment-variables)
- [Database Configuration](#database-configuration)
- [Authentication Settings](#authentication-settings)
- [AI Configuration](#ai-configuration)
- [Agent Settings](#agent-settings)

---

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | `sk-...` |
| `SESSION_SECRET` | Secret for session encryption (32+ chars) | Random hex string |

### Security Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_API_KEY` | Admin API authentication key | None (development mode) |
| `MTLS_SHARED_SECRET` | Shared secret for mTLS header validation | None |
| `AGENT_REGISTRATION_TOKEN` | Token for agent registration | Auto-generated |

### Application Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `5000` |
| `LOG_LEVEL` | Logging verbosity | `info` |

---

## Database Configuration

### PostgreSQL Connection

The `DATABASE_URL` format:

```
postgresql://[user]:[password]@[host]:[port]/[database]?[options]
```

**Examples:**

```bash
# Local PostgreSQL
DATABASE_URL=postgresql://postgres:password@localhost:5432/odinforge

# Neon (serverless)
DATABASE_URL=postgresql://user:pass@ep-cool-name.us-east-2.aws.neon.tech/odinforge?sslmode=require

# AWS RDS
DATABASE_URL=postgresql://admin:password@mydb.cluster-xyz.us-east-1.rds.amazonaws.com:5432/odinforge?sslmode=require
```

### Database Migrations

Initialize or update the database schema:

```bash
# Push schema changes (development)
npm run db:push

# Generate migration files
npm run db:generate

# Apply migrations (production)
npm run db:migrate
```

### Connection Pooling

For production, configure connection pooling:

```bash
# PgBouncer or similar
DATABASE_URL=postgresql://user:pass@pgbouncer:6432/odinforge?pgbouncer=true
```

---

## Authentication Settings

### Session Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SESSION_SECRET` | Secret for signing sessions | Required |
| `SESSION_MAX_AGE` | Session lifetime in milliseconds | 86400000 (24h) |

### Admin Authentication

The `ADMIN_API_KEY` protects credential management endpoints:

```bash
# Set admin key
ADMIN_API_KEY=your-secure-admin-key-here
```

Use in API requests:

```bash
curl -H "X-Admin-Key: your-secure-admin-key-here" \
  https://odinforge.example.com/api/agents
```

### mTLS Configuration

For agent authentication with mutual TLS:

| Variable | Description |
|----------|-------------|
| `MTLS_SHARED_SECRET` | Prevents header spoofing in reverse proxy setups |

Production mTLS setup requires:
1. Reverse proxy (nginx/envoy) with client certificate validation
2. CA infrastructure (HashiCorp Vault, AWS Private CA)
3. Certificate passed via `X-SSL-Client-Cert` header

---

## AI Configuration

### OpenAI Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for GPT models | Required |
| `OPENAI_MODEL` | Model to use | `gpt-4` |
| `OPENAI_MAX_TOKENS` | Max tokens per request | `4096` |

### Rate Limiting

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_RATE_LIMIT_RPM` | Requests per minute | `60` |
| `AI_RATE_LIMIT_TPM` | Tokens per minute | `90000` |

---

## Agent Settings

### Registration

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_REGISTRATION_TOKEN` | Token required for agent registration | Auto-generated |
| `AGENT_AUTO_APPROVE` | Auto-approve new agents | `false` |

### Telemetry

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_TELEMETRY_INTERVAL` | Expected telemetry interval (seconds) | `60` |
| `AGENT_OFFLINE_THRESHOLD` | Seconds before marking agent offline | `300` |

---

## Example .env File

```env
# Database
DATABASE_URL=postgresql://odinforge:password@localhost:5432/odinforge

# OpenAI
OPENAI_API_KEY=sk-your-openai-api-key

# Security
SESSION_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
ADMIN_API_KEY=OdinForgeAdmin2024SecureKey
MTLS_SHARED_SECRET=mTLSSharedSecret2024

# Agent Registration
AGENT_REGISTRATION_TOKEN=OdinForge2024SecureKey

# Environment
NODE_ENV=production
PORT=5000
LOG_LEVEL=info
```

---

## Generating Secrets

Generate secure random secrets:

```bash
# Session secret (64 hex characters)
openssl rand -hex 32

# Admin API key
openssl rand -base64 32

# Agent registration token
openssl rand -base64 24
```

---

## Next Steps

- [Production deployment guide](production.md)
- [Deploy endpoint agents](../agent/INSTALL.md)
