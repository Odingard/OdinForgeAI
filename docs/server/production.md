# Production Deployment Guide

This guide covers deploying OdinForge to production environments with security hardening, high availability, and monitoring.

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Security Hardening](#security-hardening)
- [Cloud Deployments](#cloud-deployments)
- [High Availability](#high-availability)
- [Monitoring & Observability](#monitoring--observability)
- [Backup & Recovery](#backup--recovery)

---

## Pre-Deployment Checklist

Before deploying to production, ensure:

- [ ] **Secrets configured** - All sensitive values in environment variables or secrets manager
- [ ] **Database secured** - Strong passwords, SSL/TLS enabled, network restrictions
- [ ] **TLS certificates** - Valid certificates for HTTPS
- [ ] **Admin key set** - `ADMIN_API_KEY` configured for API protection
- [ ] **OpenAI API key** - Valid key with appropriate rate limits
- [ ] **Backups configured** - Database backup strategy in place
- [ ] **Monitoring ready** - Health checks and alerting configured

---

## Security Hardening

### TLS Configuration

Always use HTTPS in production. Configure TLS at the reverse proxy level:

**Nginx Example:**

```nginx
server {
    listen 443 ssl http2;
    server_name odinforge.example.com;

    ssl_certificate /etc/letsencrypt/live/odinforge.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/odinforge.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Security Headers

Add security headers in your reverse proxy:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
```

### Network Security

1. **Firewall rules** - Only expose port 443 (HTTPS)
2. **Database isolation** - PostgreSQL should not be publicly accessible
3. **Agent communication** - Use TLS for all agent connections

---

## Cloud Deployments

### AWS Deployment

**Architecture:**
- ECS Fargate or EC2 for compute
- RDS PostgreSQL for database
- ALB for load balancing
- Secrets Manager for credentials

**ECS Task Definition:**

```json
{
  "family": "odinforge",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "odinforge",
      "image": "your-ecr-repo/odinforge:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:odinforge/database"
        },
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:odinforge/openai"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/odinforge",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Azure Deployment

**Architecture:**
- Azure Container Apps or AKS
- Azure Database for PostgreSQL
- Azure Front Door for CDN/WAF
- Key Vault for secrets

**Container App Configuration:**

```yaml
properties:
  configuration:
    ingress:
      external: true
      targetPort: 5000
      transport: auto
    secrets:
      - name: database-url
        value: <from-key-vault>
      - name: openai-api-key
        value: <from-key-vault>
  template:
    containers:
      - name: odinforge
        image: your-acr.azurecr.io/odinforge:latest
        resources:
          cpu: 1
          memory: 2Gi
        env:
          - name: DATABASE_URL
            secretRef: database-url
          - name: OPENAI_API_KEY
            secretRef: openai-api-key
          - name: NODE_ENV
            value: production
```

### Google Cloud Deployment

**Architecture:**
- Cloud Run or GKE
- Cloud SQL for PostgreSQL
- Cloud Load Balancing
- Secret Manager

**Cloud Run Service:**

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: odinforge
spec:
  template:
    spec:
      containers:
        - image: gcr.io/project/odinforge:latest
          ports:
            - containerPort: 5000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: odinforge-secrets
                  key: database-url
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: odinforge-secrets
                  key: openai-api-key
          resources:
            limits:
              memory: 2Gi
              cpu: "1"
```

---

## High Availability

### Multi-Instance Deployment

Run multiple instances behind a load balancer:

```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: odinforge-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: odinforge
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Database High Availability

- **PostgreSQL streaming replication** for read replicas
- **Managed services** (RDS, Cloud SQL, Azure PostgreSQL) for automatic failover
- **Connection pooling** with PgBouncer for connection management

### Session Persistence

Use PostgreSQL session store (already configured) for session persistence across instances.

---

## Monitoring & Observability

### Health Checks

The server exposes health endpoints:

```bash
# Liveness check
GET /api/health

# Readiness check (includes database)
GET /api/ready
```

### Logging

Configure structured logging for production:

```bash
LOG_LEVEL=info
LOG_FORMAT=json
```

Example log aggregation with CloudWatch/Stackdriver/Azure Monitor.

### Metrics

Key metrics to monitor:

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| Request latency | API response time | P95 > 2s |
| Error rate | 5xx responses | > 1% |
| CPU usage | Container CPU | > 80% |
| Memory usage | Container memory | > 85% |
| Database connections | Active connections | > 80% of max |
| AI API latency | OpenAI response time | P95 > 30s |

### Alerting

Set up alerts for:
- Server health check failures
- High error rates
- Resource exhaustion
- Database connectivity issues
- Agent offline events

---

## Backup & Recovery

### Database Backups

**Automated backups:**
- Use managed database backup features (RDS, Cloud SQL)
- Configure point-in-time recovery
- Test restores regularly

**Manual backup:**

```bash
pg_dump -h hostname -U user -d odinforge > backup.sql
```

### Disaster Recovery

1. **RTO (Recovery Time Objective)**: Target < 1 hour
2. **RPO (Recovery Point Objective)**: Target < 15 minutes
3. **Multi-region replication** for critical deployments

### Recovery Procedure

1. Provision new infrastructure
2. Restore database from backup
3. Deploy application
4. Verify functionality
5. Update DNS/load balancer

---

## Performance Tuning

### Node.js Settings

```bash
# Increase memory limit if needed
NODE_OPTIONS="--max-old-space-size=4096"
```

### Database Optimization

```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM evaluations WHERE status = 'completed';

-- Create indexes for common queries
CREATE INDEX idx_evaluations_status ON evaluations(status);
CREATE INDEX idx_agents_status ON agents(status);
```

### Connection Pooling

Use PgBouncer for connection pooling in high-traffic environments.

---

## Next Steps

- [Deploy endpoint agents](../agent/INSTALL.md)
- [API Reference](../api/reference.md)
