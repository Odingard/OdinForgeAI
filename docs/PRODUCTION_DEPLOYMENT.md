# 🚀 Production Deployment Guide

Complete guide for deploying OdinForge-AI to production environments.

---

## 📋 Pre-Deployment Checklist

### Code Quality
- [ ] All security vulnerabilities resolved (`npm audit`)
- [ ] TypeScript compilation successful (`npm run check`)
- [ ] Build completes without errors (`npm run build`)
- [ ] All critical features tested ([TESTING_CHECKLIST.md](./TESTING_CHECKLIST.md))
- [ ] Code committed and pushed to main branch

### Infrastructure
- [ ] PostgreSQL database provisioned (15+)
- [ ] Redis instance running (7+)
- [ ] Server/VM provisioned (4GB+ RAM, 2+ CPU cores)
- [ ] SSL certificate obtained for HTTPS
- [ ] DNS configured
- [ ] Firewall rules configured

### Environment Variables
- [ ] All secrets configured in production environment
- [ ] Database credentials secured
- [ ] API tokens configured (GitHub, GitLab if using PR automation)
- [ ] Session secret generated
- [ ] CORS origins configured

---

## 🔧 Environment Configuration

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@host:5432/odinforge
DATABASE_SSL=true  # Enable for production

# Redis (for job queue)
REDIS_URL=redis://user:password@host:6379
REDIS_TLS=true  # Enable for production

# Application
NODE_ENV=production
PORT=5000
HOST=0.0.0.0

# Security
SESSION_SECRET=<generate-strong-random-secret-256-bits>
COOKIE_SECURE=true  # Require HTTPS
COOKIE_SAME_SITE=strict

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# WebSocket
WS_PATH=/ws
WS_HEARTBEAT_INTERVAL=30000

# AI/LLM (if applicable)
OPENAI_API_KEY=<your-api-key>
ANTHROPIC_API_KEY=<your-api-key>

# Cloud Provider Credentials (if using)
AWS_ACCESS_KEY_ID=<your-key>
AWS_SECRET_ACCESS_KEY=<your-secret>
AWS_REGION=us-east-1

AZURE_CLIENT_ID=<your-client-id>
AZURE_CLIENT_SECRET=<your-secret>
AZURE_TENANT_ID=<your-tenant>

GCP_PROJECT_ID=<your-project>
GCP_CREDENTIALS_PATH=/path/to/service-account.json

# Git Integration (Optional - for PR automation)
# Users will configure their own tokens via UI
# These are fallback/default settings
DEFAULT_GIT_PROVIDER=github  # or gitlab
```

### Generate Secure Secrets

```bash
# Generate SESSION_SECRET (256-bit)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Generate API keys
openssl rand -base64 32
```

---

## 🐳 Docker Deployment

### Dockerfile

```dockerfile
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:5000/health', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Start application
CMD ["node", "dist/index.cjs"]
```

### docker-compose.yml

```yaml
version: '3.9'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/odinforge
      - REDIS_URL=redis://redis:6379
      - SESSION_SECRET=${SESSION_SECRET}
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - odinforge

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=odinforge
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - odinforge

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - odinforge

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - odinforge

volumes:
  postgres_data:
  redis_data:

networks:
  odinforge:
    driver: bridge
```

### Build and Deploy

```bash
# Build Docker image
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f app

# Run database migrations
docker-compose exec app npm run db:push

# Health check
curl http://localhost:5000/health
```

---

## ☁️ Cloud Platform Deployment

### AWS (Elastic Beanstalk)

```bash
# Install EB CLI
pip install awsebcli

# Initialize Elastic Beanstalk
eb init -p node.js-20 odinforge-ai

# Create environment
eb create odinforge-production \
  --instance-type t3.medium \
  --database.engine postgres \
  --database.version 15 \
  --envvars DATABASE_URL=$DB_URL,SESSION_SECRET=$SECRET

# Deploy
eb deploy

# View logs
eb logs

# SSH into instance
eb ssh
```

### Azure (App Service)

```bash
# Install Azure CLI
brew install azure-cli  # or download from Microsoft

# Login
az login

# Create resource group
az group create --name odinforge-rg --location eastus

# Create PostgreSQL server
az postgres flexible-server create \
  --resource-group odinforge-rg \
  --name odinforge-db \
  --location eastus \
  --admin-user dbadmin \
  --admin-password <strong-password> \
  --sku-name Standard_B1ms

# Create Redis cache
az redis create \
  --resource-group odinforge-rg \
  --name odinforge-redis \
  --location eastus \
  --sku Basic \
  --vm-size c0

# Create App Service
az webapp create \
  --resource-group odinforge-rg \
  --plan odinforge-plan \
  --name odinforge-app \
  --runtime "NODE:20-lts"

# Configure environment variables
az webapp config appsettings set \
  --resource-group odinforge-rg \
  --name odinforge-app \
  --settings DATABASE_URL=$DB_URL SESSION_SECRET=$SECRET

# Deploy code
az webapp deploy \
  --resource-group odinforge-rg \
  --name odinforge-app \
  --src-path ./dist.zip
```

### Google Cloud (App Engine)

```yaml
# app.yaml
runtime: nodejs20
instance_class: F2

env_variables:
  NODE_ENV: 'production'
  SESSION_SECRET: '<your-secret>'

automatic_scaling:
  target_cpu_utilization: 0.65
  min_instances: 1
  max_instances: 10
```

```bash
# Deploy
gcloud app deploy app.yaml

# View logs
gcloud app logs tail -s default

# Open in browser
gcloud app browse
```

---

## 🌐 Nginx Configuration

### nginx.conf

```nginx
upstream odinforge {
    server localhost:5000;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL certificates
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Proxy settings
    location / {
        proxy_pass http://odinforge;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://odinforge;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }

    # Static files (if serving from nginx)
    location /static/ {
        alias /var/www/odinforge/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /health {
        proxy_pass http://odinforge;
        access_log off;
    }
}
```

---

## 📊 Monitoring & Observability

### Health Check Endpoint

Add to `server/index.ts`:

```typescript
// Health check endpoint
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'connected',  // Check actual DB connection
    redis: 'connected',     // Check actual Redis connection
  };
  res.status(200).json(health);
});
```

### Application Monitoring

**Option 1: PM2 (Process Manager)**

```bash
# Install PM2
npm install -g pm2

# Start application
pm2 start dist/index.cjs --name odinforge-ai

# Monitor
pm2 monit

# View logs
pm2 logs odinforge-ai

# Auto-restart on crash
pm2 startup
pm2 save
```

**Option 2: DataDog**

```bash
# Install DataDog agent
npm install dd-trace

# Add to server/index.ts
import tracer from 'dd-trace';
tracer.init({ service: 'odinforge-ai' });
```

**Option 3: New Relic**

```bash
# Install New Relic
npm install newrelic

# Add newrelic.js config
# Require at top of server/index.ts
require('newrelic');
```

### Logging

**Structured Logging with Winston:**

```bash
npm install winston
```

```typescript
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'odinforge-ai' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}
```

---

## 🔐 Security Hardening

### Application Security

1. **Environment Variables**
   - Never commit secrets to Git
   - Use secret management (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
   - Rotate secrets regularly

2. **HTTPS Only**
   - Enforce HTTPS in production
   - Use HSTS headers
   - Obtain SSL certificate (Let's Encrypt, Cloudflare)

3. **CORS Configuration**
   ```typescript
   app.use(cors({
     origin: process.env.ALLOWED_ORIGINS?.split(',') || [],
     credentials: true,
   }));
   ```

4. **Rate Limiting**
   ```typescript
   import rateLimit from 'express-rate-limit';

   const limiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutes
     max: 100, // limit each IP to 100 requests per windowMs
   });

   app.use('/api/', limiter);
   ```

5. **Helmet for Security Headers**
   ```bash
   npm install helmet
   ```
   ```typescript
   import helmet from 'helmet';
   app.use(helmet());
   ```

### Database Security

1. **Connection Pooling**
   - Configure max connections
   - Set connection timeout
   - Use SSL/TLS for database connections

2. **Backups**
   - Automated daily backups
   - Point-in-time recovery enabled
   - Test restore procedures regularly

3. **Access Control**
   - Restrict database access to application servers only
   - Use read replicas for reporting queries
   - Implement least-privilege access

---

## 🔄 CI/CD Pipeline

### GitHub Actions

See [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)

### GitLab CI

```.yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

test:
  stage: test
  image: node:20
  services:
    - postgres:15
    - redis:7
  script:
    - npm ci
    - npm run check || true
    - npm audit
  only:
    - main
    - merge_requests

build:
  stage: build
  image: node:20
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
  only:
    - main

deploy_production:
  stage: deploy
  image: alpine:latest
  script:
    - apk add --no-cache openssh-client
    - eval $(ssh-agent -s)
    - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
    - ssh-keyscan -H $DEPLOY_SERVER >> ~/.ssh/known_hosts
    - scp -r dist/ $DEPLOY_USER@$DEPLOY_SERVER:/var/www/odinforge/
    - ssh $DEPLOY_USER@$DEPLOY_SERVER "pm2 restart odinforge-ai"
  only:
    - main
  when: manual
```

---

## 📈 Scaling Strategies

### Horizontal Scaling

**Load Balancer Configuration:**

```nginx
upstream odinforge_cluster {
    least_conn;
    server app1.example.com:5000;
    server app2.example.com:5000;
    server app3.example.com:5000;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    location / {
        proxy_pass http://odinforge_cluster;
        # ... other proxy settings
    }
}
```

**Session Management:**
- Use Redis for session storage (already configured)
- Enable sticky sessions if needed
- Ensure WebSocket affinity

### Database Scaling

1. **Read Replicas**
   - Route read queries to replicas
   - Keep writes on primary

2. **Connection Pooling**
   ```typescript
   const pool = new Pool({
     max: 20,
     min: 5,
     idleTimeoutMillis: 30000,
   });
   ```

3. **Query Optimization**
   - Add indexes on frequently queried columns
   - Use prepared statements
   - Implement caching layer

### Redis Scaling

1. **Redis Cluster**
   - Multiple Redis nodes
   - Automatic sharding

2. **Redis Sentinel**
   - High availability
   - Automatic failover

---

## 🔧 Maintenance

### Regular Tasks

**Daily:**
- Monitor error logs
- Check application health
- Review WebSocket connections

**Weekly:**
- Review security alerts (Dependabot)
- Check disk space usage
- Analyze performance metrics

**Monthly:**
- Update dependencies (`npm update`)
- Review and rotate secrets
- Test backup restore procedures
- Audit user access and permissions

### Database Maintenance

```sql
-- Vacuum and analyze tables
VACUUM ANALYZE;

-- Check table sizes
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check index usage
SELECT
  schemaname,
  tablename,
  indexname,
  idx_scan,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan;
```

---

## 🆘 Troubleshooting

### Common Issues

**Issue: Application won't start**
```bash
# Check logs
pm2 logs odinforge-ai

# Check environment variables
printenv | grep DATABASE_URL

# Test database connection
psql $DATABASE_URL -c "SELECT 1"
```

**Issue: WebSocket connections failing**
- Check nginx WebSocket configuration
- Verify firewall allows WebSocket protocol
- Check for proxy timeout settings

**Issue: High memory usage**
- Check for memory leaks with `node --inspect`
- Review connection pool sizes
- Analyze slow queries

**Issue: Slow queries**
```sql
-- Enable query logging
ALTER SYSTEM SET log_min_duration_statement = 1000;
SELECT pg_reload_conf();

-- View slow queries
SELECT * FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

---

## 📞 Support

- **Documentation**: [docs/](./README.md)
- **Issues**: [GitHub Issues](https://github.com/Odingard/OdinForgeAI/issues)
- **Security**: Report vulnerabilities to security@odinforge.ai

---

*Last Updated: February 7, 2026*
*Version: 1.1.0*
