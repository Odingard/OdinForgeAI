# Server Installation Guide

This guide covers installing and running the OdinForge server for development and production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development](#local-development)
- [Docker Installation](#docker-installation)
- [Kubernetes Deployment](#kubernetes-deployment)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Node.js | 20.x LTS | Server runtime |
| PostgreSQL | 14+ | Database |
| Go | 1.21+ | Agent compilation (optional) |

### Required Accounts

- **OpenAI API Key** - Required for AI-powered analysis
- **PostgreSQL Database** - Local or cloud-hosted (Neon, AWS RDS, etc.)

---

## Local Development

### 1. Clone the Repository

```bash
git clone <repository-url>
cd odinforge
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/odinforge

# OpenAI
OPENAI_API_KEY=sk-your-api-key

# Session Security
SESSION_SECRET=your-secure-random-string

# Optional: Admin API Key
ADMIN_API_KEY=your-admin-key
```

See [Configuration Reference](configuration.md) for all available options.

### 4. Initialize Database

Push the schema to your database:

```bash
npm run db:push
```

### 5. Start the Server

```bash
npm run dev
```

The server starts at `http://localhost:5000`.

---

## Docker Installation

### Using Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  odinforge:
    build: .
    ports:
      - "5000:5000"
    environment:
      DATABASE_URL: postgresql://odinforge:password@postgres:5432/odinforge
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      SESSION_SECRET: ${SESSION_SECRET}
      NODE_ENV: production
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: odinforge
      POSTGRES_PASSWORD: password
      POSTGRES_DB: odinforge
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

Start the stack:

```bash
# Set required environment variables
export OPENAI_API_KEY=sk-your-api-key
export SESSION_SECRET=$(openssl rand -hex 32)

# Start services
docker-compose up -d
```

### Building the Docker Image

Create a `Dockerfile`:

```dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

EXPOSE 5000

CMD ["node", "dist/index.js"]
```

Build and run:

```bash
docker build -t odinforge:latest .
docker run -p 5000:5000 \
  -e DATABASE_URL="postgresql://..." \
  -e OPENAI_API_KEY="sk-..." \
  -e SESSION_SECRET="..." \
  odinforge:latest
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Helm 3 (optional)

### Deployment Manifests

**Namespace:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: odinforge
```

**Secrets:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: odinforge-secrets
  namespace: odinforge
type: Opaque
stringData:
  DATABASE_URL: "postgresql://user:password@postgres:5432/odinforge"
  OPENAI_API_KEY: "sk-your-api-key"
  SESSION_SECRET: "your-secure-random-string"
  ADMIN_API_KEY: "your-admin-key"
```

**Deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: odinforge
  namespace: odinforge
spec:
  replicas: 2
  selector:
    matchLabels:
      app: odinforge
  template:
    metadata:
      labels:
        app: odinforge
    spec:
      containers:
        - name: odinforge
          image: odinforge:latest
          ports:
            - containerPort: 5000
          envFrom:
            - secretRef:
                name: odinforge-secrets
          env:
            - name: NODE_ENV
              value: "production"
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "2Gi"
              cpu: "1000m"
          livenessProbe:
            httpGet:
              path: /api/health
              port: 5000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /api/health
              port: 5000
            initialDelaySeconds: 5
            periodSeconds: 5
```

**Service:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: odinforge
  namespace: odinforge
spec:
  selector:
    app: odinforge
  ports:
    - port: 80
      targetPort: 5000
  type: ClusterIP
```

**Ingress (with TLS):**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: odinforge
  namespace: odinforge
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - odinforge.example.com
      secretName: odinforge-tls
  rules:
    - host: odinforge.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: odinforge
                port:
                  number: 80
```

### Apply Manifests

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

### Verify Deployment

```bash
kubectl get pods -n odinforge
kubectl logs -f deployment/odinforge -n odinforge
```

---

## Next Steps

- [Configure environment variables](configuration.md)
- [Set up for production](production.md)
- [Deploy endpoint agents](../agent/INSTALL.md)
