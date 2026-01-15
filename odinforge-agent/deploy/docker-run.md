# OdinForge Agent - Docker Deployment

Run the OdinForge agent as a Docker container for standalone hosts or container environments.

## Quick Start

```bash
docker run -d \
  --name odinforge-agent \
  --restart unless-stopped \
  -e ODINFORGE_SERVER_URL=https://your-odinforge-server.com \
  -e ODINFORGE_API_KEY=your-api-key \
  -e ODINFORGE_TENANT_ID=default \
  -v odinforge-data:/var/lib/odinforge-agent \
  ghcr.io/odinforge/agent:latest
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ODINFORGE_SERVER_URL` | Yes | URL of your OdinForge server |
| `ODINFORGE_API_KEY` | Yes | API key for agent authentication |
| `ODINFORGE_TENANT_ID` | No | Tenant/organization ID (default: `default`) |

## Volume Mounts

| Mount | Purpose |
|-------|---------|
| `/var/lib/odinforge-agent` | Persistent queue and state data |

## Advanced Options

### Host Network Mode (for full network visibility)

```bash
docker run -d \
  --name odinforge-agent \
  --restart unless-stopped \
  --network host \
  -e ODINFORGE_SERVER_URL=https://your-odinforge-server.com \
  -e ODINFORGE_API_KEY=your-api-key \
  -v odinforge-data:/var/lib/odinforge-agent \
  ghcr.io/odinforge/agent:latest
```

### With mTLS Certificate

```bash
docker run -d \
  --name odinforge-agent \
  --restart unless-stopped \
  -e ODINFORGE_SERVER_URL=https://your-odinforge-server.com \
  -e ODINFORGE_API_KEY=your-api-key \
  -e ODINFORGE_MTLS_ENABLED=true \
  -v odinforge-data:/var/lib/odinforge-agent \
  -v /path/to/certs:/etc/odinforge/certs:ro \
  ghcr.io/odinforge/agent:latest
```

## Management Commands

```bash
# View logs
docker logs -f odinforge-agent

# Check status
docker ps -f name=odinforge-agent

# Stop agent
docker stop odinforge-agent

# Remove agent
docker rm -f odinforge-agent
docker volume rm odinforge-data
```

## Docker Compose

For easier management, use Docker Compose:

```yaml
# docker-compose.yaml
version: '3.8'

services:
  odinforge-agent:
    image: ghcr.io/odinforge/agent:latest
    container_name: odinforge-agent
    restart: unless-stopped
    environment:
      - ODINFORGE_SERVER_URL=https://your-odinforge-server.com
      - ODINFORGE_API_KEY=your-api-key
      - ODINFORGE_TENANT_ID=default
    volumes:
      - odinforge-data:/var/lib/odinforge-agent

volumes:
  odinforge-data:
```

Run with:
```bash
docker-compose up -d
```
