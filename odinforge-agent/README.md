# OdinForge Agent (Go)

A lightweight, cross-platform telemetry agent that collects system metrics and sends them to the OdinForge API.

## Features

- **System Metrics**: CPU, memory, and disk usage collection
- **Durable Queue**: BoltDB-backed queue for offline resilience
- **Secure Transport**: HTTPS with optional mTLS and SPKI pinning
- **Flexible Config**: YAML file + environment variable override
- **Graceful Shutdown**: Proper signal handling (SIGINT, SIGTERM)
- **Batch Delivery**: Gzip-compressed batch uploads with retry logic

## Run Locally

```bash
export ODINFORGE_SERVER_URL="https://your-odinforge-api"
export ODINFORGE_TENANT_ID="org_123"
export ODINFORGE_AUTH_MODE="api_key"
export ODINFORGE_API_KEY="odin_..."
go run ./cmd/agent
```

## Build

```bash
go build -o odinforge-agent ./cmd/agent
```

## Docker

```bash
docker build -t odinforge-agent .
docker run -e ODINFORGE_SERVER_URL="https://api.example.com" \
           -e ODINFORGE_TENANT_ID="org_123" \
           -e ODINFORGE_API_KEY="odin_..." \
           odinforge-agent
```

## Configuration

Configuration is loaded in order (each layer overrides the previous):
1. Built-in defaults
2. YAML config file (optional, via `--config` flag)
3. Environment variables

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ODINFORGE_SERVER_URL` | API server URL | `http://localhost:8080` |
| `ODINFORGE_TENANT_ID` | Tenant identifier | `default` |
| `ODINFORGE_AUTH_MODE` | Auth mode: `api_key` or `mtls` | `api_key` |
| `ODINFORGE_API_KEY` | API key for authentication | |
| `ODINFORGE_VERIFY_TLS` | Enable TLS verification | `true` |
| `ODINFORGE_PINNED_SPKI` | Base64-encoded SPKI pin | |
| `ODINFORGE_MTLS_CERT` | Path to mTLS client certificate | |
| `ODINFORGE_MTLS_KEY` | Path to mTLS client key | |
| `ODINFORGE_CA_CERT` | Path to custom CA certificate | |
| `ODINFORGE_TELEMETRY_INTERVAL` | Telemetry collection interval | `300s` |
| `ODINFORGE_HEARTBEAT_INTERVAL` | Heartbeat interval | `60s` |
| `ODINFORGE_QUEUE_PATH` | BoltDB queue file path | `./odinforge-agent.queue.db` |
| `ODINFORGE_BATCH_SIZE` | Events per batch | `50` |
| `ODINFORGE_TIMEOUT` | HTTP request timeout | `15s` |
| `ODINFORGE_COMPRESS` | Enable gzip compression | `true` |
| `ODINFORGE_REQUIRE_HTTPS` | Require HTTPS (except localhost) | `true` |

### YAML Config Example

```yaml
server:
  url: "https://api.odinforge.com"
  verify_tls: true
  pinned_spki: ""

auth:
  tenant_id: "org_123"
  mode: "api_key"
  api_key: "odin_..."

collection:
  telemetry_interval: 5m
  heartbeat_interval: 1m

buffer:
  path: "/var/lib/odinforge/agent.queue.db"
  max_events: 50000

transport:
  timeout: 15s
  batch_size: 50
  compress: true

safety:
  require_https: true
```

## Deployment

### Linux (systemd)

```bash
sudo cp odinforge-agent /usr/local/bin/
sudo cp deployments/systemd/odinforge-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odinforge-agent
```

### macOS (launchd)

```bash
sudo cp odinforge-agent /usr/local/bin/
sudo cp deployments/launchd/com.odinforge.agent.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.odinforge.agent.plist
```

## One-Time Run

For testing or CI pipelines:

```bash
./odinforge-agent --once
```

## Project Structure

```
odinforge-agent/
├── cmd/agent/main.go           # Entry point
├── internal/
│   ├── config/config.go        # Configuration loading
│   ├── collector/
│   │   ├── collector.go        # Event collection
│   │   ├── system.go           # System info
│   │   └── metrics.go          # CPU/mem/disk metrics
│   ├── queue/queue.go          # BoltDB durable queue
│   ├── sender/
│   │   ├── sender.go           # HTTP batch sender
│   │   └── tls.go              # TLS/mTLS configuration
│   └── util/util.go            # Utilities
├── deployments/
│   ├── systemd/                # Linux service
│   └── launchd/                # macOS service
├── Dockerfile
└── README.md
```
