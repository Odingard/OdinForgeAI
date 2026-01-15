# OdinForge Agent Helm Chart

Deploy the OdinForge security agent to Kubernetes as a DaemonSet.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+

## Installation

### Quick Install

```bash
helm install odinforge-agent ./helm \
  --namespace odinforge \
  --create-namespace \
  --set odinforge.serverUrl=https://your-odinforge-server.com \
  --set odinforge.apiKey=your-api-key
```

### Using values file

Create a `my-values.yaml`:

```yaml
odinforge:
  serverUrl: https://your-odinforge-server.com
  apiKey: your-api-key
  tenantId: default
```

Install:

```bash
helm install odinforge-agent ./helm \
  --namespace odinforge \
  --create-namespace \
  -f my-values.yaml
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `odinforge.serverUrl` | OdinForge server URL (required) | `""` |
| `odinforge.apiKey` | API key for authentication (required) | `""` |
| `odinforge.tenantId` | Tenant/organization ID | `"default"` |
| `image.repository` | Agent image repository | `ghcr.io/odinforge/agent` |
| `image.tag` | Agent image tag | `latest` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `persistence.enabled` | Enable persistent storage | `true` |
| `persistence.size` | Storage size | `1Gi` |
| `mtls.enabled` | Enable mTLS | `false` |
| `mtls.certSecret` | Secret containing TLS certs | `""` |

## mTLS Configuration

To enable mTLS:

1. Create a secret with your certificates:
```bash
kubectl create secret generic odinforge-certs \
  --from-file=ca.crt=ca.crt \
  --from-file=client.crt=client.crt \
  --from-file=client.key=client.key \
  -n odinforge
```

2. Enable mTLS in values:
```yaml
mtls:
  enabled: true
  certSecret: odinforge-certs
```

## Management

```bash
# Check status
kubectl get daemonset -n odinforge

# View logs
kubectl logs -l app.kubernetes.io/name=odinforge-agent -n odinforge -f

# Upgrade
helm upgrade odinforge-agent ./helm -n odinforge -f my-values.yaml

# Uninstall
helm uninstall odinforge-agent -n odinforge
```
