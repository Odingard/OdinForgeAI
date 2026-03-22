# OdinForge-AI — Current Build State (2026-03-22)

## Repo Stats
- **Total commits**: 2,738
- **Branch**: main (up to date with origin)
- **Last deploy**: 2026-03-22 — additive live graph model + security audit fixes
- **Domain**: odinforgeai.com
- **Server**: DigitalOcean 24.199.95.237

## Recent Commits
| Hash | Description |
|------|-------------|
| f2ab3b5 | Add additive live graph model for breach chain visualization |
| 6990ea0 | Add OdinForge brand logos to README, favicon, and app UI |
| 0119f7fd | Fix Container Scan: apk upgrade to patch critical zlib CVE-2026-22184 |
| 8013737 | Fix Container Scan + Dependabot: track STIX data, bump fast-xml-parser |
| 9b9c303 | Fix CI: update circuit-breaker tests to match FAILURE_THRESHOLD=4 |
| efa9505 | Breach chain graph visual overhaul: expand/collapse, live events, subdomain branching |
| fa9b784 | Agent Mesh v1: event-driven 4-agent architecture with TCG orchestration |
| 305ae68 | Add native Anthropic Claude support as primary LLM provider |
| 57cef73 | Managed service operationalization: Engagement Package, evidence traceability, CLI v1 |

## Codebase Scale
| Metric | Value |
|--------|-------|
| Server TypeScript files | 362 |
| API endpoints | ~423 routes (routes.ts: 13,981 lines) |
| Database tables | 75 (PostgreSQL + pgvector) |
| Schema file | 5,782 lines |
| Agent service code | 15,540 lines |
| AEV subsystem | 6,007 lines |
| Validation subsystem | 3,560 lines |
| Docker services (prod) | 9 containers |
| CI/CD workflows | 13+ GitHub Actions |
| Go agent platforms | 5 (linux/darwin/windows × amd64/arm64) |

## Production Stack
```
Cloudflare DNS → Caddy (auto-TLS) → App:5000 + Worker
                                   → PostgreSQL 15 (pgvector)
                                   → Redis 7
                                   → MinIO (S3)
                                   → Prometheus + Grafana
```

## CI/CD Pipeline
Push to main → Tests + Security Scan + Container Scan → Docker build → Push to ghcr.io → SSH deploy to DigitalOcean → Health check
