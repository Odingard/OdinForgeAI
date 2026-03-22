# OdinForge Core V2 — Dependency Freeze

Everything listed below is ALLOWED in core-v2.
Everything NOT listed is non-core by default.

---

## Server Files (Allowed)

### Core Engine (the product loop)
- `server/services/active-exploit-engine.ts` — crawl, payload, validate
- `server/services/breach-orchestrator.ts` — 6-phase sequential chain (mesh path removed)
- `server/services/credential-store.ts` — in-memory credential cache during execution
- `server/lib/real-finding.ts` — RealFinding factory (ADR-001)
- `server/lib/real-evidence.ts` — RealHttpEvidence type + runtime validation
- `server/lib/breach-event-emitter.ts` — typed websocket event emitter
- `server/lib/environment.ts` — env var parsing
- `server/lib/semaphore.ts` — concurrency primitive

### Evidence & Quality
- `server/services/evidence-quality-gate.ts` — PROVEN/CORROBORATED/INFERRED/UNVERIFIABLE
- `server/services/report-integrity-filter.ts` — strips INFERRED/UNVERIFIABLE from customer output

### Engagement Package (sealed deliverable)
- `server/services/engagement/engagement-package.ts` — seal + SHA-256
- `server/services/engagement/ciso-report.ts` — risk grade, narrative
- `server/services/engagement/engineer-report.ts` — chain trace, remediation
- `server/services/engagement/breach-chain-replay.ts` — self-contained HTML
- `server/services/engagement/engagement-api-keys.ts` — per-engagement keys
- `server/services/engagement/reengagement-offer.ts` — 90-day follow-on

### Reports
- `server/services/report-generator.ts` — legacy report generation

### Chain Support (used by orchestrator post-loop)
- `server/services/defenders-mirror.ts` — Sigma rule generation
- `server/services/reachability-chain.ts` — pivot depth tracking
- `server/services/replay-recorder.ts` — replay manifest
- `server/services/metrics.ts` — Prometheus engagement metrics
- `server/services/cvss-parser.ts` — CVSS vector parsing

### Auth & Infra
- `server/services/ui-auth.ts` — JWT auth, permissions, roles
- `server/services/rate-limiter.ts` — rate limiters
- `server/services/websocket.ts` — WebSocket service
- `server/services/ws-bridge.ts` — WebSocket bridge
- `server/services/logger.ts` — structured logging
- `server/services/audit-logger.ts` — audit trail
- `server/services/rls-setup.ts` — row-level security
- `server/services/runtime-guard.ts` — sandbox enforcement

### Governance (breach chain creation checks this)
- `server/services/governance-enforcement.ts` (or `server/services/governance/`) — canStartOperation check

### Validation (execution mode checks)
- `server/services/validation/execution-modes.ts` — safe/simulation/live logic

### AI Agents (Phase 1C fallback — the LLM orchestrator)
- `server/services/agents/orchestrator.ts` — main agent pipeline
- `server/services/agents/exploit.ts` — exploit agent
- `server/services/agents/exploit-tools.ts` — 40+ exploit tools
- `server/services/agents/openai-client.ts` — LLM client factory
- `server/services/agents/anthropic-adapter.ts` — Claude adapter
- `server/services/agents/model-router.ts` — model routing
- `server/services/agents/scoring-engine.ts` — deterministic scoring v3.0
- `server/services/agents/circuit-breaker.ts` — timeout/fallback
- `server/services/agents/heartbeat-tracker.ts` — LLM call monitoring
- `server/services/agents/evidence-collector.ts` — evidence aggregation
- `server/services/agents/graph-synthesizer.ts` — attack graph construction
- `server/services/agents/synthesizer.ts` — result synthesis
- `server/services/agents/noise-reduction.ts` — false positive filter
- `server/services/agents/debate-module.ts` — critic-defender debate
- `server/services/agents/critic.ts` — finding critique
- `server/services/agents/defender.ts` — finding defense
- `server/services/agents/error-classifier.ts` — error categorization
- `server/services/agents/index.ts` — barrel export
- `server/services/agents/types.ts` — shared types

### AEV Subsystem (credential bus used by Phase 2)
- `server/services/aev/credential-bus.ts` — credential passing between phases
- `server/services/aev/agent-event-bus.ts` — event bus (used by emitter)

### Threat Intel (used by scoring engine)
- `server/services/threat-intel/` — EPSS + KEV data (scoring depends on this)

### Queue (if chain execution goes through job queue)
- `server/services/queue/queue-service.ts` — job queue
- `server/services/queue/redis-connection.ts` — Redis connection
- `server/services/queue/job-types.ts` — job type definitions
- `server/services/queue/handlers/evaluation-handler.ts` — evaluation job handler
- `server/services/queue/handlers/report-generation-handler.ts` — report job handler

### Storage & DB
- `server/storage.ts` — database abstraction (trim methods to core only)
- `server/db.ts` — Drizzle ORM connection
- `shared/schema.ts` — keep all table definitions (mark inactive ones)
- `server/feature-flags.ts` — runtime feature flags

### Entry Point
- `server/index.ts` — server startup (strip non-core init)

---

## Routes (Allowed — 4 paths only)

### Auth Path
- `POST /ui/api/auth/login`
- `POST /ui/api/auth/signup`
- `POST /ui/api/auth/refresh`
- `POST /ui/api/auth/logout`
- `GET /ui/api/auth/session`
- `HEAD /ui/api/auth/bootstrap`

### Scan Path
- `POST /api/breach-chains` — create + start chain
- `GET /api/breach-chains` — list chains
- `GET /api/breach-chains/:id` — get chain detail
- `DELETE /api/breach-chains/:id` — delete chain
- `POST /api/breach-chains/:id/resume` — resume chain
- `POST /api/breach-chains/:id/abort` — abort chain

### Report/Package Path
- `POST /api/breach-chains/:id/seal` — seal engagement package
- `GET /api/breach-chains/:id/package` — download sealed package
- `POST /api/breach-chains/:id/api-key` — create engagement API key
- `GET /api/breach-chains/:id/api-keys` — list engagement API keys
- `GET /api/breach-chains/:id/replay` — get replay manifest
- `GET /api/breach-chains/:id/defenders-mirror` — get detection rules
- `GET /api/breach-chains/:id/evidence-quality` — get quality summary
- `GET /api/breach-chains/:id/reachability` — get reachability chain
- `POST /api/reports/generate` — generate report from chain
- `GET /api/reports` — list reports
- `GET /api/reports/:id` — get report
- `GET /api/reports/:id/download` — download report

### Health/Debug Path
- `GET /healthz` — liveness
- `GET /readyz` — readiness
- `GET /metrics` — Prometheus
- `GET /api/flags` — feature flags
- `GET /api/mode` — AEV mode info
- `GET /api/aev/stats` — evaluation stats

### Governance (minimal — needed by chain creation)
- `GET /api/governance/:orgId` — get governance config
- `GET /api/aev/execution-modes` — get current execution mode

---

## Frontend Files (Allowed)

### Pages
- `client/src/pages/BreachChains.tsx` — core page
- `client/src/pages/Reports.tsx` — report viewing
- `client/src/pages/Login.tsx` — auth
- `client/src/pages/Signup.tsx` — auth
- `client/src/pages/Settings.tsx` — settings (strip billing/infra tabs)
- `client/src/pages/not-found.tsx` — 404

### Components (core)
- `client/src/components/LiveBreachChainGraph.tsx` — live breach visualization
- `client/src/components/BreachChainExport.tsx` — package download
- `client/src/components/EvidencePanel.tsx` — evidence display
- `client/src/components/ProgressModal.tsx` — chain progress
- `client/src/components/Header.tsx` — layout
- `client/src/components/AppSidebar.tsx` — navigation (simplify to 3 items)
- `client/src/components/Dashboard.tsx` — minimal dashboard
- `client/src/components/OdinForgeLogo.tsx` — branding
- `client/src/components/ThemeProvider.tsx` — theme
- `client/src/components/ViewModeToggle.tsx` — view toggle
- `client/src/components/DemoDataBanner.tsx` — banner
- `client/src/components/TrialBanner.tsx` — banner
- `client/src/components/ui/*` — all shadcn primitives (keep)
- `client/src/components/shared/*` — DataTable, MetricsGrid, etc. (keep)
- `client/src/components/dashboard/*` — minimal (keep)

### Hooks
- `client/src/hooks/useBreachChainUpdates.ts`
- `client/src/hooks/useWebSocket.ts`
- `client/src/hooks/use-toast.ts`
- `client/src/hooks/use-mobile.tsx`

### Contexts
- `client/src/contexts/UIAuthContext.tsx`
- `client/src/contexts/AuthContext.tsx`
- `client/src/contexts/ViewModeContext.tsx`

### Lib
- `client/src/lib/queryClient.ts`
- `client/src/lib/utils.ts`
- `client/src/lib/breach-events.ts`
- `client/src/lib/uiAuth.ts`

### App Shell
- `client/src/App.tsx` — router (strip to 5 pages)
- `client/src/main.tsx` — React root

---

## CI Workflows (Allowed)
- `.github/workflows/ci.yml` — tests + build (remove Go job)
- `.github/workflows/deploy.yml` — deploy to production
- `.github/workflows/container-scan.yml` — Trivy scan
- `.github/workflows/secret-scan.yml` — Gitleaks
- `.github/workflows/codeql.yml` — CodeQL analysis
- `.github/workflows/deps-node.yml` — npm audit

---

## Config Files (Allowed)
- `package.json`
- `tsconfig.json`
- `vite.config.ts`
- `vitest.config.ts`
- `drizzle.config.ts`
- `Dockerfile`
- `docker-compose.yml`
- `docker-compose.prod.yml`
- `Caddyfile`
- `.env.example`
- `.env.production.example`
- `tailwind.config.ts`
- `postcss.config.js`
- `migrations/` — all migration files (don't touch)
- `cli/odinforge.ts` — CLI tool

---

## Explicitly NOT Allowed (non-core)
- `odinforge-agent/` — Go agent (entire directory)
- `server/services/billingService.ts`
- `server/services/siem-integration/`
- `server/services/compliance/`
- `server/services/scheduler/`
- `server/services/session-replay/`
- `server/services/container-security/`
- `server/services/lateral-movement/`
- `server/services/rag/`
- `server/services/api-fuzzer/`
- `server/services/business-logic/`
- `server/services/cloud/`
- `server/services/cloud-pentest/`
- `server/services/recon/`
- `server/services/endpoint/`
- `server/services/auth-testing/`
- `server/services/continuous-validation/`
- `server/services/remediation/`
- `server/services/import-parsers.ts`
- `server/services/auto-deploy-orchestrator.ts`
- `server/services/demo-data.ts`
- `server/services/agent-builder.ts`
- `server/services/agent-cleanup.ts`
- `server/services/agent-management.ts`
- `server/services/ssh-deployment.ts`
- `server/services/external-recon.ts`
- `server/services/web-app-recon.ts`
- `server/services/live-network-testing.ts`
- `server/services/parallel-agent-dispatcher.ts`
- `server/services/data-reconciliation.ts`
- `server/services/telemetry-analyzer.ts`
- `server/services/telemetry-trends.ts`
- `server/services/coverage-calculator.ts`
- `server/services/intelligence-client.ts`
- `server/services/kill-chain-graph.ts`
- `server/services/secrets.ts`
- `server/services/openapi-parser.ts`
- `server/services/unified-auth.ts`
- `server/services/mtls-auth.ts`
- `server/services/jwt-auth.ts`
- `server/services/report-logic.ts`
- `server/services/report-signer.ts`
- `server/services/evidence-uploader.ts`
- `server/services/app-logic-analyzer.ts`
- `server/services/evaluation-differ.ts`
- `server/services/full-assessment.ts`
- `server/services/metrics-calculator.ts`
- `server/services/sarif-exporter.ts`
- `server/services/aev/agent-mesh-orchestrator.ts`
- `server/services/aev/micro-agent-orchestrator.ts`
- `server/services/aev/agents/` (mesh agents)
- `server/services/aev/attack-engine.ts`
- `server/services/aev/chain-orchestrator.ts`
- `server/services/aev/sub-agent-manager.ts`
- `server/services/aev/task-coordination-graph.ts`
- `server/services/aev/pivot-queue.ts`
- `server/services/aev/runtime-context-broker.ts`
- `server/services/aev/business-logic/`
- `server/services/aev/credential-attacks/`
- `server/services/aev/lateral-movement/`
- `server/services/aev/post-exploitation/`
- `server/services/aev/playbooks/`
- `server/services/agents/ai-simulation.ts`
- `server/services/agents/adversary-profile.ts`
- `server/services/agents/policy-context.ts`
- `server/services/agents/policy-guardian.ts`
- `server/services/agents/recon.ts`
- `server/services/agents/lateral.ts`
- `server/services/agents/impact.ts`
- `server/services/agents/multi-vector.ts`
- `server/services/agents/business-logic.ts`
- `server/services/agents/business-logic-tools.ts`
- `server/services/agents/cloud-security-tools.ts`
- `server/services/agents/scan-data-loader.ts`
- `server/services/agents/plan.ts`
- `server/services/agents/remediation-engine.ts`
- `server/benchmark/xbow/`
- All non-core CI workflows
- All non-core frontend pages and components
