# AI Coding Instructions for OdinForge

## Project Overview
**OdinForge** is an automated exploit validation platform that scans infrastructure, proves vulnerabilities are exploitable, and chains them into breach paths with HTTP evidence. It's a 7-phase agentic pipeline combining recon, exploitation, lateral movement, business logic analysis, multi-vector detection, impact scoring, and breach chaining.

**Tech Stack:** Express.js + React (TypeScript), PostgreSQL + pgvector, Redis, BullMQ, WebSockets, Stripe billing, Drizzle ORM, Zod validation.

---

## Architecture

### Core Pipeline (7 Phases)
1. **Recon Agent** — 8 scanning modules feed into evidence
2. **Exploit Agent** — Agentic loop (≤12 turns) validates SQLi, XSS, SSRF, auth bypass, path traversal, command injection
3. **Business Logic Agent** — Tests IDOR, race conditions, workflow bypass
4. **Lateral Agent** — Privilege escalation, token reuse, pivot paths
5. **Multi-Vector Agent** — Cloud (AWS/Azure/GCP), Kubernetes, SaaS, shadow admin detection
6. **Impact Agent** — Data exposure, financial/compliance impact, reputation risk
7. **Breach Chain Orchestrator** — Chains individual findings into multi-phase attack paths

**Key File:** [server/services/agents/orchestrator.ts](server/services/agents/orchestrator.ts#L1) — Pipeline timeout is 180s, phases update DB in real-time.

### Service Architecture
- **Routes:** [server/routes.ts](server/routes.ts#L1) (12,700+ lines) — All HTTP endpoints, auth, evaluation lifecycle
- **Database:** [shared/schema.ts](shared/schema.ts#L1) (5500+ lines) — 9-role RBAC, pgvector embeddings, 40+ tables
- **Job Queue:** BullMQ with 17 job types ([server/services/queue/handlers](server/services/queue/handlers)) — Async evaluation, scan scheduling
- **Agents Pkg:** [server/services/agents/](server/services/agents/) (33 files) — Core AI orchestration, debate module, noise reduction
- **Data Layer:** Drizzle ORM + PostgreSQL row-level security (RLS)

### Multi-Tenancy & Auth
- **3 auth layers:** JWT (user sessions), mTLS (agent certificates), OAuth (cloud APIs)
- **RBAC:** Platform super admin → 5 organization roles (owner, security_admin, engineer, analyst, executive_viewer) + 2 specialized (compliance_officer, automation_account)
- **Execution modes:** "safe" (no damage), "simulation", "live" (approval required)
- **Tenant isolation:** [middleware/tenant.ts](server/middleware/tenant.ts) enforces org_id in all queries

---

## Developer Workflows

### Setup
```bash
npm install
cp .env.example .env  # Set DATABASE_URL, OPENAI_API_KEY, JWT_SECRET, STRIPE_KEY
docker-compose up -d  # PostgreSQL + Redis
npm run db:push      # Drizzle migrations
npm run dev          # Start server (port 5000) + Vite dev client (port 5173)
```

### Build & Deploy
- **Build:** `npm run build` — Client (Vite → dist/public), Server (esbuild → dist/index.cjs)
- **Production:** `NODE_ENV=production node dist/index.cjs`
- **Type check:** `npm run check` (tsc, no emit)
- **Security lint:** `npm run lint:security` (eslint + security plugin, warn on `detect-object-injection`)

### Testing
- **Unit/Integration:** Vitest ([vitest.config.ts](vitest.config.ts)) — Setup at [client/tests/setup.ts](client/tests/setup.ts)
- **Run:** `vitest` watches client/tests/**/*.test.{ts,tsx}
- **No backend tests yet** — Focus on client components and integration

### Database Workflow
- **Migrations:** [migrations/](migrations/) folder (SQL files), applied via `npm run db:push`
- **Optimization:** `npm run db:optimize` — Applies [db-optimizations.sql](server/db-optimizations.sql)
- **Schema-first:** Edit [shared/schema.ts](shared/schema.ts), Drizzle generates queries

### Debugging
- **Logs:** Server logs go to stdout; check BullMQ job queue UI at `http://localhost:3000/jobs` (if enabled)
- **Telemetry:** Every LLM turn + tool call logged in `aev_llm_turns` + `aev_tool_calls` tables
- **WebSocket:** Real-time attack graph updates via [wsService](server/services/websocket.ts)

---

## Code Patterns & Conventions

### Agent Orchestration
**Type-safe agent context & results:**
```typescript
// agents/types.ts — Standard interface for all phase agents
export interface AgentContext {
  assetId: string;
  exposureType: string;
  evaluationId: string;
  adversaryProfile?: AdversaryProfile;
  executionMode: "safe" | "simulation" | "live";
  realScanData?: RealScanData; // Injected ground-truth from handlers
}

// All agents return AgentResult<T> with evidence trails
export interface AgentResult<T> {
  result: T;
  toolCalls: ToolCall[];
  confidence: number;
  evidenceArtifacts?: EvidenceArtifact[];
}
```

**Conditional phase execution:** Agents check `shouldRunPhase()` to skip if no input. See [orchestrator.ts L1000+](server/services/agents/orchestrator.ts#L1000) for phase gating.

### Database Access Pattern
```typescript
import { db } from "./db";
import { aevEvaluations, aevFindings } from "@shared/schema";
import { eq, and } from "drizzle-orm";

// Always include org_id filter (RLS) + tenant middleware
const result = await db.query.aevEvaluations.findFirst({
  where: and(eq(aevEvaluations.id, evalId), eq(aevEvaluations.org_id, orgId)),
});
```

### Route Authentication Pattern
```typescript
// Require role + permission
router.post("/api/evaluations", requireRole("security_admin"), requirePermission("evaluations:create"), async (req, res) => {
  const orgId = getOrganizationId(req);
  // Proceed with DB query including org_id filter
});
```

### WebSocket Progress Updates
```typescript
// Agents call progress callback to stream findings in real-time
progressCallback?.({
  phase: "exploit",
  status: "in_progress",
  currentTurn: 5,
  findings: exploitFindings,
  timestamp: Date.now(),
});

// Backend broadcasts via wsService.broadcastToEvaluation(evalId, message)
```

### Deterministic Scoring (No LLM)
[scoring-engine.ts](server/services/agents/scoring-engine.ts) — EPSS (45%) + CVSS (35%) + agent confidence (20%). **Never** let LLM choose severity; formula is deterministic.

---

## Key Files by Task

| Task | Files |
|------|-------|
| Add endpoint | [server/routes.ts](server/routes.ts) — Find relevant section (e.g., "/api/evaluations"), add middleware + handler |
| New DB table | [shared/schema.ts](shared/schema.ts) — Define table, run `npm run db:push` to auto-generate migration |
| Auth/permissions | [shared/schema.ts](shared/schema.ts) (roles/permissions), [server/services/ui-auth.ts](server/services/ui-auth.ts) (JWT/session), [server/middleware/tenant.ts](server/middleware/tenant.ts) (RLS) |
| New agent phase | [server/services/agents/](server/services/agents/) — Create phase file, update [orchestrator.ts](server/services/agents/orchestrator.ts) to call it |
| Job queue task | [server/services/queue/handlers](server/services/queue/handlers) — Register handler, enqueue with [queueService](server/services/queue/handlers) |
| React component | [client/src/components/](client/src/components/) — Use Radix UI primitives, TanStack React Query for data |
| Type safety | [shared/schema.ts](shared/schema.ts) — All cross-layer types centralized here; generate Zod schemas with `createInsertSchema()` |

---

## Integration Points & Guardrails

### Avoid Common Mistakes
1. **Forget org_id filter?** RLS will silently return empty results. Always include `eq(table.org_id, orgId)`.
2. **Hardcode credentials?** Use `envConfig` ([server/lib/environment.ts](server/lib/environment.ts)) to load secrets.
3. **Long-running operations?** Enqueue to BullMQ; don't block HTTP thread. Max pipeline timeout is 180s.
4. **Validate user input?** Use Zod schemas; 40+ pre-defined ones in [shared/schema.ts](shared/schema.ts).

### External Service Integration
- **OpenAI:** [openai-client.ts](server/services/agents/openai-client.ts) — Model routing (GPT-4, Claude via proxy)
- **Cloud APIs:** [server/services/cloud/](server/services/cloud/) — AWS, Azure, GCP credential handling
- **Stripe:** [billingService.ts](server/services/billingService.ts) — Usage-metered subscriptions, invoice webhooks
- **Threat Intel:** [threat-intel/](server/services/threat-intel/) — EPSS scores, CISA KEV lookups

### Evidence Artifact Storage
All HTTP requests/responses backed up to MinIO via [evidence-uploader.ts](server/services/evidence-uploader.ts). Reference artifacts in findings with `evidenceId` UUID.

---

## Testing Your Changes

- **Type check:** `npm run check`
- **Lint (security only):** `npm run lint:security`
- **Unit tests:** `vitest` (client only)
- **Manual E2E:** Start dev server, trigger evaluation via UI, check job logs in queue

**No automated backend tests yet** — Focus on feature completeness. For risky changes (auth, scoring), add console logs and verify in dev.

---

## When Stuck
1. Check [docs/README.md](docs/README.md) and [docs/API_REFERENCE.md](docs/API_REFERENCE.md) for endpoint specs
2. Look at [TESTING_GUIDE.md](docs/TESTING_GUIDE.md) for debugging patterns
3. Grep for similar patterns: `ripgrep "runAgentOrchestrator|shouldRunPhase"` to see pipeline examples
4. Ask for clarification on multi-tenant constraints or RBAC rules before building
