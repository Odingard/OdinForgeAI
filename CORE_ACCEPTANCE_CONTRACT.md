# OdinForge Core V2 — Acceptance Contract

These 5 checks MUST pass at every stage of the strip-down.
If any check fails, stop and fix before continuing.

---

## CHECK 1: Successful Exploit Path
**Trigger**: Start breach chain against `https://brokencrystals.com`
**Expected**:
- Phase 1 (application_compromise) finds >= 1 validated finding
- Finding has `source: "active_exploit_engine"` and `evidenceQuality: "proven"`
- Finding includes real `statusCode` (> 0) and non-empty `responseBody`
- Active exploit engine logs show: endpoints crawled > 0, payloads fired > 0, validated > 0
- Chain status is `"completed"`, not `"failed"`
**Fail condition**: 0 findings, or finding without real HTTP evidence, or chain completes in < 10 seconds

## CHECK 2: Failed Exploit Path with Diagnostics
**Trigger**: Start breach chain against unreachable target (e.g., `https://nonexistent.invalid`)
**Expected**:
- Exploit engine logs a clear `CONNECTIVITY FAILURE` message with target URL and error reason
- Chain status is `"failed"` (not `"completed"` with 0 findings)
- Phase 1 result includes diagnostic error message explaining WHY no findings were produced
- No silent completion — the system tells you exactly what went wrong
**Fail condition**: Chain shows `"completed"` with 0 findings and no error explanation

## CHECK 3: Evidence Rejection Path
**Trigger**: Inspect quality gate output for any chain run
**Expected**:
- `evidenceQualityGate.evaluateBatch()` classifies every finding
- Phase 6 (impact_assessment) SYNTHESIS findings are classified as `INFERRED`
- `reportIntegrityFilter.filter()` suppresses INFERRED and UNVERIFIABLE from `customerFindings`
- `customerFindings` contains ONLY PROVEN and CORROBORATED findings
- `audit.suppressed` count > 0 if any synthesis findings exist
**Fail condition**: INFERRED or UNVERIFIABLE findings appear in customer output

## CHECK 4: Package Seal Path
**Trigger**: `POST /api/breach-chains/:id/seal` on a completed chain
**Expected**:
- Package contains all 5 components: cisoReport, engineerReport, evidenceJSON, defendersMirror, breachChainReplayHTML
- Each component has a SHA-256 integrity hash
- Package has a combined `packageHash`
- `evidenceJSON.findings` contains ONLY proven/corroborated findings (integrity filter applied)
- `evidenceJSON.auditSummary` shows totalInput, customerOutput, suppressed counts
- Per-engagement API keys are deactivated
- Reengagement offer is generated (90-day window)
**Fail condition**: Missing component, missing hash, unfiltered findings in evidence JSON, or API keys still active

## CHECK 5: Disabled Phase Honesty
**Trigger**: Run chain where Phases 3-6 are disabled/stubbed in core-v2
**Expected**:
- Phase 3-6 results have `status: "skipped"` with explicit reason: `"Phase disabled in core-v2 build"`
- Executive summary does NOT claim cloud escalation, lateral movement, or impact assessment occurred
- CISO report does NOT mention cloud, K8s, lateral, or impact findings that don't exist
- Engineer report shows only phases that actually executed
- Engagement package metadata shows `phasesExecuted: 2` (not 6)
**Fail condition**: Any report or UI element implies a disabled phase produced results
