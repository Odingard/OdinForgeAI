# OdinForge E2E Test Report -- Revenue-Critical Issues

**Date:** 2026-03-22
**Branch:** main (commit 8a07e6e)
**Tester:** Automated code audit + manual investigation
**Target:** https://brokencrystals.com (planned)

---

## Issue #55 -- End-to-End Test: Chain -> Run -> Seal -> PDF -> Verify

### Test Plan

The planned E2E flow:
1. Kill server on port 5000, start with `npm run dev`
2. Wait for `/healthz` (confirmed at `server/routes.ts:94`)
3. Login as `admin@odinforge.local / admin123` via `POST /ui/api/auth/login`
4. Create breach chain via `POST /api/breach-chains` with `assetIds: ["https://brokencrystals.com"]`
5. Poll `GET /api/breach-chains/{id}` every 10s for up to 6 minutes
6. Seal via `POST /api/breach-chains/{id}/seal`
7. Download PDF via `GET /api/breach-chains/{id}/report/pdf`
8. Validate PDF file

### Test Execution

**STATUS: NOT EXECUTED** -- Shell command execution was unavailable during this audit
session. The test script below is ready for manual execution.

### Ready-to-Run E2E Script

```bash
#!/bin/bash
set -euo pipefail

BASE="http://localhost:5000"
LOG="/tmp/odinforge-e2e.log"
PDF="/Users/dre/Desktop/E2E-Test-Report.pdf"

# 1. Kill existing server
lsof -ti:5000 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 2

# 2. Start server
cd /Users/dre/prod/OdinForge-AI
npm run dev > "$LOG" 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# 3. Wait for healthz
for i in $(seq 1 30); do
  if curl -s "$BASE/healthz" | grep -q '"ok":true'; then
    echo "Server healthy after ${i}s"
    break
  fi
  sleep 1
done

# 4. Login
TOKEN=$(curl -s -X POST "$BASE/ui/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@odinforge.local","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
echo "Token: ${TOKEN:0:20}..."

# 5. Create breach chain
CHAIN_ID=$(curl -s -X POST "$BASE/api/breach-chains" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"E2E Test - brokencrystals.com",
    "description":"End-to-end test for revenue-critical issue #55",
    "assetIds":["https://brokencrystals.com"],
    "targetDomains":["application"],
    "config":{"executionMode":"safe"}
  }' | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
echo "Chain ID: $CHAIN_ID"

# 6. Poll for completion (up to 360s)
for i in $(seq 1 36); do
  STATUS=$(curl -s "$BASE/api/breach-chains/$CHAIN_ID" \
    -H "Authorization: Bearer $TOKEN" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
  echo "Poll $i: status=$STATUS"
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  sleep 10
done

# 7. Seal
curl -s -X POST "$BASE/api/breach-chains/$CHAIN_ID/seal" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' | python3 -m json.tool

# 8. Download PDF
curl -s "$BASE/api/breach-chains/$CHAIN_ID/report/pdf" \
  -H "Authorization: Bearer $TOKEN" \
  -o "$PDF"

# 9. Verify
file "$PDF"
ls -la "$PDF"

echo "E2E test complete. Check $LOG for server output."
```

### Code Path Analysis (Verified by Reading)

| Step | Route | Code Location | Status |
|---|---|---|---|
| Health check | `GET /healthz` | `server/routes.ts:94` | EXISTS |
| Login | `POST /ui/api/auth/login` | `server/routes.ts:229` | EXISTS |
| Create chain | `POST /api/breach-chains` | `server/routes.ts:2383` | EXISTS |
| Poll status | `GET /api/breach-chains/:id` | `server/routes.ts:2567` | EXISTS |
| Seal | `POST /api/breach-chains/:id/seal` | `server/routes.ts:2895` | EXISTS |
| PDF download | `GET /api/breach-chains/:id/report/pdf` | `server/routes.ts:2811` | EXISTS |
| Technical PDF | `GET /api/breach-chains/:id/report/technical-pdf` | `server/routes.ts:2854` | EXISTS |

### Known Risks Identified in Code

1. **PDF generation depends on `pdfmake`** -- If not installed, import at line 2826 fails
2. **Seal endpoint calls `sealEngagementPackage()`** -- This generates all 5 package
   components; if any fail, the entire seal fails
3. **Logo file** -- `public/odingard-logo.png` EXISTS (verified), so PDF will have branding
4. **Missing closing brace in create endpoint** -- Line 2388 has a missing `}` for the
   `if (!name...)` validation block, which may cause a parse error (the `}` on line 2398
   closes it, but the `if (engagementConfig)` block at 2390-2397 is nested inside)

---

## Issue #51 -- EvidenceContract (ADR-001) Verification

### Architecture Review

The EvidenceContract is implemented across 4 layers:

| Layer | File | Purpose |
|---|---|---|
| Evidence Factory | `server/lib/real-evidence.ts` | `makeRealHttpEvidence()` -- validates all HTTP evidence fields at creation |
| Finding Factory | `server/lib/real-finding.ts` | `RealFinding.fromHttpEvidence()` -- requires non-empty evidence array, throws otherwise |
| Quality Gate | `server/services/evidence-quality-gate.ts` | `EvidenceQualityGate.evaluate()` -- classifies PROVEN/CORROBORATED/INFERRED/UNVERIFIABLE |
| Integrity Filter | `server/services/report-integrity-filter.ts` | `ReportIntegrityFilter.filter()` -- suppresses INFERRED/UNVERIFIABLE from customer output |

### PROVEN Finding Requirements Check

For a finding to be classified as PROVEN, it needs:

| Requirement | Present in Code | Location |
|---|---|---|
| HTTP request/response evidence | YES | `evidence-quality-gate.ts:207-216` -- checks `statusCode > 0` AND `responseBody.length > 0` |
| Status code | YES | `evidence-quality-gate.ts:209,213` -- `typeof finding.statusCode === "number" && finding.statusCode > 0` |
| Matched patterns | YES (in AEE) | `active-exploit-engine.ts:2779` -- `matchedPatterns` in ExploitEvidence type |
| Confidence >= 0.6 | YES (in AEE) | `active-exploit-engine.ts:3149` -- `confidence >= 0.6 && hasHardEvidence` |
| Curl command to reproduce | YES (generated) | `active-exploit-engine.ts:3930-3941` -- `buildCurlCommand()` |

### CRITICAL GAP: Evidence Field Loss in Breach Orchestrator

**The breach orchestrator drops critical evidence fields when mapping AEE findings
to phase results.** The `mapToBreachPhaseContext()` function at
`active-exploit-engine.ts:4152` returns findings with full evidence:

```
{ title, description, severity, cwe, evidence, exploitChain, remediation, confidence, curlCommand }
```

But `breach-orchestrator.ts:1627-1635` only captures:

```
{ id, severity, title, description, technique, source, evidenceQuality }
```

**Missing fields that are dropped:**
- `statusCode` -- Not carried from AEE output to phase findings (only carried for micro-agent findings at line 1710-1711)
- `responseBody` -- Not carried from AEE output to phase findings
- `curlCommand` -- Generated per exploit but never reaches engagement package or PDF
- `confidence` -- Available in AEE but not stored in phase findings
- `matchedPatterns` -- Available in AEE evidence but not propagated
- `cwe` -- Available in mapped output but not stored

**Impact:** PROVEN findings in the AEE become harder to verify in the engagement
package because the raw HTTP evidence (status codes, response bodies, curl commands)
is not propagated through the breach orchestrator to the final deliverables.

### RealFinding Factory: Never Actually Used

**`RealFinding.fromHttpEvidence()` at `server/lib/real-finding.ts` is defined but
never imported or called anywhere in the codebase.** The breach orchestrator constructs
findings directly with object literals instead of using the factory that enforces
evidence requirements. This means the ADR-001 structural gate that prevents
synthetic findings is bypassed in practice.

### Evidence Quality Gate: Logic is Sound

The `EvidenceQualityGate` classification chain is correctly ordered:
1. Real HTTP evidence (statusCode + responseBody) -> PROVEN
2. Real protocol auth success -> PROVEN
3. Real attempt with failure -> CORROBORATED
4. Active exploit engine source -> CORROBORATED
5. LLM inference -> INFERRED
6. Fallback -> UNVERIFIABLE

The gate correctly handles missing `source` fields (line 90-107) by checking for
real evidence before falling through to UNVERIFIABLE.

### Recommendations

1. **HIGH PRIORITY:** Fix evidence field propagation in `breach-orchestrator.ts` lines
   1627-1635 to include `statusCode`, `responseBody`, and `curlCommand` from
   `mapped.findings`
2. **HIGH PRIORITY:** Actually import and use `RealFinding.fromHttpEvidence()` in the
   breach orchestrator instead of constructing findings manually
3. **MEDIUM:** Add `curlCommand` to the `BreachFinding` interface and propagate it
   to the engagement package Evidence JSON and Engineer Report PDF
4. **MEDIUM:** Store `confidence` and `matchedPatterns` in phase findings for
   audit purposes

---

## Issue #61 -- Zero Findings Diagnostic

### Current Implementation

The 0-findings diagnostic exists at `breach-orchestrator.ts:579-600`:

```typescript
if (phaseResult.findings.length === 0) {
  const reason = phaseResult.error
    ? `Phase error: ${phaseResult.error}`
    : phaseResult.status === "skipped"
      ? `Phase skipped: ${phaseResult.error || "prerequisite not met"}`
      : `Phase completed but no exploitable findings validated. ` +
        `Sub-agent runs: ${phaseResult.subAgentRuns?.length ?? 0}. ` +
        `This may indicate: target not vulnerable to tested payloads, WAF blocking, ` +
        `or crawl discovered 0 endpoints (check [AEE:precheck] and [AEE:crawl] logs).`;

  emitCognitiveEvent({
    type: "intelligence.strategy",
    chainId,
    summary: `Phase ${phaseName}: 0 findings`,
    detail: reason,
    timestamp: new Date().toISOString(),
  });
  log.warn({ phase: phaseName }, `0-findings diagnostic: ${reason}`);
}
```

### Diagnostic Capability Assessment

| Diagnostic Category | Distinguished? | How |
|---|---|---|
| **Phase error** | YES | Checks `phaseResult.error` |
| **Phase skipped** | YES | Checks `phaseResult.status === "skipped"` |
| **Target not vulnerable** | PARTIAL | Mentioned in generic message but not distinguished from other causes |
| **WAF blocking** | PARTIAL | Mentioned in generic message but not explicitly detected |
| **No vulnerable endpoints** | PARTIAL | Mentioned as "crawl discovered 0 endpoints" but not confirmed |
| **Crawl failure** | PARTIAL | References `[AEE:precheck]` and `[AEE:crawl]` logs but not programmatic |
| **Unreachable target** | NO | Not distinguished -- a DNS failure or connection timeout would appear as a phase error |

### Gaps Identified

1. **No structured diagnostic categories.** The diagnostic is a single string message,
   not a machine-readable enum. This makes it impossible to filter, report, or alert
   on specific failure modes.

2. **No pre-check reachability validation.** The orchestrator does not verify target
   reachability before starting the breach chain. A DNS failure or timeout produces
   a generic phase error, not a clear "target unreachable" message.

3. **WAF detection is passive.** The AEE does detect WAF responses (403 patterns,
   rate limiting), but this information is not surfaced in the 0-findings diagnostic.
   The orchestrator would need to inspect AEE-level WAF counters.

4. **Crawl statistics not surfaced.** The AEE tracks crawl endpoint counts, but
   the orchestrator's diagnostic only guesses "crawl discovered 0 endpoints" -- it
   does not actually read the crawl result count.

### UI Visibility

**The 0-findings diagnostic is NOT visible in the UI.** The diagnostic is emitted as
a `cognitive event` via `emitCognitiveEvent()` which goes to the WebSocket live feed
and server logs. However:

- The BreachChains.tsx page shows `"X findings"` per phase (line 260), which will
  show `"0 findings"` -- but no explanation of WHY
- There is no "No findings were discovered" empty state or explanation panel
- The Reports.tsx page has `"No validated security findings were identified during
  this assessment"` (line 1156), but no diagnostic detail

### PDF Report Visibility

The CISO report narrative at `ciso-report.ts:166-169` handles zero completed phases:
```typescript
if (completedPhases.length === 0) {
  lines.push("No breach chain phases completed successfully.");
  return lines.join(" ");
}
```
But for phases that complete with 0 findings, the narrative simply omits them
(line 177: `if (findingCount > 0)`), providing no explanation to the customer.

### Recommendations

1. **HIGH:** Create a `ZeroFindingsDiagnostic` enum with categories:
   `TARGET_UNREACHABLE`, `WAF_BLOCKING`, `CRAWL_FAILURE`, `NO_VULNERABLE_ENDPOINTS`,
   `ALL_PAYLOADS_FAILED`, `TIMEOUT`, `PHASE_ERROR`
2. **HIGH:** Add pre-chain reachability check (HTTP HEAD to target, DNS resolution)
3. **HIGH:** Surface diagnostic in the UI on the breach chain detail page when
   totalFindings === 0
4. **MEDIUM:** Include diagnostic explanation in the PDF report for 0-finding phases
5. **MEDIUM:** Pull AEE crawl stats and WAF detection counts into the phase result
   for structured diagnostics

---

## Issue #66 -- PDF Report Assessment

### Components Reviewed

- `server/services/engagement/pdf-renderer.ts` -- CISO PDF (262 lines) + Engineer PDF (512 lines)
- `server/services/engagement/ciso-report.ts` -- CISO report data generator
- `server/services/engagement/engineer-report.ts` -- Engineer report data generator

### Assessment Checklist

| Feature | Present | Location/Notes |
|---|---|---|
| **Odingard logo** | YES | `pdf-renderer.ts:18-29` -- loads `public/odingard-logo.png` as base64; falls back to text header |
| **Company branding** | YES | "Odingard Security / Six Sense Enterprise Services" in header |
| **Page size** | YES | LETTER format (8.5x11) with 40pt margins |
| **Font** | YES | Helvetica family (normal, bold, oblique, bold-oblique) |
| **Color palette** | YES | Professional dark navy (#1a1a2e), red accent (#dc2626), slate body text |
| **Section dividers** | YES | Canvas line elements with accent color |
| **Risk Grade A-F** | YES | Large 48pt grade with color-coded display |
| **Executive Summary/Narrative** | YES | "ASSESSMENT NARRATIVE" section with breach chain narrative |
| **Primary Attack Path** | YES | Steps table with MITRE ATT&CK IDs |
| **Business Impact** | YES | Dedicated section under primary breach path |
| **Key Metrics** | YES | Total findings, customer findings, critical count, duration |
| **Evidence Integrity** | YES | PROVEN/CORROBORATED/Suppressed counts and pass rate |
| **Remediation Plan** | YES | 5 categories: immediate, pivot disruption, artifact protection, privilege boundary, monitoring |
| **Findings Table** | YES (Engineer PDF) | Severity-colored findings with technique, MITRE ID, HTTP evidence |
| **Chain Trace** | YES (Engineer PDF) | Phase-by-phase table with status, findings count, duration |
| **Remediation Diffs** | YES (Engineer PDF) | Before/after state per finding with CWE/OWASP references |
| **Methodology** | YES (Engineer PDF) | Target assets, execution mode, duration, evidence standard |
| **Confidentiality notice** | YES | Footer with EvidenceContract disclaimer |

### What's Missing vs. Big 4 Pentest Report

| Gap | Severity | Description |
|---|---|---|
| **Table of Contents** | HIGH | No TOC -- Big 4 reports always have a clickable TOC for 20+ page reports |
| **Page numbers** | HIGH | No page numbers in header/footer |
| **Document classification header** | MEDIUM | No "CONFIDENTIAL" watermark or header on every page |
| **Version control block** | MEDIUM | No document version, revision history, or approval chain |
| **Scope section** | MEDIUM | No explicit "Scope of Assessment" section listing tested assets, excluded assets, testing dates |
| **Methodology detail** | MEDIUM | Engineer PDF has methodology summary but CISO PDF does not; neither explains the AEV approach in detail |
| **CVSS scores per finding** | MEDIUM | Findings show severity (critical/high/medium/low) but no CVSS 3.1 base scores |
| **Finding screenshots** | MEDIUM | No visual evidence (screenshots, response body rendered); only text descriptions |
| **Curl reproduction commands** | HIGH | `curlCommand` generated in AEE but NOT included in either PDF (see Issue #51) |
| **Appendices** | MEDIUM | No appendix section for: full HTTP evidence, scan configuration, tool versions |
| **Risk matrix visualization** | LOW | No likelihood x impact matrix chart |
| **Trend comparison** | LOW | No comparison to prior assessments (would need engagement history) |
| **Compliance mapping table** | MEDIUM | CISO report mentions compliance implications in data but not in PDF render |
| **Individual finding detail pages** | MEDIUM | Engineer PDF lists findings inline; Big 4 reports have dedicated page per critical/high finding with full evidence, reproduction steps, remediation |
| **Cover page** | LOW | No dedicated cover page with engagement details, client name, classification |
| **Executive summary on page 1** | MEDIUM | Risk grade and narrative share space; no distinct 1-page executive summary |

### Specific Code Recommendations

1. **Add page numbers:**
   ```typescript
   footer: function(currentPage, pageCount) {
     return {
       columns: [
         { text: 'CONFIDENTIAL', alignment: 'left', style: 'footer' },
         { text: `Page ${currentPage} of ${pageCount}`, alignment: 'right', style: 'footer' }
       ],
       margin: [40, 10, 40, 0]
     };
   }
   ```

2. **Add Table of Contents:**
   ```typescript
   content.push({ toc: { title: { text: 'Table of Contents', style: 'sectionHeader' } } });
   // Then add tocItem: true to each sectionHeader
   ```

3. **Add curl commands to Engineer PDF findings:**
   First fix the evidence propagation (Issue #51), then in
   `pdf-renderer.ts` finding loop add:
   ```typescript
   if (finding.curlCommand) {
     content.push({
       text: finding.curlCommand,
       font: 'Courier', fontSize: 7, color: COLORS.body,
       background: '#f1f5f9', margin: [60, 0, 0, 4]
     });
   }
   ```

4. **Add cover page:** Dedicate the first page to engagement ID, client name,
   classification, date, assessor, and logo.

5. **Add CVSS scores:** Map finding severity + technique to estimated CVSS 3.1
   base scores using the existing scoring engine data.

6. **Add scope section:** Pull `targetAssets`, `executionMode`, and date range
   from the chain config and display as a formal scope table.

---

## Issue #73 -- Legal Engagement Template

### Status: COMPLETED

Created `docs/managed-service/engagement-agreement-template.md` with all 9 required sections:

| Section | Content |
|---|---|
| 1. Scope of Assessment | In-scope/out-of-scope assets, methodology, execution mode, excluded activities |
| 2. Authorization and Legal Basis | Client authorization, Letter of Authorization (CFAA/CMA), third-party notifications |
| 3. Liability Limitations | Liability cap, consequential damages exclusion, client responsibilities, insurance |
| 4. Safe Harbor Clause | Good faith testing, vulnerability disclosure, no prosecution agreement |
| 5. Data Handling and Confidentiality | Data classification table, evidence retention policy, integrity (ADR-001), NDA |
| 6. Rules of Engagement | Testing windows, traffic identification, rate limits, emergency stop, governance controls |
| 7. Incident Notification | Critical finding (2hr), incidental discovery, service impact (15min), contact table |
| 8. Deliverables | 5-component engagement package description, integrity hashes, evidence standard, optional deliverables |
| 9. Timeline and Duration | Milestone schedule, duration estimates, delays/extensions |

Additional sections included: Fees and Payment, General Provisions (governing law,
dispute resolution, entire agreement, amendments, severability, assignment), Signatures.

The template includes a prominent disclaimer that it must be reviewed by legal counsel.

**File:** `/Users/dre/prod/OdinForge-AI/docs/managed-service/engagement-agreement-template.md`

---

## Summary

### What Passed

| Item | Status |
|---|---|
| Evidence Quality Gate logic | SOUND -- classification chain is correctly ordered and handles edge cases |
| Report Integrity Filter | SOUND -- correctly suppresses INFERRED/UNVERIFIABLE from customer output |
| PDF renderer structure | GOOD -- professional layout, branding, color palette, section organization |
| Logo integration | WORKS -- `public/odingard-logo.png` exists and is loaded |
| Engagement package sealing | GOOD -- SHA-256 hashes for all 5 components, package hash |
| Legal template | CREATED -- comprehensive 11-section template |
| Curl command generation | WORKS -- `buildCurlCommand()` at AEE level produces reproducible PoCs |
| Confidence threshold | CORRECT -- 0.6 threshold enforced in `active-exploit-engine.ts:3149` |

### What Failed / Needs Fixing

| Issue | Severity | File | Description |
|---|---|---|---|
| Evidence field loss | **CRITICAL** | `server/services/breach-orchestrator.ts:1627-1635` | `statusCode`, `responseBody`, `curlCommand` dropped when mapping AEE findings to phase results |
| RealFinding factory unused | **HIGH** | `server/lib/real-finding.ts` | Defined but never imported -- ADR-001 structural gate is bypassed |
| 0-findings UI gap | **HIGH** | `client/src/pages/BreachChains.tsx` | No explanation shown when a chain completes with 0 findings |
| 0-findings PDF gap | **HIGH** | `server/services/engagement/ciso-report.ts:177` | 0-finding phases silently omitted from narrative |
| PDF missing page numbers | **MEDIUM** | `server/services/engagement/pdf-renderer.ts` | No `footer` function with page numbers |
| PDF missing TOC | **MEDIUM** | `server/services/engagement/pdf-renderer.ts` | No table of contents for multi-page reports |
| PDF missing curl commands | **MEDIUM** | `server/services/engagement/pdf-renderer.ts` | Reproduction commands not in engineer PDF |
| PDF missing cover page | **MEDIUM** | `server/services/engagement/pdf-renderer.ts` | No dedicated cover page |
| PDF missing CVSS scores | **LOW** | `server/services/engagement/pdf-renderer.ts` | Only severity labels, no numeric CVSS 3.1 |
| 0-findings diagnostic unstructured | **MEDIUM** | `server/services/breach-orchestrator.ts:582-590` | Free-text diagnostic, no structured enum |
| No pre-chain reachability check | **MEDIUM** | `server/services/breach-orchestrator.ts` | Target unreachable not explicitly detected |
| E2E test not executed | **N/A** | N/A | Shell execution unavailable; test script provided for manual run |

### Priority Action Items

1. **Fix evidence field propagation** (Issue #51) -- Change `breach-orchestrator.ts:1627-1635`
   to include `statusCode`, `responseBody`, and `curlCommand` from `mapped.findings`:
   ```typescript
   findings.push({
     id: fid,
     severity: finding.severity as "critical" | "high" | "medium" | "low",
     title: finding.title,
     description: finding.description,
     technique: finding.exploitChain,
     source: "active_exploit_engine",
     evidenceQuality: "proven",
     statusCode: /* from AEE response */,
     responseBody: /* from AEE response */,
     curlCommand: finding.curlCommand,  // NEW
   });
   ```

2. **Add 0-findings empty state to UI** (Issue #61) -- In `BreachChains.tsx`, when
   `totalFindings === 0` and status is `completed`, show a diagnostic panel.

3. **Add page numbers and TOC to PDF** (Issue #66) -- Straightforward `pdfmake`
   features that significantly improve professionalism.

4. **Run E2E test script** (Issue #55) -- Execute the script above to verify the
   full chain->seal->PDF pipeline works end-to-end.

5. **Import and use RealFinding factory** (Issue #51) -- Replace manual finding
   construction in the breach orchestrator with `RealFinding.fromHttpEvidence()`.
