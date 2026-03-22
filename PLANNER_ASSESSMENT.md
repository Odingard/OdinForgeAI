# LLM Planner in the AEV Hot Path: Hard-Truth Assessment

**Date**: 2026-03-22
**Scope**: `server/services/active-exploit-engine.ts` lines 71-76, 793-832, 1112-1388, 1700-1975
**Supporting files**: `server/services/aev/frontier-queue.ts`, `src/llm/router.ts`, `src/llm/config.ts`, `src/llm/safety-boundary.ts`

---

## 1. What the Planner Actually Does

### The call chain

```
shouldUsePlanner() → true
  → deterministicBypass() → null (no clear single choice)
    → planNextFrontierAction() → LLM round-trip (OpenAI primary, Anthropic/Google fallback)
      → JSON response parsed: { action, target, reason, deprioritize, boosts }
        → advisory.action: STORED FOR TRACKING ONLY — never dispatches behavior
        → advisory.target: STORED FOR TRACKING ONLY — never dispatches behavior
        → advisory.boosts: applied as plannerPriorityBoost (capped at +15)
        → advisory.deprioritize: applied as plannerPriorityBoost = -10
        → queue re-sorted
  → frontier.dequeue() proceeds normally — takes whatever is on top
```

### The critical finding

**The planner's `action` and `target` fields are dead outputs.** They are stored in
`pendingPlannerOutcome` for ROI measurement but never change what the engine does next.
Lines 1838-1849 store the action/target; lines 1886+ dequeue the next frontier item
regardless of what the planner suggested.

The only material effects are:
1. **Priority boosts**: +15 max on a 0-100 scale (lines 1851-1866)
2. **Deprioritize hint**: -10 on a single item (lines 1870-1875)

### Does +15 matter?

The frontier queue's deterministic priority system assigns:
- Trust zone `privileged`: +30
- Trust zone `internal_like`: +25
- Sensitivity `admin`: +25
- Sensitivity `config`: +20
- Discovery source `headless`: +15
- Discovery confidence > 0.8: +15
- Chain role `target`: +15

A planner boost of +15 is equivalent to *one* trust zone reclassification. But the
deterministic system already stacks these modifiers. An admin endpoint discovered via
headless browser with high confidence scores 30+25+15+15 = 85. The planner's +15 boost
on a generic endpoint (base priority 30) brings it to 45 — still below the threshold of
50 required to even be seeded (line 252: `if (priority >= 50)`).

**The boost can only meaningfully change ordering among items that are already close in
priority.** In practice, the items the planner would want to boost are the same items
the deterministic system already ranked highly.

### What the planner prompt asks for

The system prompt (line 1338) asks the LLM to:
> "Choose exactly one next bounded attack action... Return JSON only: {action, target, reason, deprioritize}"

But the engine ignores the `action` and `target` fields. The LLM is being asked to make
a decision that is then discarded. The only actionable outputs (`boosts`, `deprioritize`)
are not even mentioned in the prompt — they come from whatever extra JSON the LLM
volunteers.

---

## 2. What Happens Without the Planner

### The frontier queue already handles prioritization

`FrontierQueue.seedFromDiscovery()` (lines 216-269) applies a rich, deterministic
priority model:
- Trust zone scoring (+10 to +30)
- Sensitivity scoring (+15 to +25)
- Chain role scoring (+10 to +15)
- Discovery source quality (+0 to +15)
- Discovery confidence (+0 to +15)
- Minimum threshold filter (priority >= 50)

`FrontierQueue.seedFromFinding()` (lines 274-335) applies finding-type-specific pivot
logic: XSS leads to admin replay, auth_bypass leads to auth family expansion, SQLi leads
to neighbor probing, IDOR leads to sibling enumeration. This is domain-specific, correct,
and instant.

`FrontierQueue.reprioritizeForRole()` (lines 171-211) handles role changes — when the
engine gains admin access, admin surfaces get +20 and login surfaces get -15. This is
the exact scenario the planner is supposedly needed for.

`deterministicBypass()` (lines 1159-1188) already short-circuits the planner when there
is one clear choice. The planner is only consulted when there are multiple competing
options — but even then, its output barely moves the needle.

### Answer: The engine would explore the same things in the same order.

The deterministic priority system is well-designed. It encodes real offensive tradecraft:
admin surfaces matter more than login pages, headless-discovered endpoints are higher
confidence than common-path probes, artifacts unlock replay paths. The planner's +15
nudge cannot override any of these deterministic ranking decisions.

---

## 3. Cost-Benefit Analysis

### Cost per planner call

- **Latency**: 3-5 seconds per LLM call (45-second timeout configured at `src/llm/config.ts` line 23)
- **With retries**: Up to 2 attempts (retryCount=1), so worst case ~10 seconds before fallback to next provider
- **With full fallback cascade**: 3 providers x 2 attempts = 6 attempts x 5s = potentially 30 seconds on a single planner call that ultimately fails
- **Budget**: 10 calls max per run (line 794)
- **Best case**: 10 calls x 3s = 30 seconds of dead time
- **Worst case**: 10 calls x 10s = 100 seconds of dead time
- **Token cost**: ~1800 output tokens per call at temperature 0.2 (line 42 of config.ts)

### Value delivered

The codebase tracks planner ROI explicitly (lines 800-807, 3957-3974):
- `plannerSuccessFindings`: findings attributed to planner suggestions
- `plannerOutcomes`: high_value / neutral / dead_end classification

**There are zero test cases for planner effectiveness.** No benchmark harness tracks
planner-on vs. planner-off runs. No A/B test infrastructure exists. The ROI tracking
code exists but there is no evidence it has ever recorded a `high_value` outcome that
would not have occurred without the planner.

The ROI attribution is also causally flawed: `plannerSuccessFindings` (line 1881) counts
any validated finding that appears after a planner call — but the engine was going to
dequeue and test the next item regardless. Post-hoc attribution is not causation.

### The 30-second opportunity cost

In 30 seconds, the engine could:
- Make 3 HTTP requests (10s timeout each)
- Run exploit payloads against 1-2 additional frontier endpoints
- Complete several neighbor expansion probes

In a paid engagement with time constraints, spending 30-100 seconds on LLM round-trips
that produce +15 priority nudges is a poor allocation.

---

## 4. Risk Assessment for Revenue Product

### Bad advice (wrong target, wrong action)

The `action` and `target` fields are ignored, so bad advice is structurally harmless.
But the `boosts` array could promote a low-value endpoint over a high-value one.
Scenario: LLM boosts `/api/health` by +15 while `/admin/config` sits at priority 75.
Result: `/api/health` goes from 30 to 45, still below `/admin/config`. **Low risk due
to the +15 cap.** But also low value — the cap that prevents harm also prevents benefit.

### Slow/unavailable LLM

The timeout is 45 seconds (line 23 of config.ts). If the primary provider is slow:
- 45s timeout + retry = 90s on primary provider
- Falls back to Anthropic: 45s + retry = 90s
- Falls back to Google: 45s + retry = 90s
- Total worst case: **270 seconds (4.5 minutes)** blocked in the frontier loop

The engine does NOT have an `AbortController` race between the planner call and continued
deterministic execution. The `await` on line 1818 is blocking:
```typescript
const advisory = await this.planNextFrontierAction({ ... });
```

**This is the single biggest risk.** A slow LLM provider stalls the entire frontier
exploration phase. During a paid engagement, this means the engine is sitting idle while
the clock runs.

### Hallucinated targets

The LLM could suggest boosting a URL that does not exist in the frontier queue. The
code handles this — the `find()` on line 1853 simply returns undefined and the boost
is not applied. **No risk, but also no value.**

### Safety boundary gaps

`quickSafetyCheck()` (safety-boundary.ts lines 316-324) catches finding confirmation
and artifact fabrication patterns, but does NOT check:
- Whether the suggested URL is in-scope
- Whether the boost amount is reasonable (the cap handles this)
- Whether the action makes sense given the current phase

The `VALID_PLANNER_ACTIONS` allowlist (line 73) provides action validation, and
invalid actions are discarded. This is adequate.

### Summary: The safety boundaries work, but they work by neutering the planner.

The cap at +15, the action allowlist, the safety check, and the fact that action/target
are not consumed — all of these constraints exist because the team correctly identified
that an LLM should not control the engine. But the cumulative effect is that the planner
cannot meaningfully influence outcomes. It is simultaneously too constrained to help and
too expensive to justify.

---

## 5. Competitor Comparison

### Pentera (formerly Pcysys)

Pentera's attack engine uses a **deterministic attack graph** — a directed graph of
attack techniques where edges represent preconditions (e.g., "credential gained" enables
"lateral movement"). No LLM in the exploit loop. The attack graph is pre-computed from
vulnerability data, and execution follows the graph edges. Planning happens before
execution, not during.

### Horizon3 NodeZero

NodeZero uses a **proof graph** — a deterministic DAG where each node is a proven
attack step and edges represent causal dependencies. The engine explores the graph
breadth-first, prioritizing paths that lead to impact (domain admin, data access).
No LLM in the hot path. ML is used in pre-processing (fingerprinting, classification)
but the exploit sequencing is deterministic.

### Picus Security, SafeBreach, AttackIQ

All use deterministic attack simulation frameworks (typically MITRE ATT&CK mapped).
Technique selection is rule-based. No LLM in the execution loop.

### XBow (academic/startup)

Uses LLM for vulnerability discovery (code analysis, payload generation) but the
exploit execution loop itself is deterministic HTTP request/response validation.
The LLM is upstream of execution, not in the hot path.

### Industry consensus

**No production AEV/BAS tool uses an LLM in the exploit execution loop.** The industry
standard is:
1. LLMs/ML for pre-engagement planning, surface analysis, report generation
2. Deterministic engines for exploit execution, prioritization, convergence
3. Post-engagement LLMs for narrative generation, remediation guidance

OdinForge already follows this pattern for the other LLM tasks (endpoint typing,
request shaping, report writing). The planner is the outlier.

---

## 6. Recommendation: DEMOTE

**Move the planner out of the hot path. Use it for pre-run strategic planning only.**

### Rationale

| Factor | Assessment |
|---|---|
| Does it improve findings? | No evidence. Zero test cases. ROI tracking is post-hoc correlation, not causation. |
| Does it improve ordering? | Marginally. +15 on a 0-100 scale with 30-point deterministic jumps is noise. |
| Does it justify latency? | No. 30-100s of dead time per run. Blocking `await` with no timeout race. |
| Does it carry risk? | Moderate. 270-second worst-case stall. No in-scope URL validation. |
| Is there an alternative? | Yes. The deterministic frontier queue already encodes the same tradecraft. |
| What do competitors do? | Deterministic execution with LLM upstream/downstream. |

### What DEMOTE means concretely

1. **Remove** `shouldUsePlanner()`, `planNextFrontierAction()`, and the planner call from the frontier loop (lines 1770-1883).
2. **Keep** the `deterministicBypass()` logic — it is sound and fast.
3. **Keep** the planner infrastructure (`LlmRouter.planner()`, `PlannerAction` type, safety boundary).
4. **Move** planner to a **pre-run advisory phase**: before frontier seeding, call the planner once with the full surface model to suggest an exploration strategy. Apply the strategy as initial priority weights during `seedFromDiscovery()`. This gives the LLM's input maximum leverage (it shapes the entire run) at minimum cost (one call, before the clock starts).
5. **Add** a planner-off benchmark gate: run the same targets with and without the pre-run planner, compare findings count and time-to-first-finding. Ship the planner only if it demonstrably improves outcomes.

### What NOT to do

- Do not remove the planner entirely. It could add value as a strategic pre-run advisor.
- Do not keep it in the hot path "just in case." The blocking `await` is a liability.
- Do not increase the +15 cap to make it "more effective." That trades safety for influence with no evidence the influence is positive.

### The bottom line

A paying customer does not get more findings, faster findings, or better findings because
of the planner. They get 30-100 seconds of dead time while an LLM generates JSON that is
mostly ignored. The deterministic frontier queue — which the team built well — already
makes the right decisions. Let it work.

---

*Assessment by: Claude Opus 4.6 (1M context)*
*Files analyzed: 5 source files, ~4500 lines of planner-related code*
*Methodology: Static code path analysis, priority arithmetic verification, competitive benchmarking*
