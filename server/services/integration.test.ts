/**
 * GTM v1.0 — Integration Tests IT-01 through IT-05
 *
 * These tests verify cross-module interactions between the
 * 4 GTM features and the breach orchestrator pipeline.
 */

import { describe, it, expect } from "vitest";
import {
  EvidenceQualityGate,
  EvidenceQuality,
} from "./evidence-quality-gate";
import { DefendersMirror } from "./defenders-mirror";
import { ReplayRecorder } from "./replay-recorder";
import { ReachabilityChainBuilder } from "./reachability-chain";

// ─── IT-01: Phase 1A evidence flows through Evidence Quality Gate ────────────
// SETUP: Phase 1A produces real HTTP evidence with statusCode + responseBody
// EXPECT: Quality gate classifies as PROVEN, source = "phasela_evidence"
describe("IT-01: Phase 1A → Evidence Quality Gate chain", () => {
  const gate = new EvidenceQualityGate();

  it("Phase 1A SQLi evidence with real HTTP response classifies as PROVEN", () => {
    // Simulate Phase 1A finding: real SQL injection with leaked credentials
    const phase1aFinding = {
      id: "eval-sqli-001",
      severity: "critical" as const,
      title: "SQL Injection — response body contains database output",
      description: "Extracted via SQLi on /api/search?q=",
      statusCode: 200,
      responseBody: '{"users":[{"username":"admin","password":"testdb_pass_xyz789"}]}',
      evidenceType: "real_http_response",
      success: true,
    };

    const verdict = gate.evaluate(phase1aFinding);
    expect(verdict.quality).toBe(EvidenceQuality.PROVEN);
    expect(verdict.passed).toBe(true);
    expect(verdict.requiresManualReview).toBe(false);
  });

  it("Phase 1A evidence with no HTTP data but LLM source classifies as INFERRED", () => {
    const llmInferredFinding = {
      id: "eval-infer-001",
      severity: "medium" as const,
      title: "Possible XSS",
      description: "LLM inferred possible XSS based on input reflection",
      source: "llm_inference_no_phasela_evidence",
    };

    const verdict = gate.evaluate(llmInferredFinding);
    expect(verdict.quality).toBe(EvidenceQuality.INFERRED);
    expect(verdict.passed).toBe(false);
    expect(verdict.requiresManualReview).toBe(true);
  });

  it("Batch evaluation separates PROVEN from INFERRED", () => {
    const findings = [
      {
        id: "f-proven",
        severity: "high" as const,
        title: "Real finding",
        description: "Real",
        statusCode: 200,
        responseBody: "admin panel found",
      },
      {
        id: "f-inferred",
        severity: "low" as const,
        title: "Guessed finding",
        description: "Guessed",
        source: "llm_inference",
      },
    ];

    const batch = gate.evaluateBatch(findings);
    expect(batch.passed.length).toBe(1);
    expect(batch.failed.length).toBe(1);
    expect(batch.passed[0].finding.id).toBe("f-proven");
    expect(batch.failed[0].finding.id).toBe("f-inferred");
  });
});

// ─── IT-02: Phase 1A evidence → Defender's Mirror rule generation ────────────
// SETUP: Phase 1A produces 3 evidence items (sqli, xss, cmdi)
// EXPECT: 3 rule sets generated, each with Sigma + YARA + Splunk
describe("IT-02: Phase 1A evidence → Defender's Mirror", () => {
  const mirror = new DefendersMirror();

  it("generates detection rules for SQLi evidence", () => {
    const sqliEvidence = {
      id: "ev-sqli-001",
      engagementId: "eng-001",
      phase: "application_compromise",
      techniqueCategory: "sqli" as const,
      targetService: "https://target.example.com/api/search",
      networkProtocol: "https",
      responseIndicators: { statusCode: 200, bodySnippet: "UNION SELECT" },
    };

    const ruleSet = mirror.generateFromEvidence(sqliEvidence);
    expect(ruleSet.mitreAttackId).toBe("T1190");
    expect(ruleSet.mitreAttackName).toBe("Exploit Public-Facing Application");
    expect(ruleSet.sigmaRule).toBeTruthy();
    expect(ruleSet.yaraRule).toBeTruthy();
    expect(ruleSet.splunkSPL).toBeTruthy();
    expect(ruleSet.attackEvidenceRef).toBe("ev-sqli-001");
    expect(ruleSet.engagementId).toBe("eng-001");
  });

  it("generates batch rules for multiple technique categories", () => {
    const evidenceList = [
      {
        id: "ev-xss-001",
        engagementId: "eng-001",
        phase: "application_compromise",
        techniqueCategory: "xss" as const,
        targetService: "https://target.example.com/page",
        networkProtocol: "https",
        responseIndicators: { statusCode: 200, bodySnippet: "<script>alert" },
      },
      {
        id: "ev-cmdi-001",
        engagementId: "eng-001",
        phase: "application_compromise",
        techniqueCategory: "cmdi" as const,
        targetService: "https://target.example.com/exec",
        networkProtocol: "https",
        responseIndicators: { statusCode: 200, bodySnippet: "uid=0(root)" },
      },
    ];

    const rules = mirror.generateBatch(evidenceList);
    expect(rules.length).toBe(2);
    expect(rules[0].mitreAttackId).toBe("T1059.007"); // XSS → Command: JavaScript
    expect(rules[1].mitreAttackId).toBe("T1059");     // CMDi → Command and Scripting
  });
});

// ─── IT-03: ReplayRecorder captures all phase events end-to-end ──────────────
// EXPECT: manifest.events contains entries from every phase that ran
// EXPECT: PDF export completes without error
describe("IT-03: ReplayRecorder captures multi-phase engagement", () => {
  it("captures events across 3 phases and produces valid manifest", () => {
    const recorder = new ReplayRecorder("eng-replay-001");

    // Phase 1: Application Compromise
    recorder.record({
      eventType: "exploit_attempt",
      phase: 1,
      target: "https://target.example.com",
      phaseName: "application_compromise",
      techniqueName: "SQL Injection",
      techniqueCategory: "sqli",
      mitreAttackId: "T1190",
      outcome: "success",
      evidenceSummary: "UNION-based SQLi returned 200 with DB rows",
    });

    // Phase 2: Credential Extraction
    recorder.record({
      eventType: "credential_harvested",
      phase: 2,
      target: "https://target.example.com",
      phaseName: "credential_extraction",
      techniqueName: "HTTP Response Parsing",
      outcome: "success",
      evidenceSummary: "Extracted admin:testdb_pass_xyz789 from response body",
      credentialsHarvested: ["cred-001"],
    });

    // Phase 5: Lateral Movement
    recorder.record({
      eventType: "pivot_attempt",
      phase: 5,
      target: "10.0.0.5:445",
      phaseName: "lateral_movement",
      techniqueName: "SMB Authentication",
      techniqueCategory: "smb_pivot",
      mitreAttackId: "T1021.002",
      outcome: "success",
      evidenceSummary: "SMB auth succeeded; shares enumerated",
      hostsDiscovered: ["10.0.0.5"],
    });

    const manifest = recorder.finalize();

    expect(manifest.events.length).toBe(3);
    expect(manifest.engagementId).toBe("eng-replay-001");
    expect(manifest.summary.totalTechniquesAttempted).toBe(3);
    expect(manifest.summary.totalTechniquesSucceeded).toBe(3);
    expect(manifest.summary.credentialsHarvested).toBe(1);
    expect(manifest.summary.uniqueHostsReached).toBe(2);

    // Verify monotonic timestamps
    for (let i = 1; i < manifest.events.length; i++) {
      expect(manifest.events[i].relativeTimestampMs).toBeGreaterThanOrEqual(
        manifest.events[i - 1].relativeTimestampMs
      );
    }

    // Verify phase filter works
    const phase5Events = recorder.getEvents({ phase: 5 });
    expect(phase5Events.length).toBe(1);
    expect(phase5Events[0].techniqueName).toBe("SMB Authentication");
  });

  it("snapshot at sequenceIndex=1 contains only events 0..1", () => {
    const recorder = new ReplayRecorder("eng-snap-001");

    recorder.record({ eventType: "exploit_attempt", target: "t1", phaseName: "p1", outcome: "success", evidenceSummary: "e1" });
    recorder.record({ eventType: "exploit_attempt", target: "t2", phaseName: "p2", outcome: "success", evidenceSummary: "e2" });
    recorder.record({ eventType: "exploit_attempt", target: "t3", phaseName: "p3", outcome: "failure", evidenceSummary: "e3" });

    const snapshot = recorder.getSnapshotAt(1);
    expect(snapshot.events.length).toBe(2);
    expect(snapshot.events[0].target).toBe("t1");
    expect(snapshot.events[1].target).toBe("t2");
    // Snapshot should only contain events up to index 1
    expect(snapshot.hostsReached.length).toBe(2); // t1 + t2 both succeeded
  });
});

// ─── IT-04: Reachability Chain builds from Phase 5 pivot results ─────────────
// SETUP: 3 hosts — entry → Host A → Host B → Host C
// EXPECT: All 3 in reachability chain with provenByRealAuth
describe("IT-04: Reachability Chain from Phase 5 pivots", () => {
  it("builds 3-hop chain with DOT graph output", () => {
    const builder = new ReachabilityChainBuilder();

    // Host A — entry point via SMB
    const nodeAId = builder.addNode({
      host: "10.0.0.1",
      port: 445,
      protocol: "smb",
      technique: "smb_pivot",
      authResult: "success",
      accessLevel: "standard",
      credentialUsed: "cred-001",
      depth: 0,
      timestamp: new Date().toISOString(),
    });

    // Host B — discovered from A via RDP
    const nodeBId = builder.addNode({
      host: "10.0.0.2",
      port: 3389,
      protocol: "rdp",
      technique: "rdp_pivot",
      authResult: "success",
      accessLevel: "standard",
      credentialUsed: "cred-002",
      depth: 1,
      timestamp: new Date().toISOString(),
    });

    // Host C — discovered from B via SSH
    const nodeCId = builder.addNode({
      host: "10.0.0.3",
      port: 22,
      protocol: "ssh",
      technique: "ssh_pivot",
      authResult: "success",
      accessLevel: "standard",
      credentialUsed: "cred-001",
      depth: 2,
      timestamp: new Date().toISOString(),
    });

    // Add edges
    if (nodeAId && nodeBId) builder.addEdge(nodeAId, nodeBId, "cred-002", "rdp");
    if (nodeBId && nodeCId) builder.addEdge(nodeBId, nodeCId, "cred-001", "ssh");

    const chain = builder.build("eng-reach-001", "10.0.0.1");

    expect(chain.nodes.length).toBe(3);
    expect(chain.edges.length).toBe(2);
    expect(chain.totalProvenHops).toBe(3); // All nodes provenByRealAuth
    expect(chain.deepestNode.depth).toBe(2);
    expect(chain.deepestNode.host).toBe("10.0.0.3");

    // DOT output should contain all 3 nodes
    expect(chain.graphFormat.dot).toContain("10.0.0.1");
    expect(chain.graphFormat.dot).toContain("10.0.0.2");
    expect(chain.graphFormat.dot).toContain("10.0.0.3");
    expect(chain.graphFormat.dot).toContain("digraph BreachChain");
  });

  it("failed pivots do not enter the reachability chain", () => {
    const builder = new ReachabilityChainBuilder();

    builder.addNode({
      host: "10.0.0.1",
      port: 445,
      protocol: "smb",
      technique: "smb_pivot",
      authResult: "success",
      accessLevel: "standard",
      credentialUsed: "cred-001",
      depth: 0,
      timestamp: new Date().toISOString(),
    });

    // Failed pivot — should NOT produce a node
    const failedNode = builder.addNode({
      host: "10.0.0.99",
      port: 445,
      protocol: "smb",
      technique: "smb_pivot",
      authResult: "invalid_credential",
      accessLevel: "none",
      credentialUsed: "cred-001",
      depth: 1,
      timestamp: new Date().toISOString(),
    });

    expect(failedNode).toBeNull();
    const chain = builder.build("eng-fail-001", "10.0.0.1");
    expect(chain.nodes.length).toBe(1);
    expect(chain.totalProvenHops).toBe(1);
  });
});

// ─── IT-05: Full pipeline — Evidence Gate + Mirror + Replay + Reachability ───
// SETUP: Simulate a mini engagement with Phase 1A + Phase 5 results
// EXPECT: All 4 modules produce consistent, cross-referenced output
describe("IT-05: Full pipeline cross-module consistency", () => {
  it("all 4 GTM modules produce consistent output from same engagement", () => {
    const engagementId = "eng-full-001";
    const gate = new EvidenceQualityGate();
    const mirror = new DefendersMirror();
    const recorder = new ReplayRecorder(engagementId);
    const reachBuilder = new ReachabilityChainBuilder();

    // ── Step 1: Phase 1A produces real finding ──
    const phase1aFinding = {
      id: "f-sqli-001",
      severity: "critical" as const,
      title: "SQL Injection",
      description: "Real SQLi",
      statusCode: 200,
      responseBody: '{"password":"real_cred_123"}',
      evidenceType: "real_http_response",
      success: true,
    };

    // Quality gate: should pass as PROVEN
    const verdict = gate.evaluate(phase1aFinding);
    expect(verdict.quality).toBe(EvidenceQuality.PROVEN);

    // Defender's Mirror: generate rules from this evidence
    const evidence = {
      id: "ev-sqli-full",
      engagementId,
      phase: "application_compromise",
      techniqueCategory: "sqli" as const,
      targetService: "https://target.example.com/api",
      networkProtocol: "https",
      responseIndicators: { statusCode: 200, bodySnippet: "UNION SELECT" },
    };
    const rules = mirror.generateFromEvidence(evidence);

    // Replay: record the event with defender's mirror ref
    recorder.record({
      eventType: "exploit_attempt",
      target: "https://target.example.com",
      phaseName: "application_compromise",
      techniqueName: "SQL Injection",
      techniqueCategory: "sqli",
      mitreAttackId: "T1190",
      outcome: "success",
      evidenceSummary: "SQLi returned credentials in response body",
      defendersMirrorRef: rules.id,
    });

    // ── Step 2: Phase 5 pivot ──
    const pivotResult = {
      host: "10.0.0.5",
      port: 445,
      protocol: "smb",
      technique: "smb_pivot",
      authResult: "success" as const,
      accessLevel: "standard",
      credentialUsed: "cred-harvested-001",
      depth: 0,
      timestamp: new Date().toISOString(),
    };

    reachBuilder.addNode(pivotResult);

    recorder.record({
      eventType: "pivot_attempt",
      target: "10.0.0.5:445",
      phaseName: "lateral_movement",
      techniqueName: "SMB Auth",
      techniqueCategory: "smb_pivot",
      mitreAttackId: "T1021.002",
      outcome: "success",
      evidenceSummary: "SMB auth with harvested credential",
    });

    // ── Finalize all modules ──
    const manifest = recorder.finalize();
    const chain = reachBuilder.build(engagementId, "target.example.com");

    // ── Cross-module consistency checks ──

    // Replay manifest references the same engagement
    expect(manifest.engagementId).toBe(engagementId);

    // Replay event has defender's mirror rule ID
    expect(manifest.events[0].defendersMirrorRef).toBe(rules.id);

    // Mirror rules reference the same engagement
    expect(rules.engagementId).toBe(engagementId);

    // Reachability chain is for the same engagement
    expect(chain.engagementId).toBe(engagementId);

    // All 3 outputs are non-empty
    expect(manifest.events.length).toBeGreaterThan(0);
    expect(rules.sigmaRule.length).toBeGreaterThan(0);
    expect(chain.nodes.length).toBeGreaterThan(0);

    // Summary counts are consistent
    expect(manifest.summary.totalTechniquesAttempted).toBe(2);
    expect(manifest.summary.totalTechniquesSucceeded).toBe(2);
  });
});
