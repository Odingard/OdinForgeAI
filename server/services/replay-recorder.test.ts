import { describe, it, expect } from "vitest";
import { ReplayRecorder } from "./replay-recorder";

describe("ReplayRecorder", () => {
  it("auto-fills id, sequenceIndex, and timestamps on record()", () => {
    const recorder = new ReplayRecorder("eng-001");
    const event = recorder.record({ eventType: "exploit_attempt", target: "https://target.com" });

    expect(event.id).toMatch(/^re-/);
    expect(event.sequenceIndex).toBe(0);
    expect(event.timestamp).toBeDefined();
    expect(typeof event.relativeTimestampMs).toBe("number");
  });

  it("assigns monotonically increasing sequenceIndex", () => {
    const recorder = new ReplayRecorder("eng-002");
    const e0 = recorder.record({ eventType: "phase_start", target: "t" });
    const e1 = recorder.record({ eventType: "exploit_attempt", target: "t" });
    const e2 = recorder.record({ eventType: "exploit_success", target: "t" });

    expect(e0.sequenceIndex).toBe(0);
    expect(e1.sequenceIndex).toBe(1);
    expect(e2.sequenceIndex).toBe(2);
  });

  it("produces non-negative and non-decreasing relativeTimestampMs", () => {
    const recorder = new ReplayRecorder("eng-003");
    const e0 = recorder.record({ eventType: "phase_start", target: "t" });
    const e1 = recorder.record({ eventType: "exploit_attempt", target: "t" });

    expect(e0.relativeTimestampMs).toBeGreaterThanOrEqual(0);
    expect(e1.relativeTimestampMs).toBeGreaterThanOrEqual(e0.relativeTimestampMs);
  });

  it("recordPhaseStart and recordPhaseComplete produce correct events", () => {
    const recorder = new ReplayRecorder("eng-004");
    const start = recorder.recordPhaseStart("application_compromise", "https://target.com");
    const complete = recorder.recordPhaseComplete("application_compromise", "https://target.com", 3);

    expect(start.eventType).toBe("phase_start");
    expect(start.phase).toBe(1);
    expect(start.phaseName).toBe("application_compromise");

    expect(complete.eventType).toBe("phase_complete");
    expect(complete.outcome).toBe("success");
    expect(complete.evidenceSummary).toContain("3 findings");
  });

  it("recordExploitAttempt sets correct phase and eventType", () => {
    const recorder = new ReplayRecorder("eng-005");
    const success = recorder.recordExploitAttempt({
      target: "https://target.com/login",
      technique: "SQL Injection",
      category: "sqli",
      mitreId: "T1190",
      success: true,
      evidence: "UNION SELECT returned 200",
    });

    expect(success.eventType).toBe("exploit_success");
    expect(success.phase).toBe(1);
    expect(success.phaseName).toBe("application_compromise");
    expect(success.outcome).toBe("success");

    const failure = recorder.recordExploitAttempt({
      target: "https://target.com/api",
      technique: "XSS",
      category: "xss",
      mitreId: "T1059.007",
      success: false,
      evidence: "WAF blocked",
    });

    expect(failure.eventType).toBe("exploit_attempt");
    expect(failure.outcome).toBe("failure");
  });

  it("recordCredentialExtracted with isInferred=true sets credential_inferred", () => {
    const recorder = new ReplayRecorder("eng-006");
    const event = recorder.recordCredentialExtracted({
      target: "https://target.com",
      credentialType: "database",
      credentialId: "cred-db-001",
      source: "config_file",
      isInferred: true,
    });

    expect(event.eventType).toBe("credential_inferred");
    expect(event.phase).toBe(2);
    expect(event.credentialsHarvested).toContain("cred-db-001");
  });

  it("recordPivotAttempt success produces pivot_success event", () => {
    const recorder = new ReplayRecorder("eng-007");
    const event = recorder.recordPivotAttempt({
      target: "10.0.0.5:445",
      technique: "SMB Relay",
      protocol: "smb",
      mitreId: "T1021.002",
      success: true,
      accessLevel: "admin",
      hostsDiscovered: ["10.0.0.6"],
    });

    expect(event.eventType).toBe("pivot_success");
    expect(event.phase).toBe(5);
    expect(event.outcome).toBe("success");
    expect(event.hostsDiscovered).toContain("10.0.0.6");
  });

  it("getEvents filters by phase", () => {
    const recorder = new ReplayRecorder("eng-008");
    recorder.recordPhaseStart("application_compromise", "t");
    recorder.recordExploitAttempt({
      target: "t", technique: "sqli", category: "sqli",
      mitreId: "T1190", success: true, evidence: "ok",
    });
    recorder.recordPivotAttempt({
      target: "10.0.0.1", technique: "smb", protocol: "smb",
      mitreId: "T1021.002", success: true, accessLevel: "user",
    });

    const phase1 = recorder.getEvents({ phase: 1 });
    const phase5 = recorder.getEvents({ phase: 5 });
    expect(phase1.length).toBeGreaterThanOrEqual(2);
    expect(phase5).toHaveLength(1);
  });

  it("getEvents filters by outcome", () => {
    const recorder = new ReplayRecorder("eng-009");
    recorder.recordExploitAttempt({
      target: "t", technique: "sqli", category: "sqli",
      mitreId: "T1190", success: true, evidence: "ok",
    });
    recorder.recordExploitAttempt({
      target: "t", technique: "xss", category: "xss",
      mitreId: "T1059.007", success: false, evidence: "blocked",
    });

    const successes = recorder.getEvents({ outcome: "success" });
    const failures = recorder.getEvents({ outcome: "failure" });
    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(1);
  });

  it("getSnapshotAt returns correct subset of events", () => {
    const recorder = new ReplayRecorder("eng-010");
    recorder.record({ eventType: "phase_start", target: "t", outcome: "partial" });
    recorder.recordExploitAttempt({
      target: "host-a", technique: "sqli", category: "sqli",
      mitreId: "T1190", success: true, evidence: "ok",
    });
    recorder.recordCredentialExtracted({
      target: "host-a", credentialType: "db", credentialId: "cred-1",
      source: "config", isInferred: false,
    });
    recorder.recordPivotAttempt({
      target: "host-b", technique: "smb", protocol: "smb",
      mitreId: "T1021.002", success: true, accessLevel: "admin",
    });

    const snap = recorder.getSnapshotAt(1);
    expect(snap.events).toHaveLength(2);
    expect(snap.hostsReached).toContain("host-a");

    const fullSnap = recorder.getSnapshotAt(3);
    expect(fullSnap.events).toHaveLength(4);
    expect(fullSnap.credentialCount).toBe(1);
  });

  it("finalize() builds a complete manifest with summary", () => {
    const recorder = new ReplayRecorder("eng-011");
    recorder.recordPhaseStart("application_compromise", "https://target.com");
    recorder.recordExploitAttempt({
      target: "https://target.com", technique: "sqli", category: "sqli",
      mitreId: "T1190", success: true, evidence: "200 OK",
    });
    recorder.recordCredentialExtracted({
      target: "https://target.com", credentialType: "api_key", credentialId: "key-1",
      source: "response_body", isInferred: false,
    });
    recorder.recordPhaseComplete("application_compromise", "https://target.com", 2);

    const manifest = recorder.finalize();

    expect(manifest.engagementId).toBe("eng-011");
    expect(manifest.events).toHaveLength(4);
    expect(manifest.totalDurationMs).toBeGreaterThanOrEqual(0);
    expect(manifest.startedAt).toBeDefined();
    expect(manifest.completedAt).toBeDefined();
    expect(manifest.summary.phasesCompleted).toContain(1);
  });

  it("summary counts unique credentials and unique hosts", () => {
    const recorder = new ReplayRecorder("eng-012");
    recorder.recordCredentialExtracted({
      target: "host-a", credentialType: "ssh", credentialId: "cred-1",
      source: "file", isInferred: false,
    });
    recorder.recordCredentialExtracted({
      target: "host-a", credentialType: "db", credentialId: "cred-2",
      source: "env", isInferred: false,
    });
    recorder.recordCredentialExtracted({
      target: "host-b", credentialType: "ssh", credentialId: "cred-1",
      source: "reuse", isInferred: false,
    });

    const manifest = recorder.finalize();
    // cred-1 appears twice but should be counted once (unique)
    expect(manifest.summary.credentialsHarvested).toBe(2);
    // host-a and host-b both have successful outcomes
    expect(manifest.summary.uniqueHostsReached).toBe(2);
  });
});
