import { describe, it, expect } from "vitest";
import {
  diffResponse,
  classifyAnomaly,
  type ResponseFingerprint,
  type ResponseDiff,
} from "./response-differ";

function makeFingerprint(overrides: Partial<ResponseFingerprint> = {}): ResponseFingerprint {
  return {
    statusCode: 200,
    bodyLength: 1000,
    responseTimeMs: 100,
    contentType: "text/html",
    headers: { "content-type": "text/html" },
    structureHash: "html,head,body,div",
    body: "<html><head></head><body><div>Hello</div></body></html>",
    ...overrides,
  };
}

describe("diffResponse", () => {
  it("returns zero anomaly score for identical fingerprints", () => {
    const baseline = makeFingerprint();
    const injected = makeFingerprint();
    const diff = diffResponse(baseline, injected);

    expect(diff.anomalyScore).toBe(0);
    expect(diff.statusCodeChanged).toBe(false);
    expect(diff.structureChanged).toBe(false);
    expect(diff.anomalyReasons).toHaveLength(0);
  });

  it("detects status code change from 200 to 500 as server error (+40)", () => {
    const baseline = makeFingerprint({ statusCode: 200 });
    const injected = makeFingerprint({ statusCode: 500 });
    const diff = diffResponse(baseline, injected);

    expect(diff.statusCodeChanged).toBe(true);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(40);
    expect(diff.anomalyReasons.some(r => r.includes("server error"))).toBe(true);
  });

  it("detects redirect/forbidden status change (+20)", () => {
    const baseline = makeFingerprint({ statusCode: 200 });
    const injected = makeFingerprint({ statusCode: 403 });
    const diff = diffResponse(baseline, injected);

    expect(diff.statusCodeChanged).toBe(true);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(20);
    expect(diff.anomalyReasons.some(r => r.includes("redirect/forbidden"))).toBe(true);
  });

  it("detects large body length change (+25)", () => {
    const baseline = makeFingerprint({ bodyLength: 1000 });
    const injected = makeFingerprint({ bodyLength: 2000 });
    const diff = diffResponse(baseline, injected);

    expect(diff.bodyLengthDelta).toBe(1000);
    expect(diff.bodyLengthDeltaPercent).toBe(1.0);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(25);
  });

  it("detects significant timing increase >3s (+35)", () => {
    const baseline = makeFingerprint({ responseTimeMs: 100 });
    const injected = makeFingerprint({ responseTimeMs: 5200 });
    const diff = diffResponse(baseline, injected);

    expect(diff.timingDelta).toBe(5100);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(35);
    expect(diff.anomalyReasons.some(r => r.includes("time-based blind injection"))).toBe(true);
  });

  it("detects moderate timing increase 1-3s (+15)", () => {
    const baseline = makeFingerprint({ responseTimeMs: 100 });
    const injected = makeFingerprint({ responseTimeMs: 1500 });
    const diff = diffResponse(baseline, injected);

    expect(diff.timingDelta).toBe(1400);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(15);
  });

  it("detects new SQL error patterns in injected body (+30)", () => {
    const baseline = makeFingerprint({ body: "Normal page content" });
    const injected = makeFingerprint({
      body: "You have an error in your SQL syntax near '...'",
    });
    const diff = diffResponse(baseline, injected);

    expect(diff.newContentPatterns.length).toBeGreaterThan(0);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(30);
  });

  it("detects structure hash change (+20)", () => {
    const baseline = makeFingerprint({ structureHash: "html,head,body,div" });
    const injected = makeFingerprint({ structureHash: "html,head,body,div,script,pre" });
    const diff = diffResponse(baseline, injected);

    expect(diff.structureChanged).toBe(true);
    expect(diff.anomalyScore).toBeGreaterThanOrEqual(20);
  });

  it("does not flag structure change when both hashes are empty", () => {
    const baseline = makeFingerprint({ structureHash: "" });
    const injected = makeFingerprint({ structureHash: "" });
    const diff = diffResponse(baseline, injected);

    expect(diff.structureChanged).toBe(false);
  });

  it("caps anomaly score at 100", () => {
    const baseline = makeFingerprint({
      statusCode: 200,
      bodyLength: 100,
      responseTimeMs: 50,
      body: "Normal",
      structureHash: "a",
    });
    const injected = makeFingerprint({
      statusCode: 500,
      bodyLength: 10000,
      responseTimeMs: 8000,
      body: "You have an error in your SQL syntax",
      structureHash: "b,c,d",
    });
    const diff = diffResponse(baseline, injected);
    expect(diff.anomalyScore).toBeLessThanOrEqual(100);
  });

  it("detects command output patterns in response", () => {
    const baseline = makeFingerprint({ body: "Normal response" });
    const injected = makeFingerprint({ body: "uid=1000(www-data) gid=1000(www-data)" });
    const diff = diffResponse(baseline, injected);

    expect(diff.newContentPatterns).toContain("Command output");
  });

  it("detects stack trace patterns", () => {
    const baseline = makeFingerprint({ body: "OK" });
    const injected = makeFingerprint({ body: "Error\n  at module.js:42\n  at process.js:10" });
    const diff = diffResponse(baseline, injected);

    expect(diff.newContentPatterns).toContain("Stack trace");
  });

  it("detects path disclosure patterns", () => {
    const baseline = makeFingerprint({ body: "404 Not Found" });
    const injected = makeFingerprint({ body: "root:x:0:0:root:/root:/bin/bash" });
    const diff = diffResponse(baseline, injected);

    expect(diff.newContentPatterns).toContain("Path disclosure");
  });
});

describe("classifyAnomaly", () => {
  it("returns no anomaly for low score", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: false,
      bodyLengthDelta: 10,
      bodyLengthDeltaPercent: 0.01,
      timingDelta: 50,
      structureChanged: false,
      headersDiff: [],
      newContentPatterns: [],
      anomalyScore: 10,
      anomalyReasons: [],
    };
    const result = classifyAnomaly(diff);
    expect(result.isAnomaly).toBe(false);
    expect(result.type).toBe("none");
  });

  it("classifies error_based when new content patterns present", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: true,
      bodyLengthDelta: 500,
      bodyLengthDeltaPercent: 0.5,
      timingDelta: 100,
      structureChanged: false,
      headersDiff: [],
      newContentPatterns: ["SQL error"],
      anomalyScore: 70,
      anomalyReasons: ["SQL error detected"],
    };
    const result = classifyAnomaly(diff);
    expect(result.isAnomaly).toBe(true);
    expect(result.type).toBe("error_based");
    expect(result.confidence).toBeGreaterThan(0);
  });

  it("classifies time_based when timing delta >3s", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: false,
      bodyLengthDelta: 0,
      bodyLengthDeltaPercent: 0,
      timingDelta: 5100,
      structureChanged: false,
      headersDiff: [],
      newContentPatterns: [],
      anomalyScore: 35,
      anomalyReasons: ["Response delayed"],
    };
    const result = classifyAnomaly(diff);
    expect(result.isAnomaly).toBe(true);
    expect(result.type).toBe("time_based");
  });

  it("classifies structural when structure changed", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: false,
      bodyLengthDelta: 200,
      bodyLengthDeltaPercent: 0.2,
      timingDelta: 50,
      structureChanged: true,
      headersDiff: [],
      newContentPatterns: [],
      anomalyScore: 40,
      anomalyReasons: ["Structure changed"],
    };
    const result = classifyAnomaly(diff);
    expect(result.isAnomaly).toBe(true);
    expect(result.type).toBe("structural");
  });

  it("classifies reflection when status+body changed", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: true,
      bodyLengthDelta: 500,
      bodyLengthDeltaPercent: 0.5,
      timingDelta: 50,
      structureChanged: false,
      headersDiff: [],
      newContentPatterns: [],
      anomalyScore: 45,
      anomalyReasons: ["Status changed", "Body length changed"],
    };
    const result = classifyAnomaly(diff);
    expect(result.isAnomaly).toBe(true);
    expect(result.type).toBe("reflection");
  });

  it("caps confidence at 95", () => {
    const diff: ResponseDiff = {
      statusCodeChanged: true,
      bodyLengthDelta: 5000,
      bodyLengthDeltaPercent: 5.0,
      timingDelta: 6000,
      structureChanged: true,
      headersDiff: [],
      newContentPatterns: ["SQL error", "Stack trace"],
      anomalyScore: 100,
      anomalyReasons: [],
    };
    const result = classifyAnomaly(diff);
    expect(result.confidence).toBeLessThanOrEqual(95);
  });
});
