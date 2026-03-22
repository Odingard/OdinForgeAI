import { describe, it, expect } from "vitest";
import { makeRealHttpEvidence } from "./real-evidence";

describe("makeRealHttpEvidence", () => {
  const validFields = {
    requestPayload: "' OR '1'='1",
    targetUrl: "https://example.com/api/users",
    method: "POST" as const,
    statusCode: 200,
    rawResponseBody: '{"users": []}',
    durationMs: 142,
  };

  it("creates evidence with valid fields", () => {
    const evidence = makeRealHttpEvidence(validFields);
    expect(evidence.requestPayload).toBe("' OR '1'='1");
    expect(evidence.targetUrl).toBe("https://example.com/api/users");
    expect(evidence.method).toBe("POST");
    expect(evidence.statusCode).toBe(200);
    expect(evidence.rawResponseBody).toBe('{"users": []}');
    expect(evidence.durationMs).toBe(142);
    expect(evidence.source).toBe("real_http_response");
    expect(evidence.capturedAt).toBeTruthy();
  });

  it("throws on statusCode = 0 (stub detection)", () => {
    expect(() =>
      makeRealHttpEvidence({ ...validFields, statusCode: 0 })
    ).toThrow("statusCode must be > 0");
  });

  it("throws on negative statusCode", () => {
    expect(() =>
      makeRealHttpEvidence({ ...validFields, statusCode: -1 })
    ).toThrow("statusCode must be > 0");
  });

  it("throws on empty rawResponseBody (stub detection)", () => {
    expect(() =>
      makeRealHttpEvidence({ ...validFields, rawResponseBody: "" })
    ).toThrow("rawResponseBody is empty");
  });

  it("throws on whitespace-only rawResponseBody", () => {
    expect(() =>
      makeRealHttpEvidence({ ...validFields, rawResponseBody: "   " })
    ).toThrow("rawResponseBody is empty");
  });

  it("throws on empty targetUrl", () => {
    expect(() =>
      makeRealHttpEvidence({ ...validFields, targetUrl: "" })
    ).toThrow("targetUrl is empty");
  });

  it("allows empty string requestPayload (valid for GET)", () => {
    const evidence = makeRealHttpEvidence({
      ...validFields,
      requestPayload: "",
      method: "GET",
    });
    expect(evidence.requestPayload).toBe("");
  });

  it("sets source to real_http_response (immutable)", () => {
    const evidence = makeRealHttpEvidence(validFields);
    expect(evidence.source).toBe("real_http_response");
  });

  it("sets capturedAt to ISO timestamp", () => {
    const before = new Date().toISOString();
    const evidence = makeRealHttpEvidence(validFields);
    const after = new Date().toISOString();
    expect(evidence.capturedAt >= before).toBe(true);
    expect(evidence.capturedAt <= after).toBe(true);
  });
});
