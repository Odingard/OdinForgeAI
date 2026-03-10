import { describe, it, expect } from "vitest";
import { buildPayloadRequest, type PayloadExecutionContext } from "./payload-types";

function makeCtx(location: string, overrides: Partial<PayloadExecutionContext> = {}): PayloadExecutionContext {
  return {
    targetUrl: "http://example.com/api/test",
    parameterName: "q",
    parameterLocation: location as any,
    httpMethod: "GET",
    ...overrides,
  };
}

describe("buildPayloadRequest", () => {
  it("url_param: injects payload as query parameter", () => {
    const result = buildPayloadRequest(makeCtx("url_param"), "' OR 1=1--");
    expect(result.url).toContain("q=");
    // URLSearchParams uses + for spaces, verify payload is present
    expect(result.url).toContain("1%3D1--");
  });

  it("body_param: injects payload in JSON body", () => {
    const result = buildPayloadRequest(makeCtx("body_param"), "admin");
    expect(result.body).toBeDefined();
    const parsed = JSON.parse(result.body!);
    expect(parsed.q).toBe("admin");
    expect(result.headers?.["Content-Type"]).toBe("application/json");
  });

  it("header: injects payload as custom header", () => {
    const result = buildPayloadRequest(makeCtx("header", { parameterName: "X-Forwarded-For" }), "127.0.0.1");
    expect(result.headers?.["X-Forwarded-For"]).toBe("127.0.0.1");
  });

  it("cookie: injects payload in Cookie header", () => {
    const result = buildPayloadRequest(makeCtx("cookie", { parameterName: "session" }), "abc123");
    expect(result.headers?.Cookie).toBe("session=abc123");
  });

  it("path: replaces last path segment", () => {
    const result = buildPayloadRequest(makeCtx("path"), "../../etc/passwd");
    expect(result.url).toContain("../../etc/passwd");
    expect(result.url).not.toContain("/test");
  });

  it("unknown location: returns url unchanged", () => {
    const result = buildPayloadRequest(makeCtx("unknown_loc"), "payload");
    expect(result.url).toBe("http://example.com/api/test");
  });

  it("preserves target URL for body_param", () => {
    const result = buildPayloadRequest(makeCtx("body_param"), "test");
    expect(result.url).toBe("http://example.com/api/test");
  });
});
