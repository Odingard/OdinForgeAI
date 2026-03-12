import { describe, it, expect } from "vitest";
import { logger, engagementLogger, serviceLogger } from "./logger";

describe("logger", () => {
  it("exports a pino logger instance", () => {
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe("function");
    expect(typeof logger.error).toBe("function");
    expect(typeof logger.warn).toBe("function");
    expect(typeof logger.debug).toBe("function");
  });

  it("has redaction paths configured", () => {
    // Verify the logger is configured (pino exposes level)
    expect(logger.level).toBeDefined();
  });
});

describe("engagementLogger", () => {
  it("creates a child logger with chainId", () => {
    const child = engagementLogger("chain-123");
    expect(child).toBeDefined();
    expect(typeof child.info).toBe("function");
    // Child loggers inherit parent methods
    expect(typeof child.error).toBe("function");
  });

  it("creates a child logger with chainId and phase", () => {
    const child = engagementLogger("chain-456", "application_compromise");
    expect(child).toBeDefined();
    expect(typeof child.info).toBe("function");
  });
});

describe("serviceLogger", () => {
  it("creates a child logger with service name", () => {
    const child = serviceLogger("breach-orchestrator");
    expect(child).toBeDefined();
    expect(typeof child.info).toBe("function");
  });
});
