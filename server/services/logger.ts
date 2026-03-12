/**
 * OdinForge Structured Logger
 *
 * Pino-based JSON structured logging. Replaces ad-hoc console.log/warn/error
 * with machine-parseable, correlation-aware log entries.
 *
 * Rules:
 *   - authValue NEVER appears in any log at any level
 *   - displayValue is safe to log (masked)
 *   - All log entries include service name + timestamp
 *   - Engagement IDs included as correlation context
 */

import pino from "pino";

const isProduction = process.env.NODE_ENV === "production";

export const logger = pino({
  name: "odinforge",
  level: process.env.LOG_LEVEL || (isProduction ? "info" : "debug"),
  ...(isProduction
    ? {}
    : {
        transport: {
          target: "pino/file",
          options: { destination: 1 }, // stdout
        },
      }),
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  // Redact sensitive fields that should never appear in logs
  redact: {
    paths: [
      "authValue",
      "credential.authValue",
      "cred.authValue",
      "credentials[*].authValue",
      "password",
      "secret",
      "token",
      "apiKey",
      "*.password",
      "*.secret",
    ],
    censor: "[REDACTED]",
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

/**
 * Create a child logger with engagement context.
 */
export function engagementLogger(chainId: string, phase?: string) {
  return logger.child({
    chainId,
    ...(phase ? { phase } : {}),
  });
}

/**
 * Create a child logger for a specific service module.
 */
export function serviceLogger(service: string) {
  return logger.child({ service });
}
