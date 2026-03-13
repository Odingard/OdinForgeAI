/**
 * BFLA (Broken Function Level Authorization) Payloads
 *
 * Tests for endpoints that fail to enforce proper authorization checks
 * at the function/action level — e.g., a regular user accessing admin endpoints.
 */

import type { Payload, PayloadSet } from "./payload-types";

function generatePayloadId(category: string, technique: string, index: number): string {
  return `${category}-${technique}-${index}`;
}

// ─── HTTP Method Tampering ───────────────────────────────────────────

const methodTamperingPayloads: Payload[] = [
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 1),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "low",
    value: "GET",
    description: "Access write endpoint via GET (method downgrade)",
    expectedBehavior: "Server should reject wrong HTTP method with 405",
    successIndicators: ["200", "201", "204", "302"],
    failureIndicators: ["405", "Method Not Allowed"],
    applicableContexts: ["url_param"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 2),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "low",
    value: "OPTIONS",
    description: "Probe allowed methods via OPTIONS",
    expectedBehavior: "Server should not expose admin methods to non-admin",
    successIndicators: ["Allow:", "DELETE", "PUT", "PATCH"],
    failureIndicators: ["403", "401"],
    applicableContexts: ["url_param"],
  },
];

// ─── Admin Path Probing ──────────────────────────────────────────────

const adminPathPayloads: Payload[] = [
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 3),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "safe",
    value: "/admin",
    description: "Probe for admin panel access",
    expectedBehavior: "Should return 401/403 for non-admin users",
    successIndicators: ["admin", "dashboard", "panel", "users", "settings"],
    failureIndicators: ["401", "403", "404", "Forbidden", "Unauthorized"],
    applicableContexts: ["path"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 4),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "safe",
    value: "/api/admin",
    description: "Probe for admin API access",
    expectedBehavior: "Should return 401/403 for non-admin users",
    successIndicators: ["users", "config", "settings", "\"data\""],
    failureIndicators: ["401", "403", "404", "Forbidden"],
    applicableContexts: ["path"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 5),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "safe",
    value: "/api/v1/users",
    description: "Probe for user enumeration endpoint",
    expectedBehavior: "Should not list all users to non-admin",
    successIndicators: ["\"email\"", "\"username\"", "\"users\"", "\"role\""],
    failureIndicators: ["401", "403", "404"],
    applicableContexts: ["path"],
  },
];

// ─── Privilege Escalation via Parameter ──────────────────────────────

const privescPayloads: Payload[] = [
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 6),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "low",
    value: '{"role":"admin"}',
    description: "Mass assignment: inject admin role in JSON body",
    expectedBehavior: "Server should ignore unauthorized role field",
    successIndicators: ["\"role\":\"admin\"", "\"isAdmin\":true", "admin"],
    failureIndicators: ["403", "400", "\"role\":\"user\"", "validation"],
    applicableContexts: ["body_param"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 7),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "low",
    value: '{"isAdmin":true,"verified":true}',
    description: "Mass assignment: inject privilege flags",
    expectedBehavior: "Server should not accept privilege escalation fields",
    successIndicators: ["\"isAdmin\":true", "\"verified\":true", "admin"],
    failureIndicators: ["403", "400", "ignored", "validation"],
    applicableContexts: ["body_param"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 8),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "low",
    value: "role=admin&isAdmin=true",
    description: "Mass assignment via form-encoded body",
    expectedBehavior: "Server should reject unauthorized fields",
    successIndicators: ["admin", "success", "updated"],
    failureIndicators: ["403", "400", "denied"],
    applicableContexts: ["body_param"],
  },
];

// ─── IDOR Probing ────────────────────────────────────────────────────

const idorPayloads: Payload[] = [
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 9),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "safe",
    value: "1",
    description: "IDOR: access resource ID 1 (likely admin/first user)",
    expectedBehavior: "Should not return other user's data",
    successIndicators: ["\"email\"", "\"name\"", "\"username\"", "\"data\""],
    failureIndicators: ["403", "401", "404", "own resource only"],
    applicableContexts: ["url_param", "path"],
  },
  {
    id: generatePayloadId("mass_assignment", "parameter_pollution", 10),
    category: "mass_assignment",
    technique: "parameter_pollution",
    riskLevel: "safe",
    value: "0",
    description: "IDOR: access resource ID 0 (common edge case)",
    expectedBehavior: "Should return 404 or forbidden",
    successIndicators: ["\"email\"", "\"name\"", "\"data\"", "200"],
    failureIndicators: ["403", "404", "400"],
    applicableContexts: ["url_param", "path"],
  },
];

// ─── Exported Sets ───────────────────────────────────────────────────

export function getBflaPayloads(): Payload[] {
  return [
    ...adminPathPayloads,
    ...privescPayloads,
    ...idorPayloads,
  ];
}

export function getMethodTamperingPayloads(): Payload[] {
  return methodTamperingPayloads;
}

export function getMassAssignmentPayloads(): Payload[] {
  return privescPayloads;
}

export const bflaPayloadSet: PayloadSet = {
  category: "mass_assignment",
  name: "BFLA & Mass Assignment",
  description: "Tests for Broken Function Level Authorization, mass assignment, IDOR, and privilege escalation",
  payloads: [
    ...methodTamperingPayloads,
    ...adminPathPayloads,
    ...privescPayloads,
    ...idorPayloads,
  ],
};
