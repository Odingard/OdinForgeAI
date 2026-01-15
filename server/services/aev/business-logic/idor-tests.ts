/**
 * IDOR (Insecure Direct Object Reference) Test Module
 * 
 * Tests for unauthorized access to objects by modifying identifiers.
 */

import { createHash } from "crypto";

export interface IdorTestConfig {
  baseUrl: string;
  authToken?: string;
  targetUserId?: string;
  endpoints?: EndpointConfig[];
  headers?: Record<string, string>;
}

interface EndpointConfig {
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  idParam: string;
  sensitiveFields?: string[];
}

export interface IdorVulnerability {
  endpoint: string;
  type: "horizontal" | "vertical";
  severity: "medium" | "high" | "critical";
  exploitable: boolean;
  proof?: string;
  accessedData?: string[];
}

export interface IdorTestResult {
  success: boolean;
  vulnerabilities: IdorVulnerability[];
  testedEndpoints: number;
  evidence: string;
  proofArtifacts: ProofArtifact[];
  businessImpact?: string;
  executionTimeMs: number;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

const COMMON_IDOR_ENDPOINTS: EndpointConfig[] = [
  { path: "/api/users/{id}", method: "GET", idParam: "id", sensitiveFields: ["email", "phone", "address"] },
  { path: "/api/users/{id}/profile", method: "GET", idParam: "id", sensitiveFields: ["email", "ssn", "dob"] },
  { path: "/api/orders/{id}", method: "GET", idParam: "id", sensitiveFields: ["items", "total", "address"] },
  { path: "/api/invoices/{id}", method: "GET", idParam: "id", sensitiveFields: ["amount", "items"] },
  { path: "/api/documents/{id}", method: "GET", idParam: "id", sensitiveFields: ["content", "filename"] },
  { path: "/api/messages/{id}", method: "GET", idParam: "id", sensitiveFields: ["content", "sender"] },
  { path: "/api/payments/{id}", method: "GET", idParam: "id", sensitiveFields: ["amount", "card_last4"] },
  { path: "/api/accounts/{id}", method: "GET", idParam: "id", sensitiveFields: ["balance", "transactions"] },
];

export class IdorTestModule {
  async testEndpoint(
    config: IdorTestConfig,
    endpoint: EndpointConfig,
    targetId: string
  ): Promise<IdorVulnerability | null> {
    const url = new URL(
      endpoint.path.replace(`{${endpoint.idParam}}`, targetId),
      config.baseUrl
    );

    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    try {
      const response = await fetch(url.toString(), {
        method: endpoint.method,
        headers,
      });

      if (response.status === 200) {
        const body = await response.json();
        const accessedFields = this.findSensitiveFields(body, endpoint.sensitiveFields || []);

        if (accessedFields.length > 0) {
          return {
            endpoint: endpoint.path,
            type: "horizontal",
            severity: this.determineSeverity(accessedFields),
            exploitable: true,
            proof: `Accessed ${accessedFields.length} sensitive fields from unauthorized object`,
            accessedData: accessedFields,
          };
        }

        return {
          endpoint: endpoint.path,
          type: "horizontal",
          severity: "medium",
          exploitable: true,
          proof: "Object accessed but no sensitive fields detected",
        };
      }

      if (response.status === 403 || response.status === 401) {
        return null;
      }

      return null;
    } catch {
      return null;
    }
  }

  async testIdEnumeration(
    config: IdorTestConfig,
    endpoint: EndpointConfig,
    startId: number,
    count: number = 10
  ): Promise<IdorVulnerability | null> {
    const accessibleIds: number[] = [];

    for (let id = startId; id < startId + count; id++) {
      const result = await this.testEndpoint(config, endpoint, id.toString());
      if (result?.exploitable) {
        accessibleIds.push(id);
      }
    }

    if (accessibleIds.length > 1) {
      return {
        endpoint: endpoint.path,
        type: "horizontal",
        severity: "high",
        exploitable: true,
        proof: `Enumerable IDs: found ${accessibleIds.length} accessible objects`,
        accessedData: accessibleIds.map(String),
      };
    }

    return null;
  }

  async testUuidGuessing(
    config: IdorTestConfig,
    endpoint: EndpointConfig,
    knownUuids: string[]
  ): Promise<IdorVulnerability | null> {
    const accessibleUuids: string[] = [];

    for (const uuid of knownUuids) {
      const result = await this.testEndpoint(config, endpoint, uuid);
      if (result?.exploitable) {
        accessibleUuids.push(uuid);
      }
    }

    if (accessibleUuids.length > 0) {
      return {
        endpoint: endpoint.path,
        type: "horizontal",
        severity: "high",
        exploitable: true,
        proof: `UUID-based IDOR: ${accessibleUuids.length} objects accessible`,
        accessedData: accessibleUuids.map(u => u.substring(0, 8) + "..."),
      };
    }

    return null;
  }

  async testVerticalEscalation(
    config: IdorTestConfig,
    adminEndpoint: string
  ): Promise<IdorVulnerability | null> {
    const url = new URL(adminEndpoint, config.baseUrl);
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    try {
      const response = await fetch(url.toString(), { headers });

      if (response.status === 200) {
        return {
          endpoint: adminEndpoint,
          type: "vertical",
          severity: "critical",
          exploitable: true,
          proof: "Non-admin user accessed admin endpoint",
        };
      }

      return null;
    } catch {
      return null;
    }
  }

  async runFullTest(config: IdorTestConfig): Promise<IdorTestResult> {
    const startTime = Date.now();
    const vulnerabilities: IdorVulnerability[] = [];
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];

    const endpoints = config.endpoints || COMMON_IDOR_ENDPOINTS;
    let testedEndpoints = 0;

    for (const endpoint of endpoints) {
      testedEndpoints++;

      if (config.targetUserId) {
        const result = await this.testEndpoint(config, endpoint, config.targetUserId);
        if (result) {
          vulnerabilities.push(result);
          evidence.push(`IDOR at ${endpoint.path}: ${result.proof}`);
          
          proofArtifacts.push({
            type: "idor_horizontal",
            description: `Horizontal IDOR at ${endpoint.path}`,
            data: JSON.stringify({
              endpoint: endpoint.path,
              targetId: config.targetUserId,
              accessedFields: result.accessedData,
            }),
            hash: createHash("sha256").update(endpoint.path + config.targetUserId).digest("hex"),
            capturedAt: new Date(),
          });
        }
      }

      if (endpoint.path.match(/\{id\}/) && config.targetUserId?.match(/^\d+$/)) {
        const enumResult = await this.testIdEnumeration(
          config,
          endpoint,
          parseInt(config.targetUserId, 10),
          5
        );
        if (enumResult) {
          vulnerabilities.push(enumResult);
          evidence.push(`ID enumeration at ${endpoint.path}`);
        }
      }
    }

    const adminEndpoints = ["/api/admin/users", "/api/admin/config", "/admin/dashboard"];
    for (const adminEp of adminEndpoints) {
      const vertResult = await this.testVerticalEscalation(config, adminEp);
      if (vertResult) {
        vulnerabilities.push(vertResult);
        evidence.push(`Vertical escalation: ${adminEp}`);
        
        proofArtifacts.push({
          type: "idor_vertical",
          description: `Vertical IDOR at ${adminEp}`,
          data: adminEp,
          hash: createHash("sha256").update(adminEp).digest("hex"),
          capturedAt: new Date(),
        });
      }
    }

    const success = vulnerabilities.length > 0;
    const businessImpact = success
      ? this.assessBusinessImpact(vulnerabilities)
      : undefined;

    return {
      success,
      vulnerabilities,
      testedEndpoints,
      evidence: evidence.join("; "),
      proofArtifacts,
      businessImpact,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private findSensitiveFields(obj: any, sensitivePatterns: string[]): string[] {
    const found: string[] = [];

    const check = (o: any, path: string = "") => {
      if (!o || typeof o !== "object") return;

      for (const key of Object.keys(o)) {
        const fullPath = path ? `${path}.${key}` : key;
        
        if (sensitivePatterns.some(p => key.toLowerCase().includes(p.toLowerCase()))) {
          found.push(fullPath);
        }

        if (typeof o[key] === "object") {
          check(o[key], fullPath);
        }
      }
    };

    check(obj);
    return found;
  }

  private determineSeverity(fields: string[]): "medium" | "high" | "critical" {
    const criticalPatterns = ["ssn", "password", "card", "credit", "secret", "private"];
    const highPatterns = ["email", "phone", "address", "dob", "balance"];

    for (const field of fields) {
      if (criticalPatterns.some(p => field.toLowerCase().includes(p))) {
        return "critical";
      }
    }

    for (const field of fields) {
      if (highPatterns.some(p => field.toLowerCase().includes(p))) {
        return "high";
      }
    }

    return "medium";
  }

  private assessBusinessImpact(vulnerabilities: IdorVulnerability[]): string {
    const hasVertical = vulnerabilities.some(v => v.type === "vertical");
    const hasCritical = vulnerabilities.some(v => v.severity === "critical");

    if (hasVertical) {
      return "Privilege escalation allows unauthorized admin access";
    }

    if (hasCritical) {
      return "Exposure of highly sensitive personal/financial data";
    }

    return "Unauthorized access to user data across accounts";
  }
}
