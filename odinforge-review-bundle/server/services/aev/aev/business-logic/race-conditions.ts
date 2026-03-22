/**
 * Race Condition Test Module
 * 
 * Tests for TOCTOU (Time-of-Check to Time-of-Use) and other race conditions.
 */

import { createHash } from "crypto";

export interface RaceConditionConfig {
  targetUrl: string;
  endpoint?: string;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: Record<string, any>;
  authToken?: string;
  headers?: Record<string, string>;
  concurrentRequests?: number;
}

export interface RaceConditionVulnerability {
  type: "double_spend" | "limit_bypass" | "toctou" | "concurrent_update";
  severity: "medium" | "high" | "critical";
  exploitable: boolean;
  proof?: string;
  details?: {
    requestCount: number;
    successCount: number;
    expectedSuccesses: number;
  };
}

export interface RaceConditionResult {
  success: boolean;
  vulnerabilities: RaceConditionVulnerability[];
  requestsSent: number;
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

interface RequestResult {
  success: boolean;
  statusCode?: number;
  body?: any;
  timing: number;
}

export class RaceConditionModule {
  async sendConcurrentRequests(
    config: RaceConditionConfig,
    count: number
  ): Promise<RequestResult[]> {
    const url = new URL(config.endpoint || "/", config.targetUrl);
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const requestPromises: Promise<RequestResult>[] = [];

    for (let i = 0; i < count; i++) {
      const startTime = Date.now();
      
      requestPromises.push(
        fetch(url.toString(), {
          method: config.method || "POST",
          headers,
          body: config.body ? JSON.stringify(config.body) : undefined,
        })
          .then(async (response) => ({
            success: response.status >= 200 && response.status < 400,
            statusCode: response.status,
            body: await response.json().catch(() => null),
            timing: Date.now() - startTime,
          }))
          .catch(() => ({
            success: false,
            timing: Date.now() - startTime,
          }))
      );
    }

    return Promise.all(requestPromises);
  }

  async testDoubleSpend(config: RaceConditionConfig): Promise<RaceConditionVulnerability> {
    const spendConfig: RaceConditionConfig = {
      ...config,
      endpoint: config.endpoint || "/api/transfer",
      method: "POST",
      body: config.body || { amount: 100, recipient: "test" },
    };

    const results = await this.sendConcurrentRequests(spendConfig, config.concurrentRequests || 10);
    const successCount = results.filter(r => r.success).length;

    if (successCount > 1) {
      return {
        type: "double_spend",
        severity: "critical",
        exploitable: true,
        proof: `Double spend detected: ${successCount}/${results.length} requests succeeded`,
        details: {
          requestCount: results.length,
          successCount,
          expectedSuccesses: 1,
        },
      };
    }

    return {
      type: "double_spend",
      severity: "critical",
      exploitable: false,
      proof: "Race condition not detected in double spend test",
    };
  }

  async testLimitBypass(
    config: RaceConditionConfig,
    expectedLimit: number
  ): Promise<RaceConditionVulnerability> {
    const limitConfig: RaceConditionConfig = {
      ...config,
      method: "POST",
    };

    const requestCount = expectedLimit + 5;
    const results = await this.sendConcurrentRequests(limitConfig, requestCount);
    const successCount = results.filter(r => r.success).length;

    if (successCount > expectedLimit) {
      return {
        type: "limit_bypass",
        severity: "high",
        exploitable: true,
        proof: `Limit bypass: ${successCount} successes vs ${expectedLimit} limit`,
        details: {
          requestCount,
          successCount,
          expectedSuccesses: expectedLimit,
        },
      };
    }

    return {
      type: "limit_bypass",
      severity: "high",
      exploitable: false,
      proof: `Rate limit properly enforced: ${successCount}/${expectedLimit}`,
    };
  }

  async testToctou(
    config: RaceConditionConfig,
    checkEndpoint: string,
    useEndpoint: string
  ): Promise<RaceConditionVulnerability> {
    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const attacks: Promise<RequestResult>[] = [];

    for (let i = 0; i < (config.concurrentRequests || 10); i++) {
      const startTime = Date.now();
      
      attacks.push(
        (async () => {
          await fetch(new URL(checkEndpoint, config.targetUrl).toString(), {
            method: "GET",
            headers,
          });

          const response = await fetch(new URL(useEndpoint, config.targetUrl).toString(), {
            method: "POST",
            headers,
            body: config.body ? JSON.stringify(config.body) : undefined,
          });

          return {
            success: response.status >= 200 && response.status < 400,
            statusCode: response.status,
            body: await response.json().catch(() => null),
            timing: Date.now() - startTime,
          };
        })()
      );
    }

    const results = await Promise.all(attacks);
    const successCount = results.filter(r => r.success).length;

    if (successCount > 1) {
      return {
        type: "toctou",
        severity: "high",
        exploitable: true,
        proof: `TOCTOU race: ${successCount} concurrent uses succeeded`,
        details: {
          requestCount: results.length,
          successCount,
          expectedSuccesses: 1,
        },
      };
    }

    return {
      type: "toctou",
      severity: "high",
      exploitable: false,
      proof: "TOCTOU race condition not detected",
    };
  }

  async testConcurrentUpdate(
    config: RaceConditionConfig,
    resourceId: string
  ): Promise<RaceConditionVulnerability> {
    const updateConfig: RaceConditionConfig = {
      ...config,
      endpoint: config.endpoint?.replace("{id}", resourceId) || `/api/resources/${resourceId}`,
      method: "PATCH",
    };

    const bodies = Array.from({ length: config.concurrentRequests || 5 }, (_, i) => ({
      ...config.body,
      value: `concurrent-update-${i}`,
    }));

    const headers: Record<string, string> = {
      ...config.headers,
      "Content-Type": "application/json",
    };

    if (config.authToken) {
      headers["Authorization"] = `Bearer ${config.authToken}`;
    }

    const url = new URL(updateConfig.endpoint || "/", config.targetUrl);
    
    const requests = bodies.map(body =>
      fetch(url.toString(), {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      })
        .then(async (r) => ({
          success: r.status >= 200 && r.status < 400,
          statusCode: r.status,
          body: await r.json().catch(() => null),
          timing: 0,
        }))
        .catch(() => ({ success: false, timing: 0 }))
    );

    const results = await Promise.all(requests);
    const successCount = results.filter(r => r.success).length;

    if (successCount > 1) {
      const getResponse = await fetch(url.toString(), { headers });
      const finalState = await getResponse.json().catch(() => null);

      return {
        type: "concurrent_update",
        severity: "medium",
        exploitable: true,
        proof: `Concurrent updates: ${successCount} succeeded, potential data corruption`,
        details: {
          requestCount: results.length,
          successCount,
          expectedSuccesses: 1,
        },
      };
    }

    return {
      type: "concurrent_update",
      severity: "medium",
      exploitable: false,
      proof: "Concurrent update protection in place",
    };
  }

  async runFullTest(config: RaceConditionConfig): Promise<RaceConditionResult> {
    const startTime = Date.now();
    const vulnerabilities: RaceConditionVulnerability[] = [];
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];
    let totalRequests = 0;

    const doubleSpendResult = await this.testDoubleSpend({
      ...config,
      endpoint: "/api/transactions",
      body: { amount: 100, type: "transfer" },
    });
    vulnerabilities.push(doubleSpendResult);
    totalRequests += config.concurrentRequests || 10;
    
    if (doubleSpendResult.exploitable) {
      evidence.push(`Double spend: ${doubleSpendResult.proof}`);
      proofArtifacts.push({
        type: "race_double_spend",
        description: "Double spend race condition",
        data: JSON.stringify(doubleSpendResult.details),
        hash: createHash("sha256").update(doubleSpendResult.proof || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const limitResult = await this.testLimitBypass(
      { ...config, endpoint: "/api/limited-action" },
      5
    );
    vulnerabilities.push(limitResult);
    totalRequests += 10;
    
    if (limitResult.exploitable) {
      evidence.push(`Limit bypass: ${limitResult.proof}`);
    }

    const toctouResult = await this.testToctou(
      config,
      "/api/balance/check",
      "/api/balance/withdraw"
    );
    vulnerabilities.push(toctouResult);
    totalRequests += (config.concurrentRequests || 10) * 2;
    
    if (toctouResult.exploitable) {
      evidence.push(`TOCTOU: ${toctouResult.proof}`);
      proofArtifacts.push({
        type: "race_toctou",
        description: "Time-of-check to time-of-use race",
        data: JSON.stringify(toctouResult.details),
        hash: createHash("sha256").update(toctouResult.proof || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const exploitable = vulnerabilities.filter(v => v.exploitable);
    const success = exploitable.length > 0;

    const businessImpact = success
      ? this.assessBusinessImpact(exploitable)
      : undefined;

    return {
      success,
      vulnerabilities,
      requestsSent: totalRequests,
      evidence: evidence.join("; "),
      proofArtifacts,
      businessImpact,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private assessBusinessImpact(vulnerabilities: RaceConditionVulnerability[]): string {
    const types = vulnerabilities.map(v => v.type);

    if (types.includes("double_spend")) {
      return "Financial loss through duplicate transactions";
    }

    if (types.includes("toctou")) {
      return "Resource manipulation through race conditions";
    }

    if (types.includes("limit_bypass")) {
      return "Rate limiting bypass enabling abuse";
    }

    return "Data integrity issues from concurrent operations";
  }
}
