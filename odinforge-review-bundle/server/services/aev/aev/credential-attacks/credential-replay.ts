/**
 * Credential Replay Attack Module
 * 
 * Tests for credential and token reuse vulnerabilities including:
 * - Token replay after revocation
 * - Cross-context token reuse
 * - Refresh token security
 * - API key scope violations
 */

import { createHash } from "crypto";

export interface CredentialReplayConfig {
  targetUrl: string;
  authEndpoint: string;
  tokenRefreshEndpoint?: string;
  protectedEndpoints: string[];
  credentials?: { username: string; password: string };
  capturedToken?: string;
  capturedRefreshToken?: string;
  apiKey?: string;
  headers?: Record<string, string>;
}

export interface TokenInfo {
  type: "bearer" | "api_key" | "session" | "refresh" | "unknown";
  value: string;
  issuedAt?: Date;
  expiresAt?: Date;
  scope?: string[];
  claims?: Record<string, any>;
}

export interface ReplayVulnerability {
  type: "token_replay" | "refresh_token_reuse" | "cross_context_reuse" | "revocation_bypass" | "scope_escalation";
  severity: "critical" | "high" | "medium" | "low";
  exploitable: boolean;
  proof?: string;
  details?: string;
}

export interface CredentialReplayResult {
  success: boolean;
  tokenInfo?: TokenInfo;
  vulnerabilities: ReplayVulnerability[];
  testedEndpoints: EndpointTestResult[];
  evidence: string;
  proofArtifacts: ProofArtifact[];
  executionTimeMs: number;
}

interface EndpointTestResult {
  endpoint: string;
  accessible: boolean;
  statusCode?: number;
  responseSnippet?: string;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

export class CredentialReplayModule {
  async analyzeToken(token: string): Promise<TokenInfo> {
    const tokenInfo: TokenInfo = {
      type: "unknown",
      value: token,
      issuedAt: new Date(),
    };

    if (token.split(".").length === 3) {
      tokenInfo.type = "bearer";
      try {
        const parts = token.split(".");
        const payload = JSON.parse(
          Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
        );
        
        tokenInfo.claims = payload;
        if (payload.iat) tokenInfo.issuedAt = new Date(payload.iat * 1000);
        if (payload.exp) tokenInfo.expiresAt = new Date(payload.exp * 1000);
        if (payload.scope) tokenInfo.scope = payload.scope.split(" ");
      } catch {}
    } else if (token.length >= 32 && /^[a-zA-Z0-9_-]+$/.test(token)) {
      tokenInfo.type = "api_key";
    } else if (token.length >= 24) {
      tokenInfo.type = "session";
    }

    return tokenInfo;
  }

  async testTokenReplay(config: CredentialReplayConfig): Promise<ReplayVulnerability> {
    if (!config.capturedToken) {
      return {
        type: "token_replay",
        severity: "high",
        exploitable: false,
        proof: "No captured token provided",
      };
    }

    const results: EndpointTestResult[] = [];

    for (const endpoint of config.protectedEndpoints) {
      try {
        const response = await fetch(endpoint, {
          headers: {
            ...config.headers,
            Authorization: `Bearer ${config.capturedToken}`,
          },
        });

        results.push({
          endpoint,
          accessible: response.status !== 401 && response.status !== 403,
          statusCode: response.status,
        });
      } catch {
        results.push({ endpoint, accessible: false });
      }
    }

    const accessibleEndpoints = results.filter(r => r.accessible);

    if (accessibleEndpoints.length > 0) {
      return {
        type: "token_replay",
        severity: "high",
        exploitable: true,
        proof: `Token grants access to ${accessibleEndpoints.length}/${results.length} endpoints`,
        details: accessibleEndpoints.map(e => e.endpoint).join(", "),
      };
    }

    return {
      type: "token_replay",
      severity: "high",
      exploitable: false,
      proof: "Token properly rejected by all endpoints",
    };
  }

  async testRefreshTokenReuse(config: CredentialReplayConfig): Promise<ReplayVulnerability> {
    if (!config.tokenRefreshEndpoint || !config.capturedRefreshToken) {
      return {
        type: "refresh_token_reuse",
        severity: "high",
        exploitable: false,
        proof: "No refresh endpoint or token provided",
      };
    }

    try {
      const refresh1 = await fetch(config.tokenRefreshEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...config.headers,
        },
        body: JSON.stringify({ refresh_token: config.capturedRefreshToken }),
      });

      if (refresh1.status !== 200) {
        return {
          type: "refresh_token_reuse",
          severity: "high",
          exploitable: false,
          proof: "Refresh token rejected (may be expired or invalid)",
        };
      }

      const refresh2 = await fetch(config.tokenRefreshEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...config.headers,
        },
        body: JSON.stringify({ refresh_token: config.capturedRefreshToken }),
      });

      if (refresh2.status === 200) {
        return {
          type: "refresh_token_reuse",
          severity: "critical",
          exploitable: true,
          proof: "Refresh token can be reused multiple times (no rotation)",
        };
      }

      return {
        type: "refresh_token_reuse",
        severity: "high",
        exploitable: false,
        proof: "Refresh token properly rotated after use",
      };
    } catch {
      return {
        type: "refresh_token_reuse",
        severity: "high",
        exploitable: false,
        proof: "Error testing refresh token reuse",
      };
    }
  }

  async testCrossContextReuse(config: CredentialReplayConfig): Promise<ReplayVulnerability> {
    if (!config.capturedToken) {
      return {
        type: "cross_context_reuse",
        severity: "high",
        exploitable: false,
        proof: "No captured token provided",
      };
    }

    const tokenInfo = await this.analyzeToken(config.capturedToken);
    
    if (tokenInfo.type === "bearer" && tokenInfo.claims) {
      const sensitivePatterns = [
        { claim: "aud", check: (v: any) => !v || v === "*" || (Array.isArray(v) && v.includes("*")) },
        { claim: "client_id", check: (v: any) => !v },
        { claim: "azp", check: (v: any) => !v },
      ];

      const violations: string[] = [];
      for (const pattern of sensitivePatterns) {
        if (pattern.check(tokenInfo.claims[pattern.claim])) {
          violations.push(`Missing or wildcard ${pattern.claim}`);
        }
      }

      if (violations.length > 0) {
        return {
          type: "cross_context_reuse",
          severity: "high",
          exploitable: true,
          proof: violations.join("; "),
          details: "Token may be valid across multiple applications/contexts",
        };
      }
    }

    const differentOrigin = config.protectedEndpoints.find(e => {
      const url = new URL(e);
      const targetUrl = new URL(config.targetUrl);
      return url.origin !== targetUrl.origin;
    });

    if (differentOrigin) {
      try {
        const response = await fetch(differentOrigin, {
          headers: {
            Authorization: `Bearer ${config.capturedToken}`,
          },
        });

        if (response.status !== 401 && response.status !== 403) {
          return {
            type: "cross_context_reuse",
            severity: "critical",
            exploitable: true,
            proof: `Token accepted at different origin: ${differentOrigin}`,
          };
        }
      } catch {}
    }

    return {
      type: "cross_context_reuse",
      severity: "high",
      exploitable: false,
      proof: "Token appears context-bound",
    };
  }

  async testRevocationBypass(config: CredentialReplayConfig): Promise<ReplayVulnerability> {
    if (!config.credentials) {
      return {
        type: "revocation_bypass",
        severity: "critical",
        exploitable: false,
        proof: "Cannot test - no credentials provided",
      };
    }

    try {
      const loginResponse = await fetch(config.authEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config.credentials),
      });

      if (loginResponse.status !== 200) {
        return {
          type: "revocation_bypass",
          severity: "critical",
          exploitable: false,
          proof: "Login failed",
        };
      }

      const loginData = await loginResponse.json();
      const token = loginData.access_token || loginData.token;

      if (!token) {
        return {
          type: "revocation_bypass",
          severity: "critical",
          exploitable: false,
          proof: "No token in login response",
        };
      }

      const preRevokeTest = await fetch(config.protectedEndpoints[0], {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (preRevokeTest.status === 401 || preRevokeTest.status === 403) {
        return {
          type: "revocation_bypass",
          severity: "critical",
          exploitable: false,
          proof: "Token not valid before revocation test",
        };
      }

      const login2Response = await fetch(config.authEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config.credentials),
      });
      
      await new Promise(r => setTimeout(r, 1000));

      const postNewLoginTest = await fetch(config.protectedEndpoints[0], {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (postNewLoginTest.status !== 401 && postNewLoginTest.status !== 403) {
        return {
          type: "revocation_bypass",
          severity: "high",
          exploitable: true,
          proof: "Old token still valid after new login (no single-session enforcement)",
        };
      }

      return {
        type: "revocation_bypass",
        severity: "critical",
        exploitable: false,
        proof: "Token properly invalidated after new session",
      };
    } catch {
      return {
        type: "revocation_bypass",
        severity: "critical",
        exploitable: false,
        proof: "Error testing revocation bypass",
      };
    }
  }

  async testScopeEscalation(config: CredentialReplayConfig): Promise<ReplayVulnerability> {
    if (!config.capturedToken) {
      return {
        type: "scope_escalation",
        severity: "high",
        exploitable: false,
        proof: "No captured token provided",
      };
    }

    const tokenInfo = await this.analyzeToken(config.capturedToken);
    const declaredScope = tokenInfo.scope || [];

    const adminEndpoints = config.protectedEndpoints.filter(e =>
      e.includes("/admin") || e.includes("/manage") || e.includes("/config")
    );

    if (adminEndpoints.length === 0) {
      return {
        type: "scope_escalation",
        severity: "high",
        exploitable: false,
        proof: "No admin endpoints to test",
      };
    }

    const accessibleAdmin: string[] = [];

    for (const endpoint of adminEndpoints) {
      try {
        const response = await fetch(endpoint, {
          headers: {
            Authorization: `Bearer ${config.capturedToken}`,
          },
        });

        if (response.status !== 401 && response.status !== 403) {
          accessibleAdmin.push(endpoint);
        }
      } catch {}
    }

    if (accessibleAdmin.length > 0) {
      const hasAdminScope = declaredScope.some(s =>
        s.includes("admin") || s.includes("write") || s.includes("*")
      );

      if (!hasAdminScope) {
        return {
          type: "scope_escalation",
          severity: "critical",
          exploitable: true,
          proof: `Token without admin scope accessed: ${accessibleAdmin.join(", ")}`,
        };
      }
    }

    return {
      type: "scope_escalation",
      severity: "high",
      exploitable: false,
      proof: "No scope escalation detected",
    };
  }

  async runFullAttack(config: CredentialReplayConfig): Promise<CredentialReplayResult> {
    const startTime = Date.now();
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];
    const vulnerabilities: ReplayVulnerability[] = [];
    const testedEndpoints: EndpointTestResult[] = [];

    let tokenInfo: TokenInfo | undefined;
    if (config.capturedToken) {
      tokenInfo = await this.analyzeToken(config.capturedToken);
      evidence.push(`Token type: ${tokenInfo.type}`);
      
      if (tokenInfo.expiresAt) {
        const expiresIn = Math.floor((tokenInfo.expiresAt.getTime() - Date.now()) / 1000);
        evidence.push(`Expires in: ${expiresIn}s`);
      }

      proofArtifacts.push({
        type: "token_analysis",
        description: "Captured token analysis",
        data: JSON.stringify({
          type: tokenInfo.type,
          hasExpiry: !!tokenInfo.expiresAt,
          scope: tokenInfo.scope,
        }),
        hash: createHash("sha256").update(config.capturedToken).digest("hex"),
        capturedAt: new Date(),
      });
    }

    const replayResult = await this.testTokenReplay(config);
    vulnerabilities.push(replayResult);
    if (replayResult.exploitable) {
      evidence.push(`Token replay: ${replayResult.proof}`);
      proofArtifacts.push({
        type: "token_replay",
        description: "Token replay attack result",
        data: replayResult.proof || "",
        hash: createHash("sha256").update(replayResult.proof || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const refreshResult = await this.testRefreshTokenReuse(config);
    vulnerabilities.push(refreshResult);
    if (refreshResult.exploitable) {
      evidence.push("Refresh token reusable");
    }

    const crossContextResult = await this.testCrossContextReuse(config);
    vulnerabilities.push(crossContextResult);
    if (crossContextResult.exploitable) {
      evidence.push(`Cross-context: ${crossContextResult.proof}`);
    }

    const revocationResult = await this.testRevocationBypass(config);
    vulnerabilities.push(revocationResult);
    if (revocationResult.exploitable) {
      evidence.push("Revocation bypass possible");
    }

    const scopeResult = await this.testScopeEscalation(config);
    vulnerabilities.push(scopeResult);
    if (scopeResult.exploitable) {
      evidence.push(`Scope escalation: ${scopeResult.proof}`);
    }

    for (const endpoint of config.protectedEndpoints) {
      try {
        const token = config.capturedToken || config.apiKey;
        const response = await fetch(endpoint, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });

        testedEndpoints.push({
          endpoint,
          accessible: response.status !== 401 && response.status !== 403,
          statusCode: response.status,
        });
      } catch {
        testedEndpoints.push({ endpoint, accessible: false });
      }
    }

    const exploitableVulns = vulnerabilities.filter(v => v.exploitable);
    const success = exploitableVulns.length > 0;

    return {
      success,
      tokenInfo,
      vulnerabilities,
      testedEndpoints,
      evidence: evidence.join("; "),
      proofArtifacts,
      executionTimeMs: Date.now() - startTime,
    };
  }
}
