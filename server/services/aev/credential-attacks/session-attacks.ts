/**
 * Session Attack Module
 * 
 * Tests for session management vulnerabilities including:
 * - Session fixation
 * - Session hijacking susceptibility
 * - Cookie security analysis
 * - Session token predictability
 */

import { createHash, randomBytes } from "crypto";

export interface SessionAttackConfig {
  targetUrl: string;
  loginEndpoint: string;
  protectedEndpoint: string;
  logoutEndpoint?: string;
  credentials?: { username: string; password: string };
  headers?: Record<string, string>;
}

export interface CookieAnalysis {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "strict" | "lax" | "none" | "missing";
  path: string;
  expires?: Date;
  maxAge?: number;
  domain?: string;
  entropy: number;
  weaknesses: string[];
}

export interface SessionVulnerability {
  type: "session_fixation" | "predictable_token" | "insecure_cookie" | "no_logout_invalidation" | "concurrent_sessions" | "session_hijacking";
  severity: "critical" | "high" | "medium" | "low";
  exploitable: boolean;
  proof?: string;
  details?: string;
}

export interface SessionAttackResult {
  success: boolean;
  cookieAnalysis: CookieAnalysis[];
  vulnerabilities: SessionVulnerability[];
  evidence: string;
  proofArtifacts: ProofArtifact[];
  executionTimeMs: number;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

export class SessionAttackModule {
  async analyzeCookies(setCookieHeaders: string[]): Promise<CookieAnalysis[]> {
    return setCookieHeaders.map(header => this.parseCookie(header));
  }

  private parseCookie(setCookieHeader: string): CookieAnalysis {
    const parts = setCookieHeader.split(";").map(p => p.trim());
    const [nameValue, ...attributes] = parts;
    const [name, value] = nameValue.split("=");

    let httpOnly = false;
    let secure = false;
    let sameSite: CookieAnalysis["sameSite"] = "missing";
    let path = "/";
    let expires: Date | undefined;
    let maxAge: number | undefined;
    let domain: string | undefined;

    for (const attr of attributes) {
      const lowerAttr = attr.toLowerCase();
      if (lowerAttr === "httponly") {
        httpOnly = true;
      } else if (lowerAttr === "secure") {
        secure = true;
      } else if (lowerAttr.startsWith("samesite=")) {
        const val = lowerAttr.split("=")[1];
        sameSite = val as CookieAnalysis["sameSite"];
      } else if (lowerAttr.startsWith("path=")) {
        path = attr.split("=")[1];
      } else if (lowerAttr.startsWith("expires=")) {
        expires = new Date(attr.substring(8));
      } else if (lowerAttr.startsWith("max-age=")) {
        maxAge = parseInt(attr.split("=")[1], 10);
      } else if (lowerAttr.startsWith("domain=")) {
        domain = attr.split("=")[1];
      }
    }

    const entropy = this.calculateEntropy(value);
    const weaknesses = this.identifyCookieWeaknesses(
      name, value, httpOnly, secure, sameSite, entropy
    );

    return {
      name,
      value,
      httpOnly,
      secure,
      sameSite,
      path,
      expires,
      maxAge,
      domain,
      entropy,
      weaknesses,
    };
  }

  private calculateEntropy(value: string): number {
    const freq = new Map<string, number>();
    for (const char of value) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = value.length;
    const values = Array.from(freq.values());
    for (const count of values) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy * len;
  }

  private identifyCookieWeaknesses(
    name: string,
    value: string,
    httpOnly: boolean,
    secure: boolean,
    sameSite: CookieAnalysis["sameSite"],
    entropy: number
  ): string[] {
    const weaknesses: string[] = [];

    if (!httpOnly && (name.toLowerCase().includes("session") || name.toLowerCase().includes("token"))) {
      weaknesses.push("Session cookie missing HttpOnly flag");
    }

    if (!secure) {
      weaknesses.push("Missing Secure flag (transmits over HTTP)");
    }

    if (sameSite === "missing" || sameSite === "none") {
      weaknesses.push("SameSite not set or 'None' (CSRF risk)");
    }

    if (entropy < 64) {
      weaknesses.push("Low entropy token (predictability risk)");
    }

    if (value.length < 16) {
      weaknesses.push("Short session token");
    }

    if (/^[0-9]+$/.test(value)) {
      weaknesses.push("Numeric-only token (sequential risk)");
    }

    const timestampPatterns = [
      /^\d{10}/, // Unix timestamp
      /^\d{13}/, // Millisecond timestamp
    ];
    if (timestampPatterns.some(p => p.test(value))) {
      weaknesses.push("Token appears to contain timestamp (predictable)");
    }

    return weaknesses;
  }

  async testSessionFixation(config: SessionAttackConfig): Promise<SessionVulnerability> {
    try {
      const preLoginResponse = await fetch(config.targetUrl, {
        credentials: "include",
      });
      const preLoginCookies = preLoginResponse.headers.get("set-cookie");

      if (!preLoginCookies) {
        return {
          type: "session_fixation",
          severity: "high",
          exploitable: false,
          proof: "No session cookie issued before login",
        };
      }

      const preLoginSessionId = this.extractSessionId(preLoginCookies);

      if (!config.credentials) {
        return {
          type: "session_fixation",
          severity: "high",
          exploitable: false,
          proof: "Cannot test - no credentials provided",
        };
      }

      const loginResponse = await fetch(config.loginEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: preLoginCookies,
        },
        body: JSON.stringify(config.credentials),
      });

      const postLoginCookies = loginResponse.headers.get("set-cookie");
      if (!postLoginCookies) {
        return {
          type: "session_fixation",
          severity: "high",
          exploitable: true,
          proof: "Session ID not regenerated after login",
        };
      }

      const postLoginSessionId = this.extractSessionId(postLoginCookies);

      if (preLoginSessionId === postLoginSessionId) {
        return {
          type: "session_fixation",
          severity: "critical",
          exploitable: true,
          proof: `Session ID unchanged after login: ${preLoginSessionId?.substring(0, 20)}...`,
        };
      }

      return {
        type: "session_fixation",
        severity: "high",
        exploitable: false,
        proof: "Session ID properly regenerated after login",
      };
    } catch {
      return {
        type: "session_fixation",
        severity: "high",
        exploitable: false,
        proof: "Error testing session fixation",
      };
    }
  }

  async testLogoutInvalidation(config: SessionAttackConfig): Promise<SessionVulnerability> {
    if (!config.logoutEndpoint) {
      return {
        type: "no_logout_invalidation",
        severity: "medium",
        exploitable: false,
        proof: "No logout endpoint provided",
      };
    }

    try {
      if (!config.credentials) {
        return {
          type: "no_logout_invalidation",
          severity: "medium",
          exploitable: false,
          proof: "Cannot test - no credentials provided",
        };
      }

      const loginResponse = await fetch(config.loginEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config.credentials),
      });

      const sessionCookie = loginResponse.headers.get("set-cookie");
      if (!sessionCookie) {
        return {
          type: "no_logout_invalidation",
          severity: "medium",
          exploitable: false,
          proof: "No session cookie received",
        };
      }

      await fetch(config.logoutEndpoint, {
        method: "POST",
        headers: { Cookie: sessionCookie },
      });

      const postLogoutResponse = await fetch(config.protectedEndpoint, {
        headers: { Cookie: sessionCookie },
      });

      if (postLogoutResponse.status !== 401 && postLogoutResponse.status !== 403) {
        return {
          type: "no_logout_invalidation",
          severity: "high",
          exploitable: true,
          proof: "Session still valid after logout",
        };
      }

      return {
        type: "no_logout_invalidation",
        severity: "medium",
        exploitable: false,
        proof: "Session properly invalidated after logout",
      };
    } catch {
      return {
        type: "no_logout_invalidation",
        severity: "medium",
        exploitable: false,
        proof: "Error testing logout invalidation",
      };
    }
  }

  async testConcurrentSessions(config: SessionAttackConfig): Promise<SessionVulnerability> {
    if (!config.credentials) {
      return {
        type: "concurrent_sessions",
        severity: "medium",
        exploitable: false,
        proof: "Cannot test - no credentials provided",
      };
    }

    try {
      const login1 = await fetch(config.loginEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config.credentials),
      });
      const session1 = login1.headers.get("set-cookie");

      const login2 = await fetch(config.loginEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config.credentials),
      });
      const session2 = login2.headers.get("set-cookie");

      if (!session1 || !session2) {
        return {
          type: "concurrent_sessions",
          severity: "medium",
          exploitable: false,
          proof: "Could not obtain sessions",
        };
      }

      const test1 = await fetch(config.protectedEndpoint, {
        headers: { Cookie: session1 },
      });

      const test2 = await fetch(config.protectedEndpoint, {
        headers: { Cookie: session2 },
      });

      const bothValid = test1.status !== 401 && test2.status !== 401;

      return {
        type: "concurrent_sessions",
        severity: "low",
        exploitable: bothValid,
        proof: bothValid
          ? "Multiple concurrent sessions allowed (no session limit)"
          : "Server enforces single session",
        details: bothValid ? "Consider implementing session limits" : undefined,
      };
    } catch {
      return {
        type: "concurrent_sessions",
        severity: "medium",
        exploitable: false,
        proof: "Error testing concurrent sessions",
      };
    }
  }

  async testTokenPredictability(
    tokens: string[]
  ): Promise<SessionVulnerability> {
    if (tokens.length < 3) {
      return {
        type: "predictable_token",
        severity: "high",
        exploitable: false,
        proof: "Need at least 3 tokens to analyze predictability",
      };
    }

    const numericTokens = tokens.filter(t => /^\d+$/.test(t));
    if (numericTokens.length === tokens.length) {
      const numbers = numericTokens.map(n => parseInt(n, 10));
      const diffs: number[] = [];
      for (let i = 1; i < numbers.length; i++) {
        diffs.push(numbers[i] - numbers[i - 1]);
      }

      const allSame = diffs.length > 0 && diffs.every(d => d === diffs[0]);
      if (allSame) {
        return {
          type: "predictable_token",
          severity: "critical",
          exploitable: true,
          proof: `Sequential numeric tokens detected, increment: ${diffs[0]}`,
        };
      }
    }

    const avgEntropy = tokens.reduce((sum, t) => sum + this.calculateEntropy(t), 0) / tokens.length;
    if (avgEntropy < 64) {
      return {
        type: "predictable_token",
        severity: "high",
        exploitable: true,
        proof: `Low average entropy: ${avgEntropy.toFixed(2)} bits`,
      };
    }

    return {
      type: "predictable_token",
      severity: "high",
      exploitable: false,
      proof: `Token entropy appears sufficient: ${avgEntropy.toFixed(2)} bits`,
    };
  }

  async runFullAttack(config: SessionAttackConfig): Promise<SessionAttackResult> {
    const startTime = Date.now();
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];
    const vulnerabilities: SessionVulnerability[] = [];
    const cookieAnalysis: CookieAnalysis[] = [];

    try {
      const response = await fetch(config.targetUrl);
      const setCookies = response.headers.get("set-cookie");
      
      if (setCookies) {
        const cookies = setCookies.split(/,(?=\s*\w+=)/);
        for (const cookie of cookies) {
          const analysis = this.parseCookie(cookie);
          cookieAnalysis.push(analysis);
          
          if (analysis.weaknesses.length > 0) {
            evidence.push(`Cookie ${analysis.name}: ${analysis.weaknesses.join(", ")}`);
            vulnerabilities.push({
              type: "insecure_cookie",
              severity: analysis.weaknesses.some(w => w.includes("HttpOnly") || w.includes("Low entropy"))
                ? "high"
                : "medium",
              exploitable: true,
              proof: analysis.weaknesses.join("; "),
            });
          }
        }

        proofArtifacts.push({
          type: "cookie_analysis",
          description: "Session cookie security analysis",
          data: JSON.stringify(cookieAnalysis.map(c => ({
            name: c.name,
            httpOnly: c.httpOnly,
            secure: c.secure,
            sameSite: c.sameSite,
            entropy: c.entropy,
            weaknesses: c.weaknesses,
          }))),
          hash: createHash("sha256").update(JSON.stringify(cookieAnalysis)).digest("hex"),
          capturedAt: new Date(),
        });
      }
    } catch {
      evidence.push("Error analyzing cookies");
    }

    const fixationResult = await this.testSessionFixation(config);
    vulnerabilities.push(fixationResult);
    if (fixationResult.exploitable) {
      evidence.push(`Session fixation: ${fixationResult.proof}`);
      proofArtifacts.push({
        type: "session_fixation",
        description: "Session fixation vulnerability",
        data: fixationResult.proof || "",
        hash: createHash("sha256").update(fixationResult.proof || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const logoutResult = await this.testLogoutInvalidation(config);
    vulnerabilities.push(logoutResult);
    if (logoutResult.exploitable) {
      evidence.push("Logout does not invalidate session");
    }

    const concurrentResult = await this.testConcurrentSessions(config);
    vulnerabilities.push(concurrentResult);

    const exploitableVulns = vulnerabilities.filter(v => v.exploitable);
    const success = exploitableVulns.length > 0;

    return {
      success,
      cookieAnalysis,
      vulnerabilities,
      evidence: evidence.join("; "),
      proofArtifacts,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private extractSessionId(cookieHeader: string): string | undefined {
    const sessionPatterns = [
      /PHPSESSID=([^;]+)/i,
      /JSESSIONID=([^;]+)/i,
      /session_id=([^;]+)/i,
      /sid=([^;]+)/i,
      /connect\.sid=([^;]+)/i,
      /session=([^;]+)/i,
    ];

    for (const pattern of sessionPatterns) {
      const match = cookieHeader.match(pattern);
      if (match) {
        return match[1];
      }
    }

    const firstCookie = cookieHeader.split(";")[0];
    const [, value] = firstCookie.split("=");
    return value;
  }
}
