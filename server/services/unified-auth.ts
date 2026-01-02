import { mtlsAuthService } from "./mtls-auth";
import { jwtAuthService } from "./jwt-auth";
import bcrypt from "bcrypt";
import crypto from "crypto";
import type { EndpointAgent } from "@shared/schema";

export type AuthMethod = "api_key" | "mtls" | "jwt";

export interface AuthResult {
  authenticated: boolean;
  method?: AuthMethod;
  agentId?: string;
  organizationId?: string;
  scopes?: string[];
  error?: string;
}

export interface UnifiedAuthConfig {
  enableApiKey: boolean;
  enableMTLS: boolean;
  enableJWT: boolean;
  requireMTLSForCritical: boolean;
  mtlsSharedSecret?: string;
}

const defaultConfig: UnifiedAuthConfig = {
  enableApiKey: true,
  enableMTLS: true,
  enableJWT: true,
  requireMTLSForCritical: false,
  mtlsSharedSecret: process.env.MTLS_SHARED_SECRET || undefined,
};

class UnifiedAuthService {
  private config: UnifiedAuthConfig = defaultConfig;
  
  configure(config: Partial<UnifiedAuthConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  getConfig(): UnifiedAuthConfig {
    return { ...this.config };
  }
  
  async authenticateRequest(
    authHeader: string | undefined,
    clientCertHeader: string | undefined,
    agents: EndpointAgent[],
    certSecretHeader?: string,
    xApiKeyHeader?: string
  ): Promise<AuthResult> {
    if (this.config.enableMTLS && clientCertHeader) {
      const mtlsResult = await this.authenticateWithMTLS(clientCertHeader, certSecretHeader);
      if (mtlsResult.authenticated) {
        return mtlsResult;
      }
    }
    
    if (authHeader) {
      if (authHeader.startsWith("Bearer ")) {
        const token = authHeader.substring(7);
        
        if (this.config.enableJWT && this.isJWT(token)) {
          const jwtResult = await this.authenticateWithJWT(token);
          if (jwtResult.authenticated) {
            return jwtResult;
          }
        }
        
        if (this.config.enableApiKey) {
          const apiKeyResult = await this.authenticateWithApiKey(token, agents);
          if (apiKeyResult.authenticated) {
            return apiKeyResult;
          }
        }
      }
    }
    
    // Also check X-API-Key header (used by agents for command polling)
    if (this.config.enableApiKey && xApiKeyHeader) {
      const apiKeyResult = await this.authenticateWithApiKey(xApiKeyHeader, agents);
      if (apiKeyResult.authenticated) {
        return apiKeyResult;
      }
    }
    
    return {
      authenticated: false,
      error: "No valid authentication credentials provided",
    };
  }
  
  private isJWT(token: string): boolean {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    
    try {
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      return header.typ === "JWT" && header.alg === "HS256";
    } catch {
      return false;
    }
  }
  
  private async authenticateWithMTLS(certHeader: string, certSecretHeader?: string): Promise<AuthResult> {
    const fingerprint = mtlsAuthService.extractFingerprintFromHeader(certHeader);
    if (!fingerprint) {
      return { authenticated: false, error: "Invalid certificate header" };
    }
    
    // Validate shared secret to prevent header spoofing attacks
    // When a shared secret is configured, the client must provide a matching X-Cert-Secret header
    if (this.config.mtlsSharedSecret) {
      if (!certSecretHeader) {
        return { authenticated: false, error: "Certificate secret required for mTLS authentication" };
      }
      // Use timing-safe comparison to prevent timing attacks
      const expectedSecret = Buffer.from(this.config.mtlsSharedSecret);
      const providedSecret = Buffer.from(certSecretHeader);
      if (expectedSecret.length !== providedSecret.length || 
          !crypto.timingSafeEqual(expectedSecret, providedSecret)) {
        return { authenticated: false, error: "Invalid certificate secret" };
      }
    }
    
    const validation = await mtlsAuthService.validateCertificate(fingerprint);
    if (!validation.valid) {
      return { authenticated: false, error: validation.error };
    }
    
    return {
      authenticated: true,
      method: "mtls",
      agentId: validation.agentId,
      organizationId: validation.organizationId,
      scopes: ["read", "write"],
    };
  }
  
  private async authenticateWithJWT(token: string): Promise<AuthResult> {
    const validation = await jwtAuthService.validateToken(token);
    if (!validation.valid || !validation.payload) {
      return { authenticated: false, error: validation.error };
    }
    
    return {
      authenticated: true,
      method: "jwt",
      agentId: validation.payload.agentId,
      organizationId: validation.payload.organizationId,
      scopes: validation.payload.scopes,
    };
  }
  
  private async authenticateWithApiKey(
    apiKey: string,
    agents: EndpointAgent[]
  ): Promise<AuthResult> {
    for (const agent of agents) {
      if (agent.apiKeyHash) {
        const isValid = await bcrypt.compare(apiKey, agent.apiKeyHash);
        if (isValid) {
          return {
            authenticated: true,
            method: "api_key",
            agentId: agent.id,
            organizationId: agent.organizationId,
            scopes: ["read", "write"],
          };
        }
      }
      
      if (agent.apiKey === apiKey) {
        return {
          authenticated: true,
          method: "api_key",
          agentId: agent.id,
          organizationId: agent.organizationId,
          scopes: ["read", "write"],
        };
      }
    }
    
    return { authenticated: false, error: "Invalid API key" };
  }
  
  async issueJWTForAgent(agentId: string, organizationId: string, scopes: string[] = ["read", "write"]) {
    return jwtAuthService.generateTokenPair({
      organizationId,
      agentId,
      scopes,
    });
  }
  
  async issueCertificateForAgent(agentId: string, organizationId: string, commonName: string) {
    return mtlsAuthService.generateCertificate({
      agentId,
      organizationId,
      commonName,
    });
  }
  
  async revokeAgentCredentials(agentId: string): Promise<{ revokedCerts: number; revokedTokens: number }> {
    const revokedCerts = await mtlsAuthService.revokeAllAgentCertificates(agentId, "Agent credentials revoked");
    const revokedTokens = await jwtAuthService.revokeAllTokensForAgent(agentId);
    
    return { revokedCerts, revokedTokens };
  }
  
  async getAgentAuthStatus(agentId: string) {
    const certs = await mtlsAuthService.getAgentCertificates(agentId);
    const activeCerts = certs.filter(c => c.status === "active");
    
    return {
      hasCertificates: activeCerts.length > 0,
      certificateCount: activeCerts.length,
      certificates: activeCerts.map(c => ({
        id: c.id,
        fingerprint: c.fingerprint,
        validFrom: c.validFrom,
        validTo: c.validTo,
        status: c.status,
      })),
    };
  }
}

export const unifiedAuthService = new UnifiedAuthService();
