import { randomUUID } from "crypto";
import * as crypto from "crypto";

export interface JWTPayload {
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  organizationId: string;
  tenantId?: string;
  agentId?: string;
  scopes: string[];
  type: "access" | "refresh";
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

export interface TokenValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

export interface TenantConfig {
  id: string;
  organizationId: string;
  name: string;
  secretKey: string;
  accessTokenTTL: number;
  refreshTokenTTL: number;
  allowedScopes: string[];
  createdAt: Date;
  updatedAt: Date;
  active: boolean;
}

class JWTAuthService {
  private tenants: Map<string, TenantConfig> = new Map();
  private refreshTokens: Map<string, { tokenId: string; payload: JWTPayload; expiresAt: Date }> = new Map();
  private revokedTokens: Set<string> = new Set();
  
  private readonly ISSUER = "odinforge-aev";
  private readonly AUDIENCE = "odinforge-api";
  private readonly DEFAULT_ACCESS_TOKEN_TTL = 3600;
  private readonly DEFAULT_REFRESH_TOKEN_TTL = 86400 * 7;
  private readonly JWT_SECRET = process.env.SESSION_SECRET || "odinforge-jwt-secret-dev";
  
  async createTenant(config: {
    organizationId: string;
    name: string;
    allowedScopes?: string[];
    accessTokenTTL?: number;
    refreshTokenTTL?: number;
  }): Promise<TenantConfig> {
    const tenantId = `tenant-${randomUUID()}`;
    const secretKey = crypto.randomBytes(32).toString("hex");
    const now = new Date();
    
    const tenant: TenantConfig = {
      id: tenantId,
      organizationId: config.organizationId,
      name: config.name,
      secretKey,
      accessTokenTTL: config.accessTokenTTL || this.DEFAULT_ACCESS_TOKEN_TTL,
      refreshTokenTTL: config.refreshTokenTTL || this.DEFAULT_REFRESH_TOKEN_TTL,
      allowedScopes: config.allowedScopes || ["read", "write", "admin"],
      createdAt: now,
      updatedAt: now,
      active: true,
    };
    
    this.tenants.set(tenantId, tenant);
    return tenant;
  }
  
  async getTenant(tenantId: string): Promise<TenantConfig | undefined> {
    return this.tenants.get(tenantId);
  }
  
  async updateTenant(tenantId: string, updates: Partial<TenantConfig>): Promise<TenantConfig | null> {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) return null;
    
    const updated: TenantConfig = {
      ...tenant,
      ...updates,
      id: tenant.id,
      createdAt: tenant.createdAt,
      updatedAt: new Date(),
    };
    
    this.tenants.set(tenantId, updated);
    return updated;
  }
  
  async deactivateTenant(tenantId: string): Promise<boolean> {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) return false;
    
    tenant.active = false;
    tenant.updatedAt = new Date();
    return true;
  }
  
  async generateTokenPair(params: {
    organizationId: string;
    tenantId?: string;
    agentId?: string;
    scopes: string[];
    subject?: string;
  }): Promise<TokenPair> {
    const now = Math.floor(Date.now() / 1000);
    const tenant = params.tenantId ? this.tenants.get(params.tenantId) : undefined;
    
    const accessTokenTTL = tenant?.accessTokenTTL || this.DEFAULT_ACCESS_TOKEN_TTL;
    const refreshTokenTTL = tenant?.refreshTokenTTL || this.DEFAULT_REFRESH_TOKEN_TTL;
    
    const accessPayload: JWTPayload = {
      sub: params.subject || params.agentId || params.organizationId,
      iss: this.ISSUER,
      aud: this.AUDIENCE,
      iat: now,
      exp: now + accessTokenTTL,
      organizationId: params.organizationId,
      tenantId: params.tenantId,
      agentId: params.agentId,
      scopes: params.scopes,
      type: "access",
    };
    
    const refreshPayload: JWTPayload = {
      ...accessPayload,
      exp: now + refreshTokenTTL,
      type: "refresh",
    };
    
    const accessToken = this.encodeToken(accessPayload);
    const refreshToken = this.encodeToken(refreshPayload);
    
    const refreshTokenId = `rt-${randomUUID()}`;
    this.refreshTokens.set(refreshToken, {
      tokenId: refreshTokenId,
      payload: refreshPayload,
      expiresAt: new Date((now + refreshTokenTTL) * 1000),
    });
    
    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date((now + accessTokenTTL) * 1000),
      refreshTokenExpiresAt: new Date((now + refreshTokenTTL) * 1000),
    };
  }
  
  private encodeToken(payload: JWTPayload): string {
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
    
    const signature = crypto
      .createHmac("sha256", this.JWT_SECRET)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest("base64url");
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }
  
  async validateToken(token: string): Promise<TokenValidationResult> {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        return { valid: false, error: "Invalid token format" };
      }
      
      const [encodedHeader, encodedPayload, signature] = parts;
      
      const expectedSignature = crypto
        .createHmac("sha256", this.JWT_SECRET)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest("base64url");
      
      if (signature !== expectedSignature) {
        return { valid: false, error: "Invalid signature" };
      }
      
      const payload: JWTPayload = JSON.parse(
        Buffer.from(encodedPayload, "base64url").toString()
      );
      
      if (this.revokedTokens.has(token)) {
        return { valid: false, error: "Token has been revoked" };
      }
      
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return { valid: false, error: "Token has expired" };
      }
      
      if (payload.iat > now) {
        return { valid: false, error: "Token not yet valid" };
      }
      
      if (payload.iss !== this.ISSUER) {
        return { valid: false, error: "Invalid issuer" };
      }
      
      if (payload.aud !== this.AUDIENCE) {
        return { valid: false, error: "Invalid audience" };
      }
      
      if (payload.tenantId) {
        const tenant = this.tenants.get(payload.tenantId);
        if (tenant && !tenant.active) {
          return { valid: false, error: "Tenant is inactive" };
        }
      }
      
      return { valid: true, payload };
    } catch (error) {
      return { valid: false, error: "Token validation failed" };
    }
  }
  
  async refreshAccessToken(refreshToken: string): Promise<TokenPair | null> {
    const stored = this.refreshTokens.get(refreshToken);
    if (!stored) {
      return null;
    }
    
    const validation = await this.validateToken(refreshToken);
    if (!validation.valid || !validation.payload) {
      return null;
    }
    
    if (validation.payload.type !== "refresh") {
      return null;
    }
    
    this.refreshTokens.delete(refreshToken);
    
    return this.generateTokenPair({
      organizationId: validation.payload.organizationId,
      tenantId: validation.payload.tenantId,
      agentId: validation.payload.agentId,
      scopes: validation.payload.scopes,
      subject: validation.payload.sub,
    });
  }
  
  async revokeToken(token: string): Promise<boolean> {
    this.revokedTokens.add(token);
    this.refreshTokens.delete(token);
    return true;
  }
  
  async revokeAllTokensForAgent(agentId: string): Promise<number> {
    let count = 0;
    const tokensToRevoke: string[] = [];
    
    this.refreshTokens.forEach((value, key) => {
      if (value.payload.agentId === agentId) {
        tokensToRevoke.push(key);
        count++;
      }
    });
    
    for (const token of tokensToRevoke) {
      this.refreshTokens.delete(token);
      this.revokedTokens.add(token);
    }
    
    return count;
  }
  
  hasScope(payload: JWTPayload, requiredScope: string): boolean {
    return payload.scopes.includes(requiredScope) || payload.scopes.includes("admin");
  }
  
  hasAnyScope(payload: JWTPayload, requiredScopes: string[]): boolean {
    return requiredScopes.some(scope => this.hasScope(payload, scope));
  }
  
  async listTenants(organizationId?: string): Promise<TenantConfig[]> {
    const tenants: TenantConfig[] = [];
    this.tenants.forEach((tenant) => {
      if (!organizationId || tenant.organizationId === organizationId) {
        tenants.push({ ...tenant, secretKey: "***" });
      }
    });
    return tenants;
  }
  
  async cleanupExpiredTokens(): Promise<number> {
    const now = new Date();
    let count = 0;
    const tokensToRemove: string[] = [];
    
    this.refreshTokens.forEach((value, key) => {
      if (value.expiresAt < now) {
        tokensToRemove.push(key);
        count++;
      }
    });
    
    for (const token of tokensToRemove) {
      this.refreshTokens.delete(token);
    }
    
    return count;
  }
  
  getTokenInfo(token: string): { header: any; payload: JWTPayload | null } | null {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      
      return { header, payload };
    } catch {
      return null;
    }
  }
}

export const jwtAuthService = new JWTAuthService();
