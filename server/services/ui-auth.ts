import { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import * as bcrypt from "bcrypt";
import { SignJWT, jwtVerify, JWTPayload as JoseJWTPayload } from "jose";
import { storage } from "../storage";
import type { UIUser, InsertUIRole, Permission } from "@shared/schema";
import { getPermissionsForDbRole } from "@shared/schema";
import { setTenantContext, clearTenantContext } from "./rls-setup";

const UI_JWT_SECRET = new TextEncoder().encode(
  process.env.SESSION_SECRET || "odinforge-ui-jwt-secret-dev"
);
const ISSUER = "odinforge-ui";
const AUDIENCE = "odinforge-control-plane";
const ACCESS_TOKEN_TTL = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60; // 7 days
const BCRYPT_ROUNDS = 12;

export interface UIJWTPayload extends JoseJWTPayload {
  userId: string;
  tenantId: string;
  organizationId: string;
  email: string;
  roleId: string;
  tokenVersion: number;
  type: "access" | "refresh";
}

export interface UIAuthTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

export interface UIAuthenticatedRequest extends Request {
  uiUser?: {
    userId: string;
    tenantId: string;
    organizationId: string;
    email: string;
    roleId: string;
    tokenVersion: number;
  };
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export async function generateUITokens(user: UIUser): Promise<UIAuthTokens> {
  const now = Math.floor(Date.now() / 1000);
  const accessTokenExpiresAt = new Date((now + ACCESS_TOKEN_TTL) * 1000);
  const refreshTokenExpiresAt = new Date((now + REFRESH_TOKEN_TTL) * 1000);
  const sessionId = crypto.randomUUID();

  const accessPayload: Partial<UIJWTPayload> = {
    userId: user.id,
    tenantId: user.tenantId,
    organizationId: user.organizationId,
    email: user.email,
    roleId: user.roleId,
    tokenVersion: user.tokenVersion,
    type: "access",
  };

  const accessToken = await new SignJWT(accessPayload as Record<string, unknown>)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime(`${ACCESS_TOKEN_TTL}s`)
    .setJti(crypto.randomUUID())
    .sign(UI_JWT_SECRET);

  const refreshPayload: Partial<UIJWTPayload> = {
    userId: user.id,
    tenantId: user.tenantId,
    organizationId: user.organizationId,
    email: user.email,
    roleId: user.roleId,
    tokenVersion: user.tokenVersion,
    type: "refresh",
  };

  const refreshToken = await new SignJWT(refreshPayload as Record<string, unknown>)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime(`${REFRESH_TOKEN_TTL}s`)
    .setJti(sessionId)
    .sign(UI_JWT_SECRET);

  return {
    accessToken,
    refreshToken,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
  };
}

export async function verifyUIAccessToken(token: string): Promise<UIJWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, UI_JWT_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    const uiPayload = payload as unknown as UIJWTPayload;
    if (uiPayload.type !== "access") {
      return null;
    }

    const user = await storage.getUIUser(uiPayload.userId);
    if (!user || user.tokenVersion !== uiPayload.tokenVersion) {
      return null;
    }
    if (user.status !== "active") {
      return null;
    }

    return uiPayload;
  } catch {
    return null;
  }
}

export async function verifyUIRefreshToken(token: string): Promise<UIJWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, UI_JWT_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    const uiPayload = payload as unknown as UIJWTPayload;
    if (uiPayload.type !== "refresh") {
      return null;
    }

    const user = await storage.getUIUser(uiPayload.userId);
    if (!user || user.tokenVersion !== uiPayload.tokenVersion) {
      return null;
    }
    if (user.status !== "active") {
      return null;
    }

    const tokenHash = hashToken(token);
    const storedToken = await storage.getUIRefreshTokenByHash(tokenHash);
    if (!storedToken || storedToken.revokedAt) {
      return null;
    }
    if (storedToken.expiresAt < new Date()) {
      return null;
    }

    return uiPayload;
  } catch {
    return null;
  }
}

export async function storeRefreshToken(
  token: string,
  user: UIUser,
  req: Request
): Promise<void> {
  const tokenHash = hashToken(token);
  const forwardedFor = req.headers["x-forwarded-for"];
  const ipAddress = forwardedFor
    ? (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor.split(",")[0])
    : req.ip || req.socket.remoteAddress || "unknown";

  await storage.createUIRefreshToken({
    userId: user.id,
    tenantId: user.tenantId,
    tokenHash,
    tokenVersion: user.tokenVersion,
    userAgent: req.headers["user-agent"] || null,
    ipAddress,
    sessionId: crypto.randomUUID(),
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
  });
}

export async function revokeRefreshToken(token: string): Promise<void> {
  const tokenHash = hashToken(token);
  const storedToken = await storage.getUIRefreshTokenByHash(tokenHash);
  if (storedToken) {
    await storage.revokeUIRefreshToken(storedToken.id, "logout");
  }
}

export function uiAuthMiddleware(
  req: UIAuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized", message: "Missing or invalid authorization header" });
    return;
  }

  const token = authHeader.slice(7);
  verifyUIAccessToken(token)
    .then(async (payload) => {
      if (!payload) {
        res.status(401).json({ error: "Unauthorized", message: "Invalid or expired token" });
        return;
      }

      req.uiUser = {
        userId: payload.userId,
        tenantId: payload.tenantId,
        organizationId: payload.organizationId,
        email: payload.email,
        roleId: payload.roleId,
        tokenVersion: payload.tokenVersion,
      };

      // Set RLS context for database queries based on JWT organizationId
      try {
        await setTenantContext(payload.organizationId);
        
        // Clear RLS context when response finishes
        res.on("finish", () => {
          clearTenantContext().catch((err) => {
            console.error("[RLS] Failed to clear context after request:", err);
          });
        });
        
        storage.updateUIUser(payload.userId, { lastActivityAt: new Date() })
          .catch((err) => console.error("Failed to update lastActivityAt:", err));

        next();
      } catch (rlsError) {
        console.error("[RLS] Failed to set context from JWT:", rlsError);
        res.status(500).json({ error: "Failed to establish tenant context" });
        return;
      }
    })
    .catch(() => {
      res.status(401).json({ error: "Unauthorized", message: "Token verification failed" });
    });
}

export function requireRole(...roleIds: string[]) {
  return (req: UIAuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.uiUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!roleIds.includes(req.uiUser.roleId)) {
      return res.status(403).json({
        error: "Forbidden",
        message: `This action requires one of the following roles: ${roleIds.join(", ")}`
      });
    }

    next();
  };
}

// Granular permission check: user must have ANY of the listed permissions
export function requirePermission(...requiredPermissions: Permission[]) {
  return (req: UIAuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.uiUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userPermissions = getPermissionsForDbRole(req.uiUser.roleId);
    const hasPermission = requiredPermissions.some(p => userPermissions.includes(p));

    if (!hasPermission) {
      console.warn(`[RBAC] Permission denied for ${req.uiUser.email} (role: ${req.uiUser.roleId}). Required: ${requiredPermissions.join(" or ")}. Has ${userPermissions.length} permissions.`);
      return res.status(403).json({
        error: "Forbidden",
        message: `Requires permission: ${requiredPermissions.join(" or ")}`,
      });
    }

    next();
  };
}

// Strict permission check: user must have ALL listed permissions
export function requireAllPermissions(...requiredPermissions: Permission[]) {
  return (req: UIAuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.uiUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userPermissions = getPermissionsForDbRole(req.uiUser.roleId);
    const missingPermissions = requiredPermissions.filter(p => !userPermissions.includes(p));

    if (missingPermissions.length > 0) {
      return res.status(403).json({
        error: "Forbidden",
        message: `Missing permissions: ${missingPermissions.join(", ")}`,
      });
    }

    next();
  };
}

export async function loginUser(
  email: string,
  password: string,
  tenantId: string = "default",
  req: Request
): Promise<{ success: false; error: string } | { success: true; user: UIUser; tokens: UIAuthTokens }> {
  const user = await storage.getUIUserByEmail(email, tenantId);

  if (!user) {
    return { success: false, error: "Invalid email or password" };
  }

  if (user.status === "locked") {
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const minutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
      return { success: false, error: `Account locked. Try again in ${minutes} minutes.` };
    }
    await storage.updateUIUser(user.id, { status: "active", lockedUntil: null, failedLoginAttempts: 0 });
  }

  if (user.status === "inactive" || user.status === "pending") {
    return { success: false, error: "Account is not active" };
  }

  const passwordValid = await verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    await storage.recordLoginAttempt(user.id, false);
    return { success: false, error: "Invalid email or password" };
  }

  await storage.recordLoginAttempt(user.id, true);
  const tokens = await generateUITokens(user);
  await storeRefreshToken(tokens.refreshToken, user, req);

  return { success: true, user, tokens };
}

export async function refreshUserTokens(
  refreshToken: string,
  req: Request
): Promise<{ success: false; error: string } | { success: true; user: UIUser; tokens: UIAuthTokens }> {
  const payload = await verifyUIRefreshToken(refreshToken);
  if (!payload) {
    return { success: false, error: "Invalid or expired refresh token" };
  }

  const user = await storage.getUIUser(payload.userId);
  if (!user || user.status !== "active") {
    return { success: false, error: "User not found or inactive" };
  }

  await revokeRefreshToken(refreshToken);

  const tokens = await generateUITokens(user);
  await storeRefreshToken(tokens.refreshToken, user, req);

  return { success: true, user, tokens };
}

export async function logoutUser(refreshToken: string, userId: string): Promise<void> {
  if (refreshToken) {
    await revokeRefreshToken(refreshToken);
  }
}

export async function logoutAllSessions(userId: string): Promise<void> {
  await storage.incrementUIUserTokenVersion(userId);
  await storage.revokeAllUIRefreshTokensForUser(userId);
}

export async function createInitialAdminUser(
  email: string,
  password: string,
  tenantId: string = "default",
  organizationId: string = "default"
): Promise<UIUser> {
  const existing = await storage.getUIUserByEmail(email, tenantId);
  if (existing) {
    throw new Error("User with this email already exists");
  }

  const passwordHash = await hashPassword(password);
  return storage.createUIUser({
    tenantId,
    organizationId,
    email,
    passwordHash,
    displayName: "Admin",
    roleId: "org_owner",
    status: "active",
  });
}

// Default admin credentials - password from environment secret
const DEFAULT_ADMIN_EMAIL = "admin@odinforge.local";
const DEFAULT_TENANT_ID = "default";
const DEFAULT_ORG_ID = "default";

function getAdminPassword(): string {
  const password = process.env.ADMIN_PASSWORD;
  if (!password) {
    throw new Error("ADMIN_PASSWORD environment variable is required");
  }
  return password;
}

// The 6 immutable system roles with their permissions
const SYSTEM_ROLES: InsertUIRole[] = [
  {
    id: "org_owner",
    name: "Organization Owner",
    description: "Full access to all features including billing and user management",
    canManageUsers: true,
    canManageRoles: true,
    canManageSettings: true,
    canManageAgents: true,
    canCreateEvaluations: true,
    canRunSimulations: true,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: true,
    canAccessAuditLogs: true,
    canManageCompliance: true,
    canUseKillSwitch: true,
    isSystemRole: true,
    hierarchyLevel: 10,
  },
  {
    id: "security_admin",
    name: "Security Administrator",
    description: "Manage security settings, agents, and configurations",
    canManageUsers: true,
    canManageRoles: false,
    canManageSettings: true,
    canManageAgents: true,
    canCreateEvaluations: true,
    canRunSimulations: true,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: true,
    canAccessAuditLogs: true,
    canManageCompliance: true,
    canUseKillSwitch: true,
    isSystemRole: true,
    hierarchyLevel: 20,
  },
  {
    id: "security_engineer",
    name: "Security Engineer",
    description: "Create and run evaluations, simulations, and technical operations",
    canManageUsers: false,
    canManageRoles: false,
    canManageSettings: false,
    canManageAgents: true,
    canCreateEvaluations: true,
    canRunSimulations: true,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: true,
    canAccessAuditLogs: false,
    canManageCompliance: false,
    canUseKillSwitch: false,
    isSystemRole: true,
    hierarchyLevel: 30,
  },
  {
    id: "security_analyst",
    name: "Security Analyst",
    description: "View and analyze evaluation results, create reports",
    canManageUsers: false,
    canManageRoles: false,
    canManageSettings: false,
    canManageAgents: false,
    canCreateEvaluations: true,
    canRunSimulations: false,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: true,
    canAccessAuditLogs: false,
    canManageCompliance: false,
    canUseKillSwitch: false,
    isSystemRole: true,
    hierarchyLevel: 40,
  },
  {
    id: "executive_viewer",
    name: "Executive Viewer",
    description: "Read-only access to dashboards and executive reports",
    canManageUsers: false,
    canManageRoles: false,
    canManageSettings: false,
    canManageAgents: false,
    canCreateEvaluations: false,
    canRunSimulations: false,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: false,
    canAccessAuditLogs: false,
    canManageCompliance: false,
    canUseKillSwitch: false,
    isSystemRole: true,
    hierarchyLevel: 50,
  },
  {
    id: "compliance_officer",
    name: "Compliance Officer",
    description: "Access compliance reports, audit trails, and governance controls",
    canManageUsers: false,
    canManageRoles: false,
    canManageSettings: false,
    canManageAgents: false,
    canCreateEvaluations: false,
    canRunSimulations: false,
    canViewEvaluations: true,
    canViewReports: true,
    canExportData: true,
    canAccessAuditLogs: true,
    canManageCompliance: true,
    canUseKillSwitch: false,
    isSystemRole: true,
    hierarchyLevel: 35,
  },
];

export async function seedSystemRoles(): Promise<void> {
  console.log("[UI Auth] Seeding system roles...");
  try {
    for (const role of SYSTEM_ROLES) {
      await storage.upsertUIRole(role);
    }
    console.log(`[UI Auth] ${SYSTEM_ROLES.length} system roles seeded successfully`);
  } catch (error) {
    console.error("[UI Auth] Failed to seed system roles:", error);
  }
}

export async function seedDefaultUIUsers(): Promise<void> {
  try {
    const adminPassword = getAdminPassword();
    const existingUsers = await storage.getUIUsers(DEFAULT_TENANT_ID);
    
    if (existingUsers.length === 0) {
      // No users exist - create default admin
      console.log("[UI Auth] Seeding default admin user...");
      const passwordHash = await hashPassword(adminPassword);
      await storage.createUIUser({
        tenantId: DEFAULT_TENANT_ID,
        organizationId: DEFAULT_ORG_ID,
        email: DEFAULT_ADMIN_EMAIL,
        passwordHash,
        displayName: "Admin",
        roleId: "org_owner",
        status: "active",
      });
      console.log(`[UI Auth] Default admin created: ${DEFAULT_ADMIN_EMAIL}`);
    } else {
      // Check if admin user exists and reset password to environment value
      const adminUser = await storage.getUIUserByEmail(DEFAULT_ADMIN_EMAIL, DEFAULT_TENANT_ID);
      if (adminUser) {
        const passwordHash = await hashPassword(adminPassword);
        await storage.updateUIUser(adminUser.id, { passwordHash });
        console.log(`[UI Auth] Admin password synced from environment: ${DEFAULT_ADMIN_EMAIL}`);
      }
    }
  } catch (error) {
    console.error("[UI Auth] Failed to seed default users:", error);
  }
}

export function getDefaultCredentials() {
  return {
    email: DEFAULT_ADMIN_EMAIL,
    password: getAdminPassword(),
  };
}

export function getSystemRoles() {
  return SYSTEM_ROLES;
}
