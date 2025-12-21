import { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import * as bcrypt from "bcrypt";
import { SignJWT, jwtVerify, JWTPayload as JoseJWTPayload } from "jose";
import { storage } from "../storage";
import type { UIUser, UIUserRole } from "@shared/schema";

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
  role: string;
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
    role: UIUserRole;
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
    role: user.role,
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
    role: user.role,
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
    .then((payload) => {
      if (!payload) {
        res.status(401).json({ error: "Unauthorized", message: "Invalid or expired token" });
        return;
      }

      req.uiUser = {
        userId: payload.userId,
        tenantId: payload.tenantId,
        organizationId: payload.organizationId,
        email: payload.email,
        role: payload.role as UIUserRole,
        tokenVersion: payload.tokenVersion,
      };

      storage.updateUIUser(payload.userId, { lastActivityAt: new Date() })
        .catch((err) => console.error("Failed to update lastActivityAt:", err));

      next();
    })
    .catch(() => {
      res.status(401).json({ error: "Unauthorized", message: "Token verification failed" });
    });
}

export function requireRole(...roles: UIUserRole[]) {
  return (req: UIAuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.uiUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!roles.includes(req.uiUser.role)) {
      return res.status(403).json({ 
        error: "Forbidden", 
        message: `This action requires one of the following roles: ${roles.join(", ")}` 
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
    role: "admin",
    status: "active",
  });
}
