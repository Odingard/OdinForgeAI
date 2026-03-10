import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  generateUITokens,
  verifyUIAccessToken,
  verifyUIRefreshToken,
  requireRole,
  requirePermission,
  requireAllPermissions,
  hashPassword,
  verifyPassword,
  type UIAuthenticatedRequest,
} from "./ui-auth";
import type { UIUser } from "@shared/schema";

// Mock storage — verifyUIAccessToken calls storage.getUIUser internally
vi.mock("../storage", () => ({
  storage: {
    getUIUser: vi.fn(),
    getUIRefreshTokenByHash: vi.fn(),
  },
}));

// Mock rls-setup to avoid pg dependency
vi.mock("./rls-setup", () => ({
  setTenantContext: vi.fn(),
  clearTenantContext: vi.fn(),
}));

import { storage } from "../storage";

function mockUser(overrides: Partial<UIUser> = {}): UIUser {
  return {
    id: "user-1",
    tenantId: "tenant-1",
    organizationId: "org-1",
    email: "test@example.com",
    passwordHash: "hashed",
    roleId: "org_owner",
    tokenVersion: 1,
    status: "active",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as UIUser;
}

function mockReq(uiUser?: UIAuthenticatedRequest["uiUser"]): UIAuthenticatedRequest {
  return { uiUser } as UIAuthenticatedRequest;
}

function mockRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

// ── Token generation + verification ──────────────────────────────
describe("generateUITokens", () => {
  const user = mockUser();

  it("produces access and refresh tokens", async () => {
    const tokens = await generateUITokens(user);
    expect(tokens.accessToken).toBeTruthy();
    expect(tokens.refreshToken).toBeTruthy();
    expect(tokens.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(tokens.refreshTokenExpiresAt).toBeInstanceOf(Date);
  });

  it("refresh expires after access", async () => {
    const tokens = await generateUITokens(user);
    expect(tokens.refreshTokenExpiresAt.getTime()).toBeGreaterThan(
      tokens.accessTokenExpiresAt.getTime()
    );
  });
});

describe("verifyUIAccessToken", () => {
  const user = mockUser();

  beforeEach(() => {
    vi.mocked(storage.getUIUser).mockReset();
  });

  it("verifies a valid access token", async () => {
    vi.mocked(storage.getUIUser).mockResolvedValue(user);
    const tokens = await generateUITokens(user);
    const payload = await verifyUIAccessToken(tokens.accessToken);
    expect(payload).not.toBeNull();
    expect(payload!.userId).toBe("user-1");
    expect(payload!.type).toBe("access");
  });

  it("rejects a refresh token used as access", async () => {
    vi.mocked(storage.getUIUser).mockResolvedValue(user);
    const tokens = await generateUITokens(user);
    const payload = await verifyUIAccessToken(tokens.refreshToken);
    expect(payload).toBeNull();
  });

  it("rejects when tokenVersion mismatches", async () => {
    vi.mocked(storage.getUIUser).mockResolvedValue(mockUser({ tokenVersion: 99 }));
    const tokens = await generateUITokens(user);
    const payload = await verifyUIAccessToken(tokens.accessToken);
    expect(payload).toBeNull();
  });

  it("rejects when user is inactive", async () => {
    vi.mocked(storage.getUIUser).mockResolvedValue(mockUser({ status: "suspended" } as any));
    const tokens = await generateUITokens(user);
    const payload = await verifyUIAccessToken(tokens.accessToken);
    expect(payload).toBeNull();
  });

  it("rejects garbage token", async () => {
    const payload = await verifyUIAccessToken("not.a.real.token");
    expect(payload).toBeNull();
  });
});

// ── Password hashing ─────────────────────────────────────────────
describe("password hashing", () => {
  it("hash and verify round-trips", async () => {
    const hash = await hashPassword("mySecret123!");
    expect(await verifyPassword("mySecret123!", hash)).toBe(true);
    expect(await verifyPassword("wrongPassword", hash)).toBe(false);
  });
});

// ── Middleware: requireRole ──────────────────────────────────────
describe("requireRole", () => {
  it("allows matching role", () => {
    const middleware = requireRole("org_owner", "security_admin");
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "org_owner", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("denies non-matching role", () => {
    const middleware = requireRole("platform_super_admin");
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "security_analyst", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("returns 401 when no user", () => {
    const middleware = requireRole("org_owner");
    const req = mockReq();
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

// ── Middleware: requirePermission ────────────────────────────────
describe("requirePermission", () => {
  it("allows when user has ANY required permission", () => {
    const middleware = requirePermission("evaluations:read" as any);
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "org_owner", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("denies when user lacks permission", () => {
    const middleware = requirePermission("org:manage_billing" as any);
    // executive_viewer has minimal permissions, unlikely to have manage_billing
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "executive_viewer", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });
});

// ── Middleware: requireAllPermissions ────────────────────────────
describe("requireAllPermissions", () => {
  it("allows when user has ALL permissions", () => {
    const middleware = requireAllPermissions("evaluations:read" as any, "assets:read" as any);
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "org_owner", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("denies when user missing one permission", () => {
    const middleware = requireAllPermissions("evaluations:read" as any, "evaluations:delete" as any);
    // security_analyst can read but not delete
    const req = mockReq({ userId: "u1", tenantId: "t1", organizationId: "o1", email: "a@b.com", roleId: "security_analyst", tokenVersion: 1 });
    const res = mockRes();
    const next = vi.fn();
    middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });
});
