import { Request, Response, NextFunction } from "express";
import { TenantContext, TenantTier, Tenant, UserRole } from "@shared/schema";
import { storage } from "../storage";
import { setTenantContext, clearTenantContext } from "../services/rls-setup";

interface SessionUser {
  id: string;
  tenantId?: string;
  organizationId?: string;
  roleId?: string;
}

declare global {
  namespace Express {
    interface Request {
      tenant?: TenantContext;
      session?: {
        user?: SessionUser;
        destroy?: (callback: (err?: Error) => void) => void;
      };
    }
  }
}

const DEFAULT_TENANT_ID = "default";
const DEFAULT_ORG_ID = "default";

export async function tenantMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    let tenantId: string;
    let organizationId: string;
    let userId: string | undefined;
    let userRole: UserRole | undefined;

    const sessionUser = (req as any).session?.user as SessionUser | undefined;
    
    if (sessionUser) {
      tenantId = sessionUser.tenantId || DEFAULT_TENANT_ID;
      organizationId = sessionUser.organizationId || DEFAULT_ORG_ID;
      userId = sessionUser.id;
      userRole = sessionUser.roleId as UserRole;
    } else {
      tenantId = DEFAULT_TENANT_ID;
      organizationId = DEFAULT_ORG_ID;
    }

    let tenant: Tenant | null = null;
    try {
      tenant = await storage.getTenant(tenantId);
    } catch {
      tenant = null;
    }

    if (!tenant && tenantId !== DEFAULT_TENANT_ID) {
      res.status(403).json({
        error: "Invalid tenant",
        code: "TENANT_NOT_FOUND",
      });
      return;
    }

    if (tenant && tenant.status === "suspended") {
      res.status(403).json({
        error: "Tenant suspended",
        code: "TENANT_SUSPENDED",
      });
      return;
    }

    if (tenant && tenant.status === "deleted") {
      res.status(403).json({
        error: "Tenant not found",
        code: "TENANT_DELETED",
      });
      return;
    }

    if (tenant && tenant.enforceIpAllowlist) {
      const clientIp = getClientIp(req);
      const allowedRanges = (tenant.allowedIpRanges as string[]) || [];
      if (allowedRanges.length > 0 && !isIpAllowed(clientIp, allowedRanges)) {
        res.status(403).json({
          error: "IP not allowed for this tenant",
          code: "IP_NOT_ALLOWED",
        });
        return;
      }
    }

    req.tenant = {
      tenantId,
      organizationId,
      userId,
      userRole,
      tier: (tenant?.tier as TenantTier) || "starter",
      features: (tenant?.features as Tenant["features"]) || {},
    };

    // Set RLS context for database queries - fail closed if it fails
    try {
      await setTenantContext(organizationId);
      
      // Clear RLS context when response finishes
      res.on("finish", () => {
        clearTenantContext().catch((err) => {
          console.error("[RLS] Failed to clear tenant context:", err);
        });
      });
      
      next();
    } catch (rlsError) {
      console.error("[RLS] Failed to set tenant context:", rlsError);
      res.status(500).json({
        error: "Failed to establish tenant context",
        code: "TENANT_CONTEXT_ERROR",
      });
      return;
    }
  } catch (error) {
    console.error("Tenant middleware error:", error);
    next(error);
  }
}

function getClientIp(req: Request): string {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (forwardedFor) {
    const ips = (typeof forwardedFor === "string" ? forwardedFor : forwardedFor[0]).split(",");
    return ips[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "";
}

export function requireTenant(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.tenant || req.tenant.tenantId === DEFAULT_TENANT_ID) {
    res.status(401).json({
      error: "Tenant context required",
      code: "TENANT_REQUIRED",
    });
    return;
  }
  next();
}

export function requireTier(...allowedTiers: TenantTier[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.tenant) {
      res.status(401).json({
        error: "Tenant context required",
        code: "TENANT_REQUIRED",
      });
      return;
    }

    if (!allowedTiers.includes(req.tenant.tier)) {
      res.status(403).json({
        error: `This feature requires one of these tiers: ${allowedTiers.join(", ")}`,
        code: "TIER_UPGRADE_REQUIRED",
        currentTier: req.tenant.tier,
        requiredTiers: allowedTiers,
      });
      return;
    }

    next();
  };
}

export function requireFeature(feature: keyof NonNullable<Tenant["features"]>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.tenant) {
      res.status(401).json({
        error: "Tenant context required",
        code: "TENANT_REQUIRED",
      });
      return;
    }

    const features = req.tenant.features || {};
    if (!features[feature]) {
      res.status(403).json({
        error: `Feature '${feature}' is not enabled for this tenant`,
        code: "FEATURE_NOT_ENABLED",
        feature,
      });
      return;
    }

    next();
  };
}

function isIpAllowed(clientIp: string, allowedRanges: string[]): boolean {
  const normalizedIp = normalizeIp(clientIp);
  
  for (const range of allowedRanges) {
    if (range.includes("/")) {
      if (isIpInCidr(normalizedIp, range)) {
        return true;
      }
    } else {
      if (normalizeIp(range) === normalizedIp) {
        return true;
      }
    }
  }
  
  return false;
}

function normalizeIp(ip: string): string {
  if (ip.startsWith("::ffff:")) {
    return ip.slice(7);
  }
  return ip;
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const [range, bits] = cidr.split("/");
  const mask = parseInt(bits, 10);
  
  const ipNum = ipToNumber(ip);
  const rangeNum = ipToNumber(range);
  
  if (ipNum === null || rangeNum === null) {
    return false;
  }
  
  const maskNum = ~((1 << (32 - mask)) - 1) >>> 0;
  return (ipNum & maskNum) === (rangeNum & maskNum);
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }
  
  let num = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) {
      return null;
    }
    num = (num << 8) + n;
  }
  return num >>> 0;
}

export function getTenantContext(req: Request): TenantContext {
  return req.tenant || {
    tenantId: DEFAULT_TENANT_ID,
    organizationId: DEFAULT_ORG_ID,
    tier: "starter" as TenantTier,
    features: {},
  };
}

export function getTenantId(req: Request): string {
  return req.tenant?.tenantId || DEFAULT_TENANT_ID;
}

export function getOrganizationId(req: Request): string {
  return req.tenant?.organizationId || DEFAULT_ORG_ID;
}
