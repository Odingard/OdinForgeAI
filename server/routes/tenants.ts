import { Express, Request, Response, NextFunction } from "express";
import { storage } from "../storage";
import { insertTenantSchema } from "@shared/schema";
import { getTenantContext } from "../middleware/tenant";
import { uiAuthMiddleware, requireRole } from "../services/ui-auth";
import { z } from "zod";

const updateTenantSchema = z.object({
  name: z.string().min(1).max(256).optional(),
  status: z.enum(["active", "suspended", "trial", "pending_verification"]).optional(),
  tier: z.enum(["free", "starter", "professional", "enterprise", "unlimited"]).optional(),
  trialEndsAt: z.string().datetime().optional().nullable(),
  maxUsers: z.number().int().min(1).optional(),
  maxAgents: z.number().int().min(1).optional(),
  maxEvaluationsPerDay: z.number().int().min(1).optional(),
  maxConcurrentScans: z.number().int().min(1).optional(),
  features: z.object({
    liveScanning: z.boolean().optional(),
    cloudIntegration: z.boolean().optional(),
    apiAccess: z.boolean().optional(),
    customReports: z.boolean().optional(),
    aiSimulations: z.boolean().optional(),
    externalRecon: z.boolean().optional(),
    complianceFrameworks: z.array(z.string()).optional(),
  }).optional(),
  allowedIpRanges: z.array(z.string()).optional(),
  enforceIpAllowlist: z.boolean().optional(),
  billingEmail: z.string().email().optional().nullable(),
  technicalContact: z.string().email().optional().nullable(),
  industry: z.string().max(128).optional().nullable(),
});

const requirePlatformAdmin = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  const user = session?.user;
  if (!user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  if (user.roleId !== "platform_super_admin" && user.roleId !== "organization_owner") {
    return res.status(403).json({ error: "Platform admin access required" });
  }
  
  next();
};

export function registerTenantRoutes(app: Express): void {
  app.get("/api/tenants", uiAuthMiddleware, requirePlatformAdmin, async (req: Request, res: Response) => {
    try {
      const tenants = await storage.getTenants();
      res.json(tenants);
    } catch (error) {
      console.error("Error fetching tenants:", error);
      res.status(500).json({ error: "Failed to fetch tenants" });
    }
  });

  app.get("/api/tenants/current/context", async (req: Request, res: Response) => {
    try {
      const context = getTenantContext(req);
      res.json(context);
    } catch (error) {
      console.error("Error fetching tenant context:", error);
      res.status(500).json({ error: "Failed to fetch tenant context" });
    }
  });

  app.get("/api/tenants/:id", uiAuthMiddleware, requirePlatformAdmin, async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const tenant = await storage.getTenant(id);
      
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      res.json(tenant);
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ error: "Failed to fetch tenant" });
    }
  });

  app.post("/api/tenants", uiAuthMiddleware, requirePlatformAdmin, async (req: Request, res: Response) => {
    try {
      const validatedData = insertTenantSchema.parse(req.body);
      
      const existingSlug = await storage.getTenantBySlug(validatedData.slug);
      if (existingSlug) {
        return res.status(409).json({ error: "Tenant with this slug already exists" });
      }
      
      const tenant = await storage.createTenant(validatedData);
      res.status(201).json(tenant);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid tenant data", details: error.errors });
      }
      console.error("Error creating tenant:", error);
      res.status(500).json({ error: "Failed to create tenant" });
    }
  });

  app.patch("/api/tenants/:id", uiAuthMiddleware, requirePlatformAdmin, async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      
      const tenant = await storage.getTenant(id);
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      const validated = updateTenantSchema.parse(req.body);
      
      const updates: Record<string, any> = { ...validated };
      if (validated.trialEndsAt !== undefined) {
        updates.trialEndsAt = validated.trialEndsAt ? new Date(validated.trialEndsAt) : null;
      }
      
      await storage.updateTenant(id, updates);
      const updated = await storage.getTenant(id);
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid update data", details: error.errors });
      }
      console.error("Error updating tenant:", error);
      res.status(500).json({ error: "Failed to update tenant" });
    }
  });

  app.delete("/api/tenants/:id", uiAuthMiddleware, requirePlatformAdmin, async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      
      if (id === "default") {
        return res.status(400).json({ error: "Cannot delete the default tenant" });
      }
      
      const tenant = await storage.getTenant(id);
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      await storage.deleteTenant(id);
      res.json({ success: true, message: "Tenant deleted" });
    } catch (error) {
      console.error("Error deleting tenant:", error);
      res.status(500).json({ error: "Failed to delete tenant" });
    }
  });

  app.get("/api/tenants/:id/usage", uiAuthMiddleware, async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const session = (req as any).session;
      const user = session?.user;
      
      if (user.tenantId !== id && user.roleId !== "platform_super_admin") {
        return res.status(403).json({ error: "Access denied" });
      }
      
      const tenant = await storage.getTenant(id);
      
      if (!tenant) {
        return res.status(404).json({ error: "Tenant not found" });
      }
      
      res.json({
        tenantId: id,
        limits: {
          maxUsers: tenant.maxUsers,
          maxAgents: tenant.maxAgents,
          maxEvaluationsPerDay: tenant.maxEvaluationsPerDay,
          maxConcurrentScans: tenant.maxConcurrentScans,
        },
        usage: {
          users: 0,
          agents: 0,
          evaluationsToday: 0,
          currentConcurrentScans: 0,
        },
        tier: tenant.tier,
        features: tenant.features,
      });
    } catch (error) {
      console.error("Error fetching tenant usage:", error);
      res.status(500).json({ error: "Failed to fetch tenant usage" });
    }
  });
}

export async function seedDefaultTenant(): Promise<void> {
  try {
    const existingDefault = await storage.getTenant("default");
    if (!existingDefault) {
      await storage.createTenant({
        id: "default",
        name: "Default Organization",
        slug: "default",
        status: "active",
        tier: "enterprise",
        maxUsers: 100,
        maxAgents: 1000,
        maxEvaluationsPerDay: 10000,
        maxConcurrentScans: 50,
        features: {
          liveScanning: true,
          cloudIntegration: true,
          apiAccess: true,
          customReports: true,
          aiSimulations: true,
          externalRecon: true,
          complianceFrameworks: ["NIST", "CIS", "MITRE_ATTACK", "SOC2", "ISO27001"],
        },
      });
      console.log("[Tenant] Default tenant created");
    } else {
      console.log("[Tenant] Default tenant already exists");
    }
  } catch (error) {
    console.error("[Tenant] Error seeding default tenant:", error);
  }
}
