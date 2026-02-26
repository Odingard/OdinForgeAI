/**
 * Feature Flags for OdinForge Platform
 *
 * Centralized feature flag management with environment variable overrides
 * and per-tenant configuration support.
 */

/** True if this process was started with ODINFORGE_MODE=aev_only */
export const AEV_ONLY_MODE = process.env.ODINFORGE_MODE === "aev_only";

export interface FeatureFlags {
  /** Enable Report V2 Narrative generation (AI-powered pentest reports) */
  REPORTS_V2_NARRATIVE: boolean;
  /** AEV-only mode — disables all non-AEV routes, workers, and UI pages */
  AEV_ONLY: boolean;
}

/** Default feature flag values (production-safe defaults) */
const defaultFlags: FeatureFlags = {
  REPORTS_V2_NARRATIVE: false,
  AEV_ONLY: false,
};

/** Per-tenant feature flag overrides */
const tenantOverrides: Map<string, Partial<FeatureFlags>> = new Map();

/**
 * Get all feature flags for a given tenant
 * Priority: Environment variables > Tenant overrides > Defaults
 */
export function getFeatureFlags(tenantId?: string): FeatureFlags {
  const flags = { ...defaultFlags };
  
  // Apply environment variable overrides
  if (process.env.REPORTS_V2_NARRATIVE === "true") {
    flags.REPORTS_V2_NARRATIVE = true;
  }
  if (AEV_ONLY_MODE) {
    flags.AEV_ONLY = true;
  }
  
  // Apply tenant-specific overrides if available
  if (tenantId && tenantOverrides.has(tenantId)) {
    const overrides = tenantOverrides.get(tenantId)!;
    Object.assign(flags, overrides);
  }
  
  return flags;
}

/**
 * Check if a specific feature is enabled
 */
export function isFeatureEnabled(
  feature: keyof FeatureFlags,
  tenantId?: string
): boolean {
  return getFeatureFlags(tenantId)[feature];
}

/**
 * Set per-tenant feature flag overrides (for admin configuration)
 */
export function setTenantFeatureOverride(
  tenantId: string,
  feature: keyof FeatureFlags,
  enabled: boolean
): void {
  const current = tenantOverrides.get(tenantId) || {};
  current[feature] = enabled;
  tenantOverrides.set(tenantId, current);
}

/**
 * Remove per-tenant feature flag override
 */
export function removeTenantFeatureOverride(
  tenantId: string,
  feature: keyof FeatureFlags
): void {
  const current = tenantOverrides.get(tenantId);
  if (current) {
    delete current[feature];
    if (Object.keys(current).length === 0) {
      tenantOverrides.delete(tenantId);
    }
  }
}

/**
 * Get all tenant overrides (for admin dashboard)
 */
export function getAllTenantOverrides(): Record<string, Partial<FeatureFlags>> {
  const result: Record<string, Partial<FeatureFlags>> = {};
  tenantOverrides.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}
