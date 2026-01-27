/**
 * Row-Level Security (RLS) Setup for Multi-Tenant Data Isolation
 * 
 * This module enables Postgres RLS policies to automatically filter data
 * by organization_id based on the current session context.
 */

import { db } from "../db";
import { sql } from "drizzle-orm";

const TENANT_TABLES = [
  "aev_evaluations",
  "aev_results",
  "safety_decisions",
  "live_scan_results",
  "reports",
  "report_narratives",
  "scheduled_scans",
  "evaluation_history",
  "organization_governance",
  "authorization_logs",
  "scope_rules",
  "validation_audit_logs",
  "approval_requests",
  "attack_predictions",
  "defensive_posture_scores",
  "purple_team_findings",
  "ai_simulations",
  "discovered_assets",
  "vulnerability_imports",
  "import_jobs",
  "cloud_connections",
  "ssh_credentials",
  "cloud_discovery_jobs",
  "cloud_assets",
  "agent_deployment_jobs",
  "endpoint_agents",
  "agent_registration_tokens",
  "agent_commands",
  "agent_telemetry",
  "agent_findings",
  "ui_users",
  "ui_refresh_tokens",
  "full_assessments",
  "recon_scans",
  "api_scan_results",
  "auth_scan_results",
  "exploit_validation_results",
  "remediation_results",
  "validation_evidence_artifacts",
  "enrollment_tokens",
  "web_app_recon_scans",
  "auto_deploy_configs",
  "api_definitions",
  "api_endpoints",
  "sandbox_sessions",
  "sandbox_snapshots",
  "sandbox_executions",
  "discovered_credentials",
  "lateral_movement_findings",
  "pivot_points",
  "attack_paths",
  "security_policies",
  "audit_logs",
  "forensic_exports",
  "hitl_approval_requests",
];

/**
 * Initialize RLS policies for all tenant-sensitive tables
 * This should be called once during server startup
 */
export async function initializeRLS(): Promise<void> {
  console.log("[RLS] Initializing Row-Level Security policies...");
  
  try {
    // Create app-level settings for tenant context if not exists
    await db.execute(sql`
      DO $$
      BEGIN
        -- Create the setting if it doesn't exist
        PERFORM set_config('app.current_organization_id', '', FALSE);
      EXCEPTION WHEN OTHERS THEN
        -- Ignore errors, setting already exists
        NULL;
      END $$;
    `);

    let enabledCount = 0;
    let skippedCount = 0;

    for (const tableName of TENANT_TABLES) {
      try {
        // Check if table exists and has organization_id column
        const tableCheck = await db.execute(sql`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = ${tableName} 
          AND column_name = 'organization_id'
          AND table_schema = 'public'
        `);

        if (tableCheck.rows.length === 0) {
          console.log(`[RLS] Skipping ${tableName} - no organization_id column`);
          skippedCount++;
          continue;
        }

        // Enable RLS on the table
        await db.execute(sql.raw(`ALTER TABLE "${tableName}" ENABLE ROW LEVEL SECURITY`));

        // Drop existing policy if it exists
        await db.execute(sql.raw(`
          DROP POLICY IF EXISTS tenant_isolation_policy ON "${tableName}"
        `));

        // Create RLS policy that filters by organization_id
        // The policy checks current_setting('app.current_organization_id')
        // Allows access if:
        // 1. Session org matches row org
        // 2. Row has no org (global/shared data) AND session has a valid org
        // 3. Admin bypass mode is enabled (app.rls_bypass = 'true')
        // DENIES access if session org is not set (prevents cross-tenant data exposure)
        await db.execute(sql.raw(`
          CREATE POLICY tenant_isolation_policy ON "${tableName}"
          FOR ALL
          USING (
            CASE
              -- Admin bypass mode for background jobs and system operations
              WHEN current_setting('app.rls_bypass', TRUE) = 'true' THEN TRUE
              -- Deny if no org context is set (prevent accidental data exposure)
              WHEN current_setting('app.current_organization_id', TRUE) IS NULL THEN FALSE
              WHEN current_setting('app.current_organization_id', TRUE) = '' THEN FALSE
              -- Allow access to global/shared data (organization_id IS NULL)
              WHEN organization_id IS NULL THEN TRUE
              -- Allow access to data matching the current organization
              ELSE organization_id = current_setting('app.current_organization_id', TRUE)
            END
          )
          WITH CHECK (
            CASE
              -- Admin bypass mode for background jobs and system operations
              WHEN current_setting('app.rls_bypass', TRUE) = 'true' THEN TRUE
              -- Deny if no org context is set
              WHEN current_setting('app.current_organization_id', TRUE) IS NULL THEN FALSE
              WHEN current_setting('app.current_organization_id', TRUE) = '' THEN FALSE
              -- Allow inserting shared data or data matching current org
              ELSE organization_id = current_setting('app.current_organization_id', TRUE) OR organization_id IS NULL
            END
          )
        `));

        console.log(`[RLS] Enabled RLS on ${tableName}`);
        enabledCount++;
      } catch (tableError: any) {
        // Table might not exist or other issues
        console.log(`[RLS] Skipping ${tableName}: ${tableError.message}`);
        skippedCount++;
      }
    }

    console.log(`[RLS] Complete: ${enabledCount} tables protected, ${skippedCount} skipped`);
  } catch (error) {
    console.error("[RLS] Failed to initialize:", error);
    throw error;
  }
}

/**
 * Set the current organization context for the database session
 * This should be called at the start of each request
 */
export async function setTenantContext(organizationId: string | null): Promise<void> {
  const orgId = organizationId || "";
  await db.execute(sql`SELECT set_config('app.current_organization_id', ${orgId}, TRUE)`);
}

/**
 * Clear the tenant context (for cleanup or admin operations)
 */
export async function clearTenantContext(): Promise<void> {
  await db.execute(sql`SELECT set_config('app.current_organization_id', '', TRUE)`);
}

/**
 * Get the current tenant context from the session
 */
export async function getCurrentTenantContext(): Promise<string | null> {
  const result = await db.execute(sql`SELECT current_setting('app.current_organization_id', TRUE) as org_id`);
  const orgId = (result.rows[0] as any)?.org_id;
  return orgId && orgId !== "" ? orgId : null;
}

/**
 * Execute a function with a specific tenant context
 * Useful for admin operations that need to access specific tenant data
 */
export async function withTenantContext<T>(
  organizationId: string,
  fn: () => Promise<T>
): Promise<T> {
  const previousContext = await getCurrentTenantContext();
  try {
    await setTenantContext(organizationId);
    return await fn();
  } finally {
    await setTenantContext(previousContext);
  }
}

/**
 * Execute a function without any tenant restrictions (admin mode)
 * Uses RLS bypass instead of clearing context
 */
export async function withoutTenantContext<T>(fn: () => Promise<T>): Promise<T> {
  const previousContext = await getCurrentTenantContext();
  try {
    await enableRLSBypass();
    return await fn();
  } finally {
    await disableRLSBypass();
    await setTenantContext(previousContext);
  }
}

/**
 * Enable RLS bypass mode for system operations
 * Only use this for background jobs and admin operations that need cross-tenant access
 */
export async function enableRLSBypass(): Promise<void> {
  await db.execute(sql`SELECT set_config('app.rls_bypass', 'true', TRUE)`);
}

/**
 * Disable RLS bypass mode
 */
export async function disableRLSBypass(): Promise<void> {
  await db.execute(sql`SELECT set_config('app.rls_bypass', 'false', TRUE)`);
}

/**
 * Execute a function with RLS bypass enabled (for system/admin operations)
 * Use for background jobs that need to access specific tenant data
 */
export async function withRLSBypass<T>(fn: () => Promise<T>): Promise<T> {
  try {
    await enableRLSBypass();
    return await fn();
  } finally {
    await disableRLSBypass();
  }
}
