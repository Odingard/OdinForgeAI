import { sql } from "drizzle-orm";
import { db } from "./db";

export async function createDatabaseIndexes(): Promise<void> {
  console.log("Creating database indexes for optimal query performance...");
  
  const indexes = [
    {
      name: "idx_aev_evaluations_status",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_status ON aev_evaluations (status)`,
    },
    {
      name: "idx_aev_evaluations_organization",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_organization ON aev_evaluations (organization_id)`,
    },
    {
      name: "idx_aev_evaluations_created",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_created ON aev_evaluations (created_at DESC)`,
    },
    {
      name: "idx_aev_evaluations_priority",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_priority ON aev_evaluations (priority)`,
    },
    {
      name: "idx_aev_evaluations_asset",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_asset ON aev_evaluations (asset_id)`,
    },
    {
      name: "idx_aev_evaluations_composite_status_org",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_evaluations_composite_status_org ON aev_evaluations (organization_id, status, created_at DESC)`,
    },
    {
      name: "idx_aev_results_evaluation",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_results_evaluation ON aev_results (evaluation_id)`,
    },
    {
      name: "idx_aev_results_exploitability",
      query: sql`CREATE INDEX IF NOT EXISTS idx_aev_results_exploitability ON aev_results (exploitable, score)`,
    },
    {
      name: "idx_endpoint_agents_status",
      query: sql`CREATE INDEX IF NOT EXISTS idx_endpoint_agents_status ON endpoint_agents (status)`,
    },
    {
      name: "idx_endpoint_agents_last_heartbeat",
      query: sql`CREATE INDEX IF NOT EXISTS idx_endpoint_agents_last_heartbeat ON endpoint_agents (last_heartbeat DESC)`,
    },
    {
      name: "idx_endpoint_agents_org",
      query: sql`CREATE INDEX IF NOT EXISTS idx_endpoint_agents_org ON endpoint_agents (organization_id)`,
    },
    {
      name: "idx_agent_findings_severity",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_findings_severity ON agent_findings (severity)`,
    },
    {
      name: "idx_agent_findings_agent",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_findings_agent ON agent_findings (agent_id)`,
    },
    {
      name: "idx_agent_findings_detected",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_findings_detected ON agent_findings (detected_at DESC)`,
    },
    {
      name: "idx_agent_findings_composite",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_findings_composite ON agent_findings (agent_id, severity, detected_at DESC)`,
    },
    {
      name: "idx_agent_telemetry_agent",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_telemetry_agent ON agent_telemetry (agent_id)`,
    },
    {
      name: "idx_agent_telemetry_received",
      query: sql`CREATE INDEX IF NOT EXISTS idx_agent_telemetry_received ON agent_telemetry (received_at DESC)`,
    },
    {
      name: "idx_reports_org",
      query: sql`CREATE INDEX IF NOT EXISTS idx_reports_org ON reports (organization_id)`,
    },
    {
      name: "idx_reports_created",
      query: sql`CREATE INDEX IF NOT EXISTS idx_reports_created ON reports (created_at DESC)`,
    },
    {
      name: "idx_reports_type",
      query: sql`CREATE INDEX IF NOT EXISTS idx_reports_type ON reports (report_type)`,
    },
    {
      name: "idx_simulations_org",
      query: sql`CREATE INDEX IF NOT EXISTS idx_simulations_org ON ai_simulations (organization_id)`,
    },
    {
      name: "idx_simulations_status",
      query: sql`CREATE INDEX IF NOT EXISTS idx_simulations_status ON ai_simulations (simulation_status)`,
    },
    {
      name: "idx_simulations_created",
      query: sql`CREATE INDEX IF NOT EXISTS idx_simulations_created ON ai_simulations (created_at DESC)`,
    },
    {
      name: "idx_authorization_logs_user",
      query: sql`CREATE INDEX IF NOT EXISTS idx_authorization_logs_user ON authorization_logs (user_id)`,
    },
    {
      name: "idx_authorization_logs_created",
      query: sql`CREATE INDEX IF NOT EXISTS idx_authorization_logs_created ON authorization_logs (created_at DESC)`,
    },
    {
      name: "idx_rate_limit_window_type",
      query: sql`CREATE INDEX IF NOT EXISTS idx_rate_limit_window_type ON rate_limit_tracking (window_type)`,
    },
    {
      name: "idx_rate_limit_window",
      query: sql`CREATE INDEX IF NOT EXISTS idx_rate_limit_window ON rate_limit_tracking (window_start)`,
    },
    {
      name: "idx_evaluation_history_eval",
      query: sql`CREATE INDEX IF NOT EXISTS idx_evaluation_history_eval ON evaluation_history (evaluation_id)`,
    },
    {
      name: "idx_evaluation_history_created",
      query: sql`CREATE INDEX IF NOT EXISTS idx_evaluation_history_created ON evaluation_history (created_at DESC)`,
    },
    {
      name: "idx_discovered_assets_org",
      query: sql`CREATE INDEX IF NOT EXISTS idx_discovered_assets_org ON discovered_assets (organization_id)`,
    },
    {
      name: "idx_discovered_assets_type",
      query: sql`CREATE INDEX IF NOT EXISTS idx_discovered_assets_type ON discovered_assets (asset_type)`,
    },
    {
      name: "idx_discovered_assets_criticality",
      query: sql`CREATE INDEX IF NOT EXISTS idx_discovered_assets_criticality ON discovered_assets (criticality)`,
    },
    {
      name: "idx_vulnerability_imports_asset",
      query: sql`CREATE INDEX IF NOT EXISTS idx_vulnerability_imports_asset ON vulnerability_imports (asset_id)`,
    },
    {
      name: "idx_vulnerability_imports_severity",
      query: sql`CREATE INDEX IF NOT EXISTS idx_vulnerability_imports_severity ON vulnerability_imports (severity)`,
    },
    {
      name: "idx_vulnerability_imports_cve",
      query: sql`CREATE INDEX IF NOT EXISTS idx_vulnerability_imports_cve ON vulnerability_imports (cve_id)`,
    },
  ];
  
  let created = 0;
  let failed = 0;
  
  for (const index of indexes) {
    try {
      await db.execute(index.query);
      created++;
      console.log(`  [OK] ${index.name}`);
    } catch (error: any) {
      if (error.message?.includes("already exists")) {
        console.log(`  [SKIP] ${index.name} (already exists)`);
      } else {
        console.error(`  [FAIL] ${index.name}: ${error.message}`);
        failed++;
      }
    }
  }
  
  console.log(`\nDatabase indexing complete: ${created} created, ${failed} failed`);
}

export async function dropAllCustomIndexes(): Promise<void> {
  console.log("Dropping custom indexes...");
  
  const indexNames = [
    "idx_aev_evaluations_status",
    "idx_aev_evaluations_organization",
    "idx_aev_evaluations_created",
    "idx_aev_evaluations_priority",
    "idx_aev_evaluations_asset",
    "idx_aev_evaluations_composite_status_org",
    "idx_aev_results_evaluation",
    "idx_aev_results_exploitability",
    "idx_endpoint_agents_status",
    "idx_endpoint_agents_last_heartbeat",
    "idx_endpoint_agents_org",
    "idx_agent_findings_severity",
    "idx_agent_findings_agent",
    "idx_agent_findings_detected",
    "idx_agent_findings_composite",
    "idx_agent_telemetry_agent",
    "idx_agent_telemetry_received",
    "idx_reports_org",
    "idx_reports_created",
    "idx_reports_type",
    "idx_simulations_org",
    "idx_simulations_status",
    "idx_simulations_created",
    "idx_authorization_logs_user",
    "idx_authorization_logs_created",
    "idx_rate_limit_window_type",
    "idx_rate_limit_window",
    "idx_evaluation_history_eval",
    "idx_evaluation_history_created",
    "idx_discovered_assets_org",
    "idx_discovered_assets_type",
    "idx_discovered_assets_criticality",
    "idx_vulnerability_imports_asset",
    "idx_vulnerability_imports_severity",
    "idx_vulnerability_imports_cve",
  ];
  
  for (const name of indexNames) {
    try {
      await db.execute(sql`DROP INDEX IF EXISTS ${sql.identifier(name)}`);
      console.log(`  [OK] Dropped ${name}`);
    } catch (error: any) {
      console.error(`  [FAIL] ${name}: ${error.message}`);
    }
  }
}

export async function analyzeTableStats(): Promise<void> {
  console.log("\nAnalyzing table statistics for query optimization...");
  
  const tables = [
    "aev_evaluations",
    "aev_results", 
    "endpoint_agents",
    "agent_findings",
    "agent_telemetry",
    "reports",
    "ai_simulations",
  ];
  
  for (const table of tables) {
    try {
      await db.execute(sql`ANALYZE ${sql.identifier(table)}`);
      console.log(`  [OK] Analyzed ${table}`);
    } catch (error: any) {
      console.error(`  [FAIL] ${table}: ${error.message}`);
    }
  }
}
