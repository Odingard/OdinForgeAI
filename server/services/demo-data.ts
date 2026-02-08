import { db } from "../db";
import {
  endpointAgents,
  agentFindings,
  agentTelemetry,
  aevEvaluations,
  aevResults,
  scheduledScans,
  auditLogs,
  discoveredAssets,
} from "@shared/schema";
import { eq } from "drizzle-orm";
import { addDays, subDays, subHours, subMinutes } from "date-fns";

// Simple ID generator
function generateId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).substr(2, 10)}`;
}

const DEMO_ORG_ID = "default";

export interface DemoDataOptions {
  organizationId?: string;
  agentCount?: number;
  evaluationCount?: number;
  includeJobs?: boolean;
  includeScans?: boolean;
  includeSessions?: boolean;
  includeAuditLogs?: boolean;
  includeAssets?: boolean;
}

/**
 * Generate comprehensive demo data for showcasing OdinForge-AI capabilities
 */
export async function generateDemoData(options: DemoDataOptions = {}) {
  const {
    organizationId = DEMO_ORG_ID,
    agentCount = 12,
    evaluationCount = 25,
    includeJobs = true,
    includeScans = true,
    includeSessions = true,
    includeAuditLogs = true,
    includeAssets = true,
  } = options;

  console.log("[Demo Data] Starting demo data generation...");
  const results = {
    agents: 0,
    findings: 0,
    telemetry: 0,
    evaluations: 0,
    scans: 0,
    auditLogs: 0,
    assets: 0,
  };

  try {
    // 1. Generate Agents with network topology
    console.log(`[Demo Data] Generating ${agentCount} agents...`);
    const agents = await generateAgents(organizationId, agentCount);
    results.agents = agents.length;

    // 2. Generate Agent Findings
    console.log("[Demo Data] Generating agent findings...");
    const findings = await generateAgentFindings(organizationId, agents);
    results.findings = findings.length;

    // 3. Generate Agent Telemetry
    console.log("[Demo Data] Generating agent telemetry...");
    const telemetryCount = await generateAgentTelemetry(organizationId, agents);
    results.telemetry = telemetryCount;

    // 4. Generate Security Evaluations with risk scores
    console.log(`[Demo Data] Generating ${evaluationCount} evaluations...`);
    const evaluations = await generateEvaluations(organizationId, evaluationCount);
    results.evaluations = evaluations.length;

    // 5. Generate Scheduled Scans
    if (includeScans) {
      console.log("[Demo Data] Generating scheduled scans...");
      const scanCount = await generateScheduledScans(organizationId);
      results.scans = scanCount;
    }

    // 6. Generate Audit Logs
    if (includeAuditLogs) {
      console.log("[Demo Data] Generating audit logs...");
      const auditCount = await generateAuditLogs(organizationId);
      results.auditLogs = auditCount;
    }

    // 9. Generate Cloud Assets with dependencies
    if (includeAssets) {
      console.log("[Demo Data] Generating cloud assets...");
      const assetCount = await generateCloudAssets(organizationId);
      results.assets = assetCount;
    }

    console.log("[Demo Data] Demo data generation complete:", results);
    return results;
  } catch (error) {
    console.error("[Demo Data] Error generating demo data:", error);
    throw error;
  }
}

/**
 * Clear all demo data from the database
 */
export async function clearDemoData(organizationId: string = DEMO_ORG_ID) {
  console.log(`[Demo Data] Clearing demo data for organization: ${organizationId}`);

  try {
    // Get all evaluation IDs for this organization first
    const orgEvaluations = await db
      .select({ id: aevEvaluations.id })
      .from(aevEvaluations)
      .where(eq(aevEvaluations.organizationId, organizationId));

    const evaluationIds = orgEvaluations.map(e => e.id);

    // Clear in reverse dependency order
    // First delete aevResults by evaluationId (doesn't have organizationId)
    if (evaluationIds.length > 0) {
      for (const evalId of evaluationIds) {
        await db.delete(aevResults).where(eq(aevResults.evaluationId, evalId));
      }
    }

    await db.delete(agentTelemetry).where(eq(agentTelemetry.organizationId, organizationId));
    await db.delete(agentFindings).where(eq(agentFindings.organizationId, organizationId));
    await db.delete(aevEvaluations).where(eq(aevEvaluations.organizationId, organizationId));
    await db.delete(scheduledScans).where(eq(scheduledScans.organizationId, organizationId));
    await db.delete(auditLogs).where(eq(auditLogs.organizationId, organizationId));
    await db.delete(discoveredAssets).where(eq(discoveredAssets.organizationId, organizationId));
    await db.delete(endpointAgents).where(eq(endpointAgents.organizationId, organizationId));

    console.log("[Demo Data] Demo data cleared successfully");
  } catch (error) {
    console.error("[Demo Data] Error clearing demo data:", error);
    throw error;
  }
}

// Helper functions for generating specific data types

async function generateAgents(organizationId: string, count: number) {
  const roles = ["controller", "worker", "sensor"];
  const statuses = ["online", "offline", "degraded"];
  const hostnames = [
    "web-prod-01", "web-prod-02", "db-primary", "db-replica",
    "api-gateway", "cache-redis", "worker-01", "worker-02",
    "monitor-01", "backup-server", "vpn-gateway", "fileserver"
  ];

  const agentsToInsert = [];
  const now = new Date();

  for (let i = 0; i < count; i++) {
    const role = roles[i % roles.length];
    const status = i < count * 0.8 ? "online" : statuses[i % statuses.length];
    const hostname = hostnames[i] || `server-${i + 1}`;
    const agentId = generateId("agent-demo");

    agentsToInsert.push({
      id: agentId,
      organizationId,
      agentName: `${hostname} (Demo)`,
      apiKey: `demo-key-${agentId}`,
      hostname,
      ipAddresses: [`10.0.${Math.floor(i / 255)}.${(i % 255) + 1}`],
      platform: i % 2 === 0 ? "linux" : "windows",
      platformVersion: i % 2 === 0 ? "Ubuntu 22.04 LTS" : "Windows Server 2022",
      agentVersion: "1.2.3",
      status,
      lastHeartbeat: status === "online" ? now : subHours(now, Math.floor(Math.random() * 24)),
      registeredAt: subDays(now, Math.floor(Math.random() * 30)),
      capabilities: ["telemetry", "vulnerability_scan", "config_audit"],
      tags: [role, `datacenter:${i % 2 === 0 ? "us-east-1" : "us-west-2"}`],
      environment: "production",
      createdAt: subDays(now, Math.floor(Math.random() * 30)),
      updatedAt: now,
    });
  }

  await db.insert(endpointAgents).values(agentsToInsert);
  return agentsToInsert;
}

async function generateAgentFindings(organizationId: string, agents: any[]) {
  const severities = ["low", "medium", "high", "critical"];
  const findingTypes = [
    "outdated_software",
    "weak_config",
    "open_port",
    "cve_detected",
    "policy_violation",
    "suspicious_process",
    "privilege_escalation"
  ];
  const statuses = ["open", "acknowledged", "resolved", "false_positive"];

  const findingsToInsert = [];
  const now = new Date();

  for (const agent of agents.slice(0, 8)) {
    const findingCount = Math.floor(Math.random() * 5) + 1;

    for (let i = 0; i < findingCount; i++) {
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const findingType = findingTypes[Math.floor(Math.random() * findingTypes.length)];

      findingsToInsert.push({
        id: `finding-demo-${generateId("demo")}`,
        organizationId,
        agentId: agent.id,
        findingType,
        severity,
        title: `${severity.toUpperCase()}: ${findingType.replace(/_/g, ' ')} detected on ${agent.hostname}`,
        description: `Demo security finding for testing - ${findingType} discovered during automated scan`,
        detectedAt: subHours(now, Math.floor(Math.random() * 48)),
        status: statuses[Math.floor(Math.random() * statuses.length)],
        confidenceScore: Math.floor(Math.random() * 40) + 60, // 60-100
        remediationStatus: i === 0 ? "pending" : "completed",
        createdAt: subHours(now, Math.floor(Math.random() * 48)),
        updatedAt: now,
      });
    }
  }

  await db.insert(agentFindings).values(findingsToInsert);
  return findingsToInsert;
}

async function generateAgentTelemetry(organizationId: string, agents: any[]) {
  const telemetryToInsert = [];
  const now = new Date();
  let count = 0;

  // Generate last 24 hours of telemetry for online agents
  for (const agent of agents.filter(a => a.status === "online")) {
    for (let hour = 0; hour < 24; hour++) {
      telemetryToInsert.push({
        id: `telemetry-demo-${generateId("demo")}`,
        organizationId,
        agentId: agent.id,
        cpuUsage: Math.random() * 100,
        memoryUsage: Math.random() * 100,
        diskUsage: Math.random() * 100,
        networkRx: Math.floor(Math.random() * 1000000),
        networkTx: Math.floor(Math.random() * 1000000),
        processCount: Math.floor(Math.random() * 200) + 50,
        receivedAt: subHours(now, hour),
      });
      count++;
    }
  }

  if (telemetryToInsert.length > 0) {
    await db.insert(agentTelemetry).values(telemetryToInsert);
  }
  return count;
}

async function generateEvaluations(organizationId: string, count: number) {
  const statuses = ["completed", "in_progress", "pending", "failed"];
  const priorities = ["low", "medium", "high", "critical"];
  const assetTypes = ["web-server", "database", "api", "cache", "worker"];

  const evaluationsToInsert = [];
  const now = new Date();

  for (let i = 0; i < count; i++) {
    const status = i < count * 0.6 ? "completed" : statuses[i % statuses.length];
    const priority = priorities[Math.floor(Math.random() * priorities.length)];
    const exploitability = Math.floor(Math.random() * 100);
    const businessImpact = Math.floor(Math.random() * 100);
    const overallScore = (exploitability + businessImpact) / 2;

    evaluationsToInsert.push({
      id: `eval-demo-${generateId("demo")}`,
      organizationId,
      assetId: `${assetTypes[i % assetTypes.length]}-${i + 1}`,
      status,
      priority,
      createdAt: subDays(now, Math.floor(Math.random() * 30)),
      completedAt: status === "completed" ? subDays(now, Math.floor(Math.random() * 25)) : null,
      intelligentScore: {
        exploitability: { score: exploitability, level: exploitability > 75 ? "high" : "medium" },
        businessImpact: { score: businessImpact, level: businessImpact > 75 ? "high" : "medium" },
        riskRank: {
          overallScore,
          riskLevel: overallScore > 80 ? "critical" : overallScore > 60 ? "high" : overallScore > 40 ? "medium" : "low"
        }
      },
    });
  }

  await db.insert(aevEvaluations).values(evaluationsToInsert);
  return evaluationsToInsert;
}

async function generateScheduledScans(organizationId: string) {
  const scans = [
    { name: "Daily Vulnerability Scan", schedule: "0 2 * * *", enabled: true },
    { name: "Weekly Compliance Check", schedule: "0 0 * * 0", enabled: true },
    { name: "Monthly Security Audit", schedule: "0 0 1 * *", enabled: true },
    { name: "Hourly Health Check", schedule: "0 * * * *", enabled: false },
  ];

  const scansToInsert = scans.map(scan => ({
    id: `scan-demo-${generateId("demo")}`,
    organizationId,
    name: scan.name,
    schedule: scan.schedule,
    enabled: scan.enabled,
    lastRun: subHours(new Date(), Math.floor(Math.random() * 24)),
    nextRun: addDays(new Date(), 1),
    createdAt: subDays(new Date(), 30),
  }));

  await db.insert(scheduledScans).values(scansToInsert);
  return scansToInsert.length;
}

async function generateAuditLogs(organizationId: string) {
  const actions = ["login", "logout", "create", "update", "delete", "deploy", "scan"];
  const users = ["admin", "analyst", "security-team"];
  const now = new Date();

  const logsToInsert = [];

  for (let i = 0; i < 50; i++) {
    logsToInsert.push({
      id: `audit-demo-${generateId("demo")}`,
      organizationId,
      userId: users[i % users.length],
      action: actions[i % actions.length],
      resource: `resource-${i}`,
      timestamp: subMinutes(now, i * 30),
      ipAddress: `192.168.1.${(i % 255) + 1}`,
      userAgent: "Mozilla/5.0 (Demo Browser)",
      success: i % 10 !== 0,
    });
  }

  await db.insert(auditLogs).values(logsToInsert);
  return logsToInsert.length;
}

async function generateCloudAssets(organizationId: string) {
  const assetTypes = ["ec2", "rds", "s3", "lambda", "vpc"];
  const criticalities = ["low", "medium", "high", "critical"];

  const assetsToInsert = [];

  for (let i = 0; i < 10; i++) {
    assetsToInsert.push({
      id: `asset-demo-${generateId("demo")}`,
      organizationId,
      name: `${assetTypes[i % assetTypes.length]}-demo-${i + 1}`,
      type: assetTypes[i % assetTypes.length],
      provider: "aws",
      region: i % 2 === 0 ? "us-east-1" : "us-west-2",
      criticality: criticalities[i % criticalities.length],
      discoveredAt: subDays(new Date(), Math.floor(Math.random() * 30)),
      metadata: {},
    });
  }

  await db.insert(discoveredAssets).values(assetsToInsert);
  return assetsToInsert.length;
}
