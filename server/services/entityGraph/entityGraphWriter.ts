// =============================================================================
// Entity Graph Writer — OdinForge
// Writes OdinForge entities (assets, vulnerabilities, findings, evaluations)
// into the shared entity_graph schema.
// =============================================================================

import { eq, sql } from "drizzle-orm";
import { db } from "../../db";
import {
  egEntities,
  egFindings,
  egAssessments,
  egRiskSnapshots,
  egSourceRefs,
  egRelationships,
  discoveredAssets,
  vulnerabilityImports,
  aevEvaluations,
  aevResults,
  agentFindings,
  cloudAssets,
  type DiscoveredAsset,
  type VulnerabilityImport,
  type Evaluation,
  type Result,
  type AgentFinding,
  type CloudAsset,
} from "@shared/schema";

// =============================================================================
// TYPES
// =============================================================================

type EgSeverity = "critical" | "high" | "medium" | "low" | "info";

function normalizeSeverity(s: string): EgSeverity {
  if (s === "informational") return "info";
  return s as EgSeverity;
}

function assetTypeToEntityType(assetType: string): string {
  if (assetType.includes("cloud")) return "cloud_resource";
  if (assetType.includes("ip")) return "ip_address";
  if (assetType.includes("sub")) return "subdomain";
  if (assetType.includes("port")) return "port_service";
  return "domain";
}

// =============================================================================
// ENTITY GRAPH WRITER
// =============================================================================

export class EntityGraphWriter {
  constructor(
    private readonly dbInstance: typeof db,
    private readonly organizationId: string,
  ) {}

  // Set entity_graph RLS context — mirrors OdinForge's withTenantContext() pattern
  private async withEgTenantContext<T>(fn: (tx: typeof db) => Promise<T>): Promise<T> {
    return this.dbInstance.transaction(async (tx: any) => {
      await tx.execute(
        sql`SELECT set_config('entity_graph.current_organization_id', ${this.organizationId}, TRUE)`
      );
      return fn(tx);
    });
  }

  // ---------------------------------------------------------------------------
  // upsertAsset — maps discovered_assets → entity_graph.entities
  // ---------------------------------------------------------------------------
  async upsertAsset(asset: DiscoveredAsset): Promise<string> {
    const entityType = assetTypeToEntityType(asset.assetType);

    const canonicalKey =
      asset.hostname ??
      (asset.ipAddresses as string[] | null)?.[0] ??
      asset.assetIdentifier;

    const metadata: Record<string, unknown> = {
      assetIdentifier: asset.assetIdentifier,
      assetType: asset.assetType,
      environment: asset.environment,
      criticality: asset.criticality,
    };
    if (asset.cloudProvider) metadata.cloudProvider = asset.cloudProvider;
    if (asset.cloudResourceId) metadata.cloudResourceId = asset.cloudResourceId;
    if (asset.ipAddresses) metadata.ipAddresses = asset.ipAddresses;

    const result = await this.dbInstance.execute<{ id: string }>(
      sql`SELECT entity_graph.upsert_entity(
        ${this.organizationId}::uuid,
        ${entityType}::entity_graph.entity_type,
        ${canonicalKey},
        ${asset.hostname ?? asset.assetIdentifier},
        ${JSON.stringify(metadata)}::jsonb,
        ARRAY[${asset.environment ?? "unknown"}]::text[],
        'odinforge'::entity_graph.source_product,
        NULL,
        ${asset.criticality ?? null}
      ) AS id`
    );

    const entityId = (result as any).rows[0].id as string;

    // Register source ref back to discovered_assets
    await this.dbInstance.execute(
      sql`SELECT entity_graph.upsert_source_ref(
        ${entityId}::uuid,
        'odinforge'::entity_graph.source_product,
        'discovered_assets',
        ${asset.id}::uuid
      )`
    );

    return entityId;
  }

  // ---------------------------------------------------------------------------
  // upsertVulnerabilityFinding — maps vulnerability_imports → eg.findings
  // ---------------------------------------------------------------------------
  async upsertVulnerabilityFinding(
    vuln: VulnerabilityImport,
    entityId: string,
  ): Promise<string> {
    const existing = await this.dbInstance
      .select({ id: egFindings.id })
      .from(egFindings)
      .where(eq(egFindings.sourceId, vuln.id))
      .limit(1);

    if (existing.length > 0) {
      await this.withEgTenantContext((tx) =>
        tx
          .update(egFindings)
          .set({ lastSeenAt: new Date(), updatedAt: new Date() })
          .where(eq(egFindings.id, existing[0].id))
      );
      return existing[0].id;
    }

    const [finding] = await this.withEgTenantContext((tx) =>
      tx
        .insert(egFindings)
        .values({
          organizationId: this.organizationId,
          entityId,
          sourceProduct: "odinforge",
          category: "vulnerable_software",
          severity: normalizeSeverity(vuln.severity),
          title: vuln.cveId ?? `Vulnerability on ${vuln.affectedHost}`,
          description: vuln.cvssVector ?? undefined,
          cveId: vuln.cveId ?? undefined,
          cvssScore: vuln.cvssScore?.toString(),
          epssScore: vuln.epssScore?.toString(),
          isKevListed: vuln.isKevListed ?? false,
          evidence: {},
          remediation: {},
          sourceId: vuln.id,
          sourceTable: "vulnerability_imports",
        })
        .returning({ id: egFindings.id })
    );

    return finding.id;
  }

  // ---------------------------------------------------------------------------
  // upsertAgentFinding — maps agent_findings → eg.findings
  // ---------------------------------------------------------------------------
  async upsertAgentFinding(
    finding: AgentFinding,
    entityId: string,
  ): Promise<string> {
    const existing = await this.dbInstance
      .select({ id: egFindings.id })
      .from(egFindings)
      .where(eq(egFindings.sourceId, finding.id))
      .limit(1);

    if (existing.length > 0) {
      await this.withEgTenantContext((tx) =>
        tx
          .update(egFindings)
          .set({ lastSeenAt: new Date(), updatedAt: new Date() })
          .where(eq(egFindings.id, existing[0].id))
      );
      return existing[0].id;
    }

    const [created] = await this.withEgTenantContext((tx) =>
      tx
        .insert(egFindings)
        .values({
          organizationId: this.organizationId,
          entityId,
          sourceProduct: "odinforge",
          category: "active_exploit",
          severity: normalizeSeverity(finding.severity),
          title: finding.cveId ?? `Agent finding: ${finding.findingType}`,
          cveId: finding.cveId ?? undefined,
          epssScore: finding.epssScore?.toString(),
          isKevListed: finding.isKevListed ?? false,
          confidence: finding.confidenceScore?.toString(),
          evidence: {},
          remediation: {},
          sourceId: finding.id,
          sourceTable: "agent_findings",
        })
        .returning({ id: egFindings.id })
    );

    return created.id;
  }

  // ---------------------------------------------------------------------------
  // syncAevEvaluation — maps aev_evaluations + aev_results → eg.assessments
  // ---------------------------------------------------------------------------
  async syncAevEvaluation(
    evaluation: Evaluation,
    result: Result | undefined,
    entityId: string,
  ): Promise<string> {
    const existing = await this.dbInstance
      .select({ id: egAssessments.id })
      .from(egAssessments)
      .where(eq(egAssessments.sourceId, evaluation.id))
      .limit(1);

    const summary = result
      ? {
          score: result.score,
          exploitable: result.exploitable,
          intelligentScore: result.intelligentScore,
          attackGraph: result.attackGraph,
        }
      : {};

    if (existing.length > 0) {
      await this.withEgTenantContext((tx) =>
        tx
          .update(egAssessments)
          .set({
            status: evaluation.status,
            riskScore: result?.score?.toString(),
            summary,
            completedAt: evaluation.status === "completed" ? new Date() : undefined,
            updatedAt: new Date(),
          })
          .where(eq(egAssessments.id, existing[0].id))
      );
      return existing[0].id;
    }

    const assessmentType =
      evaluation.exposureType === "breach_chain" ? "breach_chain" : "exploit_validation";

    const [assessment] = await this.withEgTenantContext((tx) =>
      tx
        .insert(egAssessments)
        .values({
          organizationId: this.organizationId,
          entityId,
          assessmentType,
          sourceProduct: "odinforge",
          sourceId: evaluation.id,
          sourceTable: "aev_evaluations",
          status: evaluation.status,
          riskScore: result?.score?.toString(),
          summary,
        })
        .returning({ id: egAssessments.id })
    );

    // If the result confirms exploitability, also write a finding
    if (result?.exploitable) {
      await this.withEgTenantContext((tx) =>
        tx
          .insert(egFindings)
          .values({
            organizationId: this.organizationId,
            entityId,
            sourceProduct: "odinforge",
            category: "active_exploit",
            severity: "critical",
            title: `Confirmed exploit: ${evaluation.exposureType}`,
            riskScore: result.score?.toString(),
            evidence: (result.intelligentScore as object) ?? {},
            remediation: {},
            sourceId: result.id,
            sourceTable: "aev_results",
          })
          .onConflictDoNothing()
      );
    }

    return assessment.id;
  }

  // ---------------------------------------------------------------------------
  // upsertCloudAsset — maps cloud_assets → eg.entities
  // ---------------------------------------------------------------------------
  async upsertCloudAsset(asset: CloudAsset): Promise<string> {
    const metadata: Record<string, unknown> = {
      provider: asset.provider,
      assetType: asset.assetType,
      publicIpAddresses: asset.publicIpAddresses,
      agentInstalled: asset.agentInstalled,
      providerResourceId: asset.providerResourceId,
    };

    const result = await this.dbInstance.execute<{ id: string }>(
      sql`SELECT entity_graph.upsert_entity(
        ${this.organizationId}::uuid,
        'cloud_resource'::entity_graph.entity_type,
        ${asset.providerResourceId},
        ${asset.assetName},
        ${JSON.stringify(metadata)}::jsonb,
        ARRAY[${asset.provider}]::text[],
        'odinforge'::entity_graph.source_product,
        NULL,
        NULL
      ) AS id`
    );

    const entityId = (result as any).rows[0].id as string;

    await this.dbInstance.execute(
      sql`SELECT entity_graph.upsert_source_ref(
        ${entityId}::uuid,
        'odinforge'::entity_graph.source_product,
        'cloud_assets',
        ${asset.id}::uuid
      )`
    );

    return entityId;
  }

  // ---------------------------------------------------------------------------
  // writeFinding — generic finding writer for cloud scanners + endpoint agents
  // ---------------------------------------------------------------------------
  async writeFinding(opts: {
    organizationId: string;
    evaluationId:   string;
    source:         string;
    checkId:        string;
    title:          string;
    description:    string;
    severity:       string;
    cvssScore:      number;
    isKev:          boolean;
    resource:       string;
    resourceType:   string;
    evidence:       Record<string, unknown>;
    remediation:    { title: string; steps: string[]; effort: string };
    mitreAttackIds: string[];
  }): Promise<string> {
    // Best-effort entity lookup — use resource as canonical key
    const entityType = opts.source.startsWith("cloud:") ? "cloud_resource" : "ip_address";

    let entityId: string;
    try {
      const result = await this.dbInstance.execute<{ id: string }>(
        sql`SELECT entity_graph.upsert_entity(
          ${this.organizationId}::uuid,
          ${entityType}::entity_graph.entity_type,
          ${opts.resource},
          ${opts.resource},
          ${JSON.stringify({ source: opts.source, resourceType: opts.resourceType })}::jsonb,
          ARRAY['production']::text[],
          'odinforge'::entity_graph.source_product,
          NULL,
          NULL
        ) AS id`
      );
      entityId = (result as any).rows[0].id as string;
    } catch {
      // If entity creation fails (e.g. unsupported type), skip this finding
      return "";
    }

    const [finding] = await this.withEgTenantContext((tx) =>
      tx
        .insert(egFindings)
        .values({
          organizationId: this.organizationId,
          entityId,
          sourceProduct: "odinforge",
          category: opts.source.startsWith("cloud:") ? "cloud_misconfiguration" as any : "endpoint_misconfiguration" as any,
          severity: normalizeSeverity(opts.severity),
          title: opts.title,
          description: opts.description,
          cvssScore: opts.cvssScore?.toString(),
          isKevListed: opts.isKev,
          evidence: opts.evidence,
          remediation: opts.remediation,
          sourceId: opts.checkId,
          sourceTable: opts.source,
        })
        .onConflictDoNothing()
        .returning({ id: egFindings.id })
    );

    return finding?.id ?? "";
  }

  // ---------------------------------------------------------------------------
  // addRelationship — write a directed edge between two entity graph nodes
  // ---------------------------------------------------------------------------
  async addRelationship(
    fromEntityId: string,
    toEntityId: string,
    relationshipType: string,
    confidence = 1.0,
    metadata: Record<string, unknown> = {},
  ): Promise<void> {
    await this.dbInstance.execute(
      sql`SELECT entity_graph.upsert_relationship(
        ${this.organizationId}::uuid,
        ${fromEntityId}::uuid,
        ${toEntityId}::uuid,
        ${relationshipType}::entity_graph.relationship_type,
        ${confidence},
        ${JSON.stringify(metadata)}::jsonb,
        'odinforge'::entity_graph.source_product
      )`
    );
  }

  // ---------------------------------------------------------------------------
  // takeRiskSnapshot — saves a point-in-time risk score for an entity
  // ---------------------------------------------------------------------------
  async takeRiskSnapshot(
    entityId: string,
    riskScore: number,
    findingCounts: Record<string, number>,
  ): Promise<void> {
    await this.withEgTenantContext((tx) =>
      tx.insert(egRiskSnapshots).values({
        entityId,
        organizationId: this.organizationId,
        riskScore: riskScore.toString(),
        findingCounts,
        snapshotSource: "odinforge",
      })
    );
  }
}

// =============================================================================
// BULK SYNC — backfill existing OdinForge data into entity graph
// Run once as a migration job, then the writer handles incremental updates
// =============================================================================

export async function backfillEntityGraph(
  dbInstance: typeof db,
  organizationId: string,
): Promise<void> {
  const writer = new EntityGraphWriter(dbInstance, organizationId);

  console.log(`[EntityGraph] Starting backfill for org ${organizationId}`);

  // 1. Backfill discovered_assets
  const assets = await dbInstance
    .select()
    .from(discoveredAssets)
    .where(eq(discoveredAssets.organizationId, organizationId));

  console.log(`[EntityGraph] Syncing ${assets.length} discovered assets...`);
  for (const asset of assets) {
    await writer.upsertAsset(asset);
  }

  // 2. Backfill vulnerability_imports with entity lookups
  const vulns = await dbInstance
    .select()
    .from(vulnerabilityImports)
    .where(eq(vulnerabilityImports.organizationId, organizationId));

  console.log(`[EntityGraph] Syncing ${vulns.length} vulnerabilities...`);
  for (const vuln of vulns) {
    if (!vuln.affectedHost) continue;

    const [entity] = await dbInstance
      .select({ id: egEntities.id })
      .from(egEntities)
      .where(
        sql`${egEntities.organizationId} = ${organizationId}::uuid
          AND ${egEntities.canonicalKey} = ${vuln.affectedHost}`
      )
      .limit(1);

    if (entity) {
      await writer.upsertVulnerabilityFinding(vuln, entity.id);
    }
  }

  // 3. Backfill cloud_assets
  const clouds = await dbInstance
    .select()
    .from(cloudAssets)
    .where(eq(cloudAssets.organizationId, organizationId));

  console.log(`[EntityGraph] Syncing ${clouds.length} cloud assets...`);
  for (const asset of clouds) {
    await writer.upsertCloudAsset(asset);
  }

  console.log(`[EntityGraph] Backfill complete for org ${organizationId}`);
}
