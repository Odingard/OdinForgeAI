-- =============================================================================
-- Six Sense Entity Graph — Migration 001
-- Creates the entity_graph schema namespace in OdinForge's PostgreSQL instance
-- Both OdinForge (Drizzle) and Mimir (SQLAlchemy) read/write this schema
-- Mimir connects with a role scoped to entity_graph.* only
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS entity_graph;

-- Grant Mimir's DB role access to this schema only
-- Replace 'mimir_role' with whatever role name you use for Mimir's connection string
-- CREATE ROLE mimir_role LOGIN PASSWORD 'your_password';
GRANT USAGE ON SCHEMA entity_graph TO mimir_role;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA entity_graph TO mimir_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA entity_graph
  GRANT SELECT, INSERT, UPDATE ON TABLES TO mimir_role;

-- =============================================================================
-- ENUMS
-- =============================================================================

CREATE TYPE entity_graph.entity_type AS ENUM (
  'domain',
  'subdomain',
  'ip_address',
  'organization',
  'credential',
  'technology',
  'cloud_resource',
  'email',
  'repository',
  'certificate',
  'port_service',
  'person'
);

CREATE TYPE entity_graph.source_product AS ENUM (
  'odinforge',
  'mimir',
  'manual',
  'threat_intel'
);

CREATE TYPE entity_graph.severity_level AS ENUM (
  'critical',
  'high',
  'medium',
  'low',
  'info'
);

CREATE TYPE entity_graph.finding_category AS ENUM (
  'exposed_infrastructure',
  'credential_exposure',
  'data_breach',
  'misconfiguration',
  'vulnerable_software',
  'email_security',
  'code_leak',
  'supply_chain',
  'cloud_exposure',
  'certificate_issue',
  'active_exploit',
  'breach_path',
  'business_logic'
);

CREATE TYPE entity_graph.relationship_type AS ENUM (
  'subdomain_of',
  'resolves_to',
  'hosts',
  'owned_by',
  'credential_for',
  'exposes',
  'leads_to',
  'found_in',
  'depends_on',
  'similar_to'
);

CREATE TYPE entity_graph.assessment_type AS ENUM (
  'osint_recon',
  'exploit_validation',
  'breach_chain',
  'cloud_audit',
  'endpoint_audit'
);

-- =============================================================================
-- CORE TABLES
-- =============================================================================

CREATE TABLE entity_graph.entities (
  id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id   UUID        NOT NULL,
  entity_type       entity_graph.entity_type NOT NULL,
  canonical_key     TEXT        NOT NULL,
  display_name      TEXT        NOT NULL,
  description       TEXT,
  metadata          JSONB       NOT NULL DEFAULT '{}',
  tags              TEXT[]      NOT NULL DEFAULT '{}',

  first_seen_by     entity_graph.source_product NOT NULL,
  first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_by      entity_graph.source_product NOT NULL,
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  seen_by_products  entity_graph.source_product[] NOT NULL DEFAULT '{}',

  risk_score        DECIMAL(5,2),
  criticality       TEXT,

  embedding         vector(1536),

  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (organization_id, entity_type, canonical_key)
);

CREATE INDEX idx_entities_org           ON entity_graph.entities (organization_id);
CREATE INDEX idx_entities_type          ON entity_graph.entities (entity_type);
CREATE INDEX idx_entities_canonical_key ON entity_graph.entities (canonical_key);
CREATE INDEX idx_entities_last_seen     ON entity_graph.entities (last_seen_at DESC);
CREATE INDEX idx_entities_metadata      ON entity_graph.entities USING gin (metadata);
CREATE INDEX idx_entities_tags          ON entity_graph.entities USING gin (tags);
CREATE INDEX idx_entities_embedding     ON entity_graph.entities
  USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);


CREATE TABLE entity_graph.source_refs (
  id              UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  entity_id       UUID    NOT NULL REFERENCES entity_graph.entities(id) ON DELETE CASCADE,
  source_product  entity_graph.source_product NOT NULL,
  source_table    TEXT    NOT NULL,
  source_id       UUID    NOT NULL,
  synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (source_product, source_table, source_id)
);

CREATE INDEX idx_source_refs_entity    ON entity_graph.source_refs (entity_id);
CREATE INDEX idx_source_refs_source_id ON entity_graph.source_refs (source_id);


CREATE TABLE entity_graph.relationships (
  id                UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id   UUID    NOT NULL,
  from_entity_id    UUID    NOT NULL REFERENCES entity_graph.entities(id) ON DELETE CASCADE,
  to_entity_id      UUID    NOT NULL REFERENCES entity_graph.entities(id) ON DELETE CASCADE,
  relationship_type entity_graph.relationship_type NOT NULL,
  confidence        DECIMAL(3,2) NOT NULL DEFAULT 1.00,
  metadata          JSONB   NOT NULL DEFAULT '{}',
  source_product    entity_graph.source_product NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (from_entity_id, to_entity_id, relationship_type)
);

CREATE INDEX idx_relationships_org      ON entity_graph.relationships (organization_id);
CREATE INDEX idx_relationships_from     ON entity_graph.relationships (from_entity_id);
CREATE INDEX idx_relationships_to       ON entity_graph.relationships (to_entity_id);
CREATE INDEX idx_relationships_type     ON entity_graph.relationships (relationship_type);


CREATE TABLE entity_graph.findings (
  id              UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID    NOT NULL,
  entity_id       UUID    REFERENCES entity_graph.entities(id) ON DELETE SET NULL,

  source_product  entity_graph.source_product NOT NULL,
  category        entity_graph.finding_category NOT NULL,
  severity        entity_graph.severity_level NOT NULL,
  title           TEXT    NOT NULL,
  description     TEXT,

  cve_id          TEXT,
  cvss_score      DECIMAL(4,2),
  epss_score      DECIMAL(6,5),
  is_kev_listed   BOOLEAN NOT NULL DEFAULT FALSE,

  risk_score      DECIMAL(5,2),
  confidence      DECIMAL(3,2),

  evidence        JSONB   NOT NULL DEFAULT '{}',
  remediation     JSONB   NOT NULL DEFAULT '{}',

  source_id       UUID,
  source_table    TEXT,

  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_org       ON entity_graph.findings (organization_id);
CREATE INDEX idx_findings_entity    ON entity_graph.findings (entity_id);
CREATE INDEX idx_findings_severity  ON entity_graph.findings (severity);
CREATE INDEX idx_findings_category  ON entity_graph.findings (category);
CREATE INDEX idx_findings_cve       ON entity_graph.findings (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_findings_kev       ON entity_graph.findings (is_kev_listed) WHERE is_kev_listed = TRUE;
CREATE INDEX idx_findings_source    ON entity_graph.findings (source_product, source_id);


CREATE TABLE entity_graph.assessments (
  id              UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID    NOT NULL,
  entity_id       UUID    REFERENCES entity_graph.entities(id) ON DELETE SET NULL,

  assessment_type entity_graph.assessment_type NOT NULL,
  source_product  entity_graph.source_product NOT NULL,
  source_id       UUID    NOT NULL,
  source_table    TEXT    NOT NULL,

  status          TEXT    NOT NULL DEFAULT 'pending',
  risk_score      DECIMAL(5,2),
  deal_risk_grade TEXT,
  summary         JSONB   NOT NULL DEFAULT '{}',

  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (source_product, source_table, source_id)
);

CREATE INDEX idx_assessments_org     ON entity_graph.assessments (organization_id);
CREATE INDEX idx_assessments_entity  ON entity_graph.assessments (entity_id);
CREATE INDEX idx_assessments_type    ON entity_graph.assessments (assessment_type);
CREATE INDEX idx_assessments_status  ON entity_graph.assessments (status);


CREATE TABLE entity_graph.risk_snapshots (
  id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  entity_id       UUID        NOT NULL REFERENCES entity_graph.entities(id) ON DELETE CASCADE,
  organization_id UUID        NOT NULL,
  risk_score      DECIMAL(5,2) NOT NULL,
  deal_risk_grade TEXT,
  finding_counts  JSONB       NOT NULL DEFAULT '{}',
  snapshot_source entity_graph.source_product NOT NULL,
  snapshotted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_snapshots_entity ON entity_graph.risk_snapshots (entity_id, snapshotted_at DESC);
CREATE INDEX idx_risk_snapshots_org    ON entity_graph.risk_snapshots (organization_id);

-- =============================================================================
-- DEDUPLICATION FUNCTIONS
-- =============================================================================
CREATE OR REPLACE FUNCTION entity_graph.upsert_entity(
  p_organization_id   UUID,
  p_entity_type       entity_graph.entity_type,
  p_canonical_key     TEXT,
  p_display_name      TEXT,
  p_metadata          JSONB,
  p_tags              TEXT[],
  p_source_product    entity_graph.source_product,
  p_risk_score        DECIMAL DEFAULT NULL,
  p_criticality       TEXT DEFAULT NULL
) RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
  v_entity_id UUID;
BEGIN
  INSERT INTO entity_graph.entities (
    organization_id, entity_type, canonical_key, display_name,
    metadata, tags, first_seen_by, last_seen_by,
    seen_by_products, risk_score, criticality
  )
  VALUES (
    p_organization_id, p_entity_type, p_canonical_key, p_display_name,
    p_metadata, p_tags, p_source_product, p_source_product,
    ARRAY[p_source_product], p_risk_score, p_criticality
  )
  ON CONFLICT (organization_id, entity_type, canonical_key)
  DO UPDATE SET
    display_name      = EXCLUDED.display_name,
    metadata          = entity_graph.entities.metadata || EXCLUDED.metadata,
    tags              = ARRAY(
                          SELECT DISTINCT unnest(entity_graph.entities.tags || EXCLUDED.tags)
                        ),
    last_seen_by      = EXCLUDED.last_seen_by,
    last_seen_at      = NOW(),
    seen_by_products  = ARRAY(
                          SELECT DISTINCT unnest(
                            entity_graph.entities.seen_by_products || EXCLUDED.seen_by_products
                          )
                        ),
    risk_score        = COALESCE(EXCLUDED.risk_score, entity_graph.entities.risk_score),
    criticality       = COALESCE(EXCLUDED.criticality, entity_graph.entities.criticality),
    updated_at        = NOW()
  RETURNING id INTO v_entity_id;

  RETURN v_entity_id;
END;
$$;


CREATE OR REPLACE FUNCTION entity_graph.upsert_source_ref(
  p_entity_id     UUID,
  p_source_product entity_graph.source_product,
  p_source_table  TEXT,
  p_source_id     UUID
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO entity_graph.source_refs (entity_id, source_product, source_table, source_id)
  VALUES (p_entity_id, p_source_product, p_source_table, p_source_id)
  ON CONFLICT (source_product, source_table, source_id)
  DO UPDATE SET synced_at = NOW();
END;
$$;


CREATE OR REPLACE FUNCTION entity_graph.upsert_relationship(
  p_organization_id   UUID,
  p_from_entity_id    UUID,
  p_to_entity_id      UUID,
  p_relationship_type entity_graph.relationship_type,
  p_confidence        DECIMAL,
  p_metadata          JSONB,
  p_source_product    entity_graph.source_product
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO entity_graph.relationships (
    organization_id, from_entity_id, to_entity_id,
    relationship_type, confidence, metadata, source_product
  )
  VALUES (
    p_organization_id, p_from_entity_id, p_to_entity_id,
    p_relationship_type, p_confidence, p_metadata, p_source_product
  )
  ON CONFLICT (from_entity_id, to_entity_id, relationship_type)
  DO UPDATE SET
    confidence   = GREATEST(entity_graph.relationships.confidence, EXCLUDED.confidence),
    metadata     = entity_graph.relationships.metadata || EXCLUDED.metadata;
END;
$$;


-- =============================================================================
-- RLS — Row-Level Security
-- =============================================================================

ALTER TABLE entity_graph.entities       ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_graph.source_refs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_graph.relationships  ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_graph.findings       ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_graph.assessments    ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_graph.risk_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON entity_graph.entities
  USING (organization_id = NULLIF(current_setting('entity_graph.current_organization_id', TRUE), '')::UUID);

CREATE POLICY tenant_isolation ON entity_graph.relationships
  USING (organization_id = NULLIF(current_setting('entity_graph.current_organization_id', TRUE), '')::UUID);

CREATE POLICY tenant_isolation ON entity_graph.findings
  USING (organization_id = NULLIF(current_setting('entity_graph.current_organization_id', TRUE), '')::UUID);

CREATE POLICY tenant_isolation ON entity_graph.assessments
  USING (organization_id = NULLIF(current_setting('entity_graph.current_organization_id', TRUE), '')::UUID);

CREATE POLICY tenant_isolation ON entity_graph.risk_snapshots
  USING (organization_id = NULLIF(current_setting('entity_graph.current_organization_id', TRUE), '')::UUID);

CREATE POLICY allow_all ON entity_graph.source_refs USING (TRUE);


-- =============================================================================
-- updated_at trigger
-- =============================================================================
CREATE OR REPLACE FUNCTION entity_graph.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER set_updated_at BEFORE UPDATE ON entity_graph.entities
  FOR EACH ROW EXECUTE FUNCTION entity_graph.set_updated_at();

CREATE TRIGGER set_updated_at BEFORE UPDATE ON entity_graph.findings
  FOR EACH ROW EXECUTE FUNCTION entity_graph.set_updated_at();

CREATE TRIGGER set_updated_at BEFORE UPDATE ON entity_graph.assessments
  FOR EACH ROW EXECUTE FUNCTION entity_graph.set_updated_at();
