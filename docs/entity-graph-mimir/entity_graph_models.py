# =============================================================================
# Entity Graph Models — Mimir
# Destination: src/mimir/models/entity_graph.py
#
# SQLAlchemy 2.0 mapped classes for entity_graph.* tables.
# These live alongside Mimir's existing models (Target, Assessment, etc.)
# and use the same async engine — they just point at the entity_graph schema.
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, Any

from sqlalchemy import (
    String, Text, Boolean, Numeric, DateTime, UniqueConstraint,
    ForeignKey, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class EntityGraphBase(DeclarativeBase):
    pass


class EntityType(str, PyEnum):
    DOMAIN         = "domain"
    SUBDOMAIN      = "subdomain"
    IP_ADDRESS     = "ip_address"
    ORGANIZATION   = "organization"
    CREDENTIAL     = "credential"
    TECHNOLOGY     = "technology"
    CLOUD_RESOURCE = "cloud_resource"
    EMAIL          = "email"
    REPOSITORY     = "repository"
    CERTIFICATE    = "certificate"
    PORT_SERVICE   = "port_service"
    PERSON         = "person"


class SourceProduct(str, PyEnum):
    ODINFORGE    = "odinforge"
    MIMIR        = "mimir"
    MANUAL       = "manual"
    THREAT_INTEL = "threat_intel"


class SeverityLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingCategory(str, PyEnum):
    EXPOSED_INFRASTRUCTURE = "exposed_infrastructure"
    CREDENTIAL_EXPOSURE    = "credential_exposure"
    DATA_BREACH            = "data_breach"
    MISCONFIGURATION       = "misconfiguration"
    VULNERABLE_SOFTWARE    = "vulnerable_software"
    EMAIL_SECURITY         = "email_security"
    CODE_LEAK              = "code_leak"
    SUPPLY_CHAIN           = "supply_chain"
    CLOUD_EXPOSURE         = "cloud_exposure"
    CERTIFICATE_ISSUE      = "certificate_issue"
    ACTIVE_EXPLOIT         = "active_exploit"
    BREACH_PATH            = "breach_path"
    BUSINESS_LOGIC         = "business_logic"


class RelationshipType(str, PyEnum):
    SUBDOMAIN_OF   = "subdomain_of"
    RESOLVES_TO    = "resolves_to"
    HOSTS          = "hosts"
    OWNED_BY       = "owned_by"
    CREDENTIAL_FOR = "credential_for"
    EXPOSES        = "exposes"
    LEADS_TO       = "leads_to"
    FOUND_IN       = "found_in"
    DEPENDS_ON     = "depends_on"
    SIMILAR_TO     = "similar_to"


class AssessmentType(str, PyEnum):
    OSINT_RECON        = "osint_recon"
    EXPLOIT_VALIDATION = "exploit_validation"
    BREACH_CHAIN       = "breach_chain"
    CLOUD_AUDIT        = "cloud_audit"
    ENDPOINT_AUDIT     = "endpoint_audit"


# Mimir finding category → entity graph category mapping
MIMIR_TO_EG_CATEGORY: dict[str, FindingCategory] = {
    "exposed_infrastructure": FindingCategory.EXPOSED_INFRASTRUCTURE,
    "credential_exposure":    FindingCategory.CREDENTIAL_EXPOSURE,
    "data_breach":            FindingCategory.DATA_BREACH,
    "misconfiguration":       FindingCategory.MISCONFIGURATION,
    "vulnerable_software":    FindingCategory.VULNERABLE_SOFTWARE,
    "email_security":         FindingCategory.EMAIL_SECURITY,
    "code_leak":              FindingCategory.CODE_LEAK,
    "supply_chain":           FindingCategory.SUPPLY_CHAIN,
    "cloud_exposure":         FindingCategory.CLOUD_EXPOSURE,
    "certificate_issue":      FindingCategory.CERTIFICATE_ISSUE,
}

# Mimir module → entity type mapping
MODULE_TO_ENTITY_TYPE: dict[str, EntityType] = {
    "subdomains":       EntityType.SUBDOMAIN,
    "ports":            EntityType.PORT_SERVICE,
    "certificates":     EntityType.CERTIFICATE,
    "dns_intel":        EntityType.DOMAIN,
    "darkweb":          EntityType.CREDENTIAL,
    "credentials":      EntityType.CREDENTIAL,
    "code_exposure":    EntityType.REPOSITORY,
    "tech_stack":       EntityType.TECHNOLOGY,
    "cloud_footprint":  EntityType.CLOUD_RESOURCE,
    "virustotal":       EntityType.DOMAIN,
    "hunter":           EntityType.EMAIL,
    "securitytrails":   EntityType.DOMAIN,
}


class EgEntity(EntityGraphBase):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("organization_id", "entity_type", "canonical_key",
                         name="uidx_eg_entities_org_type_key"),
        {"schema": "entity_graph"},
    )

    id:               Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id:  Mapped[uuid.UUID]         = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_type:      Mapped[str]               = mapped_column(String(50), nullable=False)
    canonical_key:    Mapped[str]               = mapped_column(Text, nullable=False)
    display_name:     Mapped[str]               = mapped_column(Text, nullable=False)
    description:      Mapped[Optional[str]]     = mapped_column(Text, nullable=True)
    metadata_:        Mapped[dict[str, Any]]    = mapped_column("metadata", JSONB, nullable=False, default=dict)
    tags:             Mapped[list[str]]         = mapped_column(ARRAY(Text), nullable=False, default=list)

    first_seen_by:    Mapped[str]               = mapped_column(String(20), nullable=False)
    first_seen_at:    Mapped[datetime]          = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_by:     Mapped[str]               = mapped_column(String(20), nullable=False)
    last_seen_at:     Mapped[datetime]          = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    seen_by_products: Mapped[list[str]]         = mapped_column(ARRAY(Text), nullable=False, default=list)

    risk_score:       Mapped[Optional[float]]   = mapped_column(Numeric(5, 2), nullable=True)
    criticality:      Mapped[Optional[str]]     = mapped_column(Text, nullable=True)

    created_at:       Mapped[datetime]          = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at:       Mapped[datetime]          = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    source_refs:  Mapped[list["EgSourceRef"]]   = relationship("EgSourceRef", back_populates="entity")
    findings:     Mapped[list["EgFinding"]]     = relationship("EgFinding", back_populates="entity")


class EgSourceRef(EntityGraphBase):
    __tablename__ = "source_refs"
    __table_args__ = (
        UniqueConstraint("source_product", "source_table", "source_id",
                         name="uidx_eg_source_refs"),
        {"schema": "entity_graph"},
    )

    id:             Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id:      Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="CASCADE"), nullable=False)
    source_product: Mapped[str]       = mapped_column(String(20), nullable=False)
    source_table:   Mapped[str]       = mapped_column(Text, nullable=False)
    source_id:      Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    synced_at:      Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    entity: Mapped["EgEntity"] = relationship("EgEntity", back_populates="source_refs")


class EgRelationship(EntityGraphBase):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("from_entity_id", "to_entity_id", "relationship_type",
                         name="uidx_eg_relationships_edge"),
        {"schema": "entity_graph"},
    )

    id:                Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id:   Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), nullable=False)
    from_entity_id:    Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="CASCADE"), nullable=False)
    to_entity_id:      Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="CASCADE"), nullable=False)
    relationship_type: Mapped[str]              = mapped_column(String(30), nullable=False)
    confidence:        Mapped[float]            = mapped_column(Numeric(3, 2), nullable=False, default=1.0)
    metadata_:         Mapped[dict[str, Any]]   = mapped_column("metadata", JSONB, nullable=False, default=dict)
    source_product:    Mapped[str]              = mapped_column(String(20), nullable=False)
    created_at:        Mapped[datetime]         = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class EgFinding(EntityGraphBase):
    __tablename__ = "findings"
    __table_args__ = {"schema": "entity_graph"}

    id:             Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_id:      Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="SET NULL"), nullable=True)

    source_product: Mapped[str]             = mapped_column(String(20), nullable=False)
    category:       Mapped[str]             = mapped_column(String(40), nullable=False)
    severity:       Mapped[str]             = mapped_column(String(10), nullable=False)
    title:          Mapped[str]             = mapped_column(Text, nullable=False)
    description:    Mapped[Optional[str]]   = mapped_column(Text, nullable=True)

    cve_id:         Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    cvss_score:     Mapped[Optional[float]] = mapped_column(Numeric(4, 2), nullable=True)
    epss_score:     Mapped[Optional[float]] = mapped_column(Numeric(6, 5), nullable=True)
    is_kev_listed:  Mapped[bool]            = mapped_column(Boolean, nullable=False, default=False)

    risk_score:     Mapped[Optional[float]] = mapped_column(Numeric(5, 2), nullable=True)
    confidence:     Mapped[Optional[float]] = mapped_column(Numeric(3, 2), nullable=True)

    evidence:       Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict)
    remediation:    Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict)

    source_id:      Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_table:   Mapped[Optional[str]]   = mapped_column(Text, nullable=True)

    first_seen_at:  Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at:   Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    resolved_at:    Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at:     Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at:     Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    entity: Mapped[Optional["EgEntity"]] = relationship("EgEntity", back_populates="findings")


class EgAssessment(EntityGraphBase):
    __tablename__ = "assessments"
    __table_args__ = (
        UniqueConstraint("source_product", "source_table", "source_id",
                         name="uidx_eg_assessments_source"),
        {"schema": "entity_graph"},
    )

    id:             Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), nullable=False)
    entity_id:      Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="SET NULL"), nullable=True)

    assessment_type: Mapped[str]            = mapped_column(String(30), nullable=False)
    source_product: Mapped[str]             = mapped_column(String(20), nullable=False)
    source_id:      Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), nullable=False)
    source_table:   Mapped[str]             = mapped_column(Text, nullable=False)

    status:         Mapped[str]             = mapped_column(Text, nullable=False, default="pending")
    risk_score:     Mapped[Optional[float]] = mapped_column(Numeric(5, 2), nullable=True)
    deal_risk_grade: Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    summary:        Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict)

    started_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at:   Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at:     Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at:     Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class EgRiskSnapshot(EntityGraphBase):
    __tablename__ = "risk_snapshots"
    __table_args__ = {"schema": "entity_graph"}

    id:             Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id:      Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("entity_graph.entities.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), nullable=False)
    risk_score:     Mapped[float]           = mapped_column(Numeric(5, 2), nullable=False)
    deal_risk_grade: Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    finding_counts: Mapped[dict[str, Any]]  = mapped_column(JSONB, nullable=False, default=dict)
    snapshot_source: Mapped[str]            = mapped_column(String(20), nullable=False)
    snapshotted_at: Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
