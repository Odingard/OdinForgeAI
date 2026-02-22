# =============================================================================
# Entity Graph Writer — Mimir
# Destination: src/mimir/services/entity_graph_writer.py
#
# Syncs completed Mimir assessments into the shared entity_graph schema.
# Called at the end of every assessment run, after all 12 modules complete.
#
# Usage:
#   writer = EntityGraphWriter(session, organization_id)
#   entity_id = await writer.sync_assessment(assessment, summary)
# =============================================================================

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from mimir.models.entity_graph import (
    EgEntity, EgFinding, EgAssessment, EgRiskSnapshot, EgSourceRef,
    MIMIR_TO_EG_CATEGORY, MODULE_TO_ENTITY_TYPE,
    EntityType, SourceProduct, SeverityLevel, FindingCategory,
)
from mimir.models import Assessment, Finding, AssessmentSummary, Target

logger = logging.getLogger(__name__)


def normalize_severity(s: str) -> str:
    return "info" if s == "info" else s


GRADE_TO_SCORE: dict[str, float] = {
    "A": 10.0,
    "B": 30.0,
    "C": 50.0,
    "D": 70.0,
    "F": 90.0,
}


class EntityGraphWriter:
    """
    Syncs a completed Mimir assessment into entity_graph.*.

    All writes use upsert_entity() and upsert_source_ref() SQL functions
    defined in the migration — same dedup logic OdinForge uses.

    RLS: sets entity_graph.current_organization_id before every write.
    """

    def __init__(self, session: AsyncSession, organization_id: str):
        self.session = session
        self.organization_id = organization_id

    async def _set_tenant_context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('entity_graph.current_organization_id', :org_id, TRUE)"),
            {"org_id": self.organization_id},
        )

    async def sync_assessment(
        self,
        assessment: Assessment,
        summary: AssessmentSummary,
    ) -> str:
        """
        Sync a completed Mimir assessment into the entity graph.
        Returns the entity_id of the target domain entity.
        """
        await self._set_tenant_context()

        # 1. Upsert the target domain as an entity
        entity_id = await self._upsert_target_entity(assessment.target)

        # 2. Register the assessment
        await self._upsert_assessment(assessment, summary, entity_id)

        # 3. Sync all findings
        finding_counts: dict[str, int] = {}
        for finding in assessment.findings:
            await self._upsert_finding(finding, entity_id)
            finding_counts[finding.severity] = finding_counts.get(finding.severity, 0) + 1

            sub_entity_id = await self._upsert_finding_sub_entity(finding, entity_id)
            if sub_entity_id:
                await self._add_relationship(entity_id, sub_entity_id, "exposes")

        # 4. Take a risk snapshot
        risk_score = GRADE_TO_SCORE.get(summary.deal_risk_grade or "C", 50.0)
        await self._take_risk_snapshot(entity_id, risk_score, summary.deal_risk_grade, finding_counts)

        logger.info(
            "[EntityGraph] Synced assessment %s for domain %s — %d findings, grade %s",
            assessment.id, assessment.target.domain, len(assessment.findings),
            summary.deal_risk_grade,
        )

        return entity_id

    async def _upsert_target_entity(self, target: Target) -> str:
        metadata: dict[str, Any] = {"domain": target.domain}
        if target.company_name:
            metadata["company_name"] = target.company_name
        if target.industry:
            metadata["industry"] = target.industry
        if target.metadata_:
            metadata.update(target.metadata_ or {})

        result = await self.session.execute(
            text("""
                SELECT entity_graph.upsert_entity(
                    :org_id::uuid,
                    'domain'::entity_graph.entity_type,
                    :canonical_key,
                    :display_name,
                    :metadata::jsonb,
                    ARRAY['mimir-osint']::text[],
                    'mimir'::entity_graph.source_product,
                    NULL,
                    NULL
                ) AS id
            """),
            {
                "org_id":        self.organization_id,
                "canonical_key": target.domain,
                "display_name":  target.company_name or target.domain,
                "metadata":      str(metadata).replace("'", '"'),
            },
        )
        entity_id: str = result.scalar_one()

        await self.session.execute(
            text("""
                SELECT entity_graph.upsert_source_ref(
                    :entity_id::uuid,
                    'mimir'::entity_graph.source_product,
                    'targets',
                    :source_id::uuid
                )
            """),
            {"entity_id": entity_id, "source_id": str(target.id)},
        )

        return entity_id

    async def _upsert_assessment(
        self,
        assessment: Assessment,
        summary: AssessmentSummary,
        entity_id: str,
    ) -> str:
        risk_score = GRADE_TO_SCORE.get(summary.deal_risk_grade or "C", 50.0)

        summary_data = {
            "total_findings":       summary.total_findings,
            "findings_by_severity": summary.findings_by_severity,
            "findings_by_category": summary.findings_by_category,
            "deal_risk_grade":      summary.deal_risk_grade,
            "risk_score":           summary.risk_score,
        }

        stmt = pg_insert(EgAssessment).values(
            id=uuid.uuid4(),
            organization_id=uuid.UUID(self.organization_id),
            entity_id=uuid.UUID(entity_id),
            assessment_type="osint_recon",
            source_product="mimir",
            source_id=assessment.id,
            source_table="assessments",
            status=assessment.status,
            risk_score=risk_score,
            deal_risk_grade=summary.deal_risk_grade,
            summary=summary_data,
            started_at=assessment.started_at,
            completed_at=assessment.completed_at,
        ).on_conflict_do_update(
            constraint="uidx_eg_assessments_source",
            set_={
                "status":          assessment.status,
                "risk_score":      risk_score,
                "deal_risk_grade": summary.deal_risk_grade,
                "summary":         summary_data,
                "completed_at":    assessment.completed_at,
                "updated_at":      datetime.now(timezone.utc),
            },
        ).returning(EgAssessment.id)

        result = await self.session.execute(stmt)
        return str(result.scalar_one())

    async def _upsert_finding(self, finding: Finding, entity_id: str) -> str:
        eg_category = MIMIR_TO_EG_CATEGORY.get(
            finding.category, FindingCategory.MISCONFIGURATION
        )

        evidence = finding.evidence or {}
        remediation = {}
        if finding.remediation:
            remediation = {"guidance": finding.remediation}

        stmt = pg_insert(EgFinding).values(
            id=uuid.uuid4(),
            organization_id=uuid.UUID(self.organization_id),
            entity_id=uuid.UUID(entity_id),
            source_product="mimir",
            category=eg_category.value,
            severity=normalize_severity(finding.severity),
            title=finding.title,
            description=finding.description,
            risk_score=float(finding.risk_score) if finding.risk_score else None,
            evidence=evidence,
            remediation=remediation,
            source_id=finding.id,
            source_table="findings",
        ).on_conflict_do_nothing().returning(EgFinding.id)

        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        return str(row) if row else str(finding.id)

    async def _upsert_finding_sub_entity(
        self, finding: Finding, parent_entity_id: str
    ) -> Optional[str]:
        entity_type = MODULE_TO_ENTITY_TYPE.get(finding.module)
        if not entity_type:
            return None

        evidence = finding.evidence or {}
        canonical_key: Optional[str] = None

        if finding.module == "subdomains":
            canonical_key = evidence.get("subdomain") or evidence.get("host")
        elif finding.module == "ports":
            port = evidence.get("port")
            host = evidence.get("host")
            canonical_key = f"{host}:{port}" if host and port else None
        elif finding.module == "certificates":
            canonical_key = evidence.get("common_name") or evidence.get("domain")
        elif finding.module in ("darkweb", "credentials"):
            canonical_key = evidence.get("email") or evidence.get("username")
        elif finding.module == "code_exposure":
            canonical_key = evidence.get("repository_url") or evidence.get("repo")
        elif finding.module == "cloud_footprint":
            canonical_key = evidence.get("bucket_name") or evidence.get("resource_id")
        elif finding.module == "hunter":
            canonical_key = evidence.get("email")

        if not canonical_key:
            return None

        result = await self.session.execute(
            text("""
                SELECT entity_graph.upsert_entity(
                    :org_id::uuid,
                    :entity_type::entity_graph.entity_type,
                    :canonical_key,
                    :display_name,
                    :metadata::jsonb,
                    ARRAY[:module]::text[],
                    'mimir'::entity_graph.source_product,
                    :risk_score,
                    NULL
                ) AS id
            """),
            {
                "org_id":        self.organization_id,
                "entity_type":   entity_type.value,
                "canonical_key": canonical_key,
                "display_name":  canonical_key,
                "metadata":      f'{{"module": "{finding.module}", "source_finding": "{finding.id}"}}',
                "module":        finding.module,
                "risk_score":    float(finding.risk_score) if finding.risk_score else None,
            },
        )
        return result.scalar_one()

    async def _add_relationship(
        self,
        from_entity_id: str,
        to_entity_id: str,
        relationship_type: str,
        confidence: float = 1.0,
    ) -> None:
        await self.session.execute(
            text("""
                SELECT entity_graph.upsert_relationship(
                    :org_id::uuid,
                    :from_id::uuid,
                    :to_id::uuid,
                    :rel_type::entity_graph.relationship_type,
                    :confidence,
                    '{}'::jsonb,
                    'mimir'::entity_graph.source_product
                )
            """),
            {
                "org_id":     self.organization_id,
                "from_id":    from_entity_id,
                "to_id":      to_entity_id,
                "rel_type":   relationship_type,
                "confidence": confidence,
            },
        )

    async def _take_risk_snapshot(
        self,
        entity_id:       str,
        risk_score:      float,
        deal_risk_grade: Optional[str],
        finding_counts:  dict[str, int],
    ) -> None:
        await self.session.execute(
            pg_insert(EgRiskSnapshot).values(
                id=uuid.uuid4(),
                entity_id=uuid.UUID(entity_id),
                organization_id=uuid.UUID(self.organization_id),
                risk_score=risk_score,
                deal_risk_grade=deal_risk_grade,
                finding_counts=finding_counts,
                snapshot_source="mimir",
            )
        )


# =============================================================================
# Top-level convenience function
# Wire into assessment_service.py after all 12 modules complete
# =============================================================================

async def sync_completed_assessment(
    session:         AsyncSession,
    assessment:      Assessment,
    summary:         AssessmentSummary,
    organization_id: str,
) -> str:
    writer = EntityGraphWriter(session, organization_id)
    entity_id = await writer.sync_assessment(assessment, summary)
    await session.commit()
    return entity_id
