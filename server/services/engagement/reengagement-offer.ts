/**
 * Reengagement Offer — ADR-005
 *
 * After an engagement is sealed, the customer is eligible for a 90-day
 * reengagement window at a reduced rate. This module generates the
 * reengagement offer with:
 *   - Reference to the sealed engagement
 *   - Proposed scope (same or expanded)
 *   - Pricing tier discount
 *   - Expiration date (90 days from seal)
 */

import type { BreachChain } from "@shared/schema";
import type { EngagementPackage } from "./engagement-package";

// ─── Types ────────────────────────────────────────────────────────────────────

export type PricingTier = "standard" | "deep" | "mssp";

export interface ReengagementOffer {
  offerId: string;
  engagementId: string;
  organizationId: string;
  generatedAt: string;
  expiresAt: string;
  windowDays: number;

  originalAssessment: {
    sealedAt: string;
    riskGrade: string;
    overallRiskScore: number;
    targetAssets: string[];
    findingsCount: number;
    pricingTier: PricingTier;
  };

  proposedScope: {
    tier: PricingTier;
    targetAssets: string[];
    enabledPhases: string[];
    executionMode: string;
  };

  pricing: {
    originalPrice: number;
    discountPercent: number;
    reengagementPrice: number;
    currency: string;
  };

  callToAction: string;
}

// ─── Pricing ─────────────────────────────────────────────────────────────────

const TIER_PRICING: Record<PricingTier, number> = {
  standard: 5000,
  deep: 15000,
  mssp: 30000,
};

const REENGAGEMENT_DISCOUNT = 20; // 20% discount for reengagement within 90 days

function inferTier(chain: BreachChain): PricingTier {
  const config = chain.config as any;
  const phases = config?.enabledPhases?.length ?? 0;
  if (phases >= 5) return "deep";
  if (phases >= 3) return "standard";
  return "standard";
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function generateReengagementOffer(
  chain: BreachChain,
  pkg: EngagementPackage
): ReengagementOffer {
  const tier = inferTier(chain);
  const config = chain.config as any;
  const windowDays = 90;
  const expiresAt = new Date(
    new Date(pkg.sealedAt).getTime() + windowDays * 24 * 60 * 60 * 1000
  );

  const originalPrice = TIER_PRICING[tier];
  const reengagementPrice = Math.round(originalPrice * (1 - REENGAGEMENT_DISCOUNT / 100));

  return {
    offerId: `reo-${chain.id.slice(0, 12)}`,
    engagementId: chain.id,
    organizationId: chain.organizationId,
    generatedAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString(),
    windowDays,

    originalAssessment: {
      sealedAt: pkg.sealedAt,
      riskGrade: pkg.metadata.riskGrade,
      overallRiskScore: pkg.metadata.overallRiskScore,
      targetAssets: pkg.metadata.targetAssets,
      findingsCount: pkg.metadata.customerFindings,
      pricingTier: tier,
    },

    proposedScope: {
      tier,
      targetAssets: chain.assetIds as string[],
      enabledPhases: config?.enabledPhases ?? [],
      executionMode: config?.executionMode ?? "live",
    },

    pricing: {
      originalPrice,
      discountPercent: REENGAGEMENT_DISCOUNT,
      reengagementPrice,
      currency: "USD",
    },

    callToAction: `Your OdinForge assessment identified ${pkg.metadata.customerFindings} confirmed vulnerability(ies) with a risk grade of ${pkg.metadata.riskGrade}. ` +
      `Re-engage within ${windowDays} days to validate your remediation at ${REENGAGEMENT_DISCOUNT}% off ($${reengagementPrice.toLocaleString()} ${tier} tier). ` +
      `Offer expires ${expiresAt.toISOString().split("T")[0]}.`,
  };
}
