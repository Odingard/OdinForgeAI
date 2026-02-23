// =============================================================================
// Task 05 — Billing Service
// server/services/billingService.ts
//
// Core subscription logic. Consumed by:
//   - billing routes (API layer in routes.ts)
//   - subscription middleware (enforcement layer)
//   - webhook handler (Stripe event processor)
// =============================================================================

import Stripe from "stripe";
import { db } from "../db";
import { sql } from "drizzle-orm";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "", {
  apiVersion: "2024-06-20" as any,
});

// —— Types ———————————————————————————————————————————————————————

export interface SubscriptionRecord {
  organizationId:       string;
  subscriptionId:       string;
  status:               string;
  planId:               string;
  planName:             string;
  priceMonthlyCents:    number;
  evaluationLimit:      number | null;
  userLimit:            number | null;
  features:             Record<string, unknown>;
  trialEndsAt:          string | null;
  currentPeriodStart:   string | null;
  currentPeriodEnd:     string | null;
  cancelAtPeriodEnd:    boolean;
  stripeCustomerId:     string | null;
  stripeSubscriptionId: string | null;
  hasAccess:            boolean;
}

export interface UsageRecord {
  evaluationsUsed:  number;
  evaluationLimit:  number | null;
  periodStart:      string;
  periodEnd:        string;
  percentUsed:      number | null;
}

export interface PlanDefinition {
  id:               string;
  displayName:      string;
  priceMonthlyCents: number;
  evaluationLimit:  number | null;
  userLimit:        number | null;
  features:         Record<string, unknown>;
  stripePriceId:    string | null;
}

// —— Plan definitions ————————————————————————————————————————————

export async function getPlans(): Promise<PlanDefinition[]> {
  const result = await db.execute(sql`
    SELECT id, display_name, price_monthly_cents, evaluation_limit,
           user_limit, features, stripe_price_id
    FROM billing_plans
    WHERE is_active = true AND id != 'trial'
    ORDER BY price_monthly_cents ASC
  `);

  const rows = (result as any).rows ?? [];
  return rows.map((r: any) => ({
    id:               r.id,
    displayName:      r.display_name,
    priceMonthlyCents: r.price_monthly_cents,
    evaluationLimit:  r.evaluation_limit,
    userLimit:        r.user_limit,
    features:         r.features ?? {},
    stripePriceId:    r.stripe_price_id,
  }));
}

// —— Subscription lookup —————————————————————————————————————————

export async function getSubscription(organizationId: string): Promise<SubscriptionRecord | null> {
  const result = await db.execute(sql`
    SELECT * FROM v_org_subscriptions
    WHERE organization_id = ${organizationId}::uuid
    LIMIT 1
  `);

  const rows = (result as any).rows ?? [];
  if (rows.length === 0) return null;
  const r = rows[0];

  return {
    organizationId:       r.organization_id,
    subscriptionId:       r.subscription_id,
    status:               r.status,
    planId:               r.plan_id,
    planName:             r.plan_name,
    priceMonthlyCents:    r.price_monthly_cents,
    evaluationLimit:      r.evaluation_limit,
    userLimit:            r.user_limit,
    features:             r.features ?? {},
    trialEndsAt:          r.trial_ends_at,
    currentPeriodStart:   r.current_period_start,
    currentPeriodEnd:     r.current_period_end,
    cancelAtPeriodEnd:    r.cancel_at_period_end,
    stripeCustomerId:     r.stripe_customer_id,
    stripeSubscriptionId: r.stripe_subscription_id,
    hasAccess:            r.has_access,
  };
}

// —— Trial creation ——————————————————————————————————————————————

export async function createTrial(
  organizationId: string,
  email:          string,
  orgName?:       string,
): Promise<SubscriptionRecord> {
  const customer = await stripe.customers.create({
    email,
    name:     orgName,
    metadata: { organization_id: organizationId },
  });

  const trialEnd = new Date();
  trialEnd.setDate(trialEnd.getDate() + 14);

  await db.execute(sql`
    INSERT INTO subscriptions (
      organization_id, plan_id, stripe_customer_id,
      status, trial_ends_at
    ) VALUES (
      ${organizationId}::uuid, 'trial', ${customer.id},
      'trialing', ${trialEnd.toISOString()}
    )
    ON CONFLICT (organization_id) DO NOTHING
  `);

  const sub = await getSubscription(organizationId);
  if (!sub) throw new Error("Failed to create trial subscription");
  return sub;
}

// —— Stripe Checkout session ———————————————————————————————————————

export async function createCheckoutSession(
  organizationId: string,
  planId:         string,
  returnBaseUrl:  string,
): Promise<string> {
  const sub = await getSubscription(organizationId);
  if (!sub) throw new Error("No subscription record found. Ensure trial was created.");

  const planResult = await db.execute(sql`
    SELECT stripe_price_id FROM billing_plans WHERE id = ${planId} AND is_active = true
  `);
  const planRows = (planResult as any).rows ?? [];
  if (planRows.length === 0 || !planRows[0].stripe_price_id) {
    throw new Error(`Plan ${planId} not found or not configured in Stripe. Run setup-stripe.ts first.`);
  }
  const priceId = planRows[0].stripe_price_id;

  const session = await stripe.checkout.sessions.create({
    mode:              "subscription",
    customer:          sub.stripeCustomerId ?? undefined,
    line_items: [{ price: priceId, quantity: 1 }],
    subscription_data: {
      trial_end:       sub.status === "trialing" && sub.trialEndsAt
                         ? Math.floor(new Date(sub.trialEndsAt).getTime() / 1000)
                         : undefined,
      metadata: { organization_id: organizationId, plan_id: planId },
    },
    success_url:       `${returnBaseUrl}/billing?success=true&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:        `${returnBaseUrl}/billing?canceled=true`,
    metadata:          { organization_id: organizationId, plan_id: planId },
    allow_promotion_codes: true,
    billing_address_collection: "auto",
  });

  if (!session.url) throw new Error("Stripe did not return a checkout URL");
  return session.url;
}

// —— Customer Portal session ———————————————————————————————————————

export async function createPortalSession(
  organizationId: string,
  returnUrl:      string,
): Promise<string> {
  const sub = await getSubscription(organizationId);
  if (!sub?.stripeCustomerId) {
    throw new Error("No Stripe customer found for this organization");
  }

  const session = await stripe.billingPortal.sessions.create({
    customer:   sub.stripeCustomerId,
    return_url: returnUrl,
  });

  return session.url;
}

// —— Usage tracking ——————————————————————————————————————————————

export async function getCurrentUsage(organizationId: string): Promise<UsageRecord | null> {
  const sub = await getSubscription(organizationId);
  if (!sub || !sub.currentPeriodStart) return null;

  const result = await db.execute(sql`
    SELECT evaluations_used, billing_period_start, billing_period_end
    FROM subscription_usage
    WHERE organization_id = ${organizationId}::uuid
      AND billing_period_start = ${sub.currentPeriodStart}
    LIMIT 1
  `);

  const rows = (result as any).rows ?? [];
  const used = rows[0]?.evaluations_used ?? 0;
  const limit = sub.evaluationLimit;

  return {
    evaluationsUsed:  used,
    evaluationLimit:  limit,
    periodStart:      rows[0]?.billing_period_start ?? sub.currentPeriodStart,
    periodEnd:        rows[0]?.billing_period_end ?? sub.currentPeriodEnd!,
    percentUsed:      limit !== null ? Math.round((used / limit) * 100) : null,
  };
}

export async function incrementEvaluationUsage(organizationId: string): Promise<number> {
  const sub = await getSubscription(organizationId);
  if (!sub) throw new Error("No subscription found");

  const periodStart = sub.currentPeriodStart ?? new Date().toISOString();
  const periodEnd   = sub.currentPeriodEnd   ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const result = await db.execute(sql`
    SELECT increment_evaluation_usage(
      ${organizationId}::uuid,
      ${periodStart},
      ${periodEnd}
    )
  `);

  const rows = (result as any).rows ?? [];
  return rows[0]?.increment_evaluation_usage ?? 0;
}

export async function checkEvaluationLimit(organizationId: string): Promise<{
  allowed:    boolean;
  used:       number;
  limit:      number | null;
  reason?:    string;
}> {
  const sub = await getSubscription(organizationId);

  if (!sub) {
    return { allowed: false, used: 0, limit: 0, reason: "No subscription found" };
  }

  if (!sub.hasAccess) {
    return { allowed: false, used: 0, limit: sub.evaluationLimit, reason: `Subscription ${sub.status}` };
  }

  if (sub.evaluationLimit === null) {
    return { allowed: true, used: 0, limit: null };
  }

  const usage = await getCurrentUsage(organizationId);
  const used  = usage?.evaluationsUsed ?? 0;

  if (used >= sub.evaluationLimit) {
    return {
      allowed: false,
      used,
      limit:   sub.evaluationLimit,
      reason:  `Monthly limit of ${sub.evaluationLimit} evaluations reached. Upgrade to continue.`,
    };
  }

  return { allowed: true, used, limit: sub.evaluationLimit };
}

// —— Webhook processors ——————————————————————————————————————————

export async function syncSubscriptionFromStripe(
  stripeSubscription: Stripe.Subscription,
): Promise<void> {
  const orgId  = stripeSubscription.metadata?.organization_id;
  const planId = stripeSubscription.metadata?.plan_id;

  if (!orgId) {
    console.error("[billing] Subscription missing organization_id metadata:", stripeSubscription.id);
    return;
  }

  const priceId = stripeSubscription.items.data[0]?.price.id ?? null;
  // current_period_start/end exist in the API response but were removed from newer Stripe types
  const rawSub = stripeSubscription as any;
  const periodStart = rawSub.current_period_start
    ? new Date(rawSub.current_period_start * 1000).toISOString()
    : null;
  const periodEnd = rawSub.current_period_end
    ? new Date(rawSub.current_period_end * 1000).toISOString()
    : null;

  await db.execute(sql`
    UPDATE subscriptions SET
      stripe_subscription_id = ${stripeSubscription.id},
      stripe_price_id        = ${priceId},
      plan_id                = ${planId ?? "starter"},
      status                 = ${stripeSubscription.status},
      current_period_start   = ${periodStart},
      current_period_end     = ${periodEnd},
      cancel_at_period_end   = ${stripeSubscription.cancel_at_period_end},
      canceled_at            = ${stripeSubscription.canceled_at
                                  ? new Date(stripeSubscription.canceled_at * 1000).toISOString()
                                  : null}
    WHERE stripe_customer_id = ${stripeSubscription.customer as string}
  `);
}

export async function handleCheckoutCompleted(
  session: Stripe.Checkout.Session,
): Promise<void> {
  const orgId  = session.metadata?.organization_id;

  if (!orgId) {
    console.error("[billing] Checkout session missing metadata:", session.id);
    return;
  }

  if (session.customer) {
    await db.execute(sql`
      UPDATE subscriptions
      SET stripe_customer_id = ${session.customer as string}
      WHERE organization_id = ${orgId}::uuid
        AND (stripe_customer_id IS NULL OR stripe_customer_id != ${session.customer as string})
    `);
  }
}
