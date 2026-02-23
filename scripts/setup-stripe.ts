#!/usr/bin/env tsx
// =============================================================================
// Task 05 — Stripe Setup Script
// scripts/setup-stripe.ts
//
// Run ONCE to create Stripe products + prices and write the price IDs back
// to your billing_plans table.
//
// Usage:
//   STRIPE_SECRET_KEY=sk_live_... DATABASE_URL=... npx tsx scripts/setup-stripe.ts
//
// Idempotent: looks up existing products by metadata before creating new ones.
// Safe to re-run if something failed halfway through.
// =============================================================================

import Stripe from "stripe";
import { Pool } from "pg";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2024-06-20" as any,
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const PLANS = [
  {
    id:           "starter",
    displayName:  "Starter",
    description:  "For individuals and small teams — 25 evaluations/mo, 3 users",
    priceCents:   14900,
    metadata:     { odinforge_plan: "starter" },
  },
  {
    id:           "pro",
    displayName:  "Pro",
    description:  "For growing security teams — 200 evaluations/mo, 10 users",
    priceCents:   49900,
    metadata:     { odinforge_plan: "pro" },
  },
  {
    id:           "enterprise",
    displayName:  "Enterprise",
    description:  "Unlimited evaluations, 50 users, dedicated support",
    priceCents:   149900,
    metadata:     { odinforge_plan: "enterprise" },
  },
] as const;

async function main() {
  console.log("OdinForge Stripe Setup\n");

  for (const plan of PLANS) {
    console.log(`Processing plan: ${plan.displayName} ($${plan.priceCents / 100}/mo)`);

    // Find or create Stripe product
    const existingProducts = await stripe.products.search({
      query: `metadata['odinforge_plan']:'${plan.id}'`,
    });

    let product: Stripe.Product;
    if (existingProducts.data.length > 0) {
      product = existingProducts.data[0];
      console.log(`  Product exists: ${product.id}`);
    } else {
      product = await stripe.products.create({
        name:        `OdinForge ${plan.displayName}`,
        description: plan.description,
        metadata:    plan.metadata,
      });
      console.log(`  Product created: ${product.id}`);
    }

    // Find or create monthly price
    const existingPrices = await stripe.prices.list({
      product:  product.id,
      active:   true,
      type:     "recurring",
      limit:    10,
    });

    const monthlyPrice = existingPrices.data.find(
      p => p.recurring?.interval === "month" && p.unit_amount === plan.priceCents,
    );

    let price: Stripe.Price;
    if (monthlyPrice) {
      price = monthlyPrice;
      console.log(`  Price exists: ${price.id} ($${price.unit_amount! / 100}/mo)`);
    } else {
      price = await stripe.prices.create({
        product:    product.id,
        currency:   "usd",
        unit_amount: plan.priceCents,
        recurring:  { interval: "month" },
        metadata:   plan.metadata,
      });
      console.log(`  Price created: ${price.id} ($${price.unit_amount! / 100}/mo)`);
    }

    // Write price ID back to database
    await pool.query(
      `UPDATE billing_plans SET stripe_price_id = $1 WHERE id = $2`,
      [price.id, plan.id],
    );
    console.log(`  Database updated\n`);
  }

  // Configure Stripe customer portal
  console.log("Configuring Stripe Customer Portal...");
  try {
    await stripe.billingPortal.configurations.create({
      features: {
        subscription_cancel: { enabled: true, mode: "at_period_end" },
        subscription_update: {
          enabled:              true,
          default_allowed_updates: ["price"],
          proration_behavior:   "create_prorations",
        },
        payment_method_update: { enabled: true },
        invoice_history:       { enabled: true },
      },
      business_profile: {
        headline: "Manage your OdinForge subscription",
      },
    });
    console.log("  Portal configured\n");
  } catch (err: unknown) {
    if (err instanceof Stripe.errors.StripeError && (err as any).code === "resource_already_exists") {
      console.log("  Portal already configured\n");
    } else {
      console.warn("  Could not auto-configure portal:", (err as Error).message);
      console.log("    Configure manually: https://dashboard.stripe.com/settings/billing/portal\n");
    }
  }

  console.log("Stripe setup complete.\n");
  console.log("Next steps:");
  console.log("  1. Set STRIPE_WEBHOOK_SECRET in your environment (from Stripe Dashboard -> Webhooks)");
  console.log("  2. Add webhook endpoint: https://yourdomain.com/api/billing/webhook");
  console.log("     Events to subscribe: customer.subscription.* , invoice.payment_* , checkout.session.completed");
  console.log("  3. Set STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY in your environment");

  await pool.end();
}

main().catch(err => {
  console.error("Setup failed:", err);
  process.exit(1);
});
