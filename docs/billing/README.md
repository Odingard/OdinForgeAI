# Task 05 — Billing & Subscriptions

Stripe-powered billing for OdinForge v1. Three tiers, 14-day free trial,
self-serve checkout, and evaluation quota enforcement.

---

## Files

| File | Destination in OdinForge | Purpose |
|------|--------------------------|---------|
| `005_billing.sql` | `server/migrations/` | DB schema: subscriptions, usage, events, plans |
| `setup-stripe.ts` | `scripts/` | One-time Stripe product/price creation |
| `billingService.ts` | `server/services/` | Core business logic |
| `requireSubscription.ts` | `server/middleware/` | Subscription + quota enforcement |
| `BillingPage.tsx` | `client/src/pages/` | Frontend billing page |
| Billing routes | `server/routes.ts` | REST API routes + Stripe webhook |

---

## Environment Variables

Add to your `.env` / deployment config:

```bash
# Stripe keys (from Stripe Dashboard → Developers → API keys)
STRIPE_SECRET_KEY=sk_live_...          # Server-side only, never expose
STRIPE_PUBLISHABLE_KEY=pk_live_...     # Frontend (not currently used — checkout is server-side redirect)
STRIPE_WEBHOOK_SECRET=whsec_...        # From Stripe Dashboard → Webhooks

# Feature flag — set to "false" to disable billing enforcement in dev
BILLING_ENABLED=true
```

---

## Setup (do this once)

### 1. Run the database migration
```bash
psql $DATABASE_URL -f server/migrations/005_billing.sql
```

### 2. Create Stripe products and prices
```bash
STRIPE_SECRET_KEY=sk_live_... DATABASE_URL=... npx tsx scripts/setup-stripe.ts
```
This creates 3 Stripe products (Starter, Pro, Enterprise) and writes their
price IDs back to your `billing_plans` table. Idempotent — safe to re-run.

### 3. Register webhook in Stripe Dashboard
- Go to: **Dashboard → Developers → Webhooks → Add endpoint**
- URL: `https://yourdomain.com/api/billing/webhook`
- Events to subscribe:
  - `checkout.session.completed`
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_succeeded`
  - `invoice.payment_failed`
- Copy the **Signing secret** → set as `STRIPE_WEBHOOK_SECRET`

---

## Plans

| Plan | Price | Evaluations/mo | Users |
|------|-------|---------------|-------|
| Trial | Free (14 days) | 25 | 3 |
| Starter | $149/mo | 25 | 3 |
| Pro | $499/mo | 200 | 10 |
| Enterprise | $1,499/mo | Unlimited | 50 |

To change pricing: update `billing_plans` in the DB and re-run `setup-stripe.ts`
to create new Stripe prices. Old prices are not deleted (Stripe policy).

---

## How the trial flow works

1. User signs up → `createTrial()` runs → Stripe customer created, 14-day trial record inserted
2. User uses OdinForge → `requireActiveSubscription` passes for `trialing` status
3. Trial ends → Stripe status becomes `past_due` or `incomplete` → middleware blocks with 403
4. User upgrades → hits `/api/billing/checkout?planId=pro` → redirected to Stripe Checkout
5. Payment succeeds → `checkout.session.completed` + `customer.subscription.updated` webhooks fire
6. `syncSubscriptionFromStripe()` runs → DB updated to `active`, period dates set
7. All future requests pass subscription check

---

## Evaluation quota enforcement

1. Evaluation starts → `requireEvaluationQuota` middleware runs
2. Calls `checkEvaluationLimit()` → reads `subscription_usage` for current period
3. If at or over limit → returns `429` with upgrade redirect
4. If under limit → calls `incrementEvaluationUsage()` → increments counter atomically
5. Evaluation proceeds

Usage resets automatically each billing period (tracked by `billing_period_start` key).

---

## Webhook design

The Stripe webhook handler is integrated into the routes.ts monolith.
It uses `req.rawBody` captured by the `express.json({ verify })` callback
in `server/index.ts`, eliminating the need for a separate `express.raw()`
mount point before the JSON body parser.

---

## Dependencies

```bash
npm install stripe
# Already installed: @tanstack/react-query, wouter, shadcn/ui components
```
