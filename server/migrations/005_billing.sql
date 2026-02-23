-- =============================================================================
-- Task 05 — Billing & Subscriptions
-- server/migrations/005_billing.sql
--
-- Run this against your existing OdinForge PostgreSQL database.
-- Adds subscriptions, usage tracking, and plan configuration tables.
-- Fully multi-tenant — all rows scoped to organization_id.
-- =============================================================================

-- —— Plan definitions (seed data, not per-org) ———————————————————
CREATE TABLE IF NOT EXISTS billing_plans (
  id                  TEXT PRIMARY KEY,           -- 'starter' | 'pro' | 'enterprise'
  display_name        TEXT NOT NULL,
  price_monthly_cents INTEGER NOT NULL,            -- 14900 = $149.00
  stripe_price_id     TEXT,                        -- filled by setup script
  evaluation_limit    INTEGER,                     -- NULL = unlimited
  user_limit          INTEGER,                     -- NULL = unlimited
  features            JSONB NOT NULL DEFAULT '{}',
  is_active           BOOLEAN NOT NULL DEFAULT true,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- —— Per-org subscription state ——————————————————————————————————
CREATE TABLE IF NOT EXISTS subscriptions (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id           UUID NOT NULL UNIQUE,  -- one active sub per org

  -- Plan reference
  plan_id                   TEXT NOT NULL REFERENCES billing_plans(id),

  -- Stripe identifiers
  stripe_customer_id        TEXT UNIQUE,
  stripe_subscription_id    TEXT UNIQUE,
  stripe_price_id           TEXT,

  -- Subscription state
  status                    TEXT NOT NULL DEFAULT 'trialing',
  -- trialing | active | past_due | canceled | unpaid | incomplete

  -- Trial
  trial_ends_at             TIMESTAMPTZ,

  -- Billing period
  current_period_start      TIMESTAMPTZ,
  current_period_end        TIMESTAMPTZ,

  -- Cancellation
  cancel_at_period_end      BOOLEAN NOT NULL DEFAULT false,
  canceled_at               TIMESTAMPTZ,

  -- Metadata
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_org
  ON subscriptions (organization_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer
  ON subscriptions (stripe_customer_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_sub
  ON subscriptions (stripe_subscription_id);

-- —— Monthly usage counters (reset each billing period) ———————————
CREATE TABLE IF NOT EXISTS subscription_usage (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         UUID NOT NULL,
  billing_period_start    TIMESTAMPTZ NOT NULL,
  billing_period_end      TIMESTAMPTZ NOT NULL,
  evaluations_used        INTEGER NOT NULL DEFAULT 0,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (organization_id, billing_period_start)
);

CREATE INDEX IF NOT EXISTS idx_usage_org_period
  ON subscription_usage (organization_id, billing_period_start DESC);

-- —— Stripe event log (idempotency, debugging) ——————————————————
CREATE TABLE IF NOT EXISTS stripe_events (
  id            TEXT PRIMARY KEY,   -- Stripe event ID (evt_...)
  type          TEXT NOT NULL,
  processed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  payload       JSONB NOT NULL DEFAULT '{}'
);

-- —— Trigger: keep subscriptions.updated_at current ———————————————
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_subscriptions_updated_at ON subscriptions;
CREATE TRIGGER trg_subscriptions_updated_at
  BEFORE UPDATE ON subscriptions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trg_usage_updated_at ON subscription_usage;
CREATE TRIGGER trg_usage_updated_at
  BEFORE UPDATE ON subscription_usage
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- —— Seed plan definitions ———————————————————————————————————————
-- stripe_price_id is filled by the setup script after Stripe products are created
INSERT INTO billing_plans (id, display_name, price_monthly_cents, evaluation_limit, user_limit, features)
VALUES
  ('trial',      'Free Trial',  0,      25,   3,  '{"trial": true, "support": "community"}'),
  ('starter',    'Starter',     14900,  25,   3,  '{"support": "email", "api_access": false, "sarif_export": true}'),
  ('pro',        'Pro',         49900,  200,  10, '{"support": "priority_email", "api_access": true, "sarif_export": true, "breach_chains": true}'),
  ('enterprise', 'Enterprise',  149900, NULL, 50, '{"support": "dedicated", "api_access": true, "sarif_export": true, "breach_chains": true, "sso": true, "custom_integrations": true}')
ON CONFLICT (id) DO UPDATE SET
  display_name        = EXCLUDED.display_name,
  price_monthly_cents = EXCLUDED.price_monthly_cents,
  evaluation_limit    = EXCLUDED.evaluation_limit,
  user_limit          = EXCLUDED.user_limit,
  features            = EXCLUDED.features;

-- —— Helper view: org subscription + plan joined ———————————————————
CREATE OR REPLACE VIEW v_org_subscriptions AS
SELECT
  s.organization_id,
  s.id                     AS subscription_id,
  s.status,
  s.plan_id,
  p.display_name           AS plan_name,
  p.price_monthly_cents,
  p.evaluation_limit,
  p.user_limit,
  p.features,
  s.trial_ends_at,
  s.current_period_start,
  s.current_period_end,
  s.cancel_at_period_end,
  s.stripe_customer_id,
  s.stripe_subscription_id,
  -- Is the subscription currently access-granting?
  CASE
    WHEN s.status IN ('active', 'trialing') THEN true
    WHEN s.status = 'past_due' THEN true   -- grace period
    ELSE false
  END AS has_access
FROM subscriptions s
JOIN billing_plans p ON p.id = s.plan_id;

-- —— Helper function: increment evaluation usage ———————————————————
CREATE OR REPLACE FUNCTION increment_evaluation_usage(
  p_organization_id UUID,
  p_period_start    TIMESTAMPTZ,
  p_period_end      TIMESTAMPTZ
)
RETURNS INTEGER AS $$
DECLARE
  new_count INTEGER;
BEGIN
  INSERT INTO subscription_usage (organization_id, billing_period_start, billing_period_end, evaluations_used)
  VALUES (p_organization_id, p_period_start, p_period_end, 1)
  ON CONFLICT (organization_id, billing_period_start)
  DO UPDATE SET evaluations_used = subscription_usage.evaluations_used + 1
  RETURNING evaluations_used INTO new_count;
  RETURN new_count;
END;
$$ LANGUAGE plpgsql;
