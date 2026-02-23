// =============================================================================
// Task 05 — Subscription Enforcement Middleware
// server/middleware/requireSubscription.ts
//
// Two middleware functions:
//   requireActiveSubscription  — blocks access if trial/subscription has lapsed
//   requireEvaluationQuota     — blocks evaluation start if monthly limit is hit
//
// Both are no-ops if BILLING_ENABLED=false (for dev/self-hosted).
// =============================================================================

import { type Request, type Response, type NextFunction } from "express";
import type { UIAuthenticatedRequest } from "../services/ui-auth";
import {
  getSubscription,
  checkEvaluationLimit,
  incrementEvaluationUsage,
} from "../services/billingService";

const BILLING_ENABLED = process.env.BILLING_ENABLED !== "false";

export async function requireActiveSubscription(
  req:  Request,
  res:  Response,
  next: NextFunction,
): Promise<void> {
  if (!BILLING_ENABLED) return next();

  const orgId = (req as UIAuthenticatedRequest).uiUser?.organizationId;
  if (!orgId) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  try {
    const sub = await getSubscription(orgId);

    if (!sub) {
      res.status(403).json({
        error:       "subscription_required",
        message:     "No active subscription found. Please start your free trial.",
        redirectTo:  "/billing",
      });
      return;
    }

    if (!sub.hasAccess) {
      const statusMessages: Record<string, string> = {
        canceled:   "Your subscription has been canceled.",
        unpaid:     "Your subscription is unpaid. Please update your payment method.",
        incomplete: "Your subscription setup is incomplete.",
        past_due:   "Your payment is past due. Please update your payment method to continue.",
      };

      res.status(403).json({
        error:       "subscription_inactive",
        status:      sub.status,
        message:     statusMessages[sub.status] ?? "Your subscription is not active.",
        redirectTo:  "/billing",
      });
      return;
    }

    next();
  } catch (err: unknown) {
    console.error("[requireActiveSubscription] Error:", err);
    // Fail open — don't block access due to billing infra failure
    next();
  }
}

export async function requireEvaluationQuota(
  req:  Request,
  res:  Response,
  next: NextFunction,
): Promise<void> {
  if (!BILLING_ENABLED) return next();

  const orgId = (req as UIAuthenticatedRequest).uiUser?.organizationId;
  if (!orgId) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  try {
    const check = await checkEvaluationLimit(orgId);

    if (!check.allowed) {
      res.status(429).json({
        error:       "evaluation_limit_reached",
        message:     check.reason ?? "Monthly evaluation limit reached.",
        used:        check.used,
        limit:       check.limit,
        redirectTo:  "/billing?upgrade=true",
      });
      return;
    }

    await incrementEvaluationUsage(orgId);
    next();
  } catch (err: unknown) {
    console.error("[requireEvaluationQuota] Error:", err);
    // Fail open — don't block evaluations due to billing infra failure
    next();
  }
}
