// =============================================================================
// Task 05 — Billing Page
// client/src/pages/BillingPage.tsx
// =============================================================================

import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  CheckCircle2, XCircle, AlertTriangle, Zap, Shield, Building2,
  CreditCard, BarChart3, ArrowUpRight, Loader2, RefreshCw,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

// —— Inline types (mirrors server/services/billingService.ts) ——————

interface SubscriptionRecord {
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

interface UsageRecord {
  evaluationsUsed:  number;
  evaluationLimit:  number | null;
  periodStart:      string;
  periodEnd:        string;
  percentUsed:      number | null;
}

interface PlanDefinition {
  id:               string;
  displayName:      string;
  priceMonthlyCents: number;
  evaluationLimit:  number | null;
  userLimit:        number | null;
  features:         Record<string, unknown>;
  stripePriceId:    string | null;
}

// —— Sub-components ———————————————————————————————————————————————

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; className: string }> = {
    active:     { label: "Active",     className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
    trialing:   { label: "Trial",      className: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" },
    past_due:   { label: "Past Due",   className: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
    canceled:   { label: "Canceled",   className: "bg-red-500/10 text-red-400 border-red-500/20" },
    unpaid:     { label: "Unpaid",     className: "bg-red-500/10 text-red-400 border-red-500/20" },
    incomplete: { label: "Incomplete", className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20" },
  };
  const c = config[status] ?? config.incomplete!;
  return (
    <Badge variant="outline" className={c.className}>
      {c.label}
    </Badge>
  );
}

function UsageMeter({ usage, limit }: { usage: number; limit: number | null }) {
  if (limit === null) {
    return (
      <div className="flex items-center gap-2 text-sm text-zinc-400">
        <Zap className="h-4 w-4 text-cyan-400" />
        <span>Unlimited evaluations</span>
      </div>
    );
  }
  const pct     = Math.min(100, Math.round((usage / limit) * 100));
  const near    = pct >= 80;
  const maxed   = pct >= 100;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="text-zinc-400">Evaluations this period</span>
        <span className={maxed ? "text-red-400 font-medium" : near ? "text-amber-400 font-medium" : "text-zinc-300"}>
          {usage} / {limit}
        </span>
      </div>
      <Progress
        value={pct}
        className="h-2 bg-zinc-800"
      />
      {near && !maxed && (
        <p className="text-xs text-amber-400">
          Approaching monthly limit — consider upgrading
        </p>
      )}
      {maxed && (
        <p className="text-xs text-red-400">
          Monthly limit reached — upgrade to run more evaluations
        </p>
      )}
    </div>
  );
}

const PLAN_ICONS: Record<string, React.ReactNode> = {
  starter:    <Shield className="h-5 w-5" />,
  pro:        <Zap className="h-5 w-5" />,
  enterprise: <Building2 className="h-5 w-5" />,
};

const PLAN_COLORS: Record<string, string> = {
  starter:    "border-zinc-700 hover:border-zinc-600",
  pro:        "border-cyan-700 hover:border-cyan-600 ring-1 ring-cyan-700/30",
  enterprise: "border-purple-700 hover:border-purple-600",
};

const PLAN_BADGE: Record<string, string | null> = {
  starter:    null,
  pro:        "Most Popular",
  enterprise: null,
};

function PlanFeatureList({ features }: { features: Record<string, unknown> }) {
  const items: Array<{ label: string; available: boolean }> = [
    { label: "Exploit validation",              available: true },
    { label: "Breach chain visualization",      available: !!features.breach_chains || features.trial !== true },
    { label: "SARIF export",                    available: !!features.sarif_export },
    { label: "API access",                      available: !!features.api_access },
    { label: "Priority email support",          available: features.support === "priority_email" || features.support === "dedicated" },
    { label: "Dedicated support",               available: features.support === "dedicated" },
    { label: "SSO",                             available: !!features.sso },
    { label: "Custom integrations",             available: !!features.custom_integrations },
  ];

  return (
    <ul className="space-y-2 mt-4">
      {items.map(item => (
        <li key={item.label} className="flex items-center gap-2 text-sm">
          {item.available
            ? <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            : <XCircle className="h-4 w-4 text-zinc-600 shrink-0" />}
          <span className={item.available ? "text-zinc-300" : "text-zinc-600"}>
            {item.label}
          </span>
        </li>
      ))}
    </ul>
  );
}

// —— Main component ———————————————————————————————————————————————

export default function BillingPage() {
  const [, navigate] = useLocation();
  const { toast }    = useToast();
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  // —— URL param feedback ——————————————————————————————————————
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "true") {
      toast({ title: "Subscription activated!", description: "Welcome to OdinForge." });
      window.history.replaceState({}, "", "/billing");
    }
    if (params.get("canceled") === "true") {
      toast({ title: "Checkout canceled", description: "No charges were made.", variant: "destructive" });
      window.history.replaceState({}, "", "/billing");
    }
    if (params.get("upgrade") === "true") {
      toast({ title: "Upgrade needed", description: "You've reached your plan limit.", variant: "destructive" });
      window.history.replaceState({}, "", "/billing");
    }
  }, [toast]);

  // —— Data fetching ———————————————————————————————————————————
  const { data: subData, isLoading: subLoading, error: subError } = useQuery<{
    subscription: SubscriptionRecord;
    usage: UsageRecord | null;
  }>({
    queryKey: ["/api/billing/subscription"],
    retry: false,
  });

  const { data: plansData, isLoading: plansLoading } = useQuery<{
    plans: PlanDefinition[];
  }>({
    queryKey: ["/api/billing/plans"],
    retry: false,
  });

  // —— Checkout mutation ———————————————————————————————————————
  const checkoutMutation = useMutation({
    mutationFn: async (planId: string) => {
      const res = await apiRequest("POST", "/api/billing/checkout", { planId });
      return res.json() as Promise<{ url: string }>;
    },
    onSuccess: (data) => {
      window.location.href = data.url;
    },
    onError: (err: Error) => {
      toast({ title: "Checkout failed", description: err.message, variant: "destructive" });
      setLoadingPlan(null);
    },
  });

  // —— Portal mutation ———————————————————————————————————————————
  const portalMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/portal");
      return res.json() as Promise<{ url: string }>;
    },
    onSuccess:  (data) => { window.location.href = data.url; },
    onError:    (err: Error) => {
      toast({ title: "Could not open billing portal", description: err.message, variant: "destructive" });
    },
  });

  const handleUpgrade = (planId: string) => {
    setLoadingPlan(planId);
    checkoutMutation.mutate(planId);
  };

  // —— Loading state ———————————————————————————————————————————
  if (subLoading || plansLoading) {
    return (
      <div className="min-h-screen bg-[hsl(220_30%_4%)] flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (subError) {
    return (
      <div className="min-h-screen bg-[hsl(220_30%_4%)] flex items-center justify-center">
        <div className="text-center space-y-3">
          <AlertTriangle className="h-10 w-10 text-red-400 mx-auto" />
          <p className="text-zinc-400">Failed to load billing information</p>
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </div>
      </div>
    );
  }

  const sub   = subData?.subscription;
  const usage = subData?.usage;
  const plans = plansData?.plans ?? [];

  const isOnTrial      = sub?.status === "trialing";
  const isPastDue      = sub?.status === "past_due";
  const isCanceled     = sub?.status === "canceled";
  const trialDaysLeft  = sub?.trialEndsAt
    ? Math.max(0, Math.ceil((new Date(sub.trialEndsAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
    : 0;

  return (
    <div className="min-h-screen bg-[hsl(220_30%_4%)] text-zinc-100">
      <div className="max-w-5xl mx-auto px-6 py-10 space-y-8">

        {/* Page header */}
        <div>
          <h1 className="text-2xl font-bold text-white">Billing & Subscription</h1>
          <p className="text-zinc-400 mt-1 text-sm">Manage your OdinForge plan and usage</p>
        </div>

        {/* Status alerts */}
        {isOnTrial && trialDaysLeft <= 3 && (
          <Alert className="border-amber-500/30 bg-amber-500/5">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <AlertDescription className="text-amber-300">
              Your trial ends in <strong>{trialDaysLeft} day{trialDaysLeft !== 1 ? "s" : ""}</strong>.
              Add a payment method to keep your access.
            </AlertDescription>
          </Alert>
        )}

        {isPastDue && (
          <Alert className="border-red-500/30 bg-red-500/5">
            <XCircle className="h-4 w-4 text-red-400" />
            <AlertDescription className="text-red-300">
              Your payment failed. Update your payment method to restore access.
              <Button
                variant="ghost"
                size="sm"
                className="text-red-400 underline px-1 h-auto"
                onClick={() => portalMutation.mutate()}
              >
                Update payment method
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {isCanceled && (
          <Alert className="border-zinc-600/30 bg-zinc-800/30">
            <AlertDescription className="text-zinc-400">
              Your subscription has been canceled. Access expires at end of billing period.
            </AlertDescription>
          </Alert>
        )}

        {/* Current plan summary */}
        {sub && (
          <Card className="bg-[hsl(220_25%_7%)] border-zinc-800">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base font-semibold text-white">
                  Current Plan
                </CardTitle>
                <StatusBadge status={sub.status} />
              </div>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-2xl font-bold text-white">{sub.planName}</p>
                  <p className="text-zinc-400 text-sm mt-0.5">
                    {sub.priceMonthlyCents === 0
                      ? "Free trial"
                      : `$${(sub.priceMonthlyCents / 100).toFixed(0)}/month`}
                  </p>
                </div>
                {isOnTrial && trialDaysLeft > 0 && (
                  <div className="text-right">
                    <p className="text-sm text-zinc-400">Trial ends</p>
                    <p className="text-sm font-medium text-cyan-400">
                      {trialDaysLeft} day{trialDaysLeft !== 1 ? "s" : ""} remaining
                    </p>
                  </div>
                )}
                {sub.currentPeriodEnd && sub.status === "active" && (
                  <div className="text-right">
                    <p className="text-sm text-zinc-400">Next billing</p>
                    <p className="text-sm font-medium text-zinc-300">
                      {new Date(sub.currentPeriodEnd).toLocaleDateString("en-US", {
                        month: "short", day: "numeric", year: "numeric",
                      })}
                    </p>
                  </div>
                )}
              </div>

              {/* Usage meter */}
              {usage && (
                <UsageMeter usage={usage.evaluationsUsed} limit={sub.evaluationLimit} />
              )}

              {/* Portal button */}
              {sub.stripeSubscriptionId && (
                <div className="pt-2 border-t border-zinc-800">
                  <Button
                    variant="outline"
                    size="sm"
                    className="border-zinc-700 text-zinc-400 hover:text-zinc-100"
                    onClick={() => portalMutation.mutate()}
                    disabled={portalMutation.isPending}
                  >
                    {portalMutation.isPending
                      ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      : <CreditCard className="h-4 w-4 mr-2" />}
                    Manage billing, invoices & payment method
                    <ArrowUpRight className="h-3.5 w-3.5 ml-1.5 opacity-60" />
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Plan cards */}
        <div>
          <h2 className="text-base font-semibold text-white mb-4">
            {sub?.status === "active" && sub?.planId !== "trial" ? "Switch Plan" : "Choose a Plan"}
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {plans.map(plan => {
              const isCurrent  = sub?.planId === plan.id;
              const badge      = PLAN_BADGE[plan.id];
              const isLoading  = loadingPlan === plan.id && checkoutMutation.isPending;

              return (
                <Card
                  key={plan.id}
                  className={`bg-[hsl(220_25%_7%)] transition-colors relative ${PLAN_COLORS[plan.id] ?? "border-zinc-700"}`}
                >
                  {badge && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                      <span className="bg-cyan-500 text-black text-xs font-bold px-3 py-1 rounded-full">
                        {badge}
                      </span>
                    </div>
                  )}

                  <CardHeader className="pb-2 pt-5">
                    <div className="flex items-center gap-2 text-cyan-400 mb-1">
                      {PLAN_ICONS[plan.id]}
                      <CardTitle className="text-base text-white">{plan.displayName}</CardTitle>
                    </div>
                    <div className="flex items-baseline gap-1">
                      <span className="text-3xl font-bold text-white">
                        ${(plan.priceMonthlyCents / 100).toFixed(0)}
                      </span>
                      <span className="text-zinc-500 text-sm">/month</span>
                    </div>
                    <CardDescription className="text-zinc-500 text-xs mt-1">
                      {plan.evaluationLimit !== null
                        ? `${plan.evaluationLimit} evaluations/mo · ${plan.userLimit} users`
                        : `Unlimited evaluations · ${plan.userLimit} users`}
                    </CardDescription>
                  </CardHeader>

                  <CardContent className="space-y-4">
                    <PlanFeatureList features={plan.features} />

                    <Button
                      className={`w-full mt-2 ${
                        isCurrent
                          ? "bg-zinc-800 text-zinc-500 cursor-default"
                          : plan.id === "pro"
                            ? "bg-cyan-600 hover:bg-cyan-500 text-black font-semibold"
                            : "bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
                      }`}
                      disabled={isCurrent || isLoading}
                      onClick={() => !isCurrent && handleUpgrade(plan.id)}
                    >
                      {isLoading ? (
                        <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Redirecting...</>
                      ) : isCurrent ? (
                        <>
                          <CheckCircle2 className="h-4 w-4 mr-2 text-emerald-400" />
                          Current Plan
                        </>
                      ) : (
                        <>
                          <BarChart3 className="h-4 w-4 mr-2" />
                          {isOnTrial ? "Start with" : "Switch to"} {plan.displayName}
                        </>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <p className="text-xs text-zinc-600 text-center mt-4">
            All plans include a 14-day free trial. Cancel anytime. No contracts.
            Enterprise customers can request an annual invoice.
          </p>
        </div>

      </div>
    </div>
  );
}
