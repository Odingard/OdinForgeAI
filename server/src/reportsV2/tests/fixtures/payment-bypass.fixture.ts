/**
 * Payment Bypass Test Fixture
 * 
 * Simulates a business logic vulnerability allowing price manipulation
 * and payment bypass in an e-commerce checkout flow.
 */

import type { TestEvaluation, TestResult, TestFixture } from "./test-data.types";

export const paymentBypassEvaluation: TestEvaluation = {
  id: "eval-payment-001",
  assetId: "asset-checkout-api-001",
  assetName: "checkout-api.acmecorp.com",
  assetType: "web_application",
  exposureType: "business_logic_flaw",
  description: `Critical business logic flaw in checkout API allowing client-side price manipulation.
    Endpoint: POST /api/v2/checkout/process
    Issue: Cart total calculated client-side and trusted by server without validation
    Impact: Attackers can purchase items at arbitrary prices including $0
    Discovery: Penetration test during pre-launch security review`,
  priority: "critical",
  status: "completed",
  organizationId: "test-org-001",
  createdAt: new Date("2024-12-10T09:00:00Z"),
  updatedAt: new Date("2024-12-10T16:30:00Z"),
};

export const paymentBypassResult: TestResult = {
  id: "result-payment-001",
  evaluationId: "eval-payment-001",
  exploitable: true,
  confidence: 98,
  score: 98,
  
  attackPath: [
    {
      id: 1,
      title: "Intercept Checkout Request",
      description: "Intercept checkout request using browser developer tools or proxy",
      technique: "T1190",
      severity: "medium",
      order: 1,
      targetAsset: "checkout-api",
      tools: ["burp-suite", "browser-devtools"],
    },
    {
      id: 2,
      title: "Manipulate Cart Total",
      description: "Modify cart.total field from $5000.00 to $0.01 in POST request",
      technique: "T1565.002",
      severity: "critical",
      order: 2,
      targetAsset: "checkout-api",
      tools: ["burp-suite"],
    },
    {
      id: 3,
      title: "Complete Fraudulent Purchase",
      description: "Complete checkout with manipulated price, receiving merchandise at fraudulent price",
      technique: "T1657",
      severity: "critical",
      order: 3,
      targetAsset: "payment-processor",
      tools: ["browser"],
    },
  ],
  
  impact: `This vulnerability is trivially exploitable with no authentication bypass required. Cart total is calculated in JavaScript and sent to server which trusts the submitted total without recalculating from item prices. Stripe payment intent created with attacker-controlled amount. Successful payment of $0.01 processes order for $5000 in merchandise. Estimated $2M+ monthly exposure based on transaction volume.`,
  
  recommendations: [
    {
      id: "rec-payment-001",
      title: "Server-side cart calculation",
      description: "Always recalculate cart totals on the server using item prices from the database. Never trust client-submitted totals.",
      priority: "critical",
      type: "remediation",
      effort: "medium",
      timeline: "72 hours",
    },
    {
      id: "rec-payment-002",
      title: "Implement cart signing",
      description: "Sign cart contents with HMAC to detect tampering. Verify signature server-side before processing.",
      priority: "high",
      type: "preventive",
      effort: "medium",
      timeline: "1 week",
    },
    {
      id: "rec-payment-003",
      title: "Add quantity validation",
      description: "Reject negative quantities and enforce reasonable maximum quantities per item.",
      priority: "high",
      type: "remediation",
      effort: "low",
      timeline: "24 hours",
    },
    {
      id: "rec-payment-004",
      title: "Implement fraud detection",
      description: "Deploy anomaly detection for orders with unusual price-to-item ratios.",
      priority: "medium",
      type: "compensating",
      effort: "high",
      timeline: "1 month",
    },
  ],
  
  evidenceArtifacts: [
    {
      id: "ev-payment-001",
      type: "http_request",
      title: "Original Checkout Request",
      description: "Original checkout request with legitimate total",
      content: `POST /api/v2/checkout/process HTTP/1.1
Host: checkout-api.acmecorp.com
Content-Type: application/json

{
  "cartId": "cart_abc123",
  "items": [
    {"sku": "LAPTOP-PRO", "quantity": 1, "price": 2499.99},
    {"sku": "MONITOR-4K", "quantity": 2, "price": 899.99}
  ],
  "total": 4299.97,
  "paymentMethod": "card_xyz789"
}`,
    },
    {
      id: "ev-payment-002",
      type: "http_request",
      title: "Manipulated Checkout Request",
      description: "Manipulated checkout request with $0.01 total",
      content: `POST /api/v2/checkout/process HTTP/1.1
Host: checkout-api.acmecorp.com
Content-Type: application/json

{
  "cartId": "cart_abc123",
  "items": [
    {"sku": "LAPTOP-PRO", "quantity": 1, "price": 2499.99},
    {"sku": "MONITOR-4K", "quantity": 2, "price": 899.99}
  ],
  "total": 0.01,
  "paymentMethod": "card_xyz789"
}`,
    },
    {
      id: "ev-payment-003",
      type: "http_response",
      title: "Fraudulent Order Confirmation",
      description: "Successful order confirmation at fraudulent price",
      content: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "orderId": "ORD-2024-78901",
  "status": "confirmed",
  "chargedAmount": 0.01,
  "items": 3,
  "shippingAddress": "..."
}`,
    },
  ],
  
  completedAt: new Date("2024-12-10T16:30:00Z"),
};

export const paymentBypassFixture: TestFixture = {
  evaluation: paymentBypassEvaluation,
  result: paymentBypassResult,
  expectedNarrativeElements: [
    "business logic",
    "price manipulation",
    "client-side",
    "checkout",
    "payment bypass",
    "server-side validation",
  ],
};
