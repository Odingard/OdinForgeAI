/**
 * Per-Engagement API Keys — ADR-009
 *
 * Each managed assessment engagement gets a scoped API key that:
 *   - Is bound to a specific engagement ID
 *   - Grants access only to that engagement's data
 *   - Deactivates automatically when the Engagement Package is sealed
 *   - Has a TTL (default 30 days) as a safety net
 *
 * Key format: `odin_eng_<engagementId>_<random>`
 * Storage: In-memory map (production should use DB table)
 */

import { randomBytes, createHash } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EngagementApiKey {
  id: string;
  keyHash: string;
  engagementId: string;
  organizationId: string;
  createdAt: string;
  expiresAt: string;
  deactivatedAt: string | null;
  deactivationReason: string | null;
  status: "active" | "expired" | "sealed" | "revoked";
}

export interface KeyCreateResult {
  key: EngagementApiKey;
  plaintextKey: string; // Only returned once at creation
}

// ─── Store ────────────────────────────────────────────────────────────────────

const keyStore = new Map<string, EngagementApiKey>();

function hashKey(plaintext: string): string {
  return createHash("sha256").update(plaintext, "utf-8").digest("hex");
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function createEngagementApiKey(
  engagementId: string,
  organizationId: string,
  ttlDays: number = 30
): KeyCreateResult {
  const randomPart = randomBytes(24).toString("base64url");
  const plaintextKey = `odin_eng_${engagementId.slice(0, 12)}_${randomPart}`;
  const keyHash = hashKey(plaintextKey);
  const id = `eak-${randomBytes(8).toString("hex")}`;

  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000);

  const key: EngagementApiKey = {
    id,
    keyHash,
    engagementId,
    organizationId,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    deactivatedAt: null,
    deactivationReason: null,
    status: "active",
  };

  keyStore.set(id, key);
  return { key, plaintextKey };
}

export function validateEngagementApiKey(
  plaintextKey: string
): { valid: boolean; key?: EngagementApiKey; reason?: string } {
  const keyHash = hashKey(plaintextKey);

  for (const key of Array.from(keyStore.values())) {
    if (key.keyHash === keyHash) {
      if (key.status !== "active") {
        return { valid: false, key, reason: `Key is ${key.status}: ${key.deactivationReason ?? "no reason"}` };
      }
      if (new Date(key.expiresAt) < new Date()) {
        key.status = "expired";
        return { valid: false, key, reason: "Key has expired" };
      }
      return { valid: true, key };
    }
  }

  return { valid: false, reason: "Unknown key" };
}

export function deactivateKeysForEngagement(
  engagementId: string,
  reason: "sealed" | "revoked"
): number {
  let count = 0;
  for (const key of Array.from(keyStore.values())) {
    if (key.engagementId === engagementId && key.status === "active") {
      key.status = reason;
      key.deactivatedAt = new Date().toISOString();
      key.deactivationReason = reason === "sealed"
        ? "Engagement Package sealed — key automatically deactivated (ADR-009)"
        : "Key manually revoked";
      count++;
    }
  }
  return count;
}

export function getKeysForEngagement(engagementId: string): EngagementApiKey[] {
  const keys: EngagementApiKey[] = [];
  for (const key of Array.from(keyStore.values())) {
    if (key.engagementId === engagementId) {
      keys.push(key);
    }
  }
  return keys;
}

export function revokeKey(keyId: string): boolean {
  const key = keyStore.get(keyId);
  if (!key || key.status !== "active") return false;
  key.status = "revoked";
  key.deactivatedAt = new Date().toISOString();
  key.deactivationReason = "Manually revoked";
  return true;
}
