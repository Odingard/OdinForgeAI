/**
 * OdinForge Report Signer — Tamper-Evident Evidence Packages
 *
 * Signs report exports (SARIF, JSON, CSV) with HMAC-SHA256 to produce
 * tamper-evident evidence packages. Every export includes:
 *   - SHA-256 content hash
 *   - HMAC-SHA256 signature (using REPORT_SIGNING_SECRET)
 *   - Metadata: timestamp, version, algorithm, report type
 *
 * Verification: Recipients can verify integrity using the public
 * verification endpoint or the standalone verify script.
 */

import * as crypto from "crypto";

const SIGNING_SECRET = process.env.REPORT_SIGNING_SECRET
  || process.env.SESSION_SECRET
  || "odinforge-report-sign-dev";

const SIGNING_ALGORITHM = "sha256";
const PACKAGE_VERSION = "1.0";

export interface EvidencePackageMetadata {
  /** ISO 8601 timestamp of signing */
  signedAt: string;
  /** Package format version */
  version: string;
  /** Signing algorithm used */
  algorithm: string;
  /** SHA-256 hash of the content */
  contentHash: string;
  /** HMAC-SHA256 signature of the content */
  signature: string;
  /** Report format (sarif, json, csv) */
  format: string;
  /** Organization that generated the report */
  organizationId: string;
  /** OdinForge platform identifier */
  platform: "odinforge-aev";
  /** Unique package ID */
  packageId: string;
}

export interface SignedEvidencePackage {
  /** The original report content (string) */
  content: string;
  /** Tamper-evident metadata + signature */
  evidenceIntegrity: EvidencePackageMetadata;
}

/**
 * Sign report content and produce a tamper-evident evidence package.
 */
export function signReport(
  content: string,
  format: string,
  organizationId: string
): SignedEvidencePackage {
  const contentHash = crypto
    .createHash(SIGNING_ALGORITHM)
    .update(content)
    .digest("hex");

  const signature = crypto
    .createHmac(SIGNING_ALGORITHM, SIGNING_SECRET)
    .update(content)
    .digest("hex");

  const packageId = `odinforge-${crypto.randomUUID()}`;

  return {
    content,
    evidenceIntegrity: {
      signedAt: new Date().toISOString(),
      version: PACKAGE_VERSION,
      algorithm: `HMAC-SHA256`,
      contentHash,
      signature,
      format,
      organizationId,
      platform: "odinforge-aev",
      packageId,
    },
  };
}

/**
 * Verify a signed evidence package. Returns true if content
 * has not been tampered with since signing.
 */
export function verifyReport(pkg: SignedEvidencePackage): {
  valid: boolean;
  reason?: string;
} {
  if (!pkg.content || !pkg.evidenceIntegrity) {
    return { valid: false, reason: "Missing content or evidenceIntegrity" };
  }

  const { contentHash, signature } = pkg.evidenceIntegrity;

  // Verify content hash
  const computedHash = crypto
    .createHash(SIGNING_ALGORITHM)
    .update(pkg.content)
    .digest("hex");

  if (computedHash !== contentHash) {
    return { valid: false, reason: "Content hash mismatch — content was modified" };
  }

  // Verify HMAC signature
  const computedSig = crypto
    .createHmac(SIGNING_ALGORITHM, SIGNING_SECRET)
    .update(pkg.content)
    .digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(computedSig), Buffer.from(signature))) {
    return { valid: false, reason: "Signature mismatch — content or key was changed" };
  }

  return { valid: true };
}

/**
 * Strip the evidence package wrapper and return just the raw content.
 * Useful for tools that need the raw SARIF/JSON without the envelope.
 */
export function extractContent(pkg: SignedEvidencePackage): string {
  return pkg.content;
}
