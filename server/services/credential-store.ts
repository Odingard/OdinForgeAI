/**
 * OdinForge Credential Store
 *
 * AES-256-GCM encrypted credential storage for harvested credentials.
 * Dual-field schema: displayValue (masked, safe for UI/logs) and
 * authValue (AES-256-GCM encrypted, decrypted only at auth-attempt time).
 *
 * Rule: authValue never appears in logs, never sent to UI, never serialized
 * as plaintext. Decryption happens exactly once — at the point of auth.
 */

import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;   // 96-bit IV for GCM
const TAG_LENGTH = 16;

/**
 * Dual-field credential schema.
 * Only displayValue is safe to log or send to clients.
 */
export interface HarvestedCredential {
  id: string;
  type: "password" | "hash" | "token" | "api_key" | "certificate" | "connection_string" | "database" | "jwt_secret" | "ssh_key" | "cloud_credential";
  username?: string;
  domain?: string;
  /** Masked value — UI and logs ONLY. e.g. "pass***ord" */
  displayValue: string;
  /** AES-256-GCM ciphertext. Decrypt only at auth attempt time. */
  authValue: string;
  /** Which phase/asset extracted this credential */
  source: string;
  /** Where in the HTTP response it was found */
  context: string;
  timestamp: Date;
  /** Which phases have consumed this credential */
  usedBy: string[];
  /** Hash of plaintext for dedup — safe because sha256 is one-way */
  hash: string;
  accessLevel: "read" | "write" | "admin" | "unknown";
}

class CredentialStore {
  private readonly key: Buffer;

  constructor() {
    // Derive a session key from JWT_SECRET + a fixed pepper.
    // This ensures the key is stable within a server session but not
    // stored anywhere as plaintext.
    const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET || "odinforge-aev-dev-key-change-in-prod";
    this.key = createHash("sha256").update(`${secret}:aev-credential-store`).digest();
  }

  /** Encrypt plaintext → opaque ciphertext string (IV:ciphertext:tag, base64) */
  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("base64")}:${encrypted.toString("base64")}:${tag.toString("base64")}`;
  }

  /** Decrypt ciphertext → plaintext. Throws on tamper. */
  decrypt(ciphertext: string): string {
    const parts = ciphertext.split(":");
    if (parts.length !== 3) throw new Error("Invalid credential ciphertext format");
    const iv = Buffer.from(parts[0], "base64");
    const encrypted = Buffer.from(parts[1], "base64");
    const tag = Buffer.from(parts[2], "base64");
    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  }

  /**
   * Create a HarvestedCredential from a discovered plaintext value.
   * Plaintext is encrypted immediately — never stored in the returned object.
   */
  create(params: {
    type: HarvestedCredential["type"];
    username?: string;
    domain?: string;
    plaintext: string;
    source: string;
    context: string;
    accessLevel?: HarvestedCredential["accessLevel"];
  }): HarvestedCredential {
    const { type, username, domain, plaintext, source, context, accessLevel = "unknown" } = params;

    const hash = createHash("sha256").update(plaintext).digest("hex");
    const authValue = this.encrypt(plaintext);
    const displayValue = this.mask(plaintext);

    return {
      id: `cred-${randomBytes(4).toString("hex")}`,
      type,
      username,
      domain,
      displayValue,
      authValue,
      source,
      context,
      timestamp: new Date(),
      usedBy: [],
      hash,
      accessLevel,
    };
  }

  /**
   * Decrypt authValue to plaintext for use in an auth attempt.
   * Call this ONLY at the moment of auth — do not store the return value.
   */
  getPlaintext(cred: HarvestedCredential): string {
    return this.decrypt(cred.authValue);
  }

  /** Mask a plaintext value for safe display */
  private mask(value: string): string {
    if (value.length <= 8) return value.substring(0, 2) + "***";
    return value.substring(0, 4) + "***" + value.substring(value.length - 4);
  }
}

/** Singleton — one store per server process, one encryption key per session */
export const credentialStore = new CredentialStore();
