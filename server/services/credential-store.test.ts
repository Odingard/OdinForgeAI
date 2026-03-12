/**
 * credential-store.test.ts
 *
 * Tests for AES-256-GCM credential store (Fix 1).
 * All tests are pure — no network, no DB, no external deps.
 */

import { describe, it, expect, beforeEach } from "vitest";

// Import after setting env so the key is derived correctly in tests
process.env.JWT_SECRET = "test-jwt-secret-for-unit-tests";

import { credentialStore, type HarvestedCredential } from "./credential-store";

// ─── encrypt / decrypt ────────────────────────────────────────────────────────

describe("encrypt / decrypt round-trip", () => {
  it("recovers exact plaintext", () => {
    const plain = "super-secret-password-123";
    expect(credentialStore.decrypt(credentialStore.encrypt(plain))).toBe(plain);
  });

  it("round-trips an AWS key", () => {
    const key = "AKIAIOSFODNN7EXAMPLE";
    expect(credentialStore.decrypt(credentialStore.encrypt(key))).toBe(key);
  });

  it("round-trips an empty string", () => {
    expect(credentialStore.decrypt(credentialStore.encrypt(""))).toBe("");
  });

  it("produces different ciphertexts for the same input (random IV)", () => {
    const plain = "same-password";
    const a = credentialStore.encrypt(plain);
    const b = credentialStore.encrypt(plain);
    expect(a).not.toBe(b);
  });

  it("ciphertext format is IV:cipher:tag (three colon-separated parts)", () => {
    const parts = credentialStore.encrypt("test").split(":");
    expect(parts).toHaveLength(3);
    // Each part is base64 — non-empty
    parts.forEach(p => expect(p.length).toBeGreaterThan(0));
  });

  it("throws on tampered ciphertext", () => {
    const cipher = credentialStore.encrypt("my-secret");
    const tampered = cipher.slice(0, -3) + "xxx";
    expect(() => credentialStore.decrypt(tampered)).toThrow();
  });

  it("throws on malformed ciphertext (missing parts)", () => {
    expect(() => credentialStore.decrypt("onlyone")).toThrow("Invalid credential ciphertext format");
  });
});

// ─── create ───────────────────────────────────────────────────────────────────

describe("create", () => {
  it("authValue decrypts back to the original plaintext", () => {
    const cred = credentialStore.create({
      type: "password",
      plaintext: "hunter2",
      source: "test",
      context: "test",
    });
    expect(credentialStore.getPlaintext(cred)).toBe("hunter2");
  });

  it("displayValue does NOT contain the plaintext", () => {
    const cred = credentialStore.create({
      type: "password",
      plaintext: "hunter2",
      source: "test",
      context: "test",
    });
    expect(cred.displayValue).not.toBe("hunter2");
    expect(cred.displayValue).toContain("***");
  });

  it("masks short values (≤8 chars) with prefix + ***", () => {
    const cred = credentialStore.create({
      type: "password",
      plaintext: "short",
      source: "test",
      context: "test",
    });
    expect(cred.displayValue).toMatch(/^.{2}\*\*\*/);
  });

  it("masks long values with prefix + *** + suffix", () => {
    const cred = credentialStore.create({
      type: "api_key",
      plaintext: "sk-abcdefghijklmnop",
      source: "test",
      context: "test",
    });
    expect(cred.displayValue).toMatch(/^.{4}\*\*\*.{4}$/);
  });

  it("hash is sha256 of plaintext (one-way, stable)", () => {
    const cred1 = credentialStore.create({ type: "password", plaintext: "abc", source: "s", context: "c" });
    const cred2 = credentialStore.create({ type: "password", plaintext: "abc", source: "s", context: "c" });
    expect(cred1.hash).toBe(cred2.hash);
  });

  it("different plaintexts produce different hashes", () => {
    const a = credentialStore.create({ type: "password", plaintext: "aaa", source: "s", context: "c" });
    const b = credentialStore.create({ type: "password", plaintext: "bbb", source: "s", context: "c" });
    expect(a.hash).not.toBe(b.hash);
  });

  it("defaults accessLevel to unknown", () => {
    const cred = credentialStore.create({ type: "token", plaintext: "tok", source: "s", context: "c" });
    expect(cred.accessLevel).toBe("unknown");
  });

  it("stores provided accessLevel", () => {
    const cred = credentialStore.create({
      type: "password", plaintext: "p", source: "s", context: "c", accessLevel: "admin",
    });
    expect(cred.accessLevel).toBe("admin");
  });

  it("authValue is never the same as plaintext", () => {
    const plain = "plaintext-value";
    const cred = credentialStore.create({ type: "password", plaintext: plain, source: "s", context: "c" });
    expect(cred.authValue).not.toBe(plain);
  });
});

// ─── getPlaintext ─────────────────────────────────────────────────────────────

describe("getPlaintext", () => {
  it("decrypts authValue to original plaintext", () => {
    const cred = credentialStore.create({
      type: "ssh_key",
      plaintext: "-----BEGIN RSA PRIVATE KEY-----",
      source: "s",
      context: "c",
    });
    expect(credentialStore.getPlaintext(cred)).toBe("-----BEGIN RSA PRIVATE KEY-----");
  });

  it("throws when authValue is tampered", () => {
    const cred = credentialStore.create({ type: "password", plaintext: "x", source: "s", context: "c" });
    const tampered: HarvestedCredential = { ...cred, authValue: cred.authValue.slice(0, -3) + "BAD" };
    expect(() => credentialStore.getPlaintext(tampered)).toThrow();
  });
});
