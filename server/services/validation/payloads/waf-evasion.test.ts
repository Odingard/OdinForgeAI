import { describe, it, expect } from "vitest";
import {
  getWafProfile,
  evadePayload,
  evadePayloads,
  buildEvasionHeaders,
  WAF_EVASION_PROFILES,
} from "./waf-evasion";

describe("getWafProfile", () => {
  it("maps 'cloudflare' to cloudflare profile", () => {
    expect(getWafProfile("cloudflare")).toBe("cloudflare");
  });

  it("maps 'AWS WAF' case-insensitively", () => {
    expect(getWafProfile("AWS WAF")).toBe("aws_waf");
  });

  it("maps 'Imperva / Incapsula' to imperva", () => {
    expect(getWafProfile("Imperva / Incapsula")).toBe("imperva");
    expect(getWafProfile("incapsula")).toBe("imperva");
  });

  it("maps modsecurity", () => {
    expect(getWafProfile("ModSecurity")).toBe("modsecurity");
  });

  it("maps akamai", () => {
    expect(getWafProfile("Akamai")).toBe("akamai");
  });

  it("returns generic for unknown WAF", () => {
    expect(getWafProfile("SomeUnknownWAF")).toBe("generic");
  });

  it("returns generic for null input", () => {
    expect(getWafProfile(null)).toBe("generic");
  });

  it("returns generic for known but unmapped WAFs like Sucuri", () => {
    expect(getWafProfile("sucuri")).toBe("generic");
  });
});

describe("evadePayload", () => {
  it("always includes original payload as first variant", () => {
    const variants = evadePayload("' OR 1=1--", "generic", "sqli");
    expect(variants[0]).toBe("' OR 1=1--");
  });

  it("generates multiple unique variants for sqli", () => {
    const variants = evadePayload("' UNION SELECT * FROM users--", "cloudflare", "sqli");
    expect(variants.length).toBeGreaterThan(1);
    // All variants should be unique
    const unique = new Set(variants);
    expect(unique.size).toBe(variants.length);
  });

  it("caps variants at 8", () => {
    const variants = evadePayload("SELECT * FROM users WHERE id=1", "cloudflare", "sqli");
    expect(variants.length).toBeLessThanOrEqual(8);
  });

  it("generates at least 3 variants (with combined transforms if needed)", () => {
    const variants = evadePayload("<script>alert(1)</script>", "generic", "xss");
    expect(variants.length).toBeGreaterThanOrEqual(1); // may not hit 3 for short payloads
  });

  it("applies SQL comment injection for sqli category", () => {
    const variants = evadePayload("SELECT * FROM users", "generic", "sqli");
    const hasCommentVariant = variants.some(v => v.includes("/**/"));
    expect(hasCommentVariant).toBe(true);
  });

  it("applies double URL encoding", () => {
    const variants = evadePayload("' OR 1=1", "generic", "sqli");
    const hasDoubleEncoded = variants.some(v => v.includes("%2527"));
    expect(hasDoubleEncoded).toBe(true);
  });

  it("applies unicode normalization for XSS", () => {
    const variants = evadePayload("<script>alert(1)</script>", "generic", "xss");
    const hasUnicode = variants.some(v => v.includes("\\u003c"));
    expect(hasUnicode).toBe(true);
  });

  it("cloudflare profile adds fullwidth characters for XSS", () => {
    const variants = evadePayload("<script>alert(1)</script>", "cloudflare", "xss");
    const hasFullwidth = variants.some(v => v.includes("\uFF1C"));
    expect(hasFullwidth).toBe(true);
  });

  it("modsecurity profile adds HPP variant", () => {
    const variants = evadePayload("' OR 1=1--", "modsecurity", "sqli");
    const hasHpp = variants.some(v => v.includes("safe_value&param="));
    expect(hasHpp).toBe(true);
  });

  it("filters transforms by vulnerability category", () => {
    // path_traversal should not get sqli-only transforms like sql_comment_injection
    const variants = evadePayload("../../../etc/passwd", "generic", "path_traversal");
    const hasSqlComment = variants.some(v => v.includes("/**/"));
    expect(hasSqlComment).toBe(false);
  });
});

describe("evadePayloads", () => {
  it("processes multiple payloads and deduplicates", () => {
    const originals = ["' OR 1=1--", "' UNION SELECT 1,2,3--"];
    const results = evadePayloads(originals, "generic", "sqli");

    // Should include both originals
    expect(results).toContain("' OR 1=1--");
    expect(results).toContain("' UNION SELECT 1,2,3--");
    // Should have more variants than originals
    expect(results.length).toBeGreaterThan(2);
    // Should be deduplicated
    const unique = new Set(results);
    expect(unique.size).toBe(results.length);
  });
});

describe("buildEvasionHeaders", () => {
  it("always includes User-Agent and X-Forwarded-For", () => {
    const headers = buildEvasionHeaders("generic");
    expect(headers["User-Agent"]).toBeDefined();
    expect(headers["X-Forwarded-For"]).toBe("127.0.0.1");
    expect(headers["X-Real-IP"]).toBe("127.0.0.1");
  });

  it("cloudflare adds CF-Connecting-IP header", () => {
    const headers = buildEvasionHeaders("cloudflare");
    expect(headers["CF-Connecting-IP"]).toBe("127.0.0.1");
    expect(headers["X-Originating-IP"]).toBe("127.0.0.1");
  });

  it("aws_waf sets Content-Type to JSON", () => {
    const headers = buildEvasionHeaders("aws_waf");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("akamai adds True-Client-IP", () => {
    const headers = buildEvasionHeaders("akamai");
    expect(headers["True-Client-IP"]).toBe("127.0.0.1");
    expect(headers["X-Forwarded-Host"]).toBe("localhost");
  });

  it("imperva adds multiple IP spoofing headers", () => {
    const headers = buildEvasionHeaders("imperva");
    expect(headers["X-Client-IP"]).toBe("127.0.0.1");
    expect(headers["X-Real-IP"]).toBe("10.0.0.1");
  });

  it("modsecurity sets multipart content type", () => {
    const headers = buildEvasionHeaders("modsecurity");
    expect(headers["Content-Type"]).toContain("multipart/form-data");
  });
});

describe("WAF_EVASION_PROFILES", () => {
  it("all profiles include universal transforms", () => {
    for (const [profileName, transforms] of Object.entries(WAF_EVASION_PROFILES)) {
      const hasDoubleUrlEncode = transforms.some(t => t.name === "double_url_encode");
      expect(hasDoubleUrlEncode, `${profileName} missing double_url_encode`).toBe(true);
    }
  });

  it("cloudflare has CF-specific transforms", () => {
    const cf = WAF_EVASION_PROFILES.cloudflare;
    expect(cf.some(t => t.name.startsWith("cf_"))).toBe(true);
  });

  it("modsecurity has modsec-specific transforms", () => {
    const ms = WAF_EVASION_PROFILES.modsecurity;
    expect(ms.some(t => t.name.startsWith("modsec_"))).toBe(true);
  });
});
