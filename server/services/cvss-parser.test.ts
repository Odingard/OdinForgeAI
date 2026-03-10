import { describe, it, expect } from "vitest";
import { parseCVSSVector } from "./cvss-parser";

describe("parseCVSSVector", () => {
  // ── v3.1 parsing ─────────────────────────────────────────────────
  describe("CVSS v3.1", () => {
    it("parses critical severity vector", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
      expect(result).not.toBeNull();
      expect(result!.version).toBe("3.1");
      expect(result!.baseScore).toBeGreaterThanOrEqual(9.0);
      expect(result!.severity).toBe("critical");
    });

    it("parses low severity vector", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N");
      expect(result).not.toBeNull();
      expect(result!.baseScore).toBeLessThanOrEqual(4.0);
    });

    it("parses medium severity vector", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
      expect(result).not.toBeNull();
      expect(result!.severity).toBe("medium");
    });
  });

  // ── v3.0 parsing ─────────────────────────────────────────────────
  describe("CVSS v3.0", () => {
    it("parses v3.0 vector with changed scope", () => {
      const result = parseCVSSVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
      expect(result).not.toBeNull();
      expect(result!.version).toBe("3.0");
      expect(result!.baseScore).toBeGreaterThanOrEqual(9.0);
    });
  });

  // ── v2 parsing ───────────────────────────────────────────────────
  describe("CVSS v2", () => {
    it("parses v2 vector (no prefix)", () => {
      const result = parseCVSSVector("AV:N/AC:L/Au:N/C:C/I:C/A:C");
      expect(result).not.toBeNull();
      expect(result!.version).toBe("2.0");
      expect(result!.baseScore).toBeGreaterThanOrEqual(9.0);
    });

    it("parses v2 vector with parentheses", () => {
      const result = parseCVSSVector("(AV:N/AC:L/Au:N/C:C/I:C/A:C)");
      expect(result).not.toBeNull();
      expect(result!.version).toBe("2.0");
    });
  });

  // ── Derived fields ───────────────────────────────────────────────
  describe("derived fields", () => {
    it("AV:N → networkExposure internet", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
      expect(result!.networkExposure).toBe("internet");
    });

    it("AV:A → networkExposure dmz or adjacent", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
      expect(["dmz", "adjacent"]).toContain(result!.networkExposure);
    });

    it("PR:N → authRequired none", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
      expect(result!.authRequired).toBe("none");
    });

    it("PR:H → authRequired privileged", () => {
      const result = parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
      expect(result!.authRequired).toBe("privileged");
    });
  });

  // ── Edge cases ───────────────────────────────────────────────────
  describe("edge cases", () => {
    it("null input → null", () => {
      expect(parseCVSSVector(null as any)).toBeNull();
    });

    it("empty string → null", () => {
      expect(parseCVSSVector("")).toBeNull();
    });

    it("garbage string → null", () => {
      expect(parseCVSSVector("not-a-cvss-vector")).toBeNull();
    });

    it("incomplete v3 vector → null", () => {
      expect(parseCVSSVector("CVSS:3.1/AV:N/AC:L")).toBeNull();
    });
  });
});
