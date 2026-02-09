import { Socket } from "net";

export interface SmtpRelayProbeResult {
  target: string;
  port: number;
  scanStarted: Date;
  scanCompleted: Date;
  durationMs: number;
  accessible: boolean;
  banner?: string;
  isOpenRelay: boolean;
  relayTests: RelayTestResult[];
  securityIssues: SecurityIssue[];
}

export interface RelayTestResult {
  testName: string;
  fromAddress: string;
  toAddress: string;
  accepted: boolean;
  response: string;
  risk: "critical" | "high" | "medium" | "low";
}

export interface SecurityIssue {
  type: string;
  description: string;
  risk: "critical" | "high" | "medium" | "low";
  evidence: string;
  mitreId?: string;
}

interface SmtpConnection {
  socket: Socket;
  responses: string[];
}

async function connectSmtp(host: string, port: number, timeout: number = 10000): Promise<SmtpConnection | null> {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(timeout);
    const responses: string[] = [];
    
    socket.on("connect", () => {
    });
    
    socket.on("data", (data) => {
      responses.push(data.toString().trim());
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
    
    socket.on("error", () => {
      socket.destroy();
      resolve(null);
    });
    
    socket.connect(port, host);
    
    setTimeout(() => {
      if (responses.length > 0) {
        resolve({ socket, responses });
      } else {
        socket.destroy();
        resolve(null);
      }
    }, 3000);
  });
}

async function sendSmtpCommand(socket: Socket, command: string, timeout: number = 5000): Promise<string> {
  return new Promise((resolve) => {
    let response = "";
    
    const responseHandler = (data: Buffer) => {
      response += data.toString();
      if (response.match(/^\d{3} /m) || response.match(/^\d{3}-[\s\S]*\n\d{3} /m)) {
        socket.removeListener("data", responseHandler);
        resolve(response.trim());
      }
    };
    
    socket.on("data", responseHandler);
    socket.write(command + "\r\n");
    
    setTimeout(() => {
      socket.removeListener("data", responseHandler);
      resolve(response.trim() || "TIMEOUT");
    }, timeout);
  });
}

async function testRelayAttempt(
  socket: Socket,
  fromDomain: string,
  fromAddress: string,
  toAddress: string
): Promise<{ accepted: boolean; responses: string[] }> {
  const responses: string[] = [];
  
  const ehloResponse = await sendSmtpCommand(socket, `EHLO ${fromDomain}`);
  responses.push(ehloResponse);
  
  if (!ehloResponse.startsWith("250")) {
    const heloResponse = await sendSmtpCommand(socket, `HELO ${fromDomain}`);
    responses.push(heloResponse);
  }
  
  const mailFromResponse = await sendSmtpCommand(socket, `MAIL FROM:<${fromAddress}>`);
  responses.push(mailFromResponse);
  
  if (!mailFromResponse.startsWith("250")) {
    return { accepted: false, responses };
  }
  
  const rcptToResponse = await sendSmtpCommand(socket, `RCPT TO:<${toAddress}>`);
  responses.push(rcptToResponse);
  
  const accepted = rcptToResponse.startsWith("250") || rcptToResponse.startsWith("251");
  
  await sendSmtpCommand(socket, "RSET");
  
  return { accepted, responses };
}

export async function runSmtpRelayProbe(
  target: string,
  port: number = 25,
  testEmail?: string,
  onProgress?: (phase: string, progress: number, message: string) => void
): Promise<SmtpRelayProbeResult> {
  const startTime = Date.now();
  const relayTests: RelayTestResult[] = [];
  const securityIssues: SecurityIssue[] = [];
  
  onProgress?.("initialization", 0, `Starting SMTP relay probe against ${target}:${port}...`);
  
  const connection = await connectSmtp(target, port);
  
  if (!connection) {
    return {
      target,
      port,
      scanStarted: new Date(startTime),
      scanCompleted: new Date(),
      durationMs: Date.now() - startTime,
      accessible: false,
      isOpenRelay: false,
      relayTests: [],
      securityIssues: [],
    };
  }
  
  const { socket, responses } = connection;
  const banner = responses[0] || "";
  
  onProgress?.("connected", 10, `SMTP banner: ${banner.slice(0, 50)}...`);
  
  if (banner.toLowerCase().includes("version") || banner.match(/\d+\.\d+\.\d+/)) {
    securityIssues.push({
      type: "version_disclosure",
      description: "SMTP server discloses version information in banner",
      risk: "low",
      evidence: banner,
    });
  }
  
  const targetDomain = target.includes(".") ? target.split(".").slice(-2).join(".") : target;
  const externalDomain = "external-test.com";
  const internalTestEmail = testEmail || `test@${targetDomain}`;
  const externalTestEmail = `test@${externalDomain}`;
  
  const relayTestCases = [
    {
      testName: "External sender to external recipient",
      fromAddress: `attacker@${externalDomain}`,
      toAddress: externalTestEmail,
      risk: "critical" as const,
      description: "Classic open relay - external to external",
    },
    {
      testName: "Internal sender to external recipient",
      fromAddress: internalTestEmail,
      toAddress: externalTestEmail,
      risk: "high" as const,
      description: "Internal to external relay",
    },
    {
      testName: "Null sender to external recipient",
      fromAddress: "",
      toAddress: externalTestEmail,
      risk: "high" as const,
      description: "Null sender external relay",
    },
    {
      testName: "Spoofed internal sender to external",
      fromAddress: `admin@${targetDomain}`,
      toAddress: externalTestEmail,
      risk: "high" as const,
      description: "Sender spoofing to external",
    },
  ];
  
  let isOpenRelay = false;
  
  for (let i = 0; i < relayTestCases.length; i++) {
    const testCase = relayTestCases[i];
    
    onProgress?.("testing", Math.round(20 + (i / relayTestCases.length) * 70),
      `Testing: ${testCase.testName}...`);
    
    try {
      const result = await testRelayAttempt(
        socket,
        targetDomain,
        testCase.fromAddress,
        testCase.toAddress
      );
      
      relayTests.push({
        testName: testCase.testName,
        fromAddress: testCase.fromAddress,
        toAddress: testCase.toAddress,
        accepted: result.accepted,
        response: result.responses.join(" | "),
        risk: testCase.risk,
      });
      
      if (result.accepted) {
        isOpenRelay = true;
        securityIssues.push({
          type: "open_relay",
          description: testCase.description,
          risk: testCase.risk,
          evidence: `RCPT TO accepted for ${testCase.toAddress}`,
          mitreId: "T1071.003",
        });
      }
    } catch (error) {
      relayTests.push({
        testName: testCase.testName,
        fromAddress: testCase.fromAddress,
        toAddress: testCase.toAddress,
        accepted: false,
        response: `Error: ${error instanceof Error ? error.message : "Unknown"}`,
        risk: testCase.risk,
      });
    }
    
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  onProgress?.("checking", 90, "Checking for additional security issues...");
  
  const vrfyResponse = await sendSmtpCommand(socket, "VRFY root");
  if (vrfyResponse.startsWith("250") || vrfyResponse.startsWith("252")) {
    securityIssues.push({
      type: "vrfy_enabled",
      description: "VRFY command is enabled, allowing user enumeration",
      risk: "medium",
      evidence: vrfyResponse,
      mitreId: "T1589.002",
    });
  }
  
  const expnResponse = await sendSmtpCommand(socket, "EXPN postmaster");
  if (expnResponse.startsWith("250")) {
    securityIssues.push({
      type: "expn_enabled",
      description: "EXPN command is enabled, allowing mailing list enumeration",
      risk: "medium",
      evidence: expnResponse,
      mitreId: "T1589.002",
    });
  }
  
  try {
    await sendSmtpCommand(socket, "QUIT");
    socket.destroy();
  } catch {
    socket.destroy();
  }
  
  onProgress?.("completed", 100, `SMTP probe complete. Open relay: ${isOpenRelay ? "YES" : "No"}`);
  
  return {
    target,
    port,
    scanStarted: new Date(startTime),
    scanCompleted: new Date(),
    durationMs: Date.now() - startTime,
    accessible: true,
    banner,
    isOpenRelay,
    relayTests,
    securityIssues,
  };
}

export function generateSmtpRelayReport(result: SmtpRelayProbeResult): string {
  const lines: string[] = [
    "# SMTP Open Relay Probe Report",
    "",
    `**Target:** ${result.target}:${result.port}`,
    `**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`,
    `**SMTP Accessible:** ${result.accessible ? "Yes" : "No"}`,
    `**Open Relay Detected:** ${result.isOpenRelay ? "**YES - CRITICAL**" : "No"}`,
    "",
  ];
  
  if (!result.accessible) {
    lines.push("## Result");
    lines.push("");
    lines.push("SMTP service is not accessible on the specified port.");
    return lines.join("\n");
  }
  
  if (result.banner) {
    lines.push("## Server Banner");
    lines.push("");
    lines.push(`\`\`\`\n${result.banner}\n\`\`\``);
    lines.push("");
  }
  
  if (result.isOpenRelay) {
    lines.push("## :warning: OPEN RELAY DETECTED");
    lines.push("");
    lines.push("This SMTP server accepts mail for relay to external domains.");
    lines.push("This is a **critical** security vulnerability that can be exploited for:");
    lines.push("- Sending spam emails");
    lines.push("- Phishing campaigns");
    lines.push("- Reputation damage to your domain");
    lines.push("- Potential blacklisting of your mail server");
    lines.push("");
  }
  
  if (result.relayTests.length > 0) {
    lines.push("## Relay Test Results");
    lines.push("");
    lines.push("| Test | From | To | Result | Risk |");
    lines.push("|------|------|-----|--------|------|");
    
    for (const test of result.relayTests) {
      const status = test.accepted ? "ACCEPTED" : "Rejected";
      lines.push(`| ${test.testName} | ${test.fromAddress || "(null)"} | ${test.toAddress} | ${status} | ${test.risk.toUpperCase()} |`);
    }
    lines.push("");
  }
  
  if (result.securityIssues.length > 0) {
    lines.push("## Security Issues");
    lines.push("");
    
    for (const issue of result.securityIssues) {
      lines.push(`### ${issue.risk.toUpperCase()}: ${issue.description}`);
      lines.push("");
      lines.push(`- **Type:** ${issue.type}`);
      lines.push(`- **Evidence:** ${issue.evidence}`);
      if (issue.mitreId) {
        lines.push(`- **MITRE ATT&CK:** ${issue.mitreId}`);
      }
      lines.push("");
    }
  }
  
  lines.push("## Recommendations");
  lines.push("");
  if (result.isOpenRelay) {
    lines.push("1. **URGENT:** Configure SMTP relay restrictions immediately");
    lines.push("2. Implement SMTP authentication for outbound mail");
    lines.push("3. Use IP-based access controls for relay permissions");
    lines.push("4. Configure SPF, DKIM, and DMARC records");
  }
  lines.push("5. Disable VRFY and EXPN commands");
  lines.push("6. Remove version information from SMTP banner");
  lines.push("7. Implement rate limiting for SMTP connections");
  lines.push("8. Enable TLS/STARTTLS for encrypted communication");
  
  return lines.join("\n");
}
