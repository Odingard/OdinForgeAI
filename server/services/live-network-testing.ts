import * as net from "net";
import * as dns from "dns";
import { promisify } from "util";
import { storage } from "../storage";

const dnsLookup = promisify(dns.lookup);

export interface ScanTarget {
  host: string;
  ports?: number[];
}

export interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service?: string;
  banner?: string;
  version?: string;
}

export interface ScanResult {
  host: string;
  ip?: string;
  hostname?: string;
  scanStarted: Date;
  scanCompleted: Date;
  ports: PortResult[];
  os?: string;
  vulnerabilities: VulnerabilityHint[];
}

export interface VulnerabilityHint {
  port: number;
  service: string;
  issue: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cve?: string;
  recommendation: string;
}

export interface LiveTestProgress {
  phase: "resolving" | "scanning" | "enumerating" | "analyzing" | "complete";
  progress: number;
  message: string;
  currentPort?: number;
  portsScanned?: number;
  totalPorts?: number;
}

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
];

const SERVICE_SIGNATURES: Record<number, { name: string; probes?: string[] }> = {
  21: { name: "ftp" },
  22: { name: "ssh" },
  23: { name: "telnet" },
  25: { name: "smtp" },
  53: { name: "dns" },
  80: { name: "http", probes: ["GET / HTTP/1.0\r\n\r\n"] },
  110: { name: "pop3" },
  111: { name: "rpcbind" },
  135: { name: "msrpc" },
  139: { name: "netbios-ssn" },
  143: { name: "imap" },
  443: { name: "https" },
  445: { name: "microsoft-ds" },
  993: { name: "imaps" },
  995: { name: "pop3s" },
  1433: { name: "mssql" },
  1521: { name: "oracle" },
  3306: { name: "mysql" },
  3389: { name: "rdp" },
  5432: { name: "postgresql" },
  5900: { name: "vnc" },
  6379: { name: "redis" },
  8080: { name: "http-proxy", probes: ["GET / HTTP/1.0\r\n\r\n"] },
  8443: { name: "https-alt" },
  27017: { name: "mongodb" },
};

const VULNERABILITY_PATTERNS: Array<{
  pattern: RegExp;
  port?: number;
  service?: string;
  issue: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cve?: string;
  recommendation: string;
}> = [
  {
    pattern: /OpenSSH[_ ]([0-6]\.|7\.[0-3])/i,
    service: "ssh",
    issue: "Outdated OpenSSH version with known vulnerabilities",
    severity: "high",
    recommendation: "Upgrade OpenSSH to version 8.0 or later",
  },
  {
    pattern: /vsftpd 2\.3\.4/i,
    service: "ftp",
    issue: "vsftpd 2.3.4 backdoor vulnerability",
    severity: "critical",
    cve: "CVE-2011-2523",
    recommendation: "Immediately upgrade vsftpd to a secure version",
  },
  {
    pattern: /Apache\/2\.[0-3]\./i,
    service: "http",
    issue: "Outdated Apache version",
    severity: "medium",
    recommendation: "Upgrade Apache to version 2.4.x or later",
  },
  {
    pattern: /nginx\/1\.([0-9]|1[0-7])\./i,
    service: "http",
    issue: "Outdated nginx version",
    severity: "medium",
    recommendation: "Upgrade nginx to version 1.18 or later",
  },
  {
    pattern: /MySQL.*5\.[0-5]\./i,
    service: "mysql",
    issue: "Outdated MySQL version",
    severity: "high",
    recommendation: "Upgrade MySQL to version 8.0 or later",
  },
  {
    pattern: /redis_version:([0-5]\.|6\.[0-1]\.)/i,
    service: "redis",
    issue: "Redis version with potential vulnerabilities",
    severity: "medium",
    recommendation: "Upgrade Redis to version 6.2 or later",
  },
  {
    pattern: /anonymous.*login/i,
    service: "ftp",
    issue: "Anonymous FTP login enabled",
    severity: "medium",
    recommendation: "Disable anonymous FTP access unless required",
  },
  {
    port: 23,
    pattern: /.*/,
    issue: "Telnet service exposed - unencrypted protocol",
    severity: "high",
    recommendation: "Replace Telnet with SSH for secure remote access",
  },
  {
    port: 3389,
    pattern: /.*/,
    issue: "RDP exposed to network",
    severity: "medium",
    recommendation: "Restrict RDP access via VPN or firewall rules",
  },
  {
    port: 5900,
    pattern: /.*/,
    issue: "VNC exposed - potential for unauthorized access",
    severity: "medium",
    recommendation: "Secure VNC with strong authentication and tunnel via SSH/VPN",
  },
];

let abortController: AbortController | null = null;
let currentScanId: string | null = null;

export function abortCurrentScan(): boolean {
  if (abortController) {
    abortController.abort();
    console.log(`[LiveTesting] Scan ${currentScanId} aborted via kill switch`);
    return true;
  }
  return false;
}

export function isScanning(): boolean {
  return abortController !== null;
}

async function checkPort(
  host: string,
  port: number,
  timeout: number = 2000,
  signal?: AbortSignal
): Promise<PortResult> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve({ port, state: "filtered" });
      return;
    }

    const socket = new net.Socket();
    let banner = "";
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    const abortHandler = () => {
      cleanup();
      resolve({ port, state: "filtered" });
    };

    signal?.addEventListener("abort", abortHandler, { once: true });

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      const service = SERVICE_SIGNATURES[port]?.name || "unknown";
      
      socket.on("data", (data) => {
        banner += data.toString("utf8", 0, Math.min(data.length, 512));
      });

      const probe = SERVICE_SIGNATURES[port]?.probes?.[0];
      if (probe) {
        socket.write(probe);
      }

      setTimeout(() => {
        cleanup();
        signal?.removeEventListener("abort", abortHandler);
        resolve({
          port,
          state: "open",
          service,
          banner: banner.trim() || undefined,
          version: extractVersion(banner, service),
        });
      }, 500);
    });

    socket.on("timeout", () => {
      cleanup();
      signal?.removeEventListener("abort", abortHandler);
      resolve({ port, state: "filtered" });
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      cleanup();
      signal?.removeEventListener("abort", abortHandler);
      if (err.code === "ECONNREFUSED") {
        resolve({ port, state: "closed" });
      } else {
        resolve({ port, state: "filtered" });
      }
    });

    socket.connect(port, host);
  });
}

function extractVersion(banner: string, service: string): string | undefined {
  if (!banner) return undefined;

  const patterns: Record<string, RegExp> = {
    ssh: /SSH-[\d.]+-([^\s]+)/i,
    http: /(Apache|nginx|IIS|LiteSpeed)\/[\d.]+/i,
    ftp: /(vsftpd|ProFTPD|Pure-FTPd)[\s_][\d.]+/i,
    mysql: /[\d.]+-([\w.-]+)/i,
    postgresql: /PostgreSQL\s+([\d.]+)/i,
    redis: /redis_version:([\d.]+)/i,
  };

  const pattern = patterns[service];
  if (pattern) {
    const match = banner.match(pattern);
    return match ? match[0] : undefined;
  }

  return undefined;
}

function detectVulnerabilities(ports: PortResult[]): VulnerabilityHint[] {
  const vulnerabilities: VulnerabilityHint[] = [];

  for (const port of ports) {
    if (port.state !== "open") continue;

    for (const vuln of VULNERABILITY_PATTERNS) {
      if (vuln.port && vuln.port !== port.port) continue;
      if (vuln.service && vuln.service !== port.service) continue;

      const testString = port.banner || port.service || "";
      if (vuln.pattern.test(testString)) {
        vulnerabilities.push({
          port: port.port,
          service: port.service || "unknown",
          issue: vuln.issue,
          severity: vuln.severity,
          cve: vuln.cve,
          recommendation: vuln.recommendation,
        });
      }
    }
  }

  return vulnerabilities;
}

async function resolveHost(host: string): Promise<{ ip: string; hostname: string }> {
  try {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      return { ip: host, hostname: host };
    }
    const result = await dnsLookup(host);
    return { ip: result.address, hostname: host };
  } catch {
    return { ip: host, hostname: host };
  }
}

export async function executeLiveNetworkTest(
  evaluationId: string,
  target: ScanTarget,
  organizationId: string,
  onProgress?: (progress: LiveTestProgress) => void
): Promise<ScanResult> {
  const governance = await storage.getOrganizationGovernance(organizationId);
  
  if (governance?.killSwitchActive) {
    throw new Error("Kill switch is active - all operations halted");
  }
  
  if (governance?.executionMode !== "live") {
    throw new Error("Live testing requires Live Mode to be enabled in Governance");
  }

  const scopeRules = await storage.getScopeRules(organizationId);
  const isBlocked = scopeRules.some(rule => {
    if (rule.ruleType !== "block") return false;
    if (rule.targetType === "hostname" && target.host === rule.targetValue) return true;
    if (rule.targetType === "ip" && target.host === rule.targetValue) return true;
    if (rule.targetType === "pattern") {
      try {
        const regex = new RegExp(rule.targetValue);
        return regex.test(target.host);
      } catch {
        return false;
      }
    }
    return false;
  });

  if (isBlocked) {
    await storage.createAuthorizationLog({
      organizationId,
      action: "unauthorized_target_blocked",
      details: { target: target.host, reason: "scope_rule_block" } as Record<string, any>,
      authorized: false,
      riskLevel: "high",
    });
    throw new Error(`Target ${target.host} is blocked by scope rules`);
  }

  await storage.createAuthorizationLog({
    organizationId,
    action: "live_execution_authorized",
    evaluationId,
    targetAsset: target.host,
    executionMode: "live",
    details: { ports: (target.ports || COMMON_PORTS).slice(0, 10), portsCount: (target.ports || COMMON_PORTS).length } as Record<string, any>,
    authorized: true,
  });

  abortController = new AbortController();
  currentScanId = evaluationId;
  const signal = abortController.signal;

  try {
    const scanStarted = new Date();
    onProgress?.({ phase: "resolving", progress: 5, message: `Resolving ${target.host}...` });

    const { ip, hostname } = await resolveHost(target.host);

    if (signal.aborted) {
      throw new Error("Scan aborted");
    }

    const portsToScan = target.ports || COMMON_PORTS;
    const ports: PortResult[] = [];
    
    onProgress?.({ 
      phase: "scanning", 
      progress: 10, 
      message: `Scanning ${portsToScan.length} ports on ${ip}...`,
      totalPorts: portsToScan.length,
      portsScanned: 0,
    });

    const killSwitchCheck = setInterval(async () => {
      const gov = await storage.getOrganizationGovernance(organizationId);
      if (gov?.killSwitchActive) {
        abortController?.abort();
      }
    }, 2000);

    try {
      const CONCURRENCY = 10;
      for (let i = 0; i < portsToScan.length; i += CONCURRENCY) {
        if (signal.aborted) break;

        const batch = portsToScan.slice(i, i + CONCURRENCY);
        const results = await Promise.all(
          batch.map(port => checkPort(ip, port, 2000, signal))
        );
        ports.push(...results);

        const scanned = Math.min(i + CONCURRENCY, portsToScan.length);
        const progress = 10 + Math.floor((scanned / portsToScan.length) * 60);
        
        onProgress?.({
          phase: "scanning",
          progress,
          message: `Scanned ${scanned}/${portsToScan.length} ports`,
          portsScanned: scanned,
          totalPorts: portsToScan.length,
          currentPort: batch[batch.length - 1],
        });
      }
    } finally {
      clearInterval(killSwitchCheck);
    }

    if (signal.aborted) {
      throw new Error("Scan aborted by kill switch");
    }

    onProgress?.({ phase: "enumerating", progress: 75, message: "Enumerating services..." });

    const openPorts = ports.filter(p => p.state === "open");
    
    onProgress?.({ phase: "analyzing", progress: 85, message: "Analyzing for vulnerabilities..." });

    const vulnerabilities = detectVulnerabilities(ports);

    const scanCompleted = new Date();

    const result: ScanResult = {
      host: target.host,
      ip,
      hostname,
      scanStarted,
      scanCompleted,
      ports: openPorts,
      vulnerabilities,
    };

    await storage.createAuthorizationLog({
      organizationId,
      action: "live_scan_completed",
      evaluationId,
      targetAsset: target.host,
      executionMode: "live",
      details: {
        openPorts: openPorts.length,
        vulnerabilities: vulnerabilities.length,
        duration: scanCompleted.getTime() - scanStarted.getTime(),
      } as Record<string, any>,
      authorized: true,
    });

    onProgress?.({ 
      phase: "complete", 
      progress: 100, 
      message: `Scan complete: ${openPorts.length} open ports, ${vulnerabilities.length} potential issues` 
    });

    return result;

  } finally {
    abortController = null;
    currentScanId = null;
  }
}

export function parseTargetFromAsset(assetId: string, description: string): ScanTarget | null {
  const ipMatch = description.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) {
    return { host: ipMatch[1] };
  }

  const hostMatch = description.match(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b/);
  if (hostMatch) {
    return { host: hostMatch[0] };
  }

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(assetId)) {
    return { host: assetId };
  }

  if (/^[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$/.test(assetId)) {
    return { host: assetId };
  }

  return null;
}
