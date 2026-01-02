import type { InsertAgentFinding } from "@shared/schema";

interface PortInfo {
  port: number;
  protocol?: string;
  process?: string;
  pid?: string;
  address?: string;
}

interface ServiceInfo {
  name: string;
  status?: string;
  pid?: string;
}

interface ResourceMetrics {
  cpu_percent?: number;
  mem_used_pct?: number;
  disk_used_pct?: number;
}

interface TelemetryData {
  agentId: string;
  organizationId: string;
  telemetryId: string;
  openPorts?: PortInfo[] | null;
  services?: ServiceInfo[] | null;
  resourceMetrics?: ResourceMetrics | null;
  systemInfo?: {
    hostname?: string;
    os?: string;
    platform?: string;
  } | null;
}

interface GeneratedFinding {
  findingType: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  title: string;
  description: string;
  affectedComponent?: string;
  affectedPort?: number;
  affectedService?: string;
  recommendation?: string;
}

const HIGH_RISK_PORTS: Record<number, { name: string; severity: "critical" | "high" | "medium"; reason: string; recommendation: string }> = {
  21: { name: "FTP", severity: "high", reason: "FTP transmits credentials in cleartext and is commonly exploited", recommendation: "Disable FTP and use SFTP or SCP instead. If FTP is required, restrict access with firewall rules." },
  22: { name: "SSH", severity: "medium", reason: "SSH exposed to network - ensure strong authentication is configured", recommendation: "Use key-based authentication, disable root login, and consider using a non-standard port." },
  23: { name: "Telnet", severity: "critical", reason: "Telnet transmits all data including passwords in cleartext", recommendation: "Disable Telnet immediately and use SSH instead." },
  25: { name: "SMTP", severity: "medium", reason: "SMTP server exposed - could be used for spam relay if misconfigured", recommendation: "Ensure proper authentication is required and restrict relay to authorized senders." },
  53: { name: "DNS", severity: "medium", reason: "DNS server exposed - could be vulnerable to amplification attacks", recommendation: "Implement rate limiting and restrict recursive queries to authorized clients." },
  110: { name: "POP3", severity: "high", reason: "POP3 transmits credentials in cleartext", recommendation: "Use POP3S (SSL/TLS) on port 995 instead." },
  135: { name: "MS-RPC", severity: "high", reason: "Microsoft RPC endpoint - commonly exploited in lateral movement attacks", recommendation: "Restrict access with firewall rules. Block from external networks." },
  139: { name: "NetBIOS", severity: "high", reason: "NetBIOS session service - used in SMB attacks and enumeration", recommendation: "Disable NetBIOS over TCP/IP if not needed. Block from external networks." },
  143: { name: "IMAP", severity: "medium", reason: "IMAP transmits credentials in cleartext by default", recommendation: "Use IMAPS (SSL/TLS) on port 993 instead." },
  389: { name: "LDAP", severity: "high", reason: "LDAP exposed - could leak directory information", recommendation: "Use LDAPS on port 636. Restrict access to authorized clients only." },
  445: { name: "SMB", severity: "critical", reason: "SMB is a primary target for ransomware and lateral movement (EternalBlue, WannaCry)", recommendation: "Block SMB from external networks. Ensure SMBv1 is disabled. Apply all security patches." },
  1433: { name: "MS-SQL", severity: "critical", reason: "SQL Server exposed - database credentials could be brute-forced", recommendation: "Never expose SQL Server to the internet. Use firewall rules and VPN for remote access." },
  1521: { name: "Oracle DB", severity: "critical", reason: "Oracle database exposed - critical data at risk", recommendation: "Never expose database ports to the internet. Use firewall rules and encrypted tunnels." },
  3306: { name: "MySQL", severity: "critical", reason: "MySQL database exposed - commonly targeted for data theft", recommendation: "Never expose MySQL to the internet. Bind to localhost and use SSH tunnels for remote access." },
  3389: { name: "RDP", severity: "critical", reason: "Remote Desktop exposed - primary target for brute force and BlueKeep-style exploits", recommendation: "Use VPN for RDP access. Enable NLA, use strong passwords, and implement account lockout policies." },
  5432: { name: "PostgreSQL", severity: "critical", reason: "PostgreSQL database exposed - critical data at risk", recommendation: "Never expose PostgreSQL to the internet. Use SSH tunnels or VPN for remote access." },
  5900: { name: "VNC", severity: "critical", reason: "VNC remote desktop exposed - often has weak authentication", recommendation: "Disable VNC or restrict access via VPN. VNC should never be exposed to the internet." },
  5985: { name: "WinRM HTTP", severity: "high", reason: "Windows Remote Management over HTTP - credentials transmitted insecurely", recommendation: "Use WinRM over HTTPS (port 5986) with proper certificates." },
  5986: { name: "WinRM HTTPS", severity: "medium", reason: "Windows Remote Management exposed - could allow remote code execution", recommendation: "Restrict access to authorized management systems. Use firewall rules." },
  6379: { name: "Redis", severity: "critical", reason: "Redis exposed - often has no authentication by default", recommendation: "Never expose Redis to the internet. Enable authentication and bind to localhost." },
  8080: { name: "HTTP Proxy/Alt", severity: "medium", reason: "Alternative HTTP port - may be running unpatched web applications", recommendation: "Audit all web applications on this port. Ensure proper security configurations." },
  9200: { name: "Elasticsearch", severity: "critical", reason: "Elasticsearch exposed - could leak sensitive indexed data", recommendation: "Never expose Elasticsearch to the internet. Use authentication and network isolation." },
  27017: { name: "MongoDB", severity: "critical", reason: "MongoDB exposed - historically has had no authentication by default", recommendation: "Enable authentication, bind to localhost, and never expose to the internet." },
};

const RISKY_SERVICES: Record<string, { severity: "high" | "medium"; reason: string; recommendation: string }> = {
  "RemoteRegistry": { severity: "high", reason: "Remote Registry service allows remote access to Windows registry", recommendation: "Disable Remote Registry service unless specifically required." },
  "TermService": { severity: "medium", reason: "Terminal Services (RDP) is running", recommendation: "Ensure RDP is only accessible via VPN and uses NLA." },
  "TlntSvr": { severity: "critical" as any, reason: "Telnet Server is running - transmits data in cleartext", recommendation: "Disable Telnet Server immediately and use SSH." },
  "SNMP": { severity: "high", reason: "SNMP service running - default community strings are often used", recommendation: "Disable SNMP if not needed. If required, use SNMPv3 with authentication." },
  "W3SVC": { severity: "medium", reason: "IIS Web Server is running", recommendation: "Ensure IIS is properly configured and all applications are patched." },
  "MSSQLSERVER": { severity: "medium", reason: "SQL Server is running", recommendation: "Ensure SQL Server is not exposed to external networks." },
  "MySQL": { severity: "medium", reason: "MySQL service is running", recommendation: "Ensure MySQL is bound to localhost only." },
};

const SECURITY_SERVICES = [
  "WinDefend", "MsMpSvc", "SecurityHealthService", 
  "wscsvc",
  "MpsSvc",
  "EventLog",
  "SamSs",
  "BITS",
  "wuauserv",
];

export function analyzeTelemetry(telemetry: TelemetryData): GeneratedFinding[] {
  const findings: GeneratedFinding[] = [];
  const hostname = telemetry.systemInfo?.hostname || "Unknown Host";

  if (telemetry.openPorts && Array.isArray(telemetry.openPorts)) {
    findings.push(...analyzeOpenPorts(telemetry.openPorts, hostname));
  }

  if (telemetry.services && Array.isArray(telemetry.services)) {
    findings.push(...analyzeServices(telemetry.services, hostname));
  }

  if (telemetry.resourceMetrics) {
    findings.push(...analyzeResourceMetrics(telemetry.resourceMetrics, hostname));
  }

  return findings;
}

function analyzeOpenPorts(ports: PortInfo[], hostname: string): GeneratedFinding[] {
  const findings: GeneratedFinding[] = [];

  for (const port of ports) {
    const portNum = port.port;
    const riskInfo = HIGH_RISK_PORTS[portNum];

    if (riskInfo) {
      const isExposed = port.address === "*" || port.address === "0.0.0.0" || port.address === "::";
      const exposureNote = isExposed ? " (bound to all interfaces - externally accessible)" : "";
      
      findings.push({
        findingType: "open_port",
        severity: isExposed ? riskInfo.severity : (riskInfo.severity === "critical" ? "high" : "medium"),
        title: `${riskInfo.name} Port ${portNum} Open${exposureNote}`,
        description: `Port ${portNum} (${riskInfo.name}) is open on ${hostname}. ${riskInfo.reason}${port.process ? ` Process: ${port.process} (PID: ${port.pid || "unknown"})` : ""}`,
        affectedComponent: port.process || riskInfo.name,
        affectedPort: portNum,
        recommendation: riskInfo.recommendation,
      });
    }

    if (port.address === "*" || port.address === "0.0.0.0") {
      if (!HIGH_RISK_PORTS[portNum] && portNum < 1024) {
        findings.push({
          findingType: "exposed_service",
          severity: "low",
          title: `Well-known Port ${portNum} Exposed to All Interfaces`,
          description: `Port ${portNum} is bound to all network interfaces on ${hostname}, making it accessible from external networks.${port.process ? ` Process: ${port.process}` : ""}`,
          affectedComponent: port.process || `Port ${portNum}`,
          affectedPort: portNum,
          recommendation: "Review if this service needs to be accessible from all networks. Consider binding to specific interfaces.",
        });
      }
    }
  }

  return findings;
}

function analyzeServices(services: ServiceInfo[], hostname: string): GeneratedFinding[] {
  const findings: GeneratedFinding[] = [];
  const runningServiceNames = new Set(services.filter(s => s.status === "running" || s.status === "Running").map(s => s.name.toLowerCase()));

  for (const service of services) {
    if (service.status !== "running" && service.status !== "Running") continue;

    const riskInfo = RISKY_SERVICES[service.name];
    if (riskInfo) {
      findings.push({
        findingType: "risky_service",
        severity: riskInfo.severity,
        title: `Risky Service Running: ${service.name}`,
        description: `The ${service.name} service is running on ${hostname}. ${riskInfo.reason}`,
        affectedComponent: service.name,
        affectedService: service.name,
        recommendation: riskInfo.recommendation,
      });
    }
  }

  const missingSecurityServices: string[] = [];
  for (const secService of SECURITY_SERVICES) {
    if (!runningServiceNames.has(secService.toLowerCase())) {
      missingSecurityServices.push(secService);
    }
  }

  if (missingSecurityServices.includes("WinDefend") && missingSecurityServices.includes("MsMpSvc")) {
    findings.push({
      findingType: "missing_security",
      severity: "high",
      title: "Windows Defender Not Running",
      description: `Windows Defender antivirus service is not running on ${hostname}. The system may be unprotected against malware.`,
      affectedComponent: "Windows Defender",
      affectedService: "WinDefend",
      recommendation: "Enable Windows Defender or ensure another antivirus solution is active.",
    });
  }

  if (missingSecurityServices.includes("MpsSvc")) {
    findings.push({
      findingType: "missing_security",
      severity: "high",
      title: "Windows Firewall Not Running",
      description: `Windows Firewall service (MpsSvc) is not running on ${hostname}. Network protection is disabled.`,
      affectedComponent: "Windows Firewall",
      affectedService: "MpsSvc",
      recommendation: "Enable Windows Firewall service immediately.",
    });
  }

  if (missingSecurityServices.includes("wuauserv")) {
    findings.push({
      findingType: "missing_security",
      severity: "medium",
      title: "Windows Update Service Not Running",
      description: `Windows Update service is not running on ${hostname}. System may not receive security patches.`,
      affectedComponent: "Windows Update",
      affectedService: "wuauserv",
      recommendation: "Enable Windows Update service to ensure security patches are applied.",
    });
  }

  return findings;
}

function analyzeResourceMetrics(metrics: ResourceMetrics, hostname: string): GeneratedFinding[] {
  const findings: GeneratedFinding[] = [];

  if (metrics.cpu_percent !== undefined && metrics.cpu_percent > 90) {
    findings.push({
      findingType: "resource_anomaly",
      severity: metrics.cpu_percent > 98 ? "high" : "medium",
      title: `High CPU Usage Detected (${metrics.cpu_percent.toFixed(1)}%)`,
      description: `Sustained high CPU usage (${metrics.cpu_percent.toFixed(1)}%) detected on ${hostname}. This could indicate cryptomining malware, runaway process, or denial of service.`,
      affectedComponent: "CPU",
      recommendation: "Investigate running processes. Check for unauthorized software or cryptomining activity.",
    });
  }

  if (metrics.mem_used_pct !== undefined && metrics.mem_used_pct > 95) {
    findings.push({
      findingType: "resource_anomaly",
      severity: "medium",
      title: `Critical Memory Usage (${metrics.mem_used_pct.toFixed(1)}%)`,
      description: `Memory usage is critically high (${metrics.mem_used_pct.toFixed(1)}%) on ${hostname}. System stability may be affected.`,
      affectedComponent: "Memory",
      recommendation: "Identify memory-intensive processes. Consider increasing RAM or optimizing applications.",
    });
  }

  if (metrics.disk_used_pct !== undefined && metrics.disk_used_pct > 90) {
    findings.push({
      findingType: "resource_anomaly",
      severity: metrics.disk_used_pct > 95 ? "high" : "medium",
      title: `Low Disk Space (${(100 - metrics.disk_used_pct).toFixed(1)}% free)`,
      description: `Disk usage is at ${metrics.disk_used_pct.toFixed(1)}% on ${hostname}. Low disk space can prevent security updates and cause system instability.`,
      affectedComponent: "Disk",
      recommendation: "Free up disk space. Remove unnecessary files and ensure adequate space for security updates and logs.",
    });
  }

  return findings;
}

export function generateAgentFindings(
  telemetry: TelemetryData,
  existingFindingKeys: Set<string>
): InsertAgentFinding[] {
  const generatedFindings = analyzeTelemetry(telemetry);
  const newFindings: InsertAgentFinding[] = [];

  for (const finding of generatedFindings) {
    const findingKey = `${finding.findingType}|${finding.severity}|${finding.title}|${finding.affectedComponent || ""}`;
    
    if (existingFindingKeys.has(findingKey)) {
      continue;
    }

    existingFindingKeys.add(findingKey);

    newFindings.push({
      agentId: telemetry.agentId,
      organizationId: telemetry.organizationId,
      telemetryId: telemetry.telemetryId,
      findingType: finding.findingType,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      affectedComponent: finding.affectedComponent || null,
      affectedPort: finding.affectedPort || null,
      affectedService: finding.affectedService || null,
      recommendation: finding.recommendation || null,
      detectedAt: new Date(),
    });
  }

  return newFindings;
}
