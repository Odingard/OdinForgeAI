/**
 * Scan Data Loader — Bridges real scan results into AI agent context
 *
 * Queries existing DB tables (recon_scans, live_scan_results, auth_scan_results,
 * cloud_assets, exploit_validation_results, agent_telemetry) and returns structured
 * ground-truth data for AI agents to reason over.
 */

import { storage } from "../../storage";
import { db } from "../../db";
import { reconScans, liveScanResults, authScanResults, exploitValidationResults, cloudAssets, agentTelemetry, discoveredAssets } from "@shared/schema";
import { eq, and, desc, sql } from "drizzle-orm";

// ─── Summary types for agent consumption ───────────────────────────

export interface ReconScanSummary {
  target: string;
  openPorts: Array<{ port: number; service?: string; version?: string; banner?: string }>;
  sslSummary: string;
  technologies: string[];
  dnsSummary: string;
  authSurface: string;
  attackReadiness: number;
  securityHeaders: { present: string[]; missing: string[] };
  scanTime?: string;
}

export interface NetworkScanSummary {
  targetHost: string;
  openPorts: Array<{ port: number; service?: string; version?: string; banner?: string }>;
  vulnerabilities: Array<{ title: string; severity: string; cveIds?: string[]; port?: number; description?: string }>;
  misconfigurations: string[];
  scanCompleted?: string;
}

export interface AuthScanSummary {
  targetUrl: string;
  authType: string;
  issues: Array<{ type: string; severity: string; description: string; evidence?: string }>;
  overallScore?: number;
}

export interface CloudAssetSummary {
  provider: string;
  assets: Array<{
    resourceId: string;
    assetType: string;
    assetName: string;
    region?: string;
    publicIps?: string[];
    privateIps?: string[];
    status?: string;
  }>;
}

export interface ExploitValidationSummary {
  results: Array<{
    exploitType: string;
    verdict: string;
    confidence: number;
    exploitable: boolean;
    evidence?: string[];
  }>;
}

export interface AgentTelemetrySummary {
  services: Array<{ name: string; version?: string; port?: number }>;
  openPorts: number[];
  recentFindings: Array<{ type: string; severity: string; title: string }>;
  resourceMetrics?: { cpuPercent?: number; memoryPercent?: number; diskPercent?: number };
}

export interface RealScanData {
  reconData?: ReconScanSummary;
  networkData?: NetworkScanSummary;
  authData?: AuthScanSummary;
  cloudData?: CloudAssetSummary;
  exploitValidation?: ExploitValidationSummary;
  agentTelemetry?: AgentTelemetrySummary;
  dataAvailability: {
    hasRecon: boolean;
    hasNetwork: boolean;
    hasAuth: boolean;
    hasCloud: boolean;
    hasExploitValidation: boolean;
    hasTelemetry: boolean;
    coverageScore: number; // 0-1, how much real data is available
  };
}

// ─── Asset resolution ───────────────────────────────────────────────

async function resolveAssetTarget(assetId: string, organizationId: string): Promise<{
  hostname?: string;
  ip?: string;
  url?: string;
  cloudProvider?: string;
}> {
  try {
    // Try discovered_assets first
    const [asset] = await db
      .select()
      .from(discoveredAssets)
      .where(and(
        eq(discoveredAssets.id, assetId),
        eq(discoveredAssets.organizationId, organizationId)
      ))
      .limit(1);

    if (asset) {
      return {
        hostname: asset.hostname || asset.fqdn || asset.assetIdentifier,
        ip: (asset.ipAddresses as string[])?.[0],
        url: asset.assetIdentifier?.startsWith("http") ? asset.assetIdentifier : undefined,
        cloudProvider: asset.cloudProvider || undefined,
      };
    }

    // Fallback: assetId itself might be a hostname or IP
    return { hostname: assetId };
  } catch {
    return { hostname: assetId };
  }
}

// ─── Individual data loaders ────────────────────────────────────────

async function loadReconData(target: string, organizationId: string): Promise<ReconScanSummary | undefined> {
  try {
    const [scan] = await db
      .select()
      .from(reconScans)
      .where(and(
        eq(reconScans.target, target),
        eq(reconScans.organizationId, organizationId),
        eq(reconScans.status, "completed")
      ))
      .orderBy(desc(reconScans.scanTime))
      .limit(1);

    if (!scan) return undefined;

    const portScan = (scan.portScan as any[]) || [];
    const sslCheck = scan.sslCheck as any;
    const httpFingerprint = scan.httpFingerprint as any;
    const dnsEnum = scan.dnsEnum as any;
    const networkExposure = scan.networkExposure as any;
    const transportSecurity = scan.transportSecurity as any;
    const applicationIdentity = scan.applicationIdentity as any;

    // Build open ports from portScan + networkExposure
    const openPorts = portScan
      .filter((p: any) => p.state === "open")
      .map((p: any) => {
        const serviceInfo = networkExposure?.serviceVersions?.find((s: any) => s.port === p.port);
        return {
          port: p.port,
          service: serviceInfo?.service || p.service,
          version: serviceInfo?.version,
          banner: p.banner,
        };
      });

    // SSL summary
    const sslParts: string[] = [];
    if (sslCheck) {
      sslParts.push(sslCheck.valid ? "Valid certificate" : "Invalid/expired certificate");
      if (sslCheck.issuer) sslParts.push(`Issuer: ${sslCheck.issuer}`);
      if (sslCheck.daysUntilExpiry != null) sslParts.push(`Expires in ${sslCheck.daysUntilExpiry} days`);
      if (sslCheck.vulnerabilities?.length) sslParts.push(`Vulns: ${sslCheck.vulnerabilities.join(", ")}`);
    }
    if (transportSecurity) {
      sslParts.push(`TLS ${transportSecurity.tlsVersion}, Grade: ${transportSecurity.gradeEstimate || "?"}`);
      if (!transportSecurity.hstsEnabled) sslParts.push("HSTS not enabled");
    }

    // Technologies
    const technologies: string[] = [];
    if (httpFingerprint?.technologies) technologies.push(...httpFingerprint.technologies);
    if (httpFingerprint?.server) technologies.push(`Server: ${httpFingerprint.server}`);
    if (httpFingerprint?.poweredBy) technologies.push(`Powered by: ${httpFingerprint.poweredBy}`);
    if (applicationIdentity?.frameworks) technologies.push(...applicationIdentity.frameworks);
    if (applicationIdentity?.cms) technologies.push(`CMS: ${applicationIdentity.cms}`);

    // DNS summary
    const dnsParts: string[] = [];
    if (dnsEnum) {
      if (dnsEnum.ipv4?.length) dnsParts.push(`IPv4: ${dnsEnum.ipv4.join(", ")}`);
      if (dnsEnum.mx?.length) dnsParts.push(`MX: ${dnsEnum.mx.map((m: any) => m.exchange).join(", ")}`);
      if (dnsEnum.ns?.length) dnsParts.push(`NS: ${dnsEnum.ns.join(", ")}`);
      if (dnsEnum.cname?.length) dnsParts.push(`CNAME: ${dnsEnum.cname.join(", ")}`);
    }

    // Auth surface
    const authSurface = httpFingerprint?.securityHeaders
      ? `Security headers present: ${httpFingerprint.securityHeaders.present?.join(", ") || "none"}. Missing: ${httpFingerprint.securityHeaders.missing?.join(", ") || "none"}`
      : "No auth surface data";

    // Attack readiness
    const attackReadiness = networkExposure
      ? Math.min(100, (networkExposure.openPorts || 0) * 5 + (networkExposure.highRiskPorts || 0) * 20)
      : 0;

    return {
      target,
      openPorts,
      sslSummary: sslParts.join(". ") || "No SSL data",
      technologies: Array.from(new Set(technologies)),
      dnsSummary: dnsParts.join(". ") || "No DNS data",
      authSurface,
      attackReadiness,
      securityHeaders: httpFingerprint?.securityHeaders || { present: [], missing: [] },
      scanTime: scan.scanTime?.toISOString(),
    };
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load recon data:", err);
    return undefined;
  }
}

async function loadNetworkData(targetHost: string, organizationId: string): Promise<NetworkScanSummary | undefined> {
  try {
    const [scan] = await db
      .select()
      .from(liveScanResults)
      .where(and(
        eq(liveScanResults.targetHost, targetHost),
        eq(liveScanResults.organizationId, organizationId),
        eq(liveScanResults.status, "completed")
      ))
      .orderBy(desc(liveScanResults.scanCompleted))
      .limit(1);

    if (!scan) return undefined;

    const ports = (scan.ports as any[]) || [];
    const vulns = (scan.vulnerabilities as any[]) || [];

    return {
      targetHost,
      openPorts: ports
        .filter((p: any) => p.state === "open")
        .map((p: any) => ({
          port: p.port,
          service: p.service,
          version: p.version,
          banner: p.banner,
        })),
      vulnerabilities: vulns.map((v: any) => ({
        title: v.title || v.name || "Unknown",
        severity: v.severity || "medium",
        cveIds: v.cveIds || v.cve ? [v.cve] : [],
        port: v.port,
        description: v.description,
      })),
      misconfigurations: vulns
        .filter((v: any) => v.type === "misconfiguration" || v.category === "misconfiguration")
        .map((v: any) => v.title || v.description || "Misconfiguration detected"),
      scanCompleted: scan.scanCompleted?.toISOString(),
    };
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load network data:", err);
    return undefined;
  }
}

async function loadAuthData(target: string, organizationId: string): Promise<AuthScanSummary | undefined> {
  try {
    // Auth scans use targetUrl — try both http and https variants
    const targets = [target, `https://${target}`, `http://${target}`];

    for (const targetUrl of targets) {
      const [scan] = await db
        .select()
        .from(authScanResults)
        .where(and(
          eq(authScanResults.targetUrl, targetUrl),
          eq(authScanResults.organizationId, organizationId),
          eq(authScanResults.status, "completed")
        ))
        .orderBy(desc(authScanResults.scanCompleted))
        .limit(1);

      if (scan) {
        const vulns = (scan.vulnerabilities as any[]) || [];
        return {
          targetUrl: scan.targetUrl,
          authType: scan.authType,
          issues: vulns.map((v: any) => ({
            type: v.type,
            severity: v.severity,
            description: v.description,
            evidence: v.evidence,
          })),
          overallScore: scan.overallScore ?? undefined,
        };
      }
    }

    return undefined;
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load auth data:", err);
    return undefined;
  }
}

async function loadCloudData(organizationId: string, cloudProvider?: string): Promise<CloudAssetSummary | undefined> {
  try {
    const assets = await db
      .select()
      .from(cloudAssets)
      .where(eq(cloudAssets.organizationId, organizationId))
      .limit(50);

    if (!assets.length) return undefined;

    // Determine primary provider
    const providers = Array.from(new Set(assets.map(a => a.provider)));
    const provider = cloudProvider || providers[0] || "unknown";

    return {
      provider,
      assets: assets.map(a => ({
        resourceId: a.providerResourceId,
        assetType: a.assetType,
        assetName: a.assetName,
        region: a.region || undefined,
        publicIps: (a.publicIpAddresses as string[]) || undefined,
        privateIps: (a.privateIpAddresses as string[]) || undefined,
        status: (a as any).status || undefined,
      })),
    };
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load cloud data:", err);
    return undefined;
  }
}

async function loadExploitValidationData(evaluationId: string, organizationId: string): Promise<ExploitValidationSummary | undefined> {
  try {
    const results = await db
      .select()
      .from(exploitValidationResults)
      .where(and(
        eq(exploitValidationResults.evaluationId, evaluationId),
        eq(exploitValidationResults.organizationId, organizationId),
        eq(exploitValidationResults.status, "completed")
      ))
      .limit(50);

    if (!results.length) return undefined;

    return {
      results: results.map(r => ({
        exploitType: r.exploitType,
        verdict: r.verdict || "unknown",
        confidence: r.confidence || 0,
        exploitable: r.exploitable || false,
        evidence: (r.evidence as string[]) || undefined,
      })),
    };
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load exploit validation data:", err);
    return undefined;
  }
}

async function loadAgentTelemetryData(hostname: string, organizationId: string): Promise<AgentTelemetrySummary | undefined> {
  try {
    // Find recent telemetry for any agent matching this hostname
    const results = await db
      .select()
      .from(agentTelemetry)
      .where(eq(agentTelemetry.organizationId, organizationId))
      .orderBy(desc(agentTelemetry.collectedAt))
      .limit(10);

    // Filter by hostname match in systemInfo
    const matching = results.filter(t => {
      const sysInfo = t.systemInfo as any;
      return sysInfo?.hostname === hostname || sysInfo?.hostname?.includes(hostname);
    });

    if (!matching.length) return undefined;

    const latest = matching[0];
    const sysInfo = latest.systemInfo as any;
    const services = (latest.services as any[]) || [];
    const openPorts = (latest.openPorts as any[]) || [];
    const findings = (latest.securityFindings as any[]) || [];

    return {
      services: services.map((s: any) => ({
        name: s.name,
        version: s.version,
        port: s.port,
      })),
      openPorts: openPorts.map((p: any) => typeof p === "number" ? p : p.port),
      recentFindings: findings.map((f: any) => ({
        type: f.type,
        severity: f.severity,
        title: f.title,
      })),
      resourceMetrics: latest.resourceMetrics ? {
        cpuPercent: (latest.resourceMetrics as any).cpuPercent,
        memoryPercent: (latest.resourceMetrics as any).memoryPercent,
        diskPercent: (latest.resourceMetrics as any).diskPercent,
      } : undefined,
    };
  } catch (err) {
    console.warn("[ScanDataLoader] Failed to load agent telemetry:", err);
    return undefined;
  }
}

// ─── Main loader ────────────────────────────────────────────────────

export async function loadScanDataForAsset(
  assetId: string,
  organizationId: string,
  evaluationId?: string
): Promise<RealScanData> {
  const target = await resolveAssetTarget(assetId, organizationId);
  const hostname = target.hostname || assetId;

  // Load all data sources in parallel
  const [reconData, networkData, authData, cloudData, exploitData, telemetryData] = await Promise.allSettled([
    loadReconData(hostname, organizationId),
    loadNetworkData(hostname, organizationId),
    loadAuthData(hostname, organizationId),
    loadCloudData(organizationId, target.cloudProvider),
    evaluationId ? loadExploitValidationData(evaluationId, organizationId) : Promise.resolve(undefined),
    loadAgentTelemetryData(hostname, organizationId),
  ]);

  const recon = reconData.status === "fulfilled" ? reconData.value : undefined;
  const network = networkData.status === "fulfilled" ? networkData.value : undefined;
  const auth = authData.status === "fulfilled" ? authData.value : undefined;
  const cloud = cloudData.status === "fulfilled" ? cloudData.value : undefined;
  const exploit = exploitData.status === "fulfilled" ? exploitData.value : undefined;
  const telemetry = telemetryData.status === "fulfilled" ? telemetryData.value : undefined;

  // Calculate coverage score
  const sources = [recon, network, auth, cloud, exploit, telemetry];
  const available = sources.filter(Boolean).length;
  const coverageScore = available / sources.length;

  return {
    reconData: recon,
    networkData: network,
    authData: auth,
    cloudData: cloud,
    exploitValidation: exploit,
    agentTelemetry: telemetry,
    dataAvailability: {
      hasRecon: !!recon,
      hasNetwork: !!network,
      hasAuth: !!auth,
      hasCloud: !!cloud,
      hasExploitValidation: !!exploit,
      hasTelemetry: !!telemetry,
      coverageScore,
    },
  };
}

// ─── Prompt builders (used by individual agents) ────────────────────

export function buildReconGroundTruth(data: RealScanData): string {
  if (!data.reconData) return "";

  const r = data.reconData;
  const sections: string[] = [
    "=== VERIFIED RECON SCAN DATA (ground truth — prioritize over speculation) ===",
  ];

  if (r.openPorts.length > 0) {
    sections.push(`Open Ports: ${r.openPorts.map(p => `${p.port}/${p.service || "unknown"}${p.version ? ` v${p.version}` : ""}`).join(", ")}`);
  }
  if (r.technologies.length > 0) {
    sections.push(`Technologies Detected: ${r.technologies.join(", ")}`);
  }
  sections.push(`SSL/TLS: ${r.sslSummary}`);
  sections.push(`DNS: ${r.dnsSummary}`);
  sections.push(`Auth Surface: ${r.authSurface}`);
  if (r.securityHeaders) {
    if (r.securityHeaders.missing?.length) {
      sections.push(`Missing Security Headers: ${r.securityHeaders.missing.join(", ")}`);
    }
  }

  return sections.join("\n");
}

export function buildNetworkGroundTruth(data: RealScanData): string {
  const sections: string[] = [];

  if (data.networkData) {
    const n = data.networkData;
    sections.push("=== VERIFIED NETWORK SCAN DATA (ground truth) ===");
    if (n.openPorts.length > 0) {
      sections.push(`Open Ports: ${n.openPorts.map(p => `${p.port} (${p.service || "unknown"}${p.version ? ` v${p.version}` : ""})`).join(", ")}`);
    }
    if (n.vulnerabilities.length > 0) {
      sections.push("Known Vulnerabilities Found:");
      n.vulnerabilities.forEach(v => {
        const cves = v.cveIds?.length ? ` [${v.cveIds.join(", ")}]` : "";
        sections.push(`  - ${v.title} [${v.severity}]${cves}${v.description ? `: ${v.description}` : ""}`);
      });
    }
    if (n.misconfigurations.length > 0) {
      sections.push(`Misconfigurations: ${n.misconfigurations.join("; ")}`);
    }
  }

  if (data.authData) {
    const a = data.authData;
    sections.push("\n=== VERIFIED AUTH SCAN DATA ===");
    sections.push(`Auth Type: ${a.authType}`);
    if (a.issues.length > 0) {
      a.issues.forEach(i => {
        sections.push(`  - [${i.severity}] ${i.type}: ${i.description}`);
      });
    }
    if (a.overallScore != null) {
      sections.push(`Auth Security Score: ${a.overallScore}/100`);
    }
  }

  if (sections.length > 0) {
    sections.push("\nIMPORTANT: Only reference CVEs and vulnerabilities that appear in the verified scan data above. Do not fabricate CVE references.");
  }

  return sections.join("\n");
}

export function buildCloudGroundTruth(data: RealScanData): string {
  if (!data.cloudData) return "";

  const c = data.cloudData;
  const sections: string[] = [
    "=== VERIFIED CLOUD INFRASTRUCTURE (ground truth) ===",
    `Cloud Provider: ${c.provider}`,
    `Total Assets Discovered: ${c.assets.length}`,
  ];

  // Group by type
  const byType: Record<string, typeof c.assets> = {};
  c.assets.forEach(a => {
    if (!byType[a.assetType]) byType[a.assetType] = [];
    byType[a.assetType].push(a);
  });

  Object.entries(byType).forEach(([type, assets]) => {
    sections.push(`\n${type} (${assets.length}):`);
    assets.slice(0, 10).forEach(a => {
      const ips = a.publicIps?.length ? ` [Public: ${a.publicIps.join(", ")}]` : "";
      sections.push(`  - ${a.assetName} (${a.region || "global"})${ips}`);
    });
    if (assets.length > 10) sections.push(`  ... and ${assets.length - 10} more`);
  });

  return sections.join("\n");
}

export function buildTelemetryGroundTruth(data: RealScanData): string {
  if (!data.agentTelemetry) return "";

  const t = data.agentTelemetry;
  const sections: string[] = [
    "=== ENDPOINT AGENT TELEMETRY (ground truth) ===",
  ];

  if (t.services.length > 0) {
    sections.push(`Running Services: ${t.services.map(s => `${s.name}${s.version ? ` v${s.version}` : ""}${s.port ? ` :${s.port}` : ""}`).join(", ")}`);
  }
  if (t.openPorts.length > 0) {
    sections.push(`Open Ports (from agent): ${t.openPorts.join(", ")}`);
  }
  if (t.recentFindings.length > 0) {
    sections.push("Recent Agent Findings:");
    t.recentFindings.forEach(f => {
      sections.push(`  - [${f.severity}] ${f.type}: ${f.title}`);
    });
  }
  if (t.resourceMetrics) {
    sections.push(`System Load: CPU ${t.resourceMetrics.cpuPercent || 0}%, Memory ${t.resourceMetrics.memoryPercent || 0}%, Disk ${t.resourceMetrics.diskPercent || 0}%`);
  }

  return sections.join("\n");
}

export function buildAllGroundTruth(data: RealScanData): string {
  const parts = [
    buildReconGroundTruth(data),
    buildNetworkGroundTruth(data),
    buildCloudGroundTruth(data),
    buildTelemetryGroundTruth(data),
  ].filter(Boolean);

  if (parts.length === 0) {
    return "No prior real scan data available. Base your analysis on the exposure description.";
  }

  return parts.join("\n\n");
}
