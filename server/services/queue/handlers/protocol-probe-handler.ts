import type { Job } from "bullmq";
import { storage } from "../../../storage";
import {
  runProtocolProbes,
  runAllCredentialProbes,
  type ProbeType,
  type ProbeResult,
  type CredentialProbeConfig,
} from "../../validation/probes";
import type { ProtocolProbeJobData } from "../job-types";

export interface ProtocolProbeJobResult {
  success: boolean;
  host: string;
  probeResults: Array<{
    type: string;
    result: ProbeResult;
  }>;
  credentialResults?: Array<{
    service: string;
    result: ProbeResult;
  }>;
  summary: {
    totalProbes: number;
    vulnerableProbes: number;
    highConfidenceFindings: number;
    criticalFindings: string[];
  };
  executionTimeMs: number;
}

export async function handleProtocolProbeJob(
  job: Job<ProtocolProbeJobData>
): Promise<ProtocolProbeJobResult> {
  const startTime = Date.now();
  const {
    targetHost,
    probeTypes,
    credentialServices = [],
    organizationId,
    evaluationId,
    domain,
    timeout = 10000,
  } = job.data;

  console.log(`[ProtocolProbeHandler] Starting protocol probes for ${targetHost}`);
  console.log(`[ProtocolProbeHandler] Probe types: ${probeTypes.join(", ")}`);
  if (credentialServices.length > 0) {
    console.log(`[ProtocolProbeHandler] Credential services: ${credentialServices.join(", ")}`);
  }

  await job.updateProgress(10);

  const probeResultsMap = await runProtocolProbes(targetHost, probeTypes, {
    timeout,
    organizationId,
    evaluationId,
    domain,
  });

  await job.updateProgress(50);

  let credentialResultsMap: Map<string, ProbeResult> | undefined;
  if (credentialServices.length > 0) {
    credentialResultsMap = await runAllCredentialProbes(targetHost, credentialServices, {
      timeout: 5000,
      organizationId,
      evaluationId,
    });
  }

  await job.updateProgress(80);

  const probeResults: Array<{ type: string; result: ProbeResult }> = [];
  for (const entry of Array.from(probeResultsMap.entries())) {
    probeResults.push({ type: entry[0], result: entry[1] });
  }

  const credentialResults: Array<{ service: string; result: ProbeResult }> = [];
  if (credentialResultsMap) {
    for (const entry of Array.from(credentialResultsMap.entries())) {
      credentialResults.push({ service: entry[0], result: entry[1] });
    }
  }

  const allResults = [...probeResults.map(r => r.result), ...credentialResults.map(r => r.result)];
  const vulnerableResults = allResults.filter(r => r.vulnerable);
  const highConfidenceResults = allResults.filter(r => r.confidence >= 80);
  const criticalFindings: string[] = [];

  for (const result of vulnerableResults) {
    if (result.confidence >= 90) {
      criticalFindings.push(`${result.service}: ${result.technique} - ${result.evidence.substring(0, 100)}`);
    }
  }

  if (evaluationId) {
    await storeProbeFindings(evaluationId, organizationId, targetHost, probeResults, credentialResults);
  }

  await job.updateProgress(100);

  const executionTimeMs = Date.now() - startTime;
  console.log(`[ProtocolProbeHandler] Completed in ${executionTimeMs}ms. Found ${vulnerableResults.length} vulnerabilities.`);

  return {
    success: true,
    host: targetHost,
    probeResults,
    credentialResults: credentialResults.length > 0 ? credentialResults : undefined,
    summary: {
      totalProbes: allResults.length,
      vulnerableProbes: vulnerableResults.length,
      highConfidenceFindings: highConfidenceResults.length,
      criticalFindings,
    },
    executionTimeMs,
  };
}

async function storeProbeFindings(
  evaluationId: string,
  _organizationId: string,
  targetHost: string,
  probeResults: Array<{ type: string; result: ProbeResult }>,
  credentialResults: Array<{ service: string; result: ProbeResult }>
): Promise<void> {
  const vulnerableProbes = probeResults.filter(p => p.result.vulnerable);
  const vulnerableCreds = credentialResults.filter(c => c.result.vulnerable);
  
  for (const { type, result } of vulnerableProbes) {
    const score = Math.round(result.confidence * 0.9);
    const resultData = {
      id: `probe-${evaluationId}-${type}-${Date.now()}`,
      evaluationId,
      exploitable: result.vulnerable,
      confidence: result.confidence,
      score,
      impact: getBusinessImpact(type, result),
      recommendations: result.recommendations.map((text, idx) => ({
        id: `rec-${type}-${idx}`,
        title: `${type.toUpperCase()} Remediation`,
        description: text,
        priority: result.confidence >= 90 ? "critical" as const : "high" as const,
        type: "remediation" as const,
      })),
      attackPath: [{
        id: 1,
        title: `Protocol Probe: ${type.toUpperCase()}`,
        description: result.evidence,
        severity: result.confidence >= 90 ? "critical" : "high",
        technique: getMitreTechniques(type)[0] || "T1595",
      }],
    };
    
    try {
      await storage.createResult(resultData);
      console.log(`[ProtocolProbeHandler] Stored finding for ${type}`);
    } catch (error) {
      console.error(`[ProtocolProbeHandler] Error storing finding for ${type}:`, error);
    }
  }

  for (const { service, result } of vulnerableCreds) {
    const score = 95;
    const resultData = {
      id: `cred-${evaluationId}-${service}-${Date.now()}`,
      evaluationId,
      exploitable: true,
      confidence: result.confidence,
      score,
      impact: `Default credentials allow unauthorized access to ${service} service. This provides immediate system access without any exploitation required.`,
      recommendations: result.recommendations.map((text, idx) => ({
        id: `rec-${service}-${idx}`,
        title: `${service.toUpperCase()} Credential Remediation`,
        description: text,
        priority: "critical" as const,
        type: "remediation" as const,
      })),
      attackPath: [{
        id: 1,
        title: `T1078 - Valid Accounts: Default Credentials (${service})`,
        description: `Default credentials found for ${service} service`,
        severity: "critical",
        technique: "T1078",
      }],
    };
    
    try {
      await storage.createResult(resultData);
      console.log(`[ProtocolProbeHandler] Stored credential finding for ${service}`);
    } catch (error) {
      console.error(`[ProtocolProbeHandler] Error storing credential finding for ${service}:`, error);
    }
  }
}

function getBusinessImpact(probeType: string, result: ProbeResult): string {
  switch (probeType) {
    case "smtp":
      if (result.evidence.includes("Open relay")) {
        return "Open SMTP relay can be abused for spam campaigns, phishing attacks, and may result in domain blacklisting. This can damage organizational reputation and email deliverability.";
      }
      return "SMTP misconfiguration may allow user enumeration or unauthorized email sending.";
    
    case "dns":
      if (result.evidence.includes("Zone transfer")) {
        return "DNS zone transfer exposes internal network topology, hostnames, and IP addresses. Attackers can map the entire infrastructure for targeted attacks.";
      }
      if (result.evidence.includes("recursion")) {
        return "Open DNS recursion can be exploited for DNS amplification DDoS attacks, potentially implicating the organization in attacks against third parties.";
      }
      return "DNS misconfiguration may leak sensitive information about network infrastructure.";
    
    case "ldap":
      if (result.evidence.includes("Anonymous") || result.evidence.includes("Null")) {
        return "Anonymous LDAP access exposes directory information including usernames, email addresses, and organizational structure. This enables targeted attacks and user enumeration.";
      }
      return "LDAP misconfiguration may expose sensitive directory information.";
    
    default:
      return "Protocol misconfiguration may expose sensitive information or enable unauthorized access.";
  }
}

function getMitreTechniques(probeType: string): string[] {
  switch (probeType) {
    case "smtp":
      return ["T1566", "T1534", "T1589"];
    case "dns":
      return ["T1596", "T1590", "T1498"];
    case "ldap":
      return ["T1087", "T1069", "T1018"];
    case "credential":
      return ["T1078", "T1110"];
    default:
      return [];
  }
}
