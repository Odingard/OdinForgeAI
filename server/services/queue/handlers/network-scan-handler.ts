import { Job } from "bullmq";
import { randomUUID } from "crypto";
import { storage } from "../../../storage";
import {
  executeLiveNetworkTest,
  parseTargetFromAsset,
  ScanResult,
  LiveTestProgress,
} from "../../live-network-testing";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  NetworkScanJobData,
  JobResult,
  JobProgress,
} from "../job-types";

function emitSecureScanProgress(
  tenantId: string,
  organizationId: string,
  scanId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  // Log progress to server console
  if (type === "network_scan_started") {
    console.log(`[NetworkScan] ${scanId}: Scanning target ${event.target}`);
  } else if (type === "network_scan_progress") {
    console.log(`[NetworkScan] ${scanId}: ${event.message || `${event.portsScanned}/${event.totalPorts} ports`}`);
  } else if (type === "network_scan_target_completed") {
    console.log(`[NetworkScan] ${scanId}: Target ${event.target} - ${event.openPorts} open ports, ${event.vulnerabilities} vulnerabilities`);
  } else if (type === "network_scan_completed") {
    console.log(`[NetworkScan] ${scanId}: Completed - ${event.successCount} succeeded, ${event.failCount} failed`);
  } else if (type === "network_scan_failed" || type === "network_scan_target_failed") {
    console.log(`[NetworkScan] ${scanId}: Failed - ${event.error}`);
  }
  
  // Send secure WebSocket progress with tenant scoping via ws-bridge
  try {
    const { broadcastToChannel } = require("../../ws-bridge");
    const channel = `network-scan:${tenantId}:${organizationId}:${scanId}`;

    let phase: string | undefined;
    let progress = 0;
    let message = "";
    let portsFound = 0;
    let vulnerabilitiesFound = 0;

    if (type === "network_scan_progress") {
      phase = "ports";
      progress = event.progress || 0;
      message = event.message || "";
      portsFound = event.portsScanned;
      vulnerabilitiesFound = event.vulnerabilities;
    } else if (type === "network_scan_target_completed") {
      phase = "http"; // "vulnerabilities" maps to "http" in wsService.sendNetworkScanProgress
      progress = event.progress || 50;
      message = `Target ${event.target}: ${event.openPorts} ports, ${event.vulnerabilities} vulnerabilities`;
      portsFound = event.openPorts;
      vulnerabilitiesFound = event.vulnerabilities;
    } else if (type === "network_scan_completed") {
      phase = "complete";
      progress = 100;
      message = `Scan complete: ${event.successCount} succeeded, ${event.failCount} failed`;
      portsFound = event.totalOpenPorts;
      vulnerabilitiesFound = event.totalVulnerabilities;
    } else if (type === "network_scan_target_failed") {
      phase = "error";
      progress = event.progress || 0;
      message = `Target ${event.target} failed: ${event.error}`;
    } else if (type === "network_scan_failed") {
      phase = "error";
      message = `Scan failed: ${event.error}`;
    }

    if (phase) {
      broadcastToChannel(channel, {
        type: "recon_progress",
        scanId,
        phase,
        progress,
        message,
        portsFound,
        vulnerabilitiesFound,
      });
    }
  } catch {
    // WebSocket delivery is best-effort; failures are non-fatal
  }
}

interface NetworkScanJob {
  id?: string;
  data: NetworkScanJobData;
  updateProgress: (progress: number | object) => Promise<void>;
}

function parsePorts(portRange?: string): number[] | undefined {
  if (!portRange) return undefined;

  const ports: number[] = [];
  const parts = portRange.split(",");

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes("-")) {
      const [start, end] = trimmed.split("-").map((s) => parseInt(s.trim(), 10));
      if (!isNaN(start) && !isNaN(end) && start <= end && start >= 1 && end <= 65535) {
        for (let p = start; p <= end; p++) {
          if (!ports.includes(p)) ports.push(p);
        }
      }
    } else {
      const port = parseInt(trimmed, 10);
      if (!isNaN(port) && port >= 1 && port <= 65535 && !ports.includes(port)) {
        ports.push(port);
      }
    }
  }

  return ports.length > 0 ? ports.sort((a, b) => a - b) : undefined;
}

export async function handleNetworkScanJob(
  job: Job<NetworkScanJobData> | NetworkScanJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { scanId, targets, portRange, scanType, organizationId, tenantId } = job.data;
  const jobId = job.id || scanId;

  console.log(`[NetworkScan] Starting scan ${scanId} for ${targets.length} target(s)`);

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "network_scan",
    targets[0]
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[NetworkScan] Blocked by governance: ${governanceCheck.reason}`);
    
    emitSecureScanProgress(tenantId, organizationId, scanId, {
      type: "network_scan_failed",
      error: `Operation blocked by governance controls: ${governanceCheck.reason}`,
    });
    
    return {
      success: false,
      error: governanceCheck.reason,
      metadata: {
        blockedByGovernance: true,
        reason: governanceCheck.reason,
      },
    };
  }

  await governanceEnforcement.logOperationStarted(organizationId, "network_scan", targets.join(", "));

  const results: {
    target: string;
    scanResultId: string;
    result?: ScanResult;
    error?: string;
  }[] = [];

  const ports = parsePorts(portRange);
  let totalTargetsScanned = 0;

  try {
    for (const target of targets) {
      const scanRecord = await storage.createLiveScanResult({
        evaluationId: scanId,
        organizationId,
        targetHost: target,
        status: "running",
        scanStarted: new Date(),
      });
      const scanResultId = scanRecord.id;

      emitSecureScanProgress(tenantId, organizationId, scanId, {
        type: "network_scan_started",
        jobId,
        scanResultId,
        target,
        targetIndex: totalTargetsScanned,
        totalTargets: targets.length,
      });

      try {
        const scanTarget = parseTargetFromAsset(target, target) || { host: target };
        if (ports) {
          scanTarget.ports = ports;
        }

        const onProgress = (progress: LiveTestProgress) => {
          const overallProgress =
            (totalTargetsScanned / targets.length) * 100 +
            (progress.progress / targets.length);

          job.updateProgress?.({
            percent: Math.min(99, Math.round(overallProgress)),
            stage: progress.phase,
            message: `[${target}] ${progress.message}`,
            details: {
              currentTarget: target,
              portsScanned: progress.portsScanned,
              totalPorts: progress.totalPorts,
            },
          } as JobProgress);

          emitSecureScanProgress(tenantId, organizationId, scanId, {
            type: "network_scan_progress",
            jobId,
            scanResultId,
            target,
            phase: progress.phase,
            progress: progress.progress,
            message: progress.message,
            portsScanned: progress.portsScanned,
            totalPorts: progress.totalPorts,
          });
        };

        const result = await executeLiveNetworkTest(
          scanId,
          scanTarget,
          organizationId,
          onProgress
        );

        await storage.updateLiveScanResult(scanResultId, {
          resolvedIp: result.ip,
          resolvedHostname: result.hostname,
          ports: result.ports.map((p) => ({
            port: p.port,
            state: p.state,
            service: p.service || "",
            banner: p.banner,
            version: p.version,
          })),
          vulnerabilities: result.vulnerabilities.map((v, idx) => ({
            id: `vuln-${scanResultId}-${idx}`,
            port: v.port,
            service: v.service,
            severity: v.severity,
            title: v.issue,
            description: v.recommendation,
            cveIds: v.cve ? [v.cve] : undefined,
            remediation: v.recommendation,
          })),
          scanCompleted: new Date(),
          status: "completed",
        });

        results.push({ target, scanResultId, result });

        emitSecureScanProgress(tenantId, organizationId, scanId, {
          type: "network_scan_target_completed",
          jobId,
          scanResultId,
          target,
          openPorts: result.ports.length,
          vulnerabilities: result.vulnerabilities.length,
        });
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : "Unknown error";

        await storage.updateLiveScanResult(scanResultId, {
          status: "failed",
          errorMessage,
          scanCompleted: new Date(),
        });

        results.push({ target, scanResultId, error: errorMessage });

        emitSecureScanProgress(tenantId, organizationId, scanId, {
          type: "network_scan_target_failed",
          jobId,
          scanResultId,
          target,
          error: errorMessage,
        });
      }

      totalTargetsScanned++;
    }

    const successCount = results.filter((r) => !r.error).length;
    const failCount = results.filter((r) => r.error).length;
    const totalOpenPorts = results
      .filter((r) => r.result)
      .reduce((sum, r) => sum + (r.result?.ports.length || 0), 0);
    const totalVulnerabilities = results
      .filter((r) => r.result)
      .reduce((sum, r) => sum + (r.result?.vulnerabilities.length || 0), 0);

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: `Scan complete: ${successCount} succeeded, ${failCount} failed`,
    } as JobProgress);

    emitSecureScanProgress(tenantId, organizationId, scanId, {
      type: "network_scan_completed",
      jobId,
      successCount,
      failCount,
      totalOpenPorts,
      totalVulnerabilities,
    });

    console.log(`[NetworkScan] Scan ${scanId} completed: ${successCount}/${targets.length} targets`);

    return {
      success: failCount === 0,
      data: {
        scanId,
        results: results.map((r) => ({
          target: r.target,
          scanResultId: r.scanResultId,
          success: !r.error,
          openPorts: r.result?.ports.length || 0,
          vulnerabilities: r.result?.vulnerabilities.length || 0,
          error: r.error,
        })),
        summary: {
          totalTargets: targets.length,
          successCount,
          failCount,
          totalOpenPorts,
          totalVulnerabilities,
        },
      },
      duration: Date.now() - startTime,
      metrics: {
        targetsScanned: targets.length,
        successCount,
        failCount,
        openPorts: totalOpenPorts,
        vulnerabilities: totalVulnerabilities,
      },
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[NetworkScan] Scan ${scanId} failed:`, errorMessage);

    emitSecureScanProgress(tenantId, organizationId, scanId, {
      type: "network_scan_failed",
      jobId,
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
