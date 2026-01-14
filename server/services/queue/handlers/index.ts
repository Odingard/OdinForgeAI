import { queueService, JobHandler } from "../queue-service";
import { handleNetworkScanJob } from "./network-scan-handler";

export function registerJobHandlers(): void {
  console.log("[Queue] Registering job handlers...");
  
  queueService.registerHandler("network_scan", handleNetworkScanJob as JobHandler);
  
  console.log("[Queue] Job handlers registered: network_scan");
}

export { handleNetworkScanJob };
