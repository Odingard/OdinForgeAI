import { 
  type InsertDiscoveredAsset, 
  type InsertVulnerabilityImport,
  type ScannerType,
  assetTypes,
  vulnSeverities
} from "@shared/schema";

// Result of parsing an import file
export interface ParseResult {
  assets: InsertDiscoveredAsset[];
  vulnerabilities: InsertVulnerabilityImport[];
  errors: Array<{ line?: number; record?: string; error: string }>;
  totalRecords: number;
  successfulRecords: number;
  failedRecords: number;
}

// CSV column mapping configuration
export interface CsvColumnMapping {
  ip?: string;
  hostname?: string;
  fqdn?: string;
  assetType?: string;
  operatingSystem?: string;
  port?: string;
  service?: string;
  cveId?: string;
  vulnTitle?: string;
  vulnDescription?: string;
  severity?: string;
  cvssScore?: string;
  solution?: string;
}

// Default CSV column mappings for different scanners
const defaultMappings: Record<string, CsvColumnMapping> = {
  nessus_csv: {
    ip: "Host",
    hostname: "Hostname",
    port: "Port",
    cveId: "CVE",
    vulnTitle: "Name",
    vulnDescription: "Synopsis",
    severity: "Risk",
    cvssScore: "CVSS v3.0 Base Score",
    solution: "Solution",
  },
  qualys_csv: {
    ip: "IP",
    hostname: "DNS",
    fqdn: "FQDN",
    port: "Port",
    cveId: "CVE ID",
    vulnTitle: "Title",
    vulnDescription: "Threat",
    severity: "Severity",
    cvssScore: "CVSS Base",
    solution: "Solution",
  },
  generic: {
    ip: "ip",
    hostname: "hostname",
    fqdn: "fqdn",
    assetType: "asset_type",
    operatingSystem: "os",
    port: "port",
    service: "service",
    cveId: "cve_id",
    vulnTitle: "vulnerability",
    vulnDescription: "description",
    severity: "severity",
    cvssScore: "cvss",
    solution: "solution",
  }
};

// Normalize severity from different formats
function normalizeSeverity(value: string): typeof vulnSeverities[number] {
  const lower = value?.toLowerCase()?.trim() || "";
  
  // Nessus risk levels
  if (lower === "critical" || lower === "4") return "critical";
  if (lower === "high" || lower === "3") return "high";
  if (lower === "medium" || lower === "2") return "medium";
  if (lower === "low" || lower === "1") return "low";
  if (lower === "info" || lower === "informational" || lower === "none" || lower === "0") return "informational";
  
  // Qualys severity levels (1-5)
  if (lower === "5") return "critical";
  if (lower === "4") return "high";
  if (lower === "3") return "medium";
  if (lower === "2") return "low";
  if (lower === "1") return "informational";
  
  return "medium"; // Default
}

// Detect asset type from hostname/service
function detectAssetType(hostname?: string, service?: string, port?: number): typeof assetTypes[number] {
  const h = hostname?.toLowerCase() || "";
  const s = service?.toLowerCase() || "";
  
  if (h.includes("db") || s.includes("mysql") || s.includes("postgres") || s.includes("oracle") || port === 3306 || port === 5432) {
    return "database";
  }
  if (h.includes("web") || s.includes("http") || s.includes("nginx") || s.includes("apache") || port === 80 || port === 443) {
    return "web_application";
  }
  if (h.includes("k8s") || h.includes("kube") || h.includes("container") || s.includes("docker")) {
    return "kubernetes_cluster";
  }
  if (h.includes("lambda") || h.includes("function")) {
    return "lambda_function";
  }
  if (h.includes("lb") || h.includes("loadbalancer") || h.includes("elb") || h.includes("alb")) {
    return "load_balancer";
  }
  if (h.includes("firewall") || h.includes("fw-") || s.includes("firewall")) {
    return "firewall";
  }
  if (h.includes("switch") || h.includes("router") || h.includes("netdev")) {
    return "network_device";
  }
  if (h.includes("desktop") || h.includes("workstation") || h.includes("laptop")) {
    return "workstation";
  }
  if (h.includes("s3") || h.includes("bucket") || h.includes("storage") || h.includes("blob")) {
    return "storage_bucket";
  }
  if (h.includes("ec2") || h.includes("vm-") || h.includes("instance")) {
    return "cloud_instance";
  }
  
  return "server"; // Default
}

// Parse simple CSV (no quotes handling for now, can be enhanced)
function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  
  result.push(current.trim());
  return result;
}

// Main CSV parser
export function parseCsv(
  content: string, 
  importJobId: string,
  scannerType: ScannerType = "custom_csv",
  customMapping?: CsvColumnMapping
): ParseResult {
  const lines = content.split(/\r?\n/).filter(line => line.trim());
  
  if (lines.length < 2) {
    return {
      assets: [],
      vulnerabilities: [],
      errors: [{ error: "CSV file is empty or has no data rows" }],
      totalRecords: 0,
      successfulRecords: 0,
      failedRecords: 0,
    };
  }

  const headers = parseCsvLine(lines[0]);
  const mapping = customMapping || defaultMappings[scannerType] || defaultMappings.generic;
  
  // Find column indexes
  const getIndex = (field: keyof CsvColumnMapping): number => {
    const columnName = mapping[field];
    if (!columnName) return -1;
    return headers.findIndex(h => h.toLowerCase() === columnName.toLowerCase());
  };

  const ipIdx = getIndex("ip");
  const hostnameIdx = getIndex("hostname");
  const fqdnIdx = getIndex("fqdn");
  const assetTypeIdx = getIndex("assetType");
  const osIdx = getIndex("operatingSystem");
  const portIdx = getIndex("port");
  const serviceIdx = getIndex("service");
  const cveIdx = getIndex("cveId");
  const vulnTitleIdx = getIndex("vulnTitle");
  const vulnDescIdx = getIndex("vulnDescription");
  const severityIdx = getIndex("severity");
  const cvssIdx = getIndex("cvssScore");
  const solutionIdx = getIndex("solution");

  const assetsMap = new Map<string, InsertDiscoveredAsset>();
  const vulnerabilities: InsertVulnerabilityImport[] = [];
  const errors: Array<{ line?: number; record?: string; error: string }> = [];
  let successfulRecords = 0;
  let failedRecords = 0;

  for (let i = 1; i < lines.length; i++) {
    try {
      const values = parseCsvLine(lines[i]);
      
      const ip = ipIdx >= 0 ? values[ipIdx] : undefined;
      const hostname = hostnameIdx >= 0 ? values[hostnameIdx] : undefined;
      const fqdn = fqdnIdx >= 0 ? values[fqdnIdx] : undefined;
      const port = portIdx >= 0 ? parseInt(values[portIdx]) || undefined : undefined;
      const service = serviceIdx >= 0 ? values[serviceIdx] : undefined;
      const cveId = cveIdx >= 0 ? values[cveIdx] : undefined;
      const vulnTitle = vulnTitleIdx >= 0 ? values[vulnTitleIdx] : undefined;
      const vulnDesc = vulnDescIdx >= 0 ? values[vulnDescIdx] : undefined;
      const severity = severityIdx >= 0 ? values[severityIdx] : undefined;
      const cvssScore = cvssIdx >= 0 ? parseFloat(values[cvssIdx]) : undefined;
      const solution = solutionIdx >= 0 ? values[solutionIdx] : undefined;
      const os = osIdx >= 0 ? values[osIdx] : undefined;
      const assetTypeRaw = assetTypeIdx >= 0 ? values[assetTypeIdx] : undefined;

      // Determine asset identifier
      const assetIdentifier = ip || hostname || fqdn;
      if (!assetIdentifier) {
        errors.push({ line: i + 1, error: "No IP, hostname, or FQDN found" });
        failedRecords++;
        continue;
      }

      // Create or update asset
      if (!assetsMap.has(assetIdentifier)) {
        const assetType = assetTypeRaw && assetTypes.includes(assetTypeRaw as any) 
          ? (assetTypeRaw as typeof assetTypes[number])
          : detectAssetType(hostname, service, port);

        assetsMap.set(assetIdentifier, {
          assetIdentifier,
          displayName: hostname || fqdn || ip,
          assetType,
          ipAddresses: ip ? [ip] : [],
          hostname: hostname || undefined,
          fqdn: fqdn || undefined,
          operatingSystem: os || undefined,
          openPorts: port ? [{ port, protocol: "tcp", service }] : [],
          importJobId,
          discoverySource: scannerType,
        });
      } else if (port) {
        // Add port to existing asset
        const existing = assetsMap.get(assetIdentifier)!;
        const existingPorts = (existing.openPorts || []) as Array<{port: number; protocol: string; service?: string; version?: string}>;
        if (!existingPorts.some(p => p.port === port)) {
          existingPorts.push({ port, protocol: "tcp", service });
          existing.openPorts = existingPorts;
        }
      }

      // Create vulnerability if we have vulnerability data
      if (vulnTitle || cveId) {
        vulnerabilities.push({
          importJobId,
          title: vulnTitle || cveId || "Unknown Vulnerability",
          description: vulnDesc || undefined,
          severity: normalizeSeverity(severity || "medium"),
          cveId: cveId || undefined,
          cvssScore: cvssScore ? Math.round(cvssScore * 10) : undefined,
          scannerName: scannerType,
          affectedHost: assetIdentifier,
          affectedPort: port || undefined,
          affectedService: service || undefined,
          solution: solution || undefined,
          rawData: { line: i + 1, values },
        });
      }

      successfulRecords++;
    } catch (err) {
      errors.push({ line: i + 1, error: String(err) });
      failedRecords++;
    }
  }

  return {
    assets: Array.from(assetsMap.values()),
    vulnerabilities,
    errors,
    totalRecords: lines.length - 1,
    successfulRecords,
    failedRecords,
  };
}

// Parse JSON format (array of vulnerability objects)
export function parseJson(
  content: string,
  importJobId: string,
  scannerType: ScannerType = "custom_json"
): ParseResult {
  const assetsMap = new Map<string, InsertDiscoveredAsset>();
  const vulnerabilities: InsertVulnerabilityImport[] = [];
  const errors: Array<{ line?: number; record?: string; error: string }> = [];
  let successfulRecords = 0;
  let failedRecords = 0;

  let data: any[];
  try {
    const parsed = JSON.parse(content);
    data = Array.isArray(parsed) ? parsed : parsed.vulnerabilities || parsed.findings || parsed.data || [parsed];
  } catch (err) {
    return {
      assets: [],
      vulnerabilities: [],
      errors: [{ error: `Invalid JSON: ${err}` }],
      totalRecords: 0,
      successfulRecords: 0,
      failedRecords: 0,
    };
  }

  for (let i = 0; i < data.length; i++) {
    try {
      const item = data[i];
      
      const assetIdentifier = item.ip || item.host || item.hostname || item.target || item.asset_id;
      if (!assetIdentifier) {
        errors.push({ record: JSON.stringify(item).slice(0, 100), error: "No asset identifier found" });
        failedRecords++;
        continue;
      }

      // Create asset
      if (!assetsMap.has(assetIdentifier)) {
        const port = parseInt(item.port) || undefined;
        assetsMap.set(assetIdentifier, {
          assetIdentifier,
          displayName: item.hostname || item.name || assetIdentifier,
          assetType: item.asset_type || detectAssetType(item.hostname, item.service, port),
          ipAddresses: item.ip ? [item.ip] : [],
          hostname: item.hostname || undefined,
          fqdn: item.fqdn || undefined,
          operatingSystem: item.os || item.operating_system || undefined,
          openPorts: port ? [{ port, protocol: "tcp", service: item.service }] : [],
          importJobId,
          discoverySource: scannerType,
        });
      }

      // Create vulnerability
      const vulnTitle = item.title || item.name || item.vulnerability || item.finding;
      if (vulnTitle || item.cve || item.cve_id) {
        vulnerabilities.push({
          importJobId,
          title: vulnTitle || item.cve || item.cve_id || "Unknown Vulnerability",
          description: item.description || item.synopsis || item.summary || undefined,
          severity: normalizeSeverity(item.severity || item.risk || item.criticality || "medium"),
          cveId: item.cve || item.cve_id || item.cveId || undefined,
          cvssScore: item.cvss ? Math.round(parseFloat(item.cvss) * 10) : undefined,
          cvssVector: item.cvss_vector || item.cvssVector || undefined,
          scannerName: scannerType,
          scannerPluginId: item.plugin_id || item.pluginId || item.id || undefined,
          affectedHost: assetIdentifier,
          affectedPort: parseInt(item.port) || undefined,
          affectedService: item.service || undefined,
          affectedSoftware: item.software || item.product || undefined,
          affectedVersion: item.version || undefined,
          solution: item.solution || item.remediation || item.fix || undefined,
          exploitAvailable: item.exploit_available || item.exploitAvailable || false,
          patchAvailable: item.patch_available || item.patchAvailable || undefined,
          rawData: item,
        });
      }

      successfulRecords++;
    } catch (err) {
      errors.push({ record: JSON.stringify(data[i]).slice(0, 100), error: String(err) });
      failedRecords++;
    }
  }

  return {
    assets: Array.from(assetsMap.values()),
    vulnerabilities,
    errors,
    totalRecords: data.length,
    successfulRecords,
    failedRecords,
  };
}

// Parse Nessus XML format (.nessus)
export function parseNessusXml(
  content: string,
  importJobId: string
): ParseResult {
  const assetsMap = new Map<string, InsertDiscoveredAsset>();
  const vulnerabilities: InsertVulnerabilityImport[] = [];
  const errors: Array<{ line?: number; record?: string; error: string }> = [];
  let successfulRecords = 0;
  let failedRecords = 0;

  // Simple XML parser for Nessus format
  const hostRegex = /<ReportHost name="([^"]+)"[^>]*>([\s\S]*?)<\/ReportHost>/g;
  const itemRegex = /<ReportItem[^>]*>([\s\S]*?)<\/ReportItem>/g;
  const tagRegex = /<(\w+)[^>]*>([^<]*)<\/\1>/g;
  const attrRegex = /<ReportItem([^>]*)>/;

  let hostMatch;
  while ((hostMatch = hostRegex.exec(content)) !== null) {
    const hostName = hostMatch[1];
    const hostContent = hostMatch[2];
    
    // Extract host properties
    const hostTags: Record<string, string> = {};
    const hostPropsRegex = /<HostProperties>([\s\S]*?)<\/HostProperties>/g;
    let hostPropsMatch;
    while ((hostPropsMatch = hostPropsRegex.exec(hostContent)) !== null) {
      const tagRegexLocal = /<tag name="([^"]+)">([^<]*)<\/tag>/g;
      let tagMatch;
      while ((tagMatch = tagRegexLocal.exec(hostPropsMatch[1])) !== null) {
        hostTags[tagMatch[1]] = tagMatch[2];
      }
    }

    const assetIdentifier = hostTags["host-ip"] || hostName;
    
    // Create asset
    if (!assetsMap.has(assetIdentifier)) {
      assetsMap.set(assetIdentifier, {
        assetIdentifier,
        displayName: hostTags["host-fqdn"] || hostTags["netbios-name"] || hostName,
        assetType: detectAssetType(hostTags["host-fqdn"] || hostName, undefined, undefined),
        ipAddresses: hostTags["host-ip"] ? [hostTags["host-ip"]] : [],
        hostname: hostTags["netbios-name"] || undefined,
        fqdn: hostTags["host-fqdn"] || undefined,
        operatingSystem: hostTags["operating-system"] || undefined,
        macAddress: hostTags["mac-address"] || undefined,
        openPorts: [],
        importJobId,
        discoverySource: "nessus",
      });
    }

    // Parse ReportItems (vulnerabilities)
    let itemMatch;
    const itemRegexLocal = /<ReportItem([^>]*)>([\s\S]*?)<\/ReportItem>/g;
    while ((itemMatch = itemRegexLocal.exec(hostContent)) !== null) {
      try {
        const attrs = itemMatch[1];
        const itemContent = itemMatch[2];

        // Parse attributes
        const getAttr = (name: string): string | undefined => {
          const match = new RegExp(`${name}="([^"]+)"`).exec(attrs);
          return match ? match[1] : undefined;
        };

        // Parse child tags
        const getTag = (name: string): string | undefined => {
          const match = new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`).exec(itemContent);
          return match ? match[1].trim() : undefined;
        };

        const port = parseInt(getAttr("port") || "0");
        const protocol = getAttr("protocol") || "tcp";
        const svcName = getAttr("svc_name");
        const pluginId = getAttr("pluginID");
        const pluginName = getAttr("pluginName");
        const severity = getAttr("severity") || "0";

        // Skip informational items if desired (severity 0)
        const severityNum = parseInt(severity);

        // Add port to asset
        const asset = assetsMap.get(assetIdentifier);
        if (asset && port > 0) {
          const existingPorts = (asset.openPorts || []) as Array<{port: number; protocol: string; service?: string; version?: string}>;
          if (!existingPorts.some(p => p.port === port && p.protocol === protocol)) {
            existingPorts.push({ port, protocol, service: svcName });
            asset.openPorts = existingPorts;
          }
        }

        // Create vulnerability
        if (pluginName && severityNum > 0) {
          const cveRaw = getTag("cve");
          vulnerabilities.push({
            importJobId,
            title: pluginName,
            description: getTag("synopsis") || getTag("description"),
            severity: normalizeSeverity(severity),
            cveId: cveRaw || undefined,
            cvssScore: parseFloat(getTag("cvss3_base_score") || getTag("cvss_base_score") || "0") * 10 || undefined,
            cvssVector: getTag("cvss3_vector") || getTag("cvss_vector") || undefined,
            scannerPluginId: pluginId,
            scannerName: "nessus",
            affectedHost: assetIdentifier,
            affectedPort: port > 0 ? port : undefined,
            affectedService: svcName || undefined,
            solution: getTag("solution") || undefined,
            exploitAvailable: getTag("exploit_available") === "true",
            patchAvailable: getTag("patch_publication_date") ? true : undefined,
            rawData: { pluginId, pluginName, host: hostName },
          });
        }

        successfulRecords++;
      } catch (err) {
        errors.push({ record: hostName, error: String(err) });
        failedRecords++;
      }
    }
  }

  return {
    assets: Array.from(assetsMap.values()),
    vulnerabilities,
    errors,
    totalRecords: successfulRecords + failedRecords,
    successfulRecords,
    failedRecords,
  };
}

// Parse Qualys XML format
export function parseQualysXml(
  content: string,
  importJobId: string
): ParseResult {
  const assetsMap = new Map<string, InsertDiscoveredAsset>();
  const vulnerabilities: InsertVulnerabilityImport[] = [];
  const errors: Array<{ line?: number; record?: string; error: string }> = [];
  let successfulRecords = 0;
  let failedRecords = 0;

  // Qualys format parser (simplified)
  const hostRegex = /<HOST>([\s\S]*?)<\/HOST>/g;
  
  const getTag = (content: string, name: string): string | undefined => {
    const match = new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`).exec(content);
    return match ? match[1].trim() : undefined;
  };

  let hostMatch;
  while ((hostMatch = hostRegex.exec(content)) !== null) {
    const hostContent = hostMatch[1];
    
    const ip = getTag(hostContent, "IP");
    const dns = getTag(hostContent, "DNS");
    const netbios = getTag(hostContent, "NETBIOS");
    const os = getTag(hostContent, "OPERATING_SYSTEM");
    
    const assetIdentifier = ip || dns || netbios;
    if (!assetIdentifier) continue;

    // Create asset
    if (!assetsMap.has(assetIdentifier)) {
      assetsMap.set(assetIdentifier, {
        assetIdentifier,
        displayName: dns || netbios || ip,
        assetType: detectAssetType(dns, undefined, undefined),
        ipAddresses: ip ? [ip] : [],
        hostname: netbios || undefined,
        fqdn: dns || undefined,
        operatingSystem: os || undefined,
        openPorts: [],
        importJobId,
        discoverySource: "qualys",
      });
    }

    // Parse vulnerabilities (VULN or DETECTION tags)
    const vulnRegex = /<(?:VULN|DETECTION)[^>]*>([\s\S]*?)<\/(?:VULN|DETECTION)>/g;
    let vulnMatch;
    while ((vulnMatch = vulnRegex.exec(hostContent)) !== null) {
      try {
        const vulnContent = vulnMatch[1];
        
        const qid = getTag(vulnContent, "QID");
        const title = getTag(vulnContent, "TITLE") || getTag(vulnContent, "VULN_TITLE");
        const severity = getTag(vulnContent, "SEVERITY");
        const port = parseInt(getTag(vulnContent, "PORT") || "0");
        const protocol = getTag(vulnContent, "PROTOCOL");
        const cveList = getTag(vulnContent, "CVE_LIST") || getTag(vulnContent, "CVE_ID");

        if (title || qid) {
          vulnerabilities.push({
            importJobId,
            title: title || `Qualys QID ${qid}`,
            description: getTag(vulnContent, "DIAGNOSIS") || getTag(vulnContent, "CONSEQUENCE"),
            severity: normalizeSeverity(severity || "3"),
            cveId: cveList?.split(",")[0]?.trim() || undefined,
            scannerPluginId: qid,
            scannerName: "qualys",
            affectedHost: assetIdentifier,
            affectedPort: port > 0 ? port : undefined,
            solution: getTag(vulnContent, "SOLUTION"),
            rawData: { qid, host: assetIdentifier },
          });
        }

        successfulRecords++;
      } catch (err) {
        errors.push({ record: assetIdentifier, error: String(err) });
        failedRecords++;
      }
    }
  }

  return {
    assets: Array.from(assetsMap.values()),
    vulnerabilities,
    errors,
    totalRecords: successfulRecords + failedRecords,
    successfulRecords,
    failedRecords,
  };
}

// Auto-detect format and parse
export function autoParseFile(
  content: string,
  importJobId: string,
  fileName?: string,
  mimeType?: string
): { result: ParseResult; detectedFormat: ScannerType } {
  const lower = content.trim().toLowerCase();
  const fileExt = fileName?.split(".").pop()?.toLowerCase();

  // Check for Nessus XML
  if (lower.includes("<nessusclientdata") || lower.includes("<reporthost") || fileExt === "nessus") {
    return { result: parseNessusXml(content, importJobId), detectedFormat: "nessus" };
  }

  // Check for Qualys XML
  if (lower.includes("<qualys") || lower.includes("<host_list_output") || (lower.includes("<host>") && lower.includes("<qid>"))) {
    return { result: parseQualysXml(content, importJobId), detectedFormat: "qualys" };
  }

  // Check for JSON
  if (lower.startsWith("{") || lower.startsWith("[")) {
    return { result: parseJson(content, importJobId), detectedFormat: "custom_json" };
  }

  // Default to CSV
  return { result: parseCsv(content, importJobId), detectedFormat: "custom_csv" };
}
