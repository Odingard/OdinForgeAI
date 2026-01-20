import { 
  type InsertDiscoveredAsset, 
  type InsertVulnerabilityImport,
  type ScannerType,
  assetTypes,
  vulnSeverities
} from "@shared/schema";

// Security limits to prevent DoS via large input files
const MAX_LINE_LENGTH = 1_000_000;  // Max characters per CSV line
const MAX_IMPORT_RECORDS = 100_000; // Max records to process per import

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

// ============================================================================
// ReDoS-safe XML parsing helpers using indexOf (no regex backtracking)
// ============================================================================

/**
 * Extract content from a single XML tag using indexOf.
 * Returns the content between opening and closing tags, or undefined if not found.
 */
function safeGetTagContent(content: string, tagName: string, startPos: number = 0): { content: string; endPos: number } | undefined {
  const openTagPrefix = `<${tagName}`;
  let pos = startPos;
  
  while (pos < content.length) {
    const openStart = content.indexOf(openTagPrefix, pos);
    if (openStart === -1) return undefined;
    
    // Verify it's a valid tag (next char is > or whitespace)
    const nextChar = content[openStart + openTagPrefix.length];
    if (nextChar !== ">" && nextChar !== " " && nextChar !== "\t" && nextChar !== "\n" && nextChar !== "/") {
      pos = openStart + 1;
      continue;
    }
    
    // Find the end of opening tag
    const openEnd = content.indexOf(">", openStart + openTagPrefix.length);
    if (openEnd === -1) return undefined;
    
    // Find closing tag
    const closeTag = `</${tagName}>`;
    const closeStart = content.indexOf(closeTag, openEnd + 1);
    if (closeStart === -1) return undefined;
    
    return {
      content: content.substring(openEnd + 1, closeStart),
      endPos: closeStart + closeTag.length
    };
  }
  
  return undefined;
}

/**
 * Extract all tag contents with optional attribute capture.
 * Returns array of { content, attrs, endPos } for each match.
 */
function safeExtractAllTags(
  content: string, 
  tagName: string,
  captureAttrs: boolean = false
): Array<{ content: string; attrs?: string; endPos: number }> {
  const results: Array<{ content: string; attrs?: string; endPos: number }> = [];
  const openTagPrefix = `<${tagName}`;
  const closeTag = `</${tagName}>`;
  let pos = 0;
  
  while (pos < content.length) {
    const openStart = content.indexOf(openTagPrefix, pos);
    if (openStart === -1) break;
    
    // Verify valid tag start
    const nextChar = content[openStart + openTagPrefix.length];
    if (nextChar !== ">" && nextChar !== " " && nextChar !== "\t" && nextChar !== "\n" && nextChar !== "/") {
      pos = openStart + 1;
      continue;
    }
    
    // Find end of opening tag
    const openEnd = content.indexOf(">", openStart + openTagPrefix.length);
    if (openEnd === -1) {
      pos = openStart + 1;
      continue;
    }
    
    // Find closing tag
    const closeStart = content.indexOf(closeTag, openEnd + 1);
    if (closeStart === -1) {
      pos = openEnd + 1;
      continue;
    }
    
    const tagContent = content.substring(openEnd + 1, closeStart);
    const attrs = captureAttrs 
      ? content.substring(openStart + openTagPrefix.length, openEnd).trim()
      : undefined;
    
    results.push({ content: tagContent, attrs, endPos: closeStart + closeTag.length });
    pos = closeStart + closeTag.length;
  }
  
  return results;
}

/**
 * Extract tag content with attribute from opening tag (e.g., name="value")
 * Used for tags like <ReportHost name="hostname">
 */
function safeExtractTagsWithNameAttr(
  content: string,
  tagName: string
): Array<{ name: string; content: string; endPos: number }> {
  const results: Array<{ name: string; content: string; endPos: number }> = [];
  const openTagPrefix = `<${tagName}`;
  const closeTag = `</${tagName}>`;
  let pos = 0;
  
  while (pos < content.length) {
    const openStart = content.indexOf(openTagPrefix, pos);
    if (openStart === -1) break;
    
    // Find end of opening tag
    const openEnd = content.indexOf(">", openStart + openTagPrefix.length);
    if (openEnd === -1) {
      pos = openStart + 1;
      continue;
    }
    
    // Extract name attribute
    const attrSection = content.substring(openStart + openTagPrefix.length, openEnd);
    const nameMatch = attrSection.match(/name="([^"]+)"/);
    if (!nameMatch) {
      pos = openEnd + 1;
      continue;
    }
    
    // Find closing tag
    const closeStart = content.indexOf(closeTag, openEnd + 1);
    if (closeStart === -1) {
      pos = openEnd + 1;
      continue;
    }
    
    results.push({
      name: nameMatch[1],
      content: content.substring(openEnd + 1, closeStart),
      endPos: closeStart + closeTag.length
    });
    pos = closeStart + closeTag.length;
  }
  
  return results;
}

/**
 * Safe getTag replacement - extracts content from a tag using indexOf
 */
function safeGetTag(content: string, tagName: string): string | undefined {
  const result = safeGetTagContent(content, tagName);
  return result ? result.content.trim() : undefined;
}

// ============================================================================

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
  
  // Limit iteration to prevent DoS via extremely long lines
  const maxLen = Math.min(line.length, MAX_LINE_LENGTH);
  for (let i = 0; i < maxLen; i++) {
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

  // Limit iteration to prevent DoS via extremely large files
  const maxRecords = Math.min(lines.length, MAX_IMPORT_RECORDS + 1); // +1 for header
  for (let i = 1; i < maxRecords; i++) {
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

  // ReDoS-safe XML parser for Nessus format using indexOf-based extraction
  const reportHosts = safeExtractTagsWithNameAttr(content, "ReportHost");
  
  for (const hostData of reportHosts) {
    const hostName = hostData.name;
    const hostContent = hostData.content;
    
    // Extract host properties using safe extraction
    const hostTags: Record<string, string> = {};
    const hostPropsContents = safeExtractAllTags(hostContent, "HostProperties");
    for (const hostProps of hostPropsContents) {
      // Extract <tag name="...">value</tag> patterns
      const tagMatches = safeExtractTagsWithNameAttr(hostProps.content, "tag");
      for (const tagMatch of tagMatches) {
        hostTags[tagMatch.name] = tagMatch.content;
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

    // Parse ReportItems (vulnerabilities) using safe extraction
    const reportItems = safeExtractAllTags(hostContent, "ReportItem", true);
    for (const item of reportItems) {
      try {
        const attrs = item.attrs || "";
        const itemContent = item.content;

        // Parse attributes (safe - no backtracking risk with [^"]+ pattern)
        const getAttr = (name: string): string | undefined => {
          const match = new RegExp(`${name}="([^"]+)"`).exec(attrs);
          return match ? match[1] : undefined;
        };

        // Parse child tags using safe extraction
        const getTagSafe = (name: string): string | undefined => {
          return safeGetTag(itemContent, name);
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
          const cveRaw = getTagSafe("cve");
          vulnerabilities.push({
            importJobId,
            title: pluginName,
            description: getTagSafe("synopsis") || getTagSafe("description"),
            severity: normalizeSeverity(severity),
            cveId: cveRaw || undefined,
            cvssScore: parseFloat(getTagSafe("cvss3_base_score") || getTagSafe("cvss_base_score") || "0") * 10 || undefined,
            cvssVector: getTagSafe("cvss3_vector") || getTagSafe("cvss_vector") || undefined,
            scannerPluginId: pluginId,
            scannerName: "nessus",
            affectedHost: assetIdentifier,
            affectedPort: port > 0 ? port : undefined,
            affectedService: svcName || undefined,
            solution: getTagSafe("solution") || undefined,
            exploitAvailable: getTagSafe("exploit_available") === "true",
            patchAvailable: getTagSafe("patch_publication_date") ? true : undefined,
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

  // ReDoS-safe Qualys format parser using indexOf-based extraction
  const hostContents = safeExtractAllTags(content, "HOST");
  
  // Helper using module-level safe function
  const getTagLocal = (content: string, name: string): string | undefined => {
    return safeGetTag(content, name);
  };

  // ReDoS-safe, order-preserving tag extraction for VULN/DETECTION
  // Scans content once and returns tags in document order
  const extractTagContentsLocal = (content: string, tagNames: string[]): string[] => {
    const results: string[] = [];
    let pos = 0;
    
    while (pos < content.length) {
      let earliestStart = -1;
      let matchedTagName = "";
      
      // Find earliest occurrence of any tag
      for (const tagName of tagNames) {
        const openTagPrefix = `<${tagName}`;
        let searchPos = pos;
        
        while (searchPos < content.length) {
          const openStart = content.indexOf(openTagPrefix, searchPos);
          if (openStart === -1) break;
          
          const nextChar = content[openStart + openTagPrefix.length];
          if (nextChar === ">" || nextChar === " " || nextChar === "\t" || nextChar === "\n" || nextChar === "/") {
            if (earliestStart === -1 || openStart < earliestStart) {
              earliestStart = openStart;
              matchedTagName = tagName;
            }
            break;
          }
          searchPos = openStart + 1;
        }
      }
      
      if (earliestStart === -1 || !matchedTagName) break;
      
      const openTagPrefix = `<${matchedTagName}`;
      const closeTag = `</${matchedTagName}>`;
      
      const openEnd = content.indexOf(">", earliestStart + openTagPrefix.length);
      if (openEnd === -1) {
        pos = earliestStart + 1;
        continue;
      }
      
      const closeStart = content.indexOf(closeTag, openEnd + 1);
      if (closeStart === -1) {
        pos = openEnd + 1;
        continue;
      }
      
      results.push(content.substring(openEnd + 1, closeStart));
      pos = closeStart + closeTag.length;
    }
    
    return results;
  };

  for (const hostData of hostContents) {
    const hostContent = hostData.content;
    
    const ip = getTagLocal(hostContent, "IP");
    const dns = getTagLocal(hostContent, "DNS");
    const netbios = getTagLocal(hostContent, "NETBIOS");
    const os = getTagLocal(hostContent, "OPERATING_SYSTEM");
    
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
    // Using programmatic extraction to avoid ReDoS vulnerability (CWE-1333, CWE-400, CWE-730)
    const vulnContents = extractTagContentsLocal(hostContent, ["VULN", "DETECTION"]);
    for (const vulnContent of vulnContents) {
      try {
        
        const qid = getTagLocal(vulnContent, "QID");
        const title = getTagLocal(vulnContent, "TITLE") || getTagLocal(vulnContent, "VULN_TITLE");
        const severity = getTagLocal(vulnContent, "SEVERITY");
        const port = parseInt(getTagLocal(vulnContent, "PORT") || "0");
        const protocol = getTagLocal(vulnContent, "PROTOCOL");
        const cveList = getTagLocal(vulnContent, "CVE_LIST") || getTagLocal(vulnContent, "CVE_ID");

        if (title || qid) {
          vulnerabilities.push({
            importJobId,
            title: title || `Qualys QID ${qid}`,
            description: getTagLocal(vulnContent, "DIAGNOSIS") || getTagLocal(vulnContent, "CONSEQUENCE"),
            severity: normalizeSeverity(severity || "3"),
            cveId: cveList?.split(",")[0]?.trim() || undefined,
            scannerPluginId: qid,
            scannerName: "qualys",
            affectedHost: assetIdentifier,
            affectedPort: port > 0 ? port : undefined,
            solution: getTagLocal(vulnContent, "SOLUTION"),
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
