import { randomUUID } from "crypto";

export interface NucleiScanResult {
  id: string;
  target: string;
  templatesUsed: string[];
  scanStartTime: Date;
  scanEndTime: Date;
  findings: NucleiFinding[];
  statistics: ScanStatistics;
  recommendations: string[];
}

export interface NucleiFinding {
  id: string;
  templateId: string;
  templateName: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  type: string;
  matchedAt: string;
  extractedData?: string[];
  curlCommand?: string;
  description: string;
  remediation: string;
  cveIds?: string[];
  cweIds?: string[];
  cvssScore?: number;
  mitreId?: string;
  tags: string[];
  reference: string[];
}

export interface ScanStatistics {
  totalTemplates: number;
  templatesMatched: number;
  totalRequests: number;
  duration: number;
  findingsBySeverity: Record<string, number>;
}

export interface NucleiTemplate {
  id: string;
  name: string;
  author: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  tags: string[];
  type: "http" | "network" | "dns" | "file" | "headless";
  cveIds?: string[];
  cweIds?: string[];
}

export interface NucleiScanRequest {
  target: string;
  templates?: string[];
  tags?: string[];
  severity?: string[];
  excludeTags?: string[];
  rateLimit?: number;
  concurrency?: number;
  timeout?: number;
}

const NUCLEI_TEMPLATES: NucleiTemplate[] = [
  {
    id: "cve-2021-44228-log4j-rce",
    name: "Apache Log4j RCE (Log4Shell)",
    author: "pdteam",
    severity: "critical",
    description: "Apache Log4j2 <= 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    tags: ["cve", "cve2021", "rce", "log4j", "apache", "jndi"],
    type: "http",
    cveIds: ["CVE-2021-44228"],
    cweIds: ["CWE-502"],
  },
  {
    id: "cve-2023-22515-atlassian-confluence-unauth-rce",
    name: "Atlassian Confluence Broken Access Control",
    author: "pdteam",
    severity: "critical",
    description: "Atlassian Confluence Data Center and Server versions suffer from a broken access control vulnerability that allows an attacker to create unauthorized administrator accounts.",
    tags: ["cve", "cve2023", "confluence", "atlassian", "rce"],
    type: "http",
    cveIds: ["CVE-2023-22515"],
    cweIds: ["CWE-284"],
  },
  {
    id: "cve-2024-1708-screenconnect-auth-bypass",
    name: "ScreenConnect Authentication Bypass",
    author: "pdteam",
    severity: "critical",
    description: "ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel vulnerability.",
    tags: ["cve", "cve2024", "screenconnect", "auth-bypass"],
    type: "http",
    cveIds: ["CVE-2024-1708", "CVE-2024-1709"],
    cweIds: ["CWE-288"],
  },
  {
    id: "exposed-git-directory",
    name: "Git Config Exposure",
    author: "pdteam",
    severity: "high",
    description: "Git repository configuration file is publicly accessible, which may expose sensitive information.",
    tags: ["exposure", "git", "config"],
    type: "http",
  },
  {
    id: "exposed-env-file",
    name: "Environment File Disclosure",
    author: "pdteam",
    severity: "high",
    description: ".env file is publicly accessible and may contain sensitive credentials.",
    tags: ["exposure", "env", "config", "secrets"],
    type: "http",
  },
  {
    id: "springboot-actuator-env",
    name: "Spring Boot Actuator Environment Exposure",
    author: "pdteam",
    severity: "high",
    description: "Spring Boot Actuator environment endpoint is accessible without authentication.",
    tags: ["exposure", "springboot", "actuator", "misconfig"],
    type: "http",
    cweIds: ["CWE-200"],
  },
  {
    id: "apache-struts-devmode",
    name: "Apache Struts DevMode Enabled",
    author: "pdteam",
    severity: "medium",
    description: "Apache Struts DevMode is enabled which may expose sensitive information.",
    tags: ["apache", "struts", "misconfig", "devmode"],
    type: "http",
  },
  {
    id: "wordpress-xmlrpc-listmethods",
    name: "WordPress XML-RPC Methods Exposed",
    author: "pdteam",
    severity: "medium",
    description: "WordPress XML-RPC interface is exposed and lists available methods.",
    tags: ["wordpress", "xmlrpc", "exposure"],
    type: "http",
  },
  {
    id: "http-missing-security-headers",
    name: "Missing Security Headers",
    author: "pdteam",
    severity: "info",
    description: "The application is missing important security headers.",
    tags: ["headers", "security", "misconfig"],
    type: "http",
  },
  {
    id: "ssl-dns-names",
    name: "SSL/TLS Certificate Information",
    author: "pdteam",
    severity: "info",
    description: "Extracts DNS names from SSL/TLS certificates.",
    tags: ["ssl", "tls", "certificate"],
    type: "network",
  },
];

const FINDING_TEMPLATES: Record<string, Partial<NucleiFinding>> = {
  "cve-2021-44228-log4j-rce": {
    type: "http",
    description: "Remote code execution vulnerability in Apache Log4j2 via JNDI lookup",
    remediation: "Upgrade Log4j to version 2.17.0 or later. Apply mitigations: set log4j2.formatMsgNoLookups=true",
    cvssScore: 10.0,
    mitreId: "T1190",
    reference: [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://logging.apache.org/log4j/2.x/security.html",
    ],
  },
  "cve-2023-22515-atlassian-confluence-unauth-rce": {
    type: "http",
    description: "Broken access control allows unauthenticated admin account creation",
    remediation: "Upgrade Confluence to a patched version. Block access to /setup/* endpoints",
    cvssScore: 9.8,
    mitreId: "T1190",
    reference: [
      "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
      "https://confluence.atlassian.com/security/cve-2023-22515-1190561938.html",
    ],
  },
  "exposed-git-directory": {
    type: "http",
    description: "Git directory is exposed allowing source code disclosure",
    remediation: "Block access to .git directory in web server configuration",
    mitreId: "T1213",
    reference: ["https://owasp.org/www-community/attacks/Forced_browsing"],
  },
  "exposed-env-file": {
    type: "http",
    description: ".env file is accessible containing sensitive credentials",
    remediation: "Remove .env from web-accessible directories, configure web server to block access",
    mitreId: "T1552.001",
    reference: ["https://owasp.org/www-project-web-security-testing-guide/"],
  },
};

class NucleiService {
  private customTemplates: Map<string, NucleiTemplate> = new Map();

  async listTemplates(tags?: string[], severity?: string[]): Promise<NucleiTemplate[]> {
    let templates = [...NUCLEI_TEMPLATES, ...Array.from(this.customTemplates.values())];

    if (tags && tags.length > 0) {
      templates = templates.filter(t => 
        tags.some(tag => t.tags.includes(tag.toLowerCase()))
      );
    }

    if (severity && severity.length > 0) {
      templates = templates.filter(t => 
        severity.includes(t.severity)
      );
    }

    return templates;
  }

  async getTemplate(templateId: string): Promise<NucleiTemplate | null> {
    const builtin = NUCLEI_TEMPLATES.find(t => t.id === templateId);
    if (builtin) return builtin;
    
    return this.customTemplates.get(templateId) || null;
  }

  async addCustomTemplate(template: NucleiTemplate): Promise<void> {
    this.customTemplates.set(template.id, template);
  }

  async runScan(request: NucleiScanRequest): Promise<NucleiScanResult> {
    const startTime = new Date();
    const findings: NucleiFinding[] = [];

    let templates = await this.listTemplates(request.tags, request.severity);

    if (request.templates && request.templates.length > 0) {
      templates = templates.filter(t => request.templates!.includes(t.id));
    }

    if (request.excludeTags && request.excludeTags.length > 0) {
      templates = templates.filter(t =>
        !request.excludeTags!.some(tag => t.tags.includes(tag))
      );
    }

    await this.simulateDelay(500, 1500);

    for (const template of templates) {
      const matches = Math.random() > 0.6;
      
      if (matches) {
        const templateDefaults = FINDING_TEMPLATES[template.id] || {};
        
        findings.push({
          id: `finding-${randomUUID().slice(0, 8)}`,
          templateId: template.id,
          templateName: template.name,
          severity: template.severity,
          type: template.type,
          matchedAt: `${request.target}/${this.generateRandomPath()}`,
          description: templateDefaults.description || template.description,
          remediation: templateDefaults.remediation || "Review and apply security best practices",
          cveIds: template.cveIds,
          cweIds: template.cweIds,
          cvssScore: templateDefaults.cvssScore,
          mitreId: templateDefaults.mitreId,
          tags: template.tags,
          reference: templateDefaults.reference || [],
          extractedData: this.generateExtractedData(template),
          curlCommand: this.generateCurlCommand(request.target, template),
        });
      }
    }

    const endTime = new Date();
    const durationMs = endTime.getTime() - startTime.getTime();

    const findingsBySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const finding of findings) {
      findingsBySeverity[finding.severity]++;
    }

    const recommendations = this.generateRecommendations(findings);

    return {
      id: `nuclei-scan-${randomUUID().slice(0, 8)}`,
      target: request.target,
      templatesUsed: templates.map(t => t.id),
      scanStartTime: startTime,
      scanEndTime: endTime,
      findings,
      statistics: {
        totalTemplates: templates.length,
        templatesMatched: findings.length,
        totalRequests: templates.length * Math.floor(Math.random() * 5 + 1),
        duration: durationMs,
        findingsBySeverity,
      },
      recommendations,
    };
  }

  private generateRandomPath(): string {
    const paths = [
      ".git/config",
      ".env",
      "actuator/env",
      "api/v1/users",
      "admin/login",
      "wp-admin/",
      "struts2-showcase/",
      "server-status",
      "phpinfo.php",
      "robots.txt",
    ];
    return paths[Math.floor(Math.random() * paths.length)];
  }

  private generateExtractedData(template: NucleiTemplate): string[] | undefined {
    if (template.id.includes("git")) {
      return ["[core]", "repositoryformatversion = 0", "remote \"origin\""];
    }
    if (template.id.includes("env")) {
      return ["DB_HOST=*****", "API_KEY=*****", "SECRET_KEY=*****"];
    }
    if (template.id.includes("ssl")) {
      return ["CN=*.example.com", "O=Example Inc", "Valid until: 2025-12-31"];
    }
    return undefined;
  }

  private generateCurlCommand(target: string, template: NucleiTemplate): string {
    if (template.type === "http") {
      return `curl -k -H "User-Agent: Nuclei Scanner" "${target}/${this.generateRandomPath()}"`;
    }
    return `# Network scan - no curl command available`;
  }

  private generateRecommendations(findings: NucleiFinding[]): string[] {
    const recs: string[] = [];

    const criticalFindings = findings.filter(f => f.severity === "critical");
    const highFindings = findings.filter(f => f.severity === "high");

    if (criticalFindings.length > 0) {
      recs.push(`URGENT: Address ${criticalFindings.length} critical vulnerability findings immediately`);
      
      for (const finding of criticalFindings.slice(0, 3)) {
        recs.push(`- ${finding.templateName}: ${finding.remediation}`);
      }
    }

    if (highFindings.length > 0) {
      recs.push(`HIGH PRIORITY: Remediate ${highFindings.length} high severity findings within 7 days`);
    }

    if (findings.some(f => f.templateId.includes("git"))) {
      recs.push("Block access to version control directories (.git, .svn, .hg)");
    }

    if (findings.some(f => f.templateId.includes("env"))) {
      recs.push("Remove sensitive configuration files from web-accessible paths");
    }

    if (findings.some(f => f.templateId.includes("header"))) {
      recs.push("Implement security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options");
    }

    recs.push("Schedule regular vulnerability scanning with Nuclei");
    recs.push("Integrate scanning into CI/CD pipeline");

    return recs;
  }

  private simulateDelay(minMs: number, maxMs: number): Promise<void> {
    const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

export const nucleiService = new NucleiService();
