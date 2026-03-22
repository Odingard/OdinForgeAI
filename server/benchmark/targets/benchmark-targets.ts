export type TargetCategory = "web" | "infrastructure" | "cloud" | "active_directory" | "ctf";
export type HostingType = "local" | "online" | "cloud_deploy";
export type OdinForgeSupport = "full" | "partial" | "planned" | "not_applicable";

export interface BenchmarkTarget {
  id: string;
  name: string;
  category: TargetCategory;
  hosting: HostingType;
  url?: string;
  dockerImage?: string;
  description: string;
  vulnClasses: string[];
  odinforgeSupport: OdinForgeSupport;
  priority: "critical" | "high" | "medium" | "low";
  lastRunDate?: string;
  lastRunFindings?: number;
  lastRunEndpoints?: number;
  lastRunVerdict?: "GO" | "HOLD" | "NO_GO";
  notes?: string;
}

export const BENCHMARK_TARGETS: BenchmarkTarget[] = [
  // ── LOCAL / SELF-HOSTED ──────────────────────────────────────────
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    category: "web",
    hosting: "local",
    dockerImage: "bkimminich/juice-shop",
    description: "Modern Node.js app with 100+ vulnerabilities. Good for API testing.",
    vulnClasses: ["sqli", "xss", "ssrf", "auth_bypass", "idor", "api_abuse", "business_logic"],
    odinforgeSupport: "full",
    priority: "critical",
  },
  {
    id: "dvwa",
    name: "DVWA (Damn Vulnerable Web App)",
    category: "web",
    hosting: "local",
    dockerImage: "vulnerables/web-dvwa",
    description: "Classic. SQLi, XSS, CSRF, file upload, command injection.",
    vulnClasses: ["sqli", "xss", "command_injection", "path_traversal"],
    odinforgeSupport: "full",
    priority: "critical",
  },
  {
    id: "broken-crystals",
    name: "BrokenCrystals",
    category: "web",
    hosting: "online",
    url: "https://brokencrystals.com",
    description: "NeuraLegion demo app. GraphQL, JWT, XSS, SSRF, command injection.",
    vulnClasses: ["sqli", "xss", "ssrf", "auth_bypass", "jwt_abuse", "api_abuse", "command_injection"],
    odinforgeSupport: "full",
    priority: "critical",
  },
  {
    id: "webgoat",
    name: "OWASP WebGoat",
    category: "web",
    hosting: "local",
    dockerImage: "webgoat/webgoat",
    description: "Java-based intentionally vulnerable app covering OWASP Top 10.",
    vulnClasses: ["sqli", "xss", "auth_bypass", "path_traversal", "idor"],
    odinforgeSupport: "full",
    priority: "high",
  },
  {
    id: "zero-bank",
    name: "zero.webappsecurity.com",
    category: "web",
    hosting: "online",
    url: "http://zero.webappsecurity.com",
    description: "Banking SPA — tests JS-driven navigation discovery.",
    vulnClasses: ["auth_bypass", "idor", "xss"],
    odinforgeSupport: "partial",
    priority: "high",
  },
  {
    id: "metasploitable3",
    name: "Metasploitable 3",
    category: "infrastructure",
    hosting: "local",
    description: "Full Linux/Windows VMs with exploitable services. SSH, FTP, SMB, MySQL.",
    vulnClasses: ["command_injection", "auth_bypass", "path_traversal"],
    odinforgeSupport: "planned",
    priority: "high",
  },
  {
    id: "portswigger-labs",
    name: "PortSwigger Web Security Academy",
    category: "web",
    hosting: "online",
    url: "https://portswigger.net/web-security",
    description: "Labs built around OWASP vuln classes. Great for web agent validation.",
    vulnClasses: ["sqli", "xss", "ssrf", "auth_bypass", "path_traversal", "command_injection"],
    odinforgeSupport: "partial",
    priority: "high",
  },
  {
    id: "hackthebox",
    name: "HackTheBox",
    category: "ctf",
    hosting: "online",
    url: "https://hackthebox.com",
    description: "Active machines — web, network, AD, cloud.",
    vulnClasses: ["sqli", "xss", "auth_bypass", "command_injection", "path_traversal"],
    odinforgeSupport: "partial",
    priority: "medium",
  },
  {
    id: "tryhackme",
    name: "TryHackMe",
    category: "ctf",
    hosting: "online",
    url: "https://tryhackme.com",
    description: "Guided rooms with standalone vulnerable targets.",
    vulnClasses: ["sqli", "xss", "auth_bypass", "command_injection"],
    odinforgeSupport: "partial",
    priority: "medium",
  },
  {
    id: "pentesterlab",
    name: "PentesterLab",
    category: "web",
    hosting: "online",
    url: "https://pentesterlab.com",
    description: "Web-focused exercises for validating web exploitation.",
    vulnClasses: ["sqli", "xss", "auth_bypass", "jwt_abuse"],
    odinforgeSupport: "partial",
    priority: "medium",
  },

  // ── CLOUD ────────────────────────────────────────────────────────
  {
    id: "cloudgoat",
    name: "CloudGoat (Rhinosecurity)",
    category: "cloud",
    hosting: "cloud_deploy",
    description: "Intentionally vulnerable AWS environment.",
    vulnClasses: ["auth_bypass", "idor"],
    odinforgeSupport: "planned",
    priority: "high",
  },
  {
    id: "flaws-cloud",
    name: "flaws.cloud / flaws2.cloud",
    category: "cloud",
    hosting: "online",
    url: "http://flaws.cloud",
    description: "S3 and AWS misconfiguration challenges.",
    vulnClasses: ["auth_bypass", "idor"],
    odinforgeSupport: "planned",
    priority: "medium",
  },
  {
    id: "terragoat",
    name: "TerraGoat / AzureGoat / GCPGoat",
    category: "cloud",
    hosting: "cloud_deploy",
    description: "IaC-deployed vulnerable cloud infra for all three major clouds.",
    vulnClasses: ["auth_bypass"],
    odinforgeSupport: "not_applicable",
    priority: "low",
  },

  // ── ACTIVE DIRECTORY ─────────────────────────────────────────────
  {
    id: "goad",
    name: "GOAD (Game of Active Directory)",
    category: "active_directory",
    hosting: "local",
    description: "Full multi-VM AD lab with Kerberoastable accounts, misconfigs.",
    vulnClasses: ["auth_bypass"],
    odinforgeSupport: "planned",
    priority: "high",
  },
  {
    id: "detection-lab",
    name: "Detection Lab",
    category: "active_directory",
    hosting: "local",
    description: "Pre-built Windows AD environment with logging stack.",
    vulnClasses: ["auth_bypass"],
    odinforgeSupport: "planned",
    priority: "medium",
  },
];

export function getTargetById(id: string): BenchmarkTarget | undefined {
  return BENCHMARK_TARGETS.find((t) => t.id === id);
}

export function getTargetsByCategory(category: TargetCategory): BenchmarkTarget[] {
  return BENCHMARK_TARGETS.filter((t) => t.category === category);
}

export function getTargetsByPriority(priority: BenchmarkTarget["priority"]): BenchmarkTarget[] {
  return BENCHMARK_TARGETS.filter((t) => t.priority === priority);
}

export function getSupportedTargets(): BenchmarkTarget[] {
  return BENCHMARK_TARGETS.filter((t) => t.odinforgeSupport === "full" || t.odinforgeSupport === "partial");
}
