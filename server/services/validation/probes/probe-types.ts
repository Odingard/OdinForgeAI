import type { ValidationVerdict } from "@shared/schema";

export interface ProbeResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  protocol: string;
  service: string;
  technique: string;
  evidence: string;
  details: ProbeDetails;
  recommendations: string[];
  executionTimeMs: number;
}

export interface ProbeDetails {
  targetHost: string;
  targetPort: number;
  banner?: string;
  responseData?: string;
  attemptedCredentials?: string[];
  successfulCredential?: string;
  errorMessage?: string;
}

export interface ProbeConfig {
  host: string;
  port?: number;
  timeout?: number;
  organizationId?: string;
  evaluationId?: string;
}

export interface SmtpProbeConfig extends ProbeConfig {
  testSender?: string;
  testRecipient?: string;
  testDomain?: string;
}

export interface DnsProbeConfig extends ProbeConfig {
  domain: string;
}

export interface LdapProbeConfig extends ProbeConfig {
  baseDn?: string;
}

export interface CredentialProbeConfig extends ProbeConfig {
  service: "ssh" | "ftp" | "mysql" | "postgresql" | "redis" | "mongodb" | "telnet";
  customCredentials?: Array<{ username: string; password: string }>;
}

export const DEFAULT_CREDENTIALS: Record<string, Array<{ username: string; password: string }>> = {
  ssh: [
    { username: "root", password: "root" },
    { username: "root", password: "toor" },
    { username: "root", password: "password" },
    { username: "root", password: "123456" },
    { username: "admin", password: "admin" },
    { username: "admin", password: "password" },
    { username: "ubuntu", password: "ubuntu" },
    { username: "pi", password: "raspberry" },
  ],
  ftp: [
    { username: "anonymous", password: "" },
    { username: "anonymous", password: "anonymous" },
    { username: "ftp", password: "ftp" },
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
  ],
  mysql: [
    { username: "root", password: "" },
    { username: "root", password: "root" },
    { username: "root", password: "mysql" },
    { username: "admin", password: "admin" },
    { username: "mysql", password: "mysql" },
  ],
  postgresql: [
    { username: "postgres", password: "postgres" },
    { username: "postgres", password: "" },
    { username: "postgres", password: "password" },
    { username: "admin", password: "admin" },
  ],
  redis: [
    { username: "", password: "" },
    { username: "", password: "redis" },
    { username: "", password: "password" },
  ],
  mongodb: [
    { username: "", password: "" },
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
    { username: "mongodb", password: "mongodb" },
  ],
  telnet: [
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
    { username: "user", password: "user" },
  ],
};

export const DEFAULT_PORTS: Record<string, number> = {
  smtp: 25,
  smtps: 465,
  submission: 587,
  dns: 53,
  ldap: 389,
  ldaps: 636,
  ssh: 22,
  ftp: 21,
  mysql: 3306,
  postgresql: 5432,
  redis: 6379,
  mongodb: 27017,
  telnet: 23,
};

export function createErrorProbeResult(
  protocol: string,
  service: string,
  host: string,
  port: number,
  errorMessage: string
): ProbeResult {
  return {
    vulnerable: false,
    confidence: 0,
    verdict: "error",
    protocol,
    service,
    technique: "connection_failed",
    evidence: `Failed to connect to ${host}:${port}: ${errorMessage}`,
    details: {
      targetHost: host,
      targetPort: port,
      errorMessage,
    },
    recommendations: [
      "Verify the target host and port are correct",
      "Check network connectivity and firewall rules",
    ],
    executionTimeMs: 0,
  };
}

export function determineVerdict(confidence: number): ValidationVerdict {
  if (confidence >= 90) return "confirmed";
  if (confidence >= 70) return "likely";
  if (confidence >= 40) return "theoretical";
  return "false_positive";
}
