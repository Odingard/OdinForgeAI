export * from "./probe-types";
export * from "./smtp-relay-probe";
export * from "./dns-probe";
export * from "./ldap-probe";
export * from "./credential-probe";

import { createSmtpRelayProbe, SmtpRelayProbe } from "./smtp-relay-probe";
import { createDnsProbe, DnsProbe } from "./dns-probe";
import { createLdapProbe, LdapProbe } from "./ldap-probe";
import { createCredentialProbe, CredentialProbe } from "./credential-probe";
import type {
  ProbeConfig,
  SmtpProbeConfig,
  DnsProbeConfig,
  LdapProbeConfig,
  CredentialProbeConfig,
  ProbeResult,
} from "./probe-types";

export type ProbeType = "smtp" | "dns" | "ldap" | "credential";

export interface ProtocolProbeConfig {
  type: ProbeType;
  config: SmtpProbeConfig | DnsProbeConfig | LdapProbeConfig | CredentialProbeConfig;
}

export type ProtocolProbe = SmtpRelayProbe | DnsProbe | LdapProbe | CredentialProbe;

export function createProtocolProbe(probeConfig: ProtocolProbeConfig): ProtocolProbe {
  switch (probeConfig.type) {
    case "smtp":
      return createSmtpRelayProbe(probeConfig.config as SmtpProbeConfig);
    case "dns":
      return createDnsProbe(probeConfig.config as DnsProbeConfig);
    case "ldap":
      return createLdapProbe(probeConfig.config as LdapProbeConfig);
    case "credential":
      return createCredentialProbe(probeConfig.config as CredentialProbeConfig);
    default:
      throw new Error(`Unknown probe type: ${probeConfig.type}`);
  }
}

export async function runProtocolProbes(
  host: string,
  probes: ProbeType[],
  options: {
    timeout?: number;
    organizationId?: string;
    evaluationId?: string;
    domain?: string;
  } = {}
): Promise<Map<ProbeType, ProbeResult>> {
  const results = new Map<ProbeType, ProbeResult>();
  const { timeout = 10000, organizationId, evaluationId, domain = host } = options;

  const probePromises = probes.map(async (probeType) => {
    let probe: ProtocolProbe;
    
    switch (probeType) {
      case "smtp":
        probe = createSmtpRelayProbe({ host, timeout, organizationId, evaluationId });
        break;
      case "dns":
        probe = createDnsProbe({ host, timeout, organizationId, evaluationId, domain });
        break;
      case "ldap":
        probe = createLdapProbe({ host, timeout, organizationId, evaluationId });
        break;
      case "credential":
        probe = createCredentialProbe({ host, timeout, organizationId, evaluationId, service: "ssh" });
        break;
    }

    try {
      const result = await probe.probe();
      return { type: probeType, result };
    } catch (error) {
      console.error(`[ProtocolProbes] Error running ${probeType} probe:`, error);
      return { type: probeType, result: null };
    }
  });

  const probeResults = await Promise.all(probePromises);
  
  for (const { type, result } of probeResults) {
    if (result) {
      results.set(type, result);
    }
  }

  return results;
}

export async function runAllCredentialProbes(
  host: string,
  services: CredentialProbeConfig["service"][],
  options: {
    timeout?: number;
    organizationId?: string;
    evaluationId?: string;
  } = {}
): Promise<Map<string, ProbeResult>> {
  const results = new Map<string, ProbeResult>();
  const { timeout = 5000, organizationId, evaluationId } = options;

  const probePromises = services.map(async (service) => {
    const probe = createCredentialProbe({
      host,
      service,
      timeout,
      organizationId,
      evaluationId,
    });

    try {
      const result = await probe.probe();
      return { service, result };
    } catch (error) {
      console.error(`[CredentialProbes] Error running ${service} probe:`, error);
      return { service, result: null };
    }
  });

  const probeResults = await Promise.all(probePromises);
  
  for (const { service, result } of probeResults) {
    if (result) {
      results.set(service, result);
    }
  }

  return results;
}
