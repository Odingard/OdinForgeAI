import * as dgram from "dgram";
import * as net from "net";
import type { DnsProbeConfig, ProbeResult } from "./probe-types";
import { createErrorProbeResult, determineVerdict, DEFAULT_PORTS } from "./probe-types";

export interface DnsProbeResult extends ProbeResult {
  protocol: "dns";
  zoneTransferAllowed: boolean;
  recursionEnabled: boolean;
  dnssecEnabled: boolean;
  versionExposed: boolean;
  serverVersion?: string;
  transferredRecords?: number;
}

export class DnsProbe {
  private config: Required<DnsProbeConfig>;
  private timeout: number;

  constructor(config: DnsProbeConfig) {
    this.config = {
      host: config.host,
      port: config.port || DEFAULT_PORTS.dns,
      timeout: config.timeout || 10000,
      organizationId: config.organizationId || "",
      evaluationId: config.evaluationId || "",
      domain: config.domain,
    };
    this.timeout = this.config.timeout;
  }

  async probe(): Promise<DnsProbeResult> {
    const startTime = Date.now();
    
    try {
      const recursionResult = await this.testRecursion();
      const versionResult = await this.testVersionExposure();
      const axfrResult = await this.testZoneTransfer();
      const dnssecResult = await this.testDnssec();

      const vulnerable = axfrResult.allowed || versionResult.exposed || recursionResult.enabled;
      let confidence = 0;
      const issues: string[] = [];

      if (axfrResult.allowed) {
        confidence = Math.max(confidence, 95);
        issues.push(`Zone transfer allowed - ${axfrResult.recordCount} records exposed`);
      }
      if (versionResult.exposed) {
        confidence = Math.max(confidence, 50);
        issues.push(`DNS version exposed: ${versionResult.version}`);
      }
      if (recursionResult.enabled) {
        confidence = Math.max(confidence, 60);
        issues.push("DNS recursion enabled - potential for amplification attacks");
      }

      const executionTimeMs = Date.now() - startTime;

      return {
        vulnerable,
        confidence,
        verdict: determineVerdict(confidence),
        protocol: "dns",
        service: "dns",
        technique: axfrResult.allowed ? "zone_transfer" : recursionResult.enabled ? "recursion_enabled" : "version_exposure",
        evidence: issues.join("; ") || "No significant DNS vulnerabilities detected",
        details: {
          targetHost: this.config.host,
          targetPort: this.config.port,
          responseData: axfrResult.allowed ? `Zone transfer successful` : undefined,
        },
        recommendations: this.generateRecommendations(axfrResult.allowed, recursionResult.enabled, versionResult.exposed),
        executionTimeMs,
        zoneTransferAllowed: axfrResult.allowed,
        recursionEnabled: recursionResult.enabled,
        dnssecEnabled: dnssecResult.enabled,
        versionExposed: versionResult.exposed,
        serverVersion: versionResult.version,
        transferredRecords: axfrResult.recordCount,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      return {
        ...createErrorProbeResult("dns", "dns", this.config.host, this.config.port, errorMessage),
        zoneTransferAllowed: false,
        recursionEnabled: false,
        dnssecEnabled: false,
        versionExposed: false,
        protocol: "dns",
      } as DnsProbeResult;
    }
  }

  private async testZoneTransfer(): Promise<{ allowed: boolean; recordCount: number }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      const axfrQuery = this.buildAxfrQuery(this.config.domain);
      let responseData = Buffer.alloc(0);
      let recordCount = 0;

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ allowed: false, recordCount: 0 });
      }, this.timeout);

      socket.on("connect", () => {
        const lengthPrefix = Buffer.alloc(2);
        lengthPrefix.writeUInt16BE(axfrQuery.length, 0);
        socket.write(Buffer.concat([lengthPrefix, axfrQuery]));
      });

      socket.on("data", (chunk: Buffer) => {
        responseData = Buffer.concat([responseData, chunk]);
        const answerCount = this.parseAnswerCount(responseData);
        if (answerCount > 0) {
          recordCount = answerCount;
        }
      });

      socket.on("end", () => {
        clearTimeout(timeoutId);
        const allowed = recordCount > 2;
        resolve({ allowed, recordCount });
      });

      socket.on("error", () => {
        clearTimeout(timeoutId);
        resolve({ allowed: false, recordCount: 0 });
      });
    });
  }

  private async testRecursion(): Promise<{ enabled: boolean }> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket("udp4");
      const query = this.buildRecursionQuery("google.com");

      const timeoutId = setTimeout(() => {
        socket.close();
        resolve({ enabled: false });
      }, this.timeout);

      socket.on("message", (msg) => {
        clearTimeout(timeoutId);
        socket.close();
        const flags = msg.readUInt16BE(2);
        const ra = (flags & 0x0080) !== 0;
        const rcode = flags & 0x000f;
        const enabled = ra && rcode === 0;
        resolve({ enabled });
      });

      socket.on("error", () => {
        clearTimeout(timeoutId);
        socket.close();
        resolve({ enabled: false });
      });

      socket.send(query, this.config.port, this.config.host);
    });
  }

  private async testVersionExposure(): Promise<{ exposed: boolean; version?: string }> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket("udp4");
      const query = this.buildVersionQuery();

      const timeoutId = setTimeout(() => {
        socket.close();
        resolve({ exposed: false });
      }, this.timeout);

      socket.on("message", (msg) => {
        clearTimeout(timeoutId);
        socket.close();
        const version = this.parseVersionResponse(msg);
        resolve({ exposed: !!version, version });
      });

      socket.on("error", () => {
        clearTimeout(timeoutId);
        socket.close();
        resolve({ exposed: false });
      });

      socket.send(query, this.config.port, this.config.host);
    });
  }

  private async testDnssec(): Promise<{ enabled: boolean }> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket("udp4");
      const query = this.buildDnssecQuery(this.config.domain);

      const timeoutId = setTimeout(() => {
        socket.close();
        resolve({ enabled: false });
      }, this.timeout);

      socket.on("message", (msg) => {
        clearTimeout(timeoutId);
        socket.close();
        const flags = msg.readUInt16BE(2);
        const ad = (flags & 0x0020) !== 0;
        resolve({ enabled: ad });
      });

      socket.on("error", () => {
        clearTimeout(timeoutId);
        socket.close();
        resolve({ enabled: false });
      });

      socket.send(query, this.config.port, this.config.host);
    });
  }

  private buildAxfrQuery(domain: string): Buffer {
    const transactionId = Buffer.from([0x00, 0x01]);
    const flags = Buffer.from([0x00, 0x00]);
    const qdcount = Buffer.from([0x00, 0x01]);
    const ancount = Buffer.from([0x00, 0x00]);
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x00]);

    const qname = this.encodeDomainName(domain);
    const qtype = Buffer.from([0x00, 0xfc]);
    const qclass = Buffer.from([0x00, 0x01]);

    return Buffer.concat([
      transactionId, flags, qdcount, ancount, nscount, arcount,
      qname, qtype, qclass,
    ]);
  }

  private buildRecursionQuery(domain: string): Buffer {
    const transactionId = Buffer.from([0x12, 0x34]);
    const flags = Buffer.from([0x01, 0x00]);
    const qdcount = Buffer.from([0x00, 0x01]);
    const ancount = Buffer.from([0x00, 0x00]);
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x00]);

    const qname = this.encodeDomainName(domain);
    const qtype = Buffer.from([0x00, 0x01]);
    const qclass = Buffer.from([0x00, 0x01]);

    return Buffer.concat([
      transactionId, flags, qdcount, ancount, nscount, arcount,
      qname, qtype, qclass,
    ]);
  }

  private buildVersionQuery(): Buffer {
    const transactionId = Buffer.from([0xab, 0xcd]);
    const flags = Buffer.from([0x00, 0x00]);
    const qdcount = Buffer.from([0x00, 0x01]);
    const ancount = Buffer.from([0x00, 0x00]);
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x00]);

    const versionBind = Buffer.from([
      0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
      0x04, 0x62, 0x69, 0x6e, 0x64, 0x00,
    ]);
    const qtype = Buffer.from([0x00, 0x10]);
    const qclass = Buffer.from([0x00, 0x03]);

    return Buffer.concat([
      transactionId, flags, qdcount, ancount, nscount, arcount,
      versionBind, qtype, qclass,
    ]);
  }

  private buildDnssecQuery(domain: string): Buffer {
    const transactionId = Buffer.from([0xde, 0xad]);
    const flags = Buffer.from([0x01, 0x20]);
    const qdcount = Buffer.from([0x00, 0x01]);
    const ancount = Buffer.from([0x00, 0x00]);
    const nscount = Buffer.from([0x00, 0x00]);
    const arcount = Buffer.from([0x00, 0x01]);

    const qname = this.encodeDomainName(domain);
    const qtype = Buffer.from([0x00, 0x01]);
    const qclass = Buffer.from([0x00, 0x01]);

    const optRecord = Buffer.from([
      0x00,
      0x00, 0x29,
      0x10, 0x00,
      0x00, 0x00, 0x80, 0x00,
      0x00, 0x00,
    ]);

    return Buffer.concat([
      transactionId, flags, qdcount, ancount, nscount, arcount,
      qname, qtype, qclass, optRecord,
    ]);
  }

  private encodeDomainName(domain: string): Buffer {
    const parts = domain.split(".");
    const buffers: Buffer[] = [];

    for (const part of parts) {
      buffers.push(Buffer.from([part.length]));
      buffers.push(Buffer.from(part));
    }
    buffers.push(Buffer.from([0x00]));

    return Buffer.concat(buffers);
  }

  private parseAnswerCount(data: Buffer): number {
    if (data.length < 14) return 0;
    if (data.length >= 2) {
      const messageLength = data.readUInt16BE(0);
      if (data.length >= messageLength + 2 && messageLength >= 12) {
        return data.readUInt16BE(8);
      }
    }
    return 0;
  }

  private parseVersionResponse(data: Buffer): string | undefined {
    if (data.length < 12) return undefined;
    
    const ancount = data.readUInt16BE(6);
    if (ancount === 0) return undefined;

    let offset = 12;
    while (offset < data.length && data[offset] !== 0) {
      offset += data[offset] + 1;
    }
    offset += 5;

    if (offset + 12 > data.length) return undefined;

    offset += 10;
    const rdlength = data.readUInt16BE(offset);
    offset += 2;

    if (offset + rdlength > data.length) return undefined;

    const txtLength = data[offset];
    if (offset + 1 + txtLength > data.length) return undefined;

    return data.slice(offset + 1, offset + 1 + txtLength).toString();
  }

  private generateRecommendations(
    zoneTransferAllowed: boolean,
    recursionEnabled: boolean,
    versionExposed: boolean
  ): string[] {
    const recommendations: string[] = [];

    if (zoneTransferAllowed) {
      recommendations.push("Restrict zone transfers to authorized secondary nameservers only");
      recommendations.push("Configure allow-transfer ACL in BIND or equivalent setting");
    }
    if (recursionEnabled) {
      recommendations.push("Disable recursion for authoritative-only DNS servers");
      recommendations.push("If recursion is needed, restrict to trusted networks");
      recommendations.push("Implement rate limiting to prevent amplification attacks");
    }
    if (versionExposed) {
      recommendations.push("Hide DNS server version information (version.bind)");
      recommendations.push("Configure: version \"not disclosed\"; in named.conf");
    }

    if (recommendations.length === 0) {
      recommendations.push("DNS server appears properly configured");
    }

    return recommendations;
  }
}

export function createDnsProbe(config: DnsProbeConfig): DnsProbe {
  return new DnsProbe(config);
}
