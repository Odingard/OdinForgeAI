import * as net from "net";
import type { LdapProbeConfig, ProbeResult } from "./probe-types";
import { createErrorProbeResult, determineVerdict, DEFAULT_PORTS } from "./probe-types";

export interface LdapProbeResult extends ProbeResult {
  protocol: "ldap";
  anonymousBindAllowed: boolean;
  nullBindAllowed: boolean;
  baseDnExposed: boolean;
  schemaExposed: boolean;
  discoveredBaseDns: string[];
  userCount?: number;
}

export class LdapProbe {
  private config: Required<LdapProbeConfig>;
  private timeout: number;

  constructor(config: LdapProbeConfig) {
    this.config = {
      host: config.host,
      port: config.port || DEFAULT_PORTS.ldap,
      timeout: config.timeout || 10000,
      organizationId: config.organizationId || "",
      evaluationId: config.evaluationId || "",
      baseDn: config.baseDn || "",
    };
    this.timeout = this.config.timeout;
  }

  async probe(): Promise<LdapProbeResult> {
    const startTime = Date.now();
    
    try {
      const connection = await this.connect();
      
      const anonymousResult = await this.testAnonymousBind(connection);
      const nullResult = await this.testNullBind(connection);
      
      let baseDnResult = { exposed: false, baseDns: [] as string[] };
      let schemaResult = { exposed: false };
      
      if (anonymousResult.allowed || nullResult.allowed) {
        baseDnResult = await this.discoverBaseDns(connection);
        schemaResult = await this.testSchemaAccess(connection);
      }

      connection.destroy();

      const vulnerable = anonymousResult.allowed || nullResult.allowed;
      let confidence = 0;
      const issues: string[] = [];

      if (anonymousResult.allowed) {
        confidence = Math.max(confidence, 80);
        issues.push("Anonymous LDAP bind allowed");
      }
      if (nullResult.allowed) {
        confidence = Math.max(confidence, 85);
        issues.push("Null bind allowed (empty credentials)");
      }
      if (baseDnResult.exposed && baseDnResult.baseDns.length > 0) {
        confidence = Math.max(confidence, 70);
        issues.push(`Base DNs exposed: ${baseDnResult.baseDns.join(", ")}`);
      }
      if (schemaResult.exposed) {
        confidence = Math.max(confidence, 50);
        issues.push("LDAP schema is readable without authentication");
      }

      const executionTimeMs = Date.now() - startTime;

      return {
        vulnerable,
        confidence,
        verdict: determineVerdict(confidence),
        protocol: "ldap",
        service: "directory",
        technique: anonymousResult.allowed ? "anonymous_bind" : nullResult.allowed ? "null_bind" : "none",
        evidence: issues.join("; ") || "No significant LDAP vulnerabilities detected",
        details: {
          targetHost: this.config.host,
          targetPort: this.config.port,
          responseData: baseDnResult.baseDns.length > 0 ? `Base DNs: ${baseDnResult.baseDns.join(", ")}` : undefined,
        },
        recommendations: this.generateRecommendations(anonymousResult.allowed, nullResult.allowed, baseDnResult.exposed),
        executionTimeMs,
        anonymousBindAllowed: anonymousResult.allowed,
        nullBindAllowed: nullResult.allowed,
        baseDnExposed: baseDnResult.exposed,
        schemaExposed: schemaResult.exposed,
        discoveredBaseDns: baseDnResult.baseDns,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      return {
        ...createErrorProbeResult("ldap", "directory", this.config.host, this.config.port, errorMessage),
        anonymousBindAllowed: false,
        nullBindAllowed: false,
        baseDnExposed: false,
        schemaExposed: false,
        discoveredBaseDns: [],
        protocol: "ldap",
      } as LdapProbeResult;
    }
  }

  private connect(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      socket.setTimeout(this.timeout);
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
      socket.once("timeout", () => reject(new Error("Connection timeout")));
    });
  }

  private async testAnonymousBind(socket: net.Socket): Promise<{ allowed: boolean }> {
    const bindRequest = this.buildSimpleBindRequest("", "");
    
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({ allowed: false });
      }, this.timeout);

      socket.once("data", (data) => {
        clearTimeout(timeoutId);
        const resultCode = this.parseBindResponse(data);
        resolve({ allowed: resultCode === 0 });
      });

      socket.write(bindRequest);
    });
  }

  private async testNullBind(socket: net.Socket): Promise<{ allowed: boolean }> {
    const bindRequest = this.buildSimpleBindRequest("cn=null", "");
    
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({ allowed: false });
      }, this.timeout);

      socket.once("data", (data) => {
        clearTimeout(timeoutId);
        const resultCode = this.parseBindResponse(data);
        resolve({ allowed: resultCode === 0 });
      });

      socket.write(bindRequest);
    });
  }

  private async discoverBaseDns(socket: net.Socket): Promise<{ exposed: boolean; baseDns: string[] }> {
    const searchRequest = this.buildRootDseSearchRequest();
    
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({ exposed: false, baseDns: [] });
      }, this.timeout);

      let responseData = Buffer.alloc(0);
      
      const onData = (data: Buffer) => {
        responseData = Buffer.concat([responseData, data]);
        
        if (this.isSearchComplete(responseData)) {
          clearTimeout(timeoutId);
          socket.removeListener("data", onData);
          const baseDns = this.parseNamingContexts(responseData);
          resolve({ exposed: baseDns.length > 0, baseDns });
        }
      };

      socket.on("data", onData);
      socket.write(searchRequest);
    });
  }

  private async testSchemaAccess(socket: net.Socket): Promise<{ exposed: boolean }> {
    const searchRequest = this.buildSchemaSearchRequest();
    
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve({ exposed: false });
      }, this.timeout);

      socket.once("data", (data) => {
        clearTimeout(timeoutId);
        const hasEntries = this.hasSearchResults(data);
        resolve({ exposed: hasEntries });
      });

      socket.write(searchRequest);
    });
  }

  private buildSimpleBindRequest(dn: string, password: string): Buffer {
    const messageId = this.encodeLdapInt(1);
    const version = this.encodeLdapInt(3);
    const dnOctet = this.encodeLdapOctetString(dn);
    const passwordOctet = Buffer.concat([
      Buffer.from([0x80]),
      this.encodeLength(password.length),
      Buffer.from(password),
    ]);

    const bindRequest = Buffer.concat([
      Buffer.from([0x60]),
      this.encodeLength(version.length + dnOctet.length + passwordOctet.length),
      version,
      dnOctet,
      passwordOctet,
    ]);

    const message = Buffer.concat([
      Buffer.from([0x30]),
      this.encodeLength(messageId.length + bindRequest.length),
      messageId,
      bindRequest,
    ]);

    return message;
  }

  private buildRootDseSearchRequest(): Buffer {
    const messageId = this.encodeLdapInt(2);
    const baseDn = this.encodeLdapOctetString("");
    const scope = Buffer.from([0x0a, 0x01, 0x00]);
    const derefAliases = Buffer.from([0x0a, 0x01, 0x00]);
    const sizeLimit = this.encodeLdapInt(0);
    const timeLimit = this.encodeLdapInt(10);
    const typesOnly = Buffer.from([0x01, 0x01, 0x00]);
    const filter = Buffer.from([0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73]);
    
    const namingContextsAttr = this.encodeLdapOctetString("namingContexts");
    const attributes = Buffer.concat([
      Buffer.from([0x30]),
      this.encodeLength(namingContextsAttr.length),
      namingContextsAttr,
    ]);

    const searchRequest = Buffer.concat([
      Buffer.from([0x63]),
      this.encodeLength(
        baseDn.length + scope.length + derefAliases.length +
        sizeLimit.length + timeLimit.length + typesOnly.length +
        filter.length + attributes.length
      ),
      baseDn, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes,
    ]);

    const message = Buffer.concat([
      Buffer.from([0x30]),
      this.encodeLength(messageId.length + searchRequest.length),
      messageId,
      searchRequest,
    ]);

    return message;
  }

  private buildSchemaSearchRequest(): Buffer {
    const messageId = this.encodeLdapInt(3);
    const baseDn = this.encodeLdapOctetString("cn=schema");
    const scope = Buffer.from([0x0a, 0x01, 0x00]);
    const derefAliases = Buffer.from([0x0a, 0x01, 0x00]);
    const sizeLimit = this.encodeLdapInt(1);
    const timeLimit = this.encodeLdapInt(5);
    const typesOnly = Buffer.from([0x01, 0x01, 0x00]);
    const filter = Buffer.from([0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73]);
    const attributes = Buffer.from([0x30, 0x00]);

    const searchRequest = Buffer.concat([
      Buffer.from([0x63]),
      this.encodeLength(
        baseDn.length + scope.length + derefAliases.length +
        sizeLimit.length + timeLimit.length + typesOnly.length +
        filter.length + attributes.length
      ),
      baseDn, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes,
    ]);

    const message = Buffer.concat([
      Buffer.from([0x30]),
      this.encodeLength(messageId.length + searchRequest.length),
      messageId,
      searchRequest,
    ]);

    return message;
  }

  private encodeLdapInt(value: number): Buffer {
    if (value < 128) {
      return Buffer.from([0x02, 0x01, value]);
    }
    if (value < 256) {
      return Buffer.from([0x02, 0x01, value]);
    }
    return Buffer.from([0x02, 0x02, (value >> 8) & 0xff, value & 0xff]);
  }

  private encodeLdapOctetString(str: string): Buffer {
    const strBuffer = Buffer.from(str);
    return Buffer.concat([
      Buffer.from([0x04]),
      this.encodeLength(strBuffer.length),
      strBuffer,
    ]);
  }

  private encodeLength(length: number): Buffer {
    if (length < 128) {
      return Buffer.from([length]);
    }
    if (length < 256) {
      return Buffer.from([0x81, length]);
    }
    return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
  }

  private parseBindResponse(data: Buffer): number {
    if (data.length < 10) return -1;
    
    let offset = 0;
    if (data[offset] !== 0x30) return -1;
    offset++;
    
    const seqLength = this.decodeLength(data, offset);
    offset += seqLength.bytesRead;
    
    if (data[offset] !== 0x02) return -1;
    offset++;
    const msgIdLength = data[offset];
    offset += 1 + msgIdLength;
    
    if (data[offset] !== 0x61) return -1;
    offset++;
    const bindRespLength = this.decodeLength(data, offset);
    offset += bindRespLength.bytesRead;
    
    if (data[offset] !== 0x0a) return -1;
    offset++;
    if (data[offset] !== 0x01) return -1;
    offset++;
    
    return data[offset];
  }

  private decodeLength(data: Buffer, offset: number): { length: number; bytesRead: number } {
    if (data[offset] < 128) {
      return { length: data[offset], bytesRead: 1 };
    }
    const numBytes = data[offset] & 0x7f;
    let length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | data[offset + 1 + i];
    }
    return { length, bytesRead: 1 + numBytes };
  }

  private isSearchComplete(data: Buffer): boolean {
    return data.includes(Buffer.from([0x65]));
  }

  private hasSearchResults(data: Buffer): boolean {
    return data.includes(Buffer.from([0x64]));
  }

  private parseNamingContexts(data: Buffer): string[] {
    const contexts: string[] = [];
    const dataStr = data.toString("latin1");
    
    const dcPattern = /dc=[a-zA-Z0-9-]+(?:,dc=[a-zA-Z0-9-]+)*/g;
    const matches = dataStr.match(dcPattern);
    
    if (matches) {
      for (const match of matches) {
        if (!contexts.includes(match)) {
          contexts.push(match);
        }
      }
    }
    
    return contexts;
  }

  private generateRecommendations(
    anonymousAllowed: boolean,
    nullAllowed: boolean,
    baseDnExposed: boolean
  ): string[] {
    const recommendations: string[] = [];

    if (anonymousAllowed) {
      recommendations.push("Disable anonymous LDAP binds");
      recommendations.push("Configure: olcDisallows: bind_anon in slapd.conf or equivalent");
    }
    if (nullAllowed) {
      recommendations.push("Disable null/unauthenticated binds");
      recommendations.push("Require authentication for all LDAP operations");
    }
    if (baseDnExposed) {
      recommendations.push("Restrict access to RootDSE information");
      recommendations.push("Configure ACLs to limit anonymous access to directory metadata");
    }

    if (recommendations.length === 0) {
      recommendations.push("LDAP server appears properly configured");
    }

    return recommendations;
  }
}

export function createLdapProbe(config: LdapProbeConfig): LdapProbe {
  return new LdapProbe(config);
}
