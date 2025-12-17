import { randomUUID } from "crypto";
import * as crypto from "crypto";

export interface CertificateInfo {
  id: string;
  agentId: string;
  organizationId: string;
  fingerprint: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  status: "active" | "revoked" | "expired";
  createdAt: Date;
  revokedAt?: Date;
  revokedReason?: string;
  publicKeyHash: string;
}

export interface CertificateRequest {
  agentId: string;
  organizationId: string;
  commonName: string;
  validityDays?: number;
}

export interface CertificateResponse {
  certificateId: string;
  certificate: string;
  privateKey: string;
  fingerprint: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
}

export interface MTLSValidationResult {
  valid: boolean;
  agentId?: string;
  organizationId?: string;
  certificateId?: string;
  error?: string;
}

class MTLSAuthService {
  private certificates: Map<string, CertificateInfo> = new Map();
  private fingerprintIndex: Map<string, string> = new Map();
  private publicKeyHashIndex: Map<string, string> = new Map();
  private agentCertificates: Map<string, string[]> = new Map();
  
  private readonly CA_SUBJECT = "CN=OdinForge CA,O=OdinForge,OU=Security";
  private readonly CERT_VALIDITY_DAYS = 365;
  
  async generateCertificate(request: CertificateRequest): Promise<CertificateResponse> {
    const validityDays = request.validityDays || this.CERT_VALIDITY_DAYS;
    const certificateId = `cert-${randomUUID()}`;
    const serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase();
    const now = new Date();
    const validFrom = new Date(now);
    const validTo = new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000);
    
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    
    const subject = `CN=${request.commonName},O=${request.organizationId},OU=Endpoint Agent`;
    
    const certDer = this.createX509Certificate({
      subject,
      issuer: this.CA_SUBJECT,
      serialNumber,
      validFrom,
      validTo,
      publicKeyPem: publicKey,
      privateKeyPem: privateKey,
    });
    
    const fingerprint = crypto
      .createHash("sha256")
      .update(certDer)
      .digest("hex")
      .toUpperCase();
    
    const publicKeyHash = crypto
      .createHash("sha256")
      .update(publicKey)
      .digest("hex")
      .toUpperCase();
    
    const certificate = this.derToPem(certDer, "CERTIFICATE");
    
    const certInfo: CertificateInfo = {
      id: certificateId,
      agentId: request.agentId,
      organizationId: request.organizationId,
      fingerprint,
      subject,
      issuer: this.CA_SUBJECT,
      serialNumber,
      validFrom,
      validTo,
      status: "active",
      createdAt: now,
      publicKeyHash,
    };
    
    this.certificates.set(certificateId, certInfo);
    this.fingerprintIndex.set(fingerprint, certificateId);
    this.publicKeyHashIndex.set(publicKeyHash, certificateId);
    
    const agentCerts = this.agentCertificates.get(request.agentId) || [];
    agentCerts.push(certificateId);
    this.agentCertificates.set(request.agentId, agentCerts);
    
    return {
      certificateId,
      certificate,
      privateKey,
      fingerprint,
      serialNumber,
      validFrom,
      validTo,
    };
  }
  
  private createX509Certificate(params: {
    subject: string;
    issuer: string;
    serialNumber: string;
    validFrom: Date;
    validTo: Date;
    publicKeyPem: string;
    privateKeyPem: string;
  }): Buffer {
    const versionDer = this.asn1ContextTag(0, this.asn1Integer(Buffer.from([2])));
    
    const serialBytes = Buffer.from(params.serialNumber, "hex");
    const serialDer = this.asn1Integer(serialBytes);
    
    const sha256WithRSAOid = Buffer.from([
      0x30, 0x0D,
      0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
      0x05, 0x00
    ]);
    
    const issuerDer = this.encodeDN(params.issuer);
    const subjectDer = this.encodeDN(params.subject);
    
    const validityDer = this.asn1Sequence(Buffer.concat([
      this.asn1UTCTime(params.validFrom),
      this.asn1UTCTime(params.validTo),
    ]));
    
    const publicKeyInfo = this.extractPublicKeyDer(params.publicKeyPem);
    
    const tbsCertificate = this.asn1Sequence(Buffer.concat([
      versionDer,
      serialDer,
      sha256WithRSAOid,
      issuerDer,
      validityDer,
      subjectDer,
      publicKeyInfo,
    ]));
    
    const signerKey = crypto.createPrivateKey(params.privateKeyPem);
    const sign = crypto.createSign("SHA256");
    sign.update(tbsCertificate);
    const signature = sign.sign(signerKey);
    
    const signatureBits = this.asn1BitString(signature);
    
    return this.asn1Sequence(Buffer.concat([
      tbsCertificate,
      sha256WithRSAOid,
      signatureBits,
    ]));
  }
  
  private encodeDN(dn: string): Buffer {
    const parts = dn.split(",").map(p => p.trim());
    const rdns: Buffer[] = [];
    
    for (const part of parts) {
      const eqIdx = part.indexOf("=");
      if (eqIdx === -1) continue;
      
      const attrType = part.substring(0, eqIdx).toUpperCase();
      const attrValue = part.substring(eqIdx + 1);
      
      let oid: Buffer;
      switch (attrType) {
        case "CN":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
          break;
        case "O":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x0A]);
          break;
        case "OU":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x0B]);
          break;
        case "C":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x06]);
          break;
        case "ST":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x08]);
          break;
        case "L":
          oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x07]);
          break;
        default:
          continue;
      }
      
      const valueBytes = Buffer.from(attrValue, "utf8");
      const valueDer = this.asn1TLV(0x0C, valueBytes);
      
      const atv = this.asn1Sequence(Buffer.concat([oid, valueDer]));
      const rdn = this.asn1Set(atv);
      rdns.push(rdn);
    }
    
    return this.asn1Sequence(Buffer.concat(rdns));
  }
  
  private extractPublicKeyDer(pem: string): Buffer {
    const base64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\s/g, "");
    return Buffer.from(base64, "base64");
  }
  
  private asn1Integer(value: Buffer): Buffer {
    let data = value;
    while (data.length > 1 && data[0] === 0 && !(data[1] & 0x80)) {
      data = data.slice(1);
    }
    if (data[0] & 0x80) {
      data = Buffer.concat([Buffer.from([0x00]), data]);
    }
    return this.asn1TLV(0x02, data);
  }
  
  private asn1UTCTime(date: Date): Buffer {
    const y = date.getUTCFullYear().toString().slice(-2);
    const M = (date.getUTCMonth() + 1).toString().padStart(2, "0");
    const d = date.getUTCDate().toString().padStart(2, "0");
    const h = date.getUTCHours().toString().padStart(2, "0");
    const m = date.getUTCMinutes().toString().padStart(2, "0");
    const s = date.getUTCSeconds().toString().padStart(2, "0");
    const str = `${y}${M}${d}${h}${m}${s}Z`;
    return this.asn1TLV(0x17, Buffer.from(str, "ascii"));
  }
  
  private asn1Sequence(content: Buffer): Buffer {
    return this.asn1TLV(0x30, content);
  }
  
  private asn1Set(content: Buffer): Buffer {
    return this.asn1TLV(0x31, content);
  }
  
  private asn1BitString(content: Buffer): Buffer {
    return this.asn1TLV(0x03, Buffer.concat([Buffer.from([0x00]), content]));
  }
  
  private asn1ContextTag(tag: number, content: Buffer): Buffer {
    return this.asn1TLV(0xA0 | tag, content);
  }
  
  private asn1TLV(tag: number, value: Buffer): Buffer {
    const len = value.length;
    let lengthBytes: Buffer;
    
    if (len < 128) {
      lengthBytes = Buffer.from([len]);
    } else if (len < 256) {
      lengthBytes = Buffer.from([0x81, len]);
    } else if (len < 65536) {
      lengthBytes = Buffer.from([0x82, (len >> 8) & 0xFF, len & 0xFF]);
    } else {
      lengthBytes = Buffer.from([0x83, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF]);
    }
    
    return Buffer.concat([Buffer.from([tag]), lengthBytes, value]);
  }
  
  private derToPem(der: Buffer, type: string): string {
    const base64 = der.toString("base64");
    const lines: string[] = [];
    for (let i = 0; i < base64.length; i += 64) {
      lines.push(base64.slice(i, i + 64));
    }
    return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
  }
  
  async validateCertificate(fingerprintOrPem: string): Promise<MTLSValidationResult> {
    let fingerprint: string;
    
    if (fingerprintOrPem.includes("-----BEGIN CERTIFICATE-----")) {
      const der = this.pemToDer(fingerprintOrPem);
      fingerprint = crypto.createHash("sha256").update(der).digest("hex").toUpperCase();
    } else {
      fingerprint = fingerprintOrPem.replace(/:/g, "").toUpperCase();
    }
    
    const certId = this.fingerprintIndex.get(fingerprint);
    if (!certId) {
      return { valid: false, error: "Certificate not found in trust store" };
    }
    
    const cert = this.certificates.get(certId);
    if (!cert) {
      return { valid: false, error: "Certificate data not found" };
    }
    
    if (cert.status === "revoked") {
      return { valid: false, error: `Certificate revoked: ${cert.revokedReason}` };
    }
    
    const now = new Date();
    if (now < cert.validFrom) {
      return { valid: false, error: "Certificate not yet valid" };
    }
    
    if (now > cert.validTo) {
      cert.status = "expired";
      return { valid: false, error: "Certificate has expired" };
    }
    
    return {
      valid: true,
      agentId: cert.agentId,
      organizationId: cert.organizationId,
      certificateId: cert.id,
    };
  }
  
  async validateByPublicKey(publicKeyPem: string): Promise<MTLSValidationResult> {
    const hash = crypto.createHash("sha256").update(publicKeyPem).digest("hex").toUpperCase();
    const certId = this.publicKeyHashIndex.get(hash);
    
    if (!certId) {
      return { valid: false, error: "Public key not found in trust store" };
    }
    
    const cert = this.certificates.get(certId);
    if (!cert) {
      return { valid: false, error: "Certificate data not found" };
    }
    
    if (cert.status === "revoked") {
      return { valid: false, error: `Certificate revoked: ${cert.revokedReason}` };
    }
    
    const now = new Date();
    if (now < cert.validFrom) {
      return { valid: false, error: "Certificate not yet valid" };
    }
    
    if (now > cert.validTo) {
      cert.status = "expired";
      return { valid: false, error: "Certificate has expired" };
    }
    
    return {
      valid: true,
      agentId: cert.agentId,
      organizationId: cert.organizationId,
      certificateId: cert.id,
    };
  }
  
  private pemToDer(pem: string): Buffer {
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s/g, "");
    return Buffer.from(base64, "base64");
  }
  
  async revokeCertificate(certificateId: string, reason: string): Promise<boolean> {
    const cert = this.certificates.get(certificateId);
    if (!cert) {
      return false;
    }
    
    cert.status = "revoked";
    cert.revokedAt = new Date();
    cert.revokedReason = reason;
    
    return true;
  }
  
  async getCertificate(certificateId: string): Promise<CertificateInfo | undefined> {
    return this.certificates.get(certificateId);
  }
  
  async getAgentCertificates(agentId: string): Promise<CertificateInfo[]> {
    const certIds = this.agentCertificates.get(agentId) || [];
    const certs: CertificateInfo[] = [];
    
    for (const certId of certIds) {
      const cert = this.certificates.get(certId);
      if (cert) {
        certs.push(cert);
      }
    }
    
    return certs;
  }
  
  async renewCertificate(certificateId: string): Promise<CertificateResponse | null> {
    const oldCert = this.certificates.get(certificateId);
    if (!oldCert) {
      return null;
    }
    
    if (oldCert.status === "revoked") {
      return null;
    }
    
    await this.revokeCertificate(certificateId, "Renewed - new certificate issued");
    
    const commonName = oldCert.subject.split(",")[0].replace("CN=", "");
    
    return this.generateCertificate({
      agentId: oldCert.agentId,
      organizationId: oldCert.organizationId,
      commonName,
    });
  }
  
  async revokeAllAgentCertificates(agentId: string, reason?: string): Promise<number> {
    const certIds = this.agentCertificates.get(agentId) || [];
    let count = 0;
    
    for (const certId of certIds) {
      const success = await this.revokeCertificate(certId, reason || "Agent credentials revoked");
      if (success) count++;
    }
    
    return count;
  }
  
  extractFingerprintFromHeader(certHeader: string): string | null {
    try {
      const match = certHeader.match(/fingerprint=([A-F0-9:]+)/i);
      if (match) {
        return match[1].replace(/:/g, "").toUpperCase();
      }
      return certHeader.replace(/:/g, "").toUpperCase();
    } catch {
      return null;
    }
  }
  
  async listAllCertificates(organizationId?: string): Promise<CertificateInfo[]> {
    const certs: CertificateInfo[] = [];
    const allCerts = Array.from(this.certificates.values());
    for (const cert of allCerts) {
      if (!organizationId || cert.organizationId === organizationId) {
        certs.push(cert);
      }
    }
    return certs;
  }
  
  async getActiveCertificateCount(): Promise<number> {
    let count = 0;
    const allCerts = Array.from(this.certificates.values());
    for (const cert of allCerts) {
      if (cert.status === "active") {
        count++;
      }
    }
    return count;
  }
  
  async cleanupExpiredCertificates(): Promise<number> {
    const now = new Date();
    let count = 0;
    const allCerts = Array.from(this.certificates.values());
    
    for (const cert of allCerts) {
      if (cert.status === "active" && now > cert.validTo) {
        cert.status = "expired";
        count++;
      }
    }
    
    return count;
  }
}

export const mtlsAuthService = new MTLSAuthService();
