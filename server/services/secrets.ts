import * as crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

function getEncryptionKey(): Buffer {
  const key = process.env.CLOUD_CREDENTIALS_KEY || process.env.SESSION_SECRET || "odinforge-default-key-change-in-production";
  return crypto.scryptSync(key, "odinforge-salt", 32);
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyId: string;
}

export class SecretsService {
  private keyId: string;
  private key: Buffer;

  constructor() {
    this.keyId = "local-key-v1";
    this.key = getEncryptionKey();
  }

  encrypt(plaintext: string): EncryptedData {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);
    
    let ciphertext = cipher.update(plaintext, "utf8", "base64");
    ciphertext += cipher.final("base64");
    
    const authTag = cipher.getAuthTag();

    return {
      ciphertext,
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      keyId: this.keyId,
    };
  }

  decrypt(encrypted: EncryptedData): string {
    const iv = Buffer.from(encrypted.iv, "base64");
    const authTag = Buffer.from(encrypted.authTag, "base64");
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);
    
    let plaintext = decipher.update(encrypted.ciphertext, "base64", "utf8");
    plaintext += decipher.final("utf8");
    
    return plaintext;
  }

  encryptCredentials(credentials: Record<string, any>): { encryptedData: string; keyId: string } {
    const plaintext = JSON.stringify(credentials);
    const encrypted = this.encrypt(plaintext);
    
    return {
      encryptedData: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
      }),
      keyId: encrypted.keyId,
    };
  }

  decryptCredentials<T = Record<string, any>>(encryptedData: string, keyId: string): T {
    const parsed = JSON.parse(encryptedData);
    const plaintext = this.decrypt({
      ...parsed,
      keyId,
    });
    return JSON.parse(plaintext) as T;
  }

  encryptField(value: string): { encryptedData: string; keyId: string } {
    const encrypted = this.encrypt(value);
    return {
      encryptedData: JSON.stringify({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
      }),
      keyId: encrypted.keyId,
    };
  }

  decryptField(encryptedData: string, keyId: string): string {
    const parsed = JSON.parse(encryptedData);
    return this.decrypt({
      ...parsed,
      keyId,
    });
  }

  maskSensitiveValue(value: string, visibleChars: number = 4): string {
    if (value.length <= visibleChars * 2) {
      return "*".repeat(value.length);
    }
    const start = value.substring(0, visibleChars);
    const end = value.substring(value.length - visibleChars);
    const masked = "*".repeat(Math.max(8, value.length - visibleChars * 2));
    return `${start}${masked}${end}`;
  }
}

export const secretsService = new SecretsService();
