import { db } from "../db";
import { auditLogs, forensicExports, aevEvaluations, type ForensicExport } from "@shared/schema";
import { eq, asc } from "drizzle-orm";
import { createCipheriv, createDecipheriv, randomBytes, createHash, scrypt } from "crypto";
import { promisify } from "util";
import { evidenceStorageService } from "./evidence-storage";
import { ObjectStorageService, objectStorageClient } from "../replit_integrations/object_storage";

const scryptAsync = promisify(scrypt);

export interface ForensicExportBundle {
  metadata: {
    evaluationId: string;
    executionId: string;
    exportedAt: string;
    exportedBy: string;
    logCount: number;
    includesScreenshots: boolean;
    includesNetworkCaptures: boolean;
  };
  auditLogs: Array<{
    id: string;
    timestamp: string;
    agentName: string;
    logType: string;
    content: string | null;
    decision: string | null;
    decisionReason: string | null;
    prompt: string | null;
    response: string | null;
    commandInput: string | null;
    commandOutput: string | null;
    modelUsed: string | null;
    tokenCount: number | null;
    durationMs: number | null;
    metadata: Record<string, unknown> | null;
    checksum: string | null;
  }>;
  evidenceFiles: Array<{
    key: string;
    name: string;
    contentType: string;
    size: number;
    base64Data?: string;
  }>;
}

export class ForensicExportService {
  private readonly ALGORITHM = "aes-256-gcm";
  private readonly IV_LENGTH = 16;
  private readonly SALT_LENGTH = 32;
  private readonly TAG_LENGTH = 16;

  private async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
    return scryptAsync(password, salt, 32) as Promise<Buffer>;
  }

  async createExport(
    evaluationId: string,
    executionId: string,
    exportedBy: string,
    encryptionPassword: string,
    includeEvidenceFiles: boolean = true
  ): Promise<{ exportId: string; downloadKey: string }> {
    const [evaluation] = await db.select()
      .from(aevEvaluations)
      .where(eq(aevEvaluations.id, evaluationId));

    if (!evaluation) {
      throw new Error(`Evaluation ${evaluationId} not found`);
    }

    const logs = await db.select()
      .from(auditLogs)
      .where(eq(auditLogs.evaluationId, evaluationId))
      .orderBy(asc(auditLogs.sequenceNumber));

    const hasScreenshots = logs.some((log) => log.logType === "screenshot");
    const hasNetworkCaptures = logs.some((log) => log.logType === "network_capture");

    const evidenceFiles: ForensicExportBundle["evidenceFiles"] = [];
    
    if (includeEvidenceFiles) {
      const files = await evidenceStorageService.listEvidenceForExecution(evaluationId, executionId);
      
      for (const file of files) {
        const data = await evidenceStorageService.getEvidence(file.key);
        if (data) {
          evidenceFiles.push({
            key: file.key,
            name: file.name,
            contentType: file.contentType,
            size: file.size,
            base64Data: data.toString("base64"),
          });
        }
      }
    }

    const bundle: ForensicExportBundle = {
      metadata: {
        evaluationId,
        executionId,
        exportedAt: new Date().toISOString(),
        exportedBy,
        logCount: logs.length,
        includesScreenshots: hasScreenshots,
        includesNetworkCaptures: hasNetworkCaptures,
      },
      auditLogs: logs.map((log) => ({
        id: log.id,
        timestamp: log.createdAt.toISOString(),
        agentName: log.agentName,
        logType: log.logType,
        content: log.content,
        decision: log.decision,
        decisionReason: log.decisionReason,
        prompt: log.prompt,
        response: log.response,
        commandInput: log.commandInput,
        commandOutput: log.commandOutput,
        modelUsed: log.modelUsed,
        tokenCount: log.tokenCount,
        durationMs: log.durationMs,
        metadata: log.metadata,
        checksum: log.checksum,
      })),
      evidenceFiles,
    };

    const jsonContent = JSON.stringify(bundle, null, 2);
    const encryptedData = await this.encrypt(jsonContent, encryptionPassword);

    const downloadKey = randomBytes(32).toString("hex");
    const exportId = `export-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const privateDir = process.env.PRIVATE_OBJECT_DIR || "";
    const objectPath = `${privateDir}/exports/${evaluationId}/${exportId}.enc`;
    
    const { bucketName, objectPath: filePath } = this.parseBucketAndPath(objectPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(filePath);

    await file.save(encryptedData, {
      contentType: "application/octet-stream",
      metadata: {
        evaluationId,
        executionId,
        exportedBy,
        encrypted: "true",
      },
    });

    const encryptionKeyHash = createHash("sha256").update(encryptionPassword).digest("hex").substring(0, 16);

    await db.insert(forensicExports).values({
      id: exportId,
      evaluationId,
      executionId,
      organizationId: evaluation.organizationId || "default",
      exportedBy,
      encryptionKeyHash,
      objectStorageKey: `/${bucketName}/${filePath}`,
      fileSize: encryptedData.length,
      logCount: logs.length,
      includesScreenshots: hasScreenshots,
      includesNetworkCaptures: hasNetworkCaptures,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      metadata: {
        bundleVersion: "1.0",
        evidenceFileCount: evidenceFiles.length,
      },
    });

    return { exportId, downloadKey };
  }

  async downloadExport(exportId: string): Promise<{ data: Buffer; filename: string } | null> {
    const [exportRecord] = await db.select()
      .from(forensicExports)
      .where(eq(forensicExports.id, exportId));

    if (!exportRecord) {
      return null;
    }

    const { bucketName, objectPath } = this.parseBucketAndPath(exportRecord.objectStorageKey);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectPath);

    const [exists] = await file.exists();
    if (!exists) {
      return null;
    }

    const [data] = await file.download();

    await db.update(forensicExports)
      .set({ downloadCount: (exportRecord.downloadCount || 0) + 1 })
      .where(eq(forensicExports.id, exportId));

    return {
      data,
      filename: `forensic-export-${exportRecord.evaluationId}-${exportId}.enc.json`,
    };
  }

  async decryptExport(encryptedData: Buffer, password: string): Promise<ForensicExportBundle> {
    const decryptedJson = await this.decrypt(encryptedData, password);
    return JSON.parse(decryptedJson);
  }

  private async encrypt(plaintext: string, password: string): Promise<Buffer> {
    const salt = randomBytes(this.SALT_LENGTH);
    const key = await this.deriveKey(password, salt);
    const iv = randomBytes(this.IV_LENGTH);

    const cipher = createCipheriv(this.ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, authTag, encrypted]);
  }

  private async decrypt(encryptedData: Buffer, password: string): Promise<string> {
    const salt = encryptedData.subarray(0, this.SALT_LENGTH);
    const iv = encryptedData.subarray(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
    const authTag = encryptedData.subarray(
      this.SALT_LENGTH + this.IV_LENGTH,
      this.SALT_LENGTH + this.IV_LENGTH + this.TAG_LENGTH
    );
    const encrypted = encryptedData.subarray(this.SALT_LENGTH + this.IV_LENGTH + this.TAG_LENGTH);

    const key = await this.deriveKey(password, salt);
    const decipher = createDecipheriv(this.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  }

  private parseBucketAndPath(fullPath: string): { bucketName: string; objectPath: string } {
    const cleanPath = fullPath.startsWith("/") ? fullPath.slice(1) : fullPath;
    const parts = cleanPath.split("/");
    if (parts.length < 2) {
      throw new Error("Invalid object storage path");
    }
    return {
      bucketName: parts[0],
      objectPath: parts.slice(1).join("/"),
    };
  }

  async getExportHistory(evaluationId: string): Promise<ForensicExport[]> {
    return db.select()
      .from(forensicExports)
      .where(eq(forensicExports.evaluationId, evaluationId));
  }
}

export const forensicExportService = new ForensicExportService();
