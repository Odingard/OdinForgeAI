import { ObjectStorageService, objectStorageClient } from "../replit_integrations/object_storage";
import { randomUUID } from "crypto";

export interface StoredEvidence {
  key: string;
  url: string;
  size: number;
  contentType: string;
}

export class EvidenceStorageService {
  private objectStorage: ObjectStorageService;

  constructor() {
    this.objectStorage = new ObjectStorageService();
  }

  private getPrivateDir(): string {
    const dir = process.env.PRIVATE_OBJECT_DIR || "";
    if (!dir) {
      throw new Error("PRIVATE_OBJECT_DIR not configured for evidence storage");
    }
    return dir;
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

  async storeScreenshot(
    evaluationId: string,
    executionId: string,
    screenshotData: Buffer,
    filename?: string
  ): Promise<StoredEvidence> {
    const privateDir = this.getPrivateDir();
    const objectId = randomUUID();
    const fileName = filename || `screenshot-${objectId}.png`;
    const fullPath = `${privateDir}/evidence/${evaluationId}/${executionId}/screenshots/${fileName}`;

    const { bucketName, objectPath } = this.parseBucketAndPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectPath);

    await file.save(screenshotData, {
      contentType: "image/png",
      metadata: {
        evaluationId,
        executionId,
        evidenceType: "screenshot",
      },
    });

    return {
      key: `/${bucketName}/${objectPath}`,
      url: `/objects/evidence/${evaluationId}/${executionId}/screenshots/${fileName}`,
      size: screenshotData.length,
      contentType: "image/png",
    };
  }

  async storeNetworkCapture(
    evaluationId: string,
    executionId: string,
    pcapData: Buffer,
    filename?: string
  ): Promise<StoredEvidence> {
    const privateDir = this.getPrivateDir();
    const objectId = randomUUID();
    const fileName = filename || `capture-${objectId}.pcap`;
    const fullPath = `${privateDir}/evidence/${evaluationId}/${executionId}/pcaps/${fileName}`;

    const { bucketName, objectPath } = this.parseBucketAndPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectPath);

    await file.save(pcapData, {
      contentType: "application/vnd.tcpdump.pcap",
      metadata: {
        evaluationId,
        executionId,
        evidenceType: "network_capture",
      },
    });

    return {
      key: `/${bucketName}/${objectPath}`,
      url: `/objects/evidence/${evaluationId}/${executionId}/pcaps/${fileName}`,
      size: pcapData.length,
      contentType: "application/vnd.tcpdump.pcap",
    };
  }

  async storeGenericEvidence(
    evaluationId: string,
    executionId: string,
    data: Buffer,
    contentType: string,
    filename: string
  ): Promise<StoredEvidence> {
    const privateDir = this.getPrivateDir();
    const fullPath = `${privateDir}/evidence/${evaluationId}/${executionId}/files/${filename}`;

    const { bucketName, objectPath } = this.parseBucketAndPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(objectPath);

    await file.save(data, {
      contentType,
      metadata: {
        evaluationId,
        executionId,
        evidenceType: "generic",
      },
    });

    return {
      key: `/${bucketName}/${objectPath}`,
      url: `/objects/evidence/${evaluationId}/${executionId}/files/${filename}`,
      size: data.length,
      contentType,
    };
  }

  async getEvidence(objectKey: string): Promise<Buffer | null> {
    try {
      const { bucketName, objectPath } = this.parseBucketAndPath(objectKey);
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectPath);

      const [exists] = await file.exists();
      if (!exists) {
        return null;
      }

      const [data] = await file.download();
      return data;
    } catch (error) {
      console.error("Error retrieving evidence:", error);
      return null;
    }
  }

  async listEvidenceForExecution(
    evaluationId: string,
    executionId: string
  ): Promise<Array<{ key: string; name: string; size: number; contentType: string }>> {
    try {
      const privateDir = this.getPrivateDir();
      const prefix = `evidence/${evaluationId}/${executionId}/`;
      const fullPrefix = `${privateDir}/${prefix}`;

      const { bucketName, objectPath } = this.parseBucketAndPath(fullPrefix);
      const bucket = objectStorageClient.bucket(bucketName);

      const [files] = await bucket.getFiles({ prefix: objectPath });

      return files.map((file) => ({
        key: `/${bucketName}/${file.name}`,
        name: file.name.split("/").pop() || file.name,
        size: Number(file.metadata.size) || 0,
        contentType: String(file.metadata.contentType) || "application/octet-stream",
      }));
    } catch (error) {
      console.error("Error listing evidence:", error);
      return [];
    }
  }
}

export const evidenceStorageService = new EvidenceStorageService();
