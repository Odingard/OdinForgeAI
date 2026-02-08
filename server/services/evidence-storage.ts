import { storageService, StorageNotFoundError } from "./storage";
import { randomUUID } from "crypto";

export interface StoredEvidence {
  key: string;
  url: string;
  size: number;
  contentType: string;
}

/**
 * Evidence Storage Service
 * Manages storage of security testing evidence (screenshots, network captures, etc.)
 * Uses standard S3-compatible storage
 */
export class EvidenceStorageService {
  /**
   * Stores a screenshot from a security test
   */
  async storeScreenshot(
    evaluationId: string,
    executionId: string,
    screenshotData: Buffer,
    filename?: string
  ): Promise<StoredEvidence> {
    const objectId = randomUUID();
    const fileName = filename || `screenshot-${objectId}.png`;
    const key = `evidence/${evaluationId}/${executionId}/screenshots/${fileName}`;

    const storagePath = await storageService.uploadFile(key, screenshotData, "image/png");

    return {
      key: storagePath,
      url: `/api/evidence/${evaluationId}/${executionId}/screenshots/${fileName}`,
      size: screenshotData.length,
      contentType: "image/png",
    };
  }

  /**
   * Stores a network packet capture (PCAP file)
   */
  async storeNetworkCapture(
    evaluationId: string,
    executionId: string,
    pcapData: Buffer,
    filename?: string
  ): Promise<StoredEvidence> {
    const objectId = randomUUID();
    const fileName = filename || `capture-${objectId}.pcap`;
    const key = `evidence/${evaluationId}/${executionId}/pcaps/${fileName}`;

    const storagePath = await storageService.uploadFile(key, pcapData, "application/vnd.tcpdump.pcap");

    return {
      key: storagePath,
      url: `/api/evidence/${evaluationId}/${executionId}/pcaps/${fileName}`,
      size: pcapData.length,
      contentType: "application/vnd.tcpdump.pcap",
    };
  }

  /**
   * Stores generic evidence files
   */
  async storeGenericEvidence(
    evaluationId: string,
    executionId: string,
    data: Buffer,
    contentType: string,
    filename: string
  ): Promise<StoredEvidence> {
    const key = `evidence/${evaluationId}/${executionId}/files/${filename}`;
    const storagePath = await storageService.uploadFile(key, data, contentType);

    return {
      key: storagePath,
      url: `/api/evidence/${evaluationId}/${executionId}/files/${filename}`,
      size: data.length,
      contentType,
    };
  }

  /**
   * Retrieves evidence by storage key
   */
  async getEvidence(objectKey: string): Promise<Buffer | null> {
    try {
      const normalizedKey = storageService.getStorageKey(objectKey);
      const exists = await storageService.exists(normalizedKey);

      if (!exists) {
        return null;
      }

      // Note: This is a simplified implementation
      // For production, you might want to stream the data or use presigned URLs
      // instead of loading everything into memory
      throw new Error("Direct evidence retrieval not implemented - use presigned URLs instead");
    } catch (error) {
      console.error("[EvidenceStorage] Error retrieving evidence:", error);
      return null;
    }
  }

  /**
   * Generates a presigned URL for downloading evidence
   */
  async getEvidenceDownloadUrl(objectKey: string, expiresIn: number = 3600): Promise<string> {
    const normalizedKey = storageService.getStorageKey(objectKey);
    return await storageService.getDownloadURL(normalizedKey, expiresIn);
  }

  /**
   * Lists all evidence files for a specific execution
   * Note: This is a placeholder - proper implementation requires S3 ListObjects
   */
  async listEvidenceForExecution(
    evaluationId: string,
    executionId: string
  ): Promise<Array<{ key: string; name: string; size: number; contentType: string }>> {
    // This would require implementing S3 ListObjects functionality
    // For now, return empty array and log a warning
    console.warn(
      `[EvidenceStorage] listEvidenceForExecution called but not fully implemented. ` +
      `evaluationId: ${evaluationId}, executionId: ${executionId}`
    );
    return [];
  }
}

export const evidenceStorageService = new EvidenceStorageService();
