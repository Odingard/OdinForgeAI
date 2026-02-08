import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Response } from "express";
import { randomUUID } from "crypto";

/**
 * Storage Service - Standard S3-compatible storage implementation
 * Replaces Replit-specific object storage with standard AWS S3 or compatible storage
 * Supports AWS S3, MinIO, DigitalOcean Spaces, Cloudflare R2, etc.
 */

export class StorageNotFoundError extends Error {
  constructor() {
    super("Object not found");
    this.name = "StorageNotFoundError";
    Object.setPrototypeOf(this, StorageNotFoundError.prototype);
  }
}

// Initialize S3-compatible client
const s3Client = new S3Client({
  region: process.env.STORAGE_REGION || "us-east-1",
  endpoint: process.env.STORAGE_ENDPOINT, // Optional: for S3-compatible services like MinIO
  credentials: process.env.STORAGE_ACCESS_KEY_ID && process.env.STORAGE_SECRET_ACCESS_KEY
    ? {
        accessKeyId: process.env.STORAGE_ACCESS_KEY_ID,
        secretAccessKey: process.env.STORAGE_SECRET_ACCESS_KEY,
      }
    : undefined, // Falls back to AWS credential chain if not provided
  forcePathStyle: process.env.STORAGE_FORCE_PATH_STYLE === "true", // Required for MinIO and some S3-compatible services
});

export interface StorageAclPolicy {
  visibility: "public" | "private";
  allowedUsers?: string[];
}

export enum StoragePermission {
  READ = "read",
  WRITE = "write",
  DELETE = "delete",
}

export class StorageService {
  private bucketName: string;
  private publicPrefix: string;
  private privatePrefix: string;

  constructor() {
    this.bucketName = process.env.STORAGE_BUCKET_NAME || "";
    this.publicPrefix = process.env.STORAGE_PUBLIC_PREFIX || "public/";
    this.privatePrefix = process.env.STORAGE_PRIVATE_PREFIX || "private/";

    if (!this.bucketName) {
      console.warn(
        "[Storage] STORAGE_BUCKET_NAME not set. Storage operations will fail. " +
        "Configure S3-compatible storage with STORAGE_BUCKET_NAME, STORAGE_ACCESS_KEY_ID, " +
        "and STORAGE_SECRET_ACCESS_KEY environment variables."
      );
    }
  }

  /**
   * Uploads a file to storage
   */
  async uploadFile(key: string, data: Buffer, contentType?: string): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      Body: data,
      ContentType: contentType || "application/octet-stream",
    });

    await s3Client.send(command);
    return `/${key}`;
  }

  /**
   * Downloads a file and streams it to the response
   */
  async downloadFile(key: string, res: Response, cacheTtlSec: number = 3600): Promise<void> {
    try {
      // Get object metadata
      const headCommand = new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });
      const metadata = await s3Client.send(headCommand);

      // Determine if public based on key prefix
      const isPublic = key.startsWith(this.publicPrefix);

      // Set headers
      res.set({
        "Content-Type": metadata.ContentType || "application/octet-stream",
        "Content-Length": metadata.ContentLength?.toString() || "0",
        "Cache-Control": `${isPublic ? "public" : "private"}, max-age=${cacheTtlSec}`,
        "ETag": metadata.ETag || "",
      });

      // Get and stream the object
      const getCommand = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });
      const response = await s3Client.send(getCommand);

      if (response.Body) {
        // @ts-ignore - Body can be streamed
        response.Body.pipe(res);
      } else {
        throw new StorageNotFoundError();
      }
    } catch (error: any) {
      if (error.name === "NotFound" || error.$metadata?.httpStatusCode === 404) {
        throw new StorageNotFoundError();
      }
      console.error("[Storage] Error downloading file:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "Error downloading file" });
      }
    }
  }

  /**
   * Generates a presigned upload URL for direct client uploads
   */
  async getUploadURL(prefix: string = "uploads", expiresIn: number = 900): Promise<{ uploadUrl: string; objectKey: string }> {
    const objectId = randomUUID();
    const objectKey = `${this.privatePrefix}${prefix}/${objectId}`;

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: objectKey,
    });

    const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn });

    return {
      uploadUrl,
      objectKey: `/${objectKey}`,
    };
  }

  /**
   * Generates a presigned download URL
   */
  async getDownloadURL(key: string, expiresIn: number = 3600): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key.startsWith("/") ? key.slice(1) : key,
    });

    return await getSignedUrl(s3Client, command, { expiresIn });
  }

  /**
   * Checks if an object exists
   */
  async exists(key: string): Promise<boolean> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: key.startsWith("/") ? key.slice(1) : key,
      });
      await s3Client.send(command);
      return true;
    } catch (error: any) {
      if (error.name === "NotFound" || error.$metadata?.httpStatusCode === 404) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Normalizes object paths for consistency
   */
  normalizeObjectPath(rawPath: string): string {
    // Remove query parameters if present
    if (rawPath.includes("?")) {
      rawPath = rawPath.split("?")[0];
    }

    // If it's a full URL, extract just the path
    if (rawPath.startsWith("http://") || rawPath.startsWith("https://")) {
      try {
        const url = new URL(rawPath);
        rawPath = url.pathname;
      } catch (e) {
        // If URL parsing fails, use as-is
      }
    }

    // Ensure path starts with /
    if (!rawPath.startsWith("/")) {
      rawPath = `/${rawPath}`;
    }

    return rawPath;
  }

  /**
   * Gets the storage key from a normalized path
   */
  getStorageKey(normalizedPath: string): string {
    return normalizedPath.startsWith("/") ? normalizedPath.slice(1) : normalizedPath;
  }
}

// Export singleton instance
export const storageService = new StorageService();
