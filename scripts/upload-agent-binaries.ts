import { objectStorageClient } from "../server/replit_integrations/object_storage/objectStorage";
import * as fs from "fs";
import * as path from "path";

async function uploadBinaries() {
  const publicPaths = process.env.PUBLIC_OBJECT_SEARCH_PATHS || "";
  const publicDir = publicPaths.split(",")[0]?.trim();
  
  if (!publicDir) {
    console.error("PUBLIC_OBJECT_SEARCH_PATHS not set");
    process.exit(1);
  }
  
  console.log("Public directory:", publicDir);
  
  // Parse bucket and path
  const parts = publicDir.split("/").filter(Boolean);
  const bucketName = parts[0];
  const basePath = parts.slice(1).join("/");
  
  console.log("Bucket:", bucketName);
  console.log("Base path:", basePath);
  
  const bucket = objectStorageClient.bucket(bucketName);
  
  const binaries = [
    "odinforge-agent-linux-amd64",
    "odinforge-agent-linux-arm64",
    "odinforge-agent-darwin-amd64",
    "odinforge-agent-darwin-arm64",
    "odinforge-agent-windows-amd64.exe"
  ];
  
  for (const binary of binaries) {
    const localPath = path.join(process.cwd(), "public", "agents", binary);
    
    if (!fs.existsSync(localPath)) {
      console.log(`Skipping ${binary} - not found locally`);
      continue;
    }
    
    const objectPath = `${basePath}/agents/${binary}`;
    console.log(`Uploading ${binary} to ${objectPath}...`);
    
    try {
      await bucket.upload(localPath, {
        destination: objectPath,
        contentType: "application/octet-stream",
        metadata: {
          cacheControl: "public, max-age=86400",
        },
      });
      console.log(`✓ Uploaded ${binary}`);
    } catch (error) {
      console.error(`✗ Failed to upload ${binary}:`, error);
    }
  }
  
  console.log("\nDone!");
}

uploadBinaries().catch(console.error);
