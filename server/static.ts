import express, { type Express } from "express";
import fs from "fs";
import path from "path";

export function serveStatic(app: Express) {
  const distPath = path.resolve(__dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`,
    );
  }

  app.use(express.static(distPath));

  // SPA fallback - serves index.html for client-side routing
  // Note: Rate limiting is intentionally omitted for static assets.
  // Static content should be rate-limited at the CDN/reverse proxy layer in production
  // (e.g., nginx, Cloudflare, AWS CloudFront) for better performance and flexibility.
  app.use("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
