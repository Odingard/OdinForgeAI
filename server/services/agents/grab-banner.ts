/**
 * Worker-Container: TCP Banner Grabber
 *
 * Pure TypeScript function — NO LLM calls.
 * Opens a raw TCP socket to the target host + port, reads the initial
 * broadcast bytes (service banner), and returns structured data.
 *
 * This feeds into ReconFindings.bannerData.
 */

import * as net from "net";

export interface BannerResult {
  port: number;
  service: string;
  banner: string | null;
  versionInfo: string | null;
}

const BANNER_TIMEOUT_MS = 2_000;

/** Well-known port → service name mapping for common services. */
const PORT_SERVICE_MAP: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  465: "smtps",
  587: "submission",
  993: "imaps",
  995: "pop3s",
  3306: "mysql",
  3389: "rdp",
  5432: "postgresql",
  6379: "redis",
  8080: "http-proxy",
  8443: "https-alt",
  27017: "mongodb",
};

/**
 * Extract a version string from a service banner using common patterns.
 * Returns null if no version pattern is found.
 */
function extractVersion(banner: string): string | null {
  // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
  const sshMatch = banner.match(/SSH-[\d.]+-(\S+)/);
  if (sshMatch) return sshMatch[1];

  // FTP: "220 vsFTPd 3.0.5"
  const ftpMatch = banner.match(/\d{3}\s+(\S+\s+[\d.]+)/);
  if (ftpMatch) return ftpMatch[1];

  // SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
  const smtpMatch = banner.match(/220\s+\S+\s+ESMTP\s+(\S+)/);
  if (smtpMatch) return smtpMatch[1];

  // Generic version pattern: "ServiceName/1.2.3" or "ServiceName 1.2.3"
  const genericMatch = banner.match(/(\w+)[/\s]([\d]+\.[\d]+(?:\.[\d]+)?)/);
  if (genericMatch) return `${genericMatch[1]}/${genericMatch[2]}`;

  return null;
}

/**
 * Identify service name from banner content when port-based lookup is insufficient.
 */
function identifyService(port: number, banner: string | null): string {
  if (PORT_SERVICE_MAP[port]) return PORT_SERVICE_MAP[port];
  if (!banner) return "unknown";

  const lowerBanner = banner.toLowerCase();
  if (lowerBanner.includes("ssh")) return "ssh";
  if (lowerBanner.includes("ftp")) return "ftp";
  if (lowerBanner.includes("smtp") || lowerBanner.includes("esmtp")) return "smtp";
  if (lowerBanner.includes("http")) return "http";
  if (lowerBanner.includes("mysql")) return "mysql";
  if (lowerBanner.includes("postgresql") || lowerBanner.includes("postgres")) return "postgresql";
  if (lowerBanner.includes("redis")) return "redis";
  if (lowerBanner.includes("mongo")) return "mongodb";
  if (lowerBanner.includes("pop3")) return "pop3";
  if (lowerBanner.includes("imap")) return "imap";

  return "unknown";
}

/**
 * Grab a service banner from a single TCP port.
 *
 * Opens a raw TCP connection, waits up to BANNER_TIMEOUT_MS for the
 * server to send initial data, then closes the connection.
 *
 * This is a pure worker-container function — no LLM involved.
 */
export function grabBanner(host: string, port: number): Promise<BannerResult> {
  return new Promise<BannerResult>((resolve) => {
    const chunks: Buffer[] = [];
    let resolved = false;

    const finish = (banner: string | null) => {
      if (resolved) return;
      resolved = true;
      const service = identifyService(port, banner);
      const versionInfo = banner ? extractVersion(banner) : null;
      resolve({
        port,
        service,
        banner: banner ? banner.slice(0, 512) : null, // Cap banner length
        versionInfo,
      });
    };

    const socket = net.createConnection({ host, port, timeout: BANNER_TIMEOUT_MS }, () => {
      // Connection established — wait for data or timeout
    });

    socket.setTimeout(BANNER_TIMEOUT_MS);

    socket.on("data", (data) => {
      chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
      // Most banners arrive in one packet; resolve immediately after first data
      const raw = Buffer.concat(chunks).toString("utf-8").trim();
      socket.destroy();
      finish(raw || null);
    });

    socket.on("timeout", () => {
      socket.destroy();
      finish(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8").trim() : null);
    });

    socket.on("error", () => {
      socket.destroy();
      finish(null);
    });

    socket.on("close", () => {
      if (!resolved) {
        finish(chunks.length > 0 ? Buffer.concat(chunks).toString("utf-8").trim() : null);
      }
    });
  });
}

/**
 * Grab banners from multiple ports in parallel.
 * Returns a map of port → BannerResult.
 */
export async function grabBanners(
  host: string,
  ports: number[]
): Promise<Map<number, BannerResult>> {
  const results = await Promise.all(
    ports.map((port) => grabBanner(host, port))
  );
  const map = new Map<number, BannerResult>();
  for (const result of results) {
    map.set(result.port, result);
  }
  return map;
}
