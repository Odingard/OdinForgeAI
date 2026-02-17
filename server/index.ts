import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { createDatabaseIndexes } from "./db-indexes";
import { seedSystemRoles, seedDefaultUIUsers } from "./services/ui-auth";
import { ensureAgentBinaries } from "./services/agent-builder";
import { queueService } from "./services/queue";
import { registerJobHandlers } from "./services/queue/handlers";
import { initScheduler } from "./services/scheduler/scan-scheduler";
import { startReconciliationScheduler, runReconciliation } from "./services/data-reconciliation";
import { gunzipSync, inflateSync } from "zlib";
import { envConfig, logEnvironmentInfo } from "./lib/environment";
import { initializeRLS } from "./services/rls-setup";
import { initWsBridge } from "./services/ws-bridge";

const app = express();
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

// Middleware to decompress gzip/deflate request bodies from Go agent
// Must be placed BEFORE express.json() parser
app.use((req: Request, res: Response, next: NextFunction) => {
  const contentEncoding = req.headers["content-encoding"];
  
  if (!contentEncoding) {
    return next();
  }
  
  const chunks: Buffer[] = [];
  
  req.on("data", (chunk: Buffer) => {
    chunks.push(chunk);
  });
  
  req.on("end", () => {
    if (chunks.length === 0) {
      // Empty compressed body - set empty object and continue
      (req as any).body = {};
      (req as any)._body = true;
      delete req.headers["content-encoding"];
      return next();
    }
    
    const compressed = Buffer.concat(chunks);
    
    try {
      let decompressed: Buffer;
      
      if (contentEncoding === "gzip") {
        decompressed = gunzipSync(compressed);
      } else if (contentEncoding === "deflate") {
        decompressed = inflateSync(compressed);
      } else {
        // Unknown encoding, pass through
        return next();
      }
      
      const decompressedStr = decompressed.toString("utf-8").trim();
      
      // Log what we received for debugging agent communication
      if (req.path.includes("/agents/events")) {
        console.log(`[Decompress] Agent events - compressed size: ${compressed.length}, decompressed size: ${decompressed.length}`);
        console.log(`[Decompress] Compressed hex: ${compressed.toString("hex").substring(0, 100)}`);
        console.log(`[Decompress] Decompressed content preview: ${decompressedStr.substring(0, 200)}`);
      }
      
      // Handle empty decompressed content (agent sending empty gzip)
      if (!decompressedStr || decompressedStr === "") {
        // Set a default empty events structure for agent events endpoint
        if (req.path.includes("/agents/events")) {
          (req as any).body = { events: [] };
        } else {
          (req as any).body = {};
        }
        (req as any)._body = true;
        delete req.headers["content-encoding"];
        return next();
      }
      
      // Replace request body with decompressed data
      (req as any).body = JSON.parse(decompressedStr);
      // Remove content-encoding header so downstream parsers don't try to decompress again
      delete req.headers["content-encoding"];
      // Mark as already parsed
      (req as any)._body = true;
      
      next();
    } catch (err) {
      console.error("[Decompress] Error decompressing request:", err);
      res.status(400).json({ error: "Failed to decompress request body" });
    }
  });
  
  req.on("error", (err) => {
    console.error("[Decompress] Stream error:", err);
    res.status(400).json({ error: "Request stream error" });
  });
});

// JSON body parser for non-compressed requests
app.use(
  express.json({
    limit: "10mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

// Serve agent binaries directly - must be before Vite middleware
import path from "path";
app.use("/agents", express.static(path.join(process.cwd(), "public", "agents"), {
  redirect: false, // Don't redirect /agents → /agents/ (conflicts with SPA route)
  setHeaders: (res) => {
    res.setHeader("Content-Type", "application/octet-stream");
  }
}));

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  try {
    await createDatabaseIndexes();
  } catch (error) {
    console.warn("Database indexing skipped:", error instanceof Error ? error.message : error);
  }
  
  // Seed system roles first (must exist before creating users)
  try {
    await seedSystemRoles();
  } catch (error) {
    console.warn("Role seeding skipped:", error instanceof Error ? error.message : error);
  }
  
  // Seed default UI admin user (for development/demo only)
  try {
    await seedDefaultUIUsers();
  } catch (error) {
    console.warn("UI user seeding skipped:", error instanceof Error ? error.message : error);
  }
  
  // Build agent binaries if not present
  try {
    await ensureAgentBinaries();
  } catch (error) {
    console.warn("Agent binary build skipped:", error instanceof Error ? error.message : error);
  }
  
  // Initialize Row-Level Security for multi-tenant isolation
  try {
    await initializeRLS();
  } catch (error) {
    console.warn("[RLS] Initialization skipped:", error instanceof Error ? error.message : error);
  }
  
  // Initialize job queue service
  try {
    await queueService.initialize();
    if (process.env.DISABLE_WORKER === "true") {
      console.log(`Job queue initialized in queue-only mode (worker disabled, using ${queueService.isUsingRedis() ? "Redis" : "in-memory fallback"})`);
    } else {
      registerJobHandlers();
      console.log(`Job queue initialized with worker (using ${queueService.isUsingRedis() ? "Redis" : "in-memory fallback"})`);
    }
  } catch (error) {
    console.warn("Job queue initialization failed:", error instanceof Error ? error.message : error);
  }

  // Initialize WebSocket bridge in app mode (subscribes to Redis pub/sub for worker events)
  try {
    await initWsBridge("app");
  } catch (error) {
    console.warn("WS bridge initialization failed:", error instanceof Error ? error.message : error);
  }
  
  // Initialize scheduled scan scheduler
  try {
    initScheduler();
  } catch (error) {
    console.warn("Scheduler initialization failed:", error instanceof Error ? error.message : error);
  }
  
  // Initialize data reconciliation scheduler and run initial cleanup
  try {
    startReconciliationScheduler();
    // Run an initial reconciliation on startup to clean any stale data
    runReconciliation().catch(err => {
      console.warn("Initial data reconciliation failed:", err instanceof Error ? err.message : err);
    });
  } catch (error) {
    console.warn("Data reconciliation scheduler initialization failed:", error instanceof Error ? error.message : error);
  }
  
  // Production environment warnings
  if (process.env.NODE_ENV === "production") {
    const warnings: string[] = [];
    if (!process.env.REDIS_URL) {
      warnings.push("REDIS_URL not set - using in-memory queue (not recommended for production)");
    }
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === "dev-secret-change-in-production") {
      warnings.push("SESSION_SECRET not set or using default - set a strong secret for production");
    }
    if (!process.env.ADMIN_API_KEY) {
      warnings.push("ADMIN_API_KEY not set - admin endpoints are less secure");
    }
    if (warnings.length > 0) {
      console.warn("[Production] Environment configuration warnings:");
      warnings.forEach(w => console.warn(`  - ${w}`));
    }
  }
  
  await registerRoutes(httpServer, app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      logEnvironmentInfo();
      log(`serving on port ${port}`);
    },
  );
})();
