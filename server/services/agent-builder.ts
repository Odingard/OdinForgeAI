import { execSync } from "child_process";
import { existsSync, mkdirSync } from "fs";
import path from "path";

const PLATFORMS = [
  { goos: "linux", goarch: "amd64" },
  { goos: "linux", goarch: "arm64" },
  { goos: "darwin", goarch: "amd64" },
  { goos: "darwin", goarch: "arm64" },
  { goos: "windows", goarch: "amd64" },
];

const OUTPUT_DIR = path.join(process.cwd(), "public", "agents");
const AGENT_DIR = path.join(process.cwd(), "odinforge-agent");

function getBinaryName(goos: string, goarch: string): string {
  const base = `odinforge-agent-${goos}-${goarch}`;
  return goos === "windows" ? `${base}.exe` : base;
}

function checkBinariesExist(): { missing: typeof PLATFORMS; existing: string[] } {
  const missing: typeof PLATFORMS = [];
  const existing: string[] = [];

  for (const platform of PLATFORMS) {
    const binaryPath = path.join(OUTPUT_DIR, getBinaryName(platform.goos, platform.goarch));
    if (existsSync(binaryPath)) {
      existing.push(getBinaryName(platform.goos, platform.goarch));
    } else {
      missing.push(platform);
    }
  }

  return { missing, existing };
}

function buildAgent(goos: string, goarch: string): boolean {
  const outputName = getBinaryName(goos, goarch);
  const outputPath = path.join(OUTPUT_DIR, outputName);

  try {
    console.log(`  Building ${goos}/${goarch}...`);
    execSync(
      `CGO_ENABLED=0 GOOS=${goos} GOARCH=${goarch} go build -ldflags="-s -w" -o "${outputPath}" ./cmd/agent/`,
      {
        cwd: AGENT_DIR,
        stdio: "pipe",
        timeout: 120000,
      }
    );
    console.log(`  -> ${outputName} built successfully`);
    return true;
  } catch (error) {
    console.error(`  -> Failed to build ${outputName}:`, error);
    return false;
  }
}

export async function ensureAgentBinaries(): Promise<void> {
  console.log("[AgentBuilder] Checking agent binaries...");

  if (!existsSync(OUTPUT_DIR)) {
    mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const { missing, existing } = checkBinariesExist();

  if (existing.length > 0) {
    console.log(`[AgentBuilder] Found ${existing.length} existing binaries: ${existing.join(", ")}`);
  }

  if (missing.length === 0) {
    console.log("[AgentBuilder] All agent binaries are present.");
    return;
  }

  console.log(`[AgentBuilder] Building ${missing.length} missing binaries...`);

  try {
    console.log("[AgentBuilder] Downloading Go dependencies...");
    execSync("go mod download", {
      cwd: AGENT_DIR,
      stdio: "pipe",
      timeout: 60000,
    });
  } catch (error) {
    console.error("[AgentBuilder] Failed to download Go dependencies:", error);
    return;
  }

  let successCount = 0;
  for (const platform of missing) {
    if (buildAgent(platform.goos, platform.goarch)) {
      successCount++;
    }
  }

  console.log(`[AgentBuilder] Built ${successCount}/${missing.length} binaries.`);
}

export function getAgentBinaryPath(platform: string): string | null {
  const binaryPath = path.join(OUTPUT_DIR, platform.startsWith("windows") 
    ? `odinforge-agent-${platform}.exe` 
    : `odinforge-agent-${platform}`);
  
  return existsSync(binaryPath) ? binaryPath : null;
}
