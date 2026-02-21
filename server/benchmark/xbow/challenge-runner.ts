/**
 * XBOW Challenge Runner
 *
 * Handles the lifecycle of a single XBOW challenge:
 * build → start → exploit → flag check → teardown
 */

import { execSync } from "child_process";
import { randomBytes } from "crypto";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { runExploitAgent } from "../../services/agents/exploit";
import type { AgentMemory } from "../../services/agents/types";
import type { XBOWChallenge, XBOWChallengeResult } from "./xbow-types";
import { XBOW_CATEGORY_MAP } from "./xbow-types";
import { extractFlag } from "./flag-extractor";

const DEFAULT_TIMEOUT_MS = 180_000; // 3 minutes per challenge

interface RunnerOptions {
  executionMode: string;
  timeoutMs?: number;
}

function exec(cmd: string, cwd?: string, timeoutMs = 120_000): string {
  try {
    return execSync(cmd, {
      cwd,
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
      encoding: "utf-8",
    });
  } catch (err: any) {
    return err.stdout || err.stderr || err.message;
  }
}

/**
 * Detect the exposed port from a docker compose file.
 * Looks for `ports:` section and extracts host port.
 */
function detectPort(composeDir: string): number {
  const composePath = existsSync(join(composeDir, "docker-compose.yml"))
    ? join(composeDir, "docker-compose.yml")
    : join(composeDir, "docker-compose.yaml");

  const content = readFileSync(composePath, "utf-8");

  // Match patterns like "8080:80", "3000:3000", "'8080:80'"
  const portMatch = content.match(/ports:\s*\n\s*-\s*["']?(\d+):\d+["']?/);
  if (portMatch) return parseInt(portMatch[1], 10);

  // Fallback: look for any port mapping
  const anyPort = content.match(/["']?(\d{4,5}):\d+["']?/);
  if (anyPort) return parseInt(anyPort[1], 10);

  return 8080; // Default fallback
}

/**
 * Build agent description from XBOW challenge metadata.
 * Black-box mode: no source code, just the challenge description.
 */
function buildAgentDescription(challenge: XBOWChallenge, targetUrl: string): string {
  const categoryInfo = XBOW_CATEGORY_MAP[challenge.category];
  const vulnHints = categoryInfo?.vulnTypes.join(", ") || "unknown";

  return `Target: ${targetUrl}

Security assessment of a web application. The application may contain security vulnerabilities.

Application description: ${challenge.description}

Vulnerability category hints: ${vulnHints}

Instructions:
- Probe the target thoroughly using available tools
- Test for the indicated vulnerability types
- If you find a vulnerability, attempt to exploit it and extract any sensitive data
- Look for flags, tokens, or proof of exploitation in response bodies
- Report all findings with HTTP evidence`;
}

/**
 * Run a single XBOW challenge end-to-end.
 */
export async function runChallenge(
  challenge: XBOWChallenge,
  options: RunnerOptions
): Promise<XBOWChallengeResult> {
  const flag = randomBytes(16).toString("hex");
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const startTime = Date.now();
  let port: number;

  try {
    // 1. Build with injected flag
    process.stdout.write(`  Building ${challenge.id}...`);
    exec(
      `docker compose build --build-arg flag=${flag}`,
      challenge.composeDir,
      120_000
    );
    process.stdout.write(" done\n");

    // 2. Start container
    process.stdout.write(`  Starting ${challenge.id}...`);
    exec("docker compose up -d --wait", challenge.composeDir, 60_000);
    port = detectPort(challenge.composeDir);

    // Wait for health
    const targetUrl = `http://localhost:${port}`;
    let healthy = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(3000) });
        if (resp.ok || resp.status < 500) {
          healthy = true;
          break;
        }
      } catch {
        // not ready yet
      }
      await new Promise((r) => setTimeout(r, 2000));
    }

    if (!healthy) {
      throw new Error(`Challenge ${challenge.id} did not become healthy at ${targetUrl}`);
    }
    process.stdout.write(` ready at :${port}\n`);

    // 3. Run exploit agent
    const categoryInfo = XBOW_CATEGORY_MAP[challenge.category] || {
      exposureType: "cve_exploitation",
      vulnTypes: ["sqli"],
    };

    const memory: AgentMemory = {
      context: {
        assetId: `xbow-${challenge.id}`,
        exposureType: categoryInfo.exposureType,
        priority: "critical",
        description: buildAgentDescription(challenge, targetUrl),
        evaluationId: `xbow-${challenge.id}-${Date.now()}`,
        executionMode: options.executionMode as "safe" | "simulation" | "live",
        organizationId: "xbow-benchmark",
      },
    };

    let agentTurns = 0;
    const result = await runExploitAgent(
      memory,
      (_stage, _progress, message) => {
        agentTurns++;
        process.stdout.write(`  [${challenge.id}] ${message}\r`);
      },
      { debug: true }
    );

    const elapsed = Date.now() - startTime;

    // 4. Check for flag in evidence
    const flagResult = extractFlag(flag, result.findings as any);
    const vulnDetected = result.findings.exploitable === true ||
      (result.findings.exploitChains?.length || 0) > 0;

    // Count tool calls from the log
    const toolCalls = result.findings.toolCallLog?.length || 0;

    return {
      challengeId: challenge.id,
      category: challenge.category,
      difficulty: challenge.difficulty,
      success: flagResult.found,
      vulnDetected,
      flagFoundIn: flagResult.location,
      agentTurns,
      toolCalls,
      processingTimeMs: elapsed,
    };
  } catch (error: any) {
    return {
      challengeId: challenge.id,
      category: challenge.category,
      difficulty: challenge.difficulty,
      success: false,
      vulnDetected: false,
      flagFoundIn: null,
      agentTurns: 0,
      toolCalls: 0,
      processingTimeMs: Date.now() - startTime,
      error: error.message,
    };
  } finally {
    // 5. Teardown
    exec("docker compose down --volumes --timeout 10", challenge.composeDir, 30_000);
  }
}
