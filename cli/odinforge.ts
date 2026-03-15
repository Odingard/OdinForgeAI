#!/usr/bin/env npx tsx
/**
 * OdinForge CLI v1 — Managed Assessment Operations
 *
 * Commands:
 *   odinforge scan    <target> [--mode live|simulation|safe] [--phases 1,2,3,4,5,6]
 *   odinforge status  <chain-id>
 *   odinforge report  <chain-id> [--component ciso|engineer|evidence|defenders-mirror|replay]
 *   odinforge package <chain-id> --seal
 *   odinforge keys    <chain-id> [--create|--list|--revoke <key-id>]
 *
 * All commands require ODINFORGE_API_URL and ODINFORGE_API_KEY env vars.
 */

const API_URL = process.env.ODINFORGE_API_URL || "http://localhost:5000";
const API_KEY = process.env.ODINFORGE_API_KEY || "";

// ─── HTTP Client ─────────────────────────────────────────────────────────────

async function api(
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: Record<string, unknown>
): Promise<{ status: number; data: any }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (API_KEY) {
    headers["Authorization"] = `Bearer ${API_KEY}`;
  }

  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data: any;
  try { data = JSON.parse(text); } catch { data = text; }

  return { status: res.status, data };
}

function die(msg: string): never {
  console.error(`\x1b[31mError:\x1b[0m ${msg}`);
  process.exit(1);
}

function ok(msg: string): void {
  console.log(`\x1b[32m[OK]\x1b[0m ${msg}`);
}

function info(msg: string): void {
  console.log(`\x1b[36m[INFO]\x1b[0m ${msg}`);
}

// ─── Commands ────────────────────────────────────────────────────────────────

async function cmdScan(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) die("Usage: odinforge scan <target-url> [--mode live] [--phases 1,2,3,4,5,6]");

  let mode = "live";
  let phases = ["application_compromise", "credential_extraction", "cloud_iam_escalation", "container_k8s_breakout", "lateral_movement", "impact_assessment"];
  const phaseMap: Record<string, string> = {
    "1": "application_compromise",
    "2": "credential_extraction",
    "3": "cloud_iam_escalation",
    "4": "container_k8s_breakout",
    "5": "lateral_movement",
    "6": "impact_assessment",
  };

  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--mode" && args[i + 1]) { mode = args[++i]; }
    if (args[i] === "--phases" && args[i + 1]) {
      phases = args[++i].split(",").map(n => phaseMap[n.trim()] || n.trim());
    }
  }

  info(`Starting breach chain against ${target} (mode: ${mode}, phases: ${phases.length})`);

  const { status, data } = await api("POST", "/api/breach-chains", {
    name: `CLI Assessment: ${target}`,
    description: `Managed assessment via OdinForge CLI`,
    assetIds: [target],
    config: {
      enabledPhases: phases,
      executionMode: mode,
      adversaryProfile: "apt",
      maxConcurrentAgents: 50,
      requireCredentialForCloud: true,
      requireCloudAccessForK8s: false,
    },
  });

  if (status >= 400) die(`Failed to start scan: ${JSON.stringify(data)}`);
  ok(`Breach chain started: ${data.id || data.chainId || "unknown"}`);
  console.log(JSON.stringify(data, null, 2));
}

async function cmdStatus(args: string[]): Promise<void> {
  const chainId = args[0];
  if (!chainId) die("Usage: odinforge status <chain-id>");

  const { status, data } = await api("GET", `/api/breach-chains/${chainId}`);
  if (status >= 400) die(`Failed to get status: ${JSON.stringify(data)}`);

  const chain = data;
  info(`Chain: ${chain.id}`);
  info(`Status: ${chain.status} | Progress: ${chain.progress}%`);
  info(`Phase: ${chain.currentPhase || "none"}`);
  info(`Risk Score: ${chain.overallRiskScore ?? "N/A"}`);
  info(`Assets Compromised: ${chain.totalAssetsCompromised ?? 0}`);
  info(`Credentials Harvested: ${chain.totalCredentialsHarvested ?? 0}`);
  info(`Domains Breached: ${(chain.domainsBreached || []).join(", ") || "none"}`);
  info(`Max Privilege: ${chain.maxPrivilegeAchieved || "none"}`);
}

async function cmdReport(args: string[]): Promise<void> {
  const chainId = args[0];
  if (!chainId) die("Usage: odinforge report <chain-id> [--component ciso|engineer|evidence|defenders-mirror|replay]");

  let component: string | undefined;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--component" && args[i + 1]) { component = args[++i]; }
  }

  const query = component ? `?component=${component}` : "";
  const { status, data } = await api("GET", `/api/breach-chains/${chainId}/package${query}`);
  if (status >= 400) die(`Failed to get report: ${JSON.stringify(data)}`);

  if (component === "replay" && typeof data === "string") {
    // Write HTML to file
    const fs = await import("fs");
    const outPath = `odinforge-replay-${chainId}.html`;
    fs.writeFileSync(outPath, data);
    ok(`Replay HTML written to ${outPath}`);
  } else {
    console.log(JSON.stringify(data, null, 2));
  }
}

async function cmdPackage(args: string[]): Promise<void> {
  const chainId = args[0];
  if (!chainId) die("Usage: odinforge package <chain-id> --seal");

  const shouldSeal = args.includes("--seal");
  if (!shouldSeal) {
    die("Must specify --seal to seal the engagement package. This action is irreversible.");
  }

  info(`Sealing engagement package for chain ${chainId}...`);
  const { status, data } = await api("POST", `/api/breach-chains/${chainId}/seal`);
  if (status >= 400) die(`Failed to seal package: ${JSON.stringify(data)}`);

  ok(`Package sealed: ${data.package?.packageId}`);
  info(`Risk Grade: ${data.package?.metadata?.riskGrade}`);
  info(`Customer Findings: ${data.package?.metadata?.customerFindings}`);
  info(`Package Hash: ${data.package?.integrity?.packageHash}`);
  info(`API Keys Deactivated: ${data.deactivatedApiKeys}`);

  if (data.reengagementOffer) {
    info(`Reengagement Offer: ${data.reengagementOffer.offerId}`);
    info(`  Expires: ${data.reengagementOffer.expiresAt}`);
    info(`  Price: $${data.reengagementOffer.pricing?.reengagementPrice} (${data.reengagementOffer.pricing?.discountPercent}% off)`);
  }
}

async function cmdKeys(args: string[]): Promise<void> {
  const chainId = args[0];
  if (!chainId) die("Usage: odinforge keys <chain-id> [--create|--list|--revoke <key-id>]");

  if (args.includes("--create")) {
    const { status, data } = await api("POST", `/api/breach-chains/${chainId}/api-key`);
    if (status >= 400) die(`Failed to create key: ${JSON.stringify(data)}`);
    ok(`API Key Created: ${data.keyId}`);
    console.log(`\x1b[33mPlaintext Key (save this — shown only once):\x1b[0m`);
    console.log(data.plaintextKey);
    info(`Expires: ${data.expiresAt}`);
  } else if (args.includes("--revoke")) {
    const keyId = args[args.indexOf("--revoke") + 1];
    if (!keyId) die("Usage: odinforge keys <chain-id> --revoke <key-id>");
    die("Key revocation via CLI not yet implemented — use the API directly");
  } else {
    // Default: list
    const { status, data } = await api("GET", `/api/breach-chains/${chainId}/api-keys`);
    if (status >= 400) die(`Failed to list keys: ${JSON.stringify(data)}`);
    if (Array.isArray(data) && data.length === 0) {
      info("No API keys for this engagement");
    } else {
      console.log(JSON.stringify(data, null, 2));
    }
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const cmdArgs = args.slice(1);

  console.log("\x1b[36m" + `
   ___  __   __ _  ____  __  ____  ___  ____
  / __)(  ) (  ( \\(  __)/  \\(  _ \\/ __)(  __)
 ( (  ) )(  /    / ) _)(  O ))   /( (_ \\ ) _)
  \\___)(__)(\\_)__)(____)\\__/(__\\_) \\___/(____)
                                    AEV CLI v1
` + "\x1b[0m");

  if (!command || command === "--help" || command === "-h") {
    console.log(`Usage: odinforge <command> [options]

Commands:
  scan    <target>     Start a breach chain assessment
  status  <chain-id>   Check breach chain status
  report  <chain-id>   Download engagement report/component
  package <chain-id>   Seal engagement package (--seal required)
  keys    <chain-id>   Manage per-engagement API keys

Environment:
  ODINFORGE_API_URL    API base URL (default: http://localhost:5000)
  ODINFORGE_API_KEY    Authentication token
`);
    return;
  }

  if (!API_KEY) {
    console.warn("\x1b[33m[WARN]\x1b[0m ODINFORGE_API_KEY not set — requests may fail auth\n");
  }

  switch (command) {
    case "scan":    return cmdScan(cmdArgs);
    case "status":  return cmdStatus(cmdArgs);
    case "report":  return cmdReport(cmdArgs);
    case "package": return cmdPackage(cmdArgs);
    case "keys":    return cmdKeys(cmdArgs);
    default:        die(`Unknown command: ${command}. Run 'odinforge --help' for usage.`);
  }
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
