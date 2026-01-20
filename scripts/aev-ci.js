/**
 * AEV CI runner (safe + deterministic)
 * - Calls your AEV engine in a conservative way
 * - Writes findings JSON
 * - Exits non-zero only if "exploitable" findings exist
 *
 * Replace the TODO section with your real internal AEV invocation.
 */

const fs = require("fs");
const path = require("path");

function getArg(flag) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

const frontend = getArg("--frontend");
const backend = getArg("--backend");
const out = getArg("--out") || "artifacts/aev-findings.json";

if (!frontend || !backend) {
  console.error("Usage: npm run aev:ci -- --frontend <url> --backend <url> --out <file>");
  process.exit(2);
}

const mode = process.env.AEV_MODE || "ci";
const failOn = process.env.AEV_FAIL_ON || "exploitable";

(async () => {
  console.log(`[AEV CI] mode=${mode} frontend=${frontend} backend=${backend} failOn=${failOn}`);

  // TODO: Replace this stub with your real AEV execution.
  // Examples:
  // - call internal Node module that runs the scan
  // - call your backend endpoint that triggers a scan and returns findings
  // - run a local binary if AEV is compiled
  //
  // For now, we write a minimal JSON skeleton so the pipeline wiring is complete.
  const findings = {
    meta: {
      mode,
      frontend,
      backend,
      ts: new Date().toISOString(),
      budget: {
        maxRequests: Number(process.env.AEV_MAX_REQUESTS || 150),
        timeoutSeconds: Number(process.env.AEV_TIMEOUT_SECONDS || 45),
      },
    },
    findings: [],
  };

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(findings, null, 2), "utf-8");
  console.log(`[AEV CI] wrote ${out}`);

  // Gate logic: fail only if exploitable exists
  const exploitable = (findings.findings || []).filter(f => f.exploitable === true);
  if (failOn === "exploitable" && exploitable.length > 0) {
    console.error(`[AEV CI] FAIL: exploitable findings=${exploitable.length}`);
    process.exit(1);
  }

  console.log("[AEV CI] PASS");
})();
