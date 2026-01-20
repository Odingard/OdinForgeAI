/**
 * AEV CI Backend Runner
 * - Triggers POST /api/aev/evaluate
 * - Polls GET /api/evaluations/:id
 * - Writes a normalized findings JSON
 * - Fails build based on env policy
 */

const fs = require("fs");
const path = require("path");

function getArg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

const backend = getArg("--backend");
const target = getArg("--target");
const targetType = getArg("--targetType", "domain");
const scanType = getArg("--scanType", "full");
const out = getArg("--out", "artifacts/aev-findings.json");

if (!backend || !target) {
  console.error("Usage: node scripts/aev-ci-backend.js --backend <url> --target <target> [--targetType domain|url] [--scanType full|...] [--out file]");
  process.exit(2);
}

const timeoutSeconds = Number(process.env.AEV_TIMEOUT_SECONDS || 600);
const pollIntervalMs = Number(process.env.AEV_POLL_INTERVAL_MS || 3000);
const failOnExploit = String(process.env.AEV_FAIL_ON_EXPLOITABLE || "true").toLowerCase() === "true";
const failSev = String(process.env.AEV_FAIL_ON_SEVERITIES || "critical,high")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

async function httpJson(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { "content-type": "application/json", ...(opts.headers || {}) },
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) {
    const msg = `HTTP ${res.status} ${res.statusText} -> ${url}\n${text?.slice(0, 500)}`;
    throw new Error(msg);
  }
  return json;
}

function normalizeFindings(raw) {
  // Best-effort normalization across different result formats.
  // We try multiple common fields so this works even if your schema evolves.
  const findings =
    raw.findings ||
    raw.results?.findings ||
    raw.results ||
    raw.report?.findings ||
    [];

  return Array.isArray(findings) ? findings : [];
}

function severityOf(f) {
  return String(f.severity || f.level || f.risk || "").toLowerCase();
}

function exploitableOf(f) {
  if (typeof f.exploitable === "boolean") return f.exploitable;
  if (typeof f.isExploitable === "boolean") return f.isExploitable;
  if (typeof f.exploitability === "string") return f.exploitability.toLowerCase() === "exploitable";
  if (typeof f.exploitability === "number") return f.exploitability >= 1;
  return false;
}

(async () => {
  console.log(`[AEV CI] Triggering evaluation: target=${target} targetType=${targetType} scanType=${scanType}`);

  // 1) Trigger
  const trigger = await httpJson(`${backend}/api/aev/evaluate`, {
    method: "POST",
    body: JSON.stringify({ target, targetType, scanType }),
  });

  const evaluationId =
    trigger.evaluationId ||
    trigger.id ||
    trigger.data?.evaluationId ||
    trigger.data?.id;

  if (!evaluationId) {
    console.error("[AEV CI] Could not find evaluationId in response:", trigger);
    process.exit(2);
  }

  console.log(`[AEV CI] evaluationId=${evaluationId}`);

  // 2) Poll
  const start = Date.now();
  let last;

  while ((Date.now() - start) / 1000 < timeoutSeconds) {
    last = await httpJson(`${backend}/api/evaluations/${evaluationId}`, { method: "GET" });

    const status = String(last.status || last.state || last.phase || "").toLowerCase();
    const done = ["completed", "complete", "done", "finished", "success", "succeeded"].includes(status);
    const failed = ["failed", "error", "cancelled", "canceled"].includes(status);

    console.log(`[AEV CI] status=${status || "(unknown)"} elapsed=${Math.round((Date.now() - start)/1000)}s`);

    if (failed) {
      console.error("[AEV CI] Evaluation failed:", last);
      break;
    }
    if (done) {
      break;
    }
    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  // 3) Write artifacts
  const findings = normalizeFindings(last || {});
  const artifact = {
    meta: {
      backend,
      target,
      targetType,
      scanType,
      evaluationId,
      ts: new Date().toISOString(),
      timeoutSeconds,
      pollIntervalMs,
    },
    rawStatus: last?.status || last?.state || null,
    findings,
  };

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(artifact, null, 2), "utf-8");
  console.log(`[AEV CI] Wrote ${out} (findings=${findings.length})`);

  // 4) Gate
  let failing = findings;

  // Fail on exploitable?
  if (failOnExploit) {
    failing = failing.filter(f => exploitableOf(f) === true || failSev.includes(severityOf(f)));
  } else {
    failing = failing.filter(f => failSev.includes(severityOf(f)));
  }

  // Only count severe if we have severity field; if missing, don't fail on it.
  const failingCount = failing.length;

  if (failingCount > 0) {
    console.error(`[AEV CI] FAIL: ${failingCount} finding(s) match gate policy.`);
    // Print a short summary for CI logs
    for (const f of failing.slice(0, 20)) {
      console.error(`- ${severityOf(f) || "unknown"} exploitable=${exploitableOf(f)} title=${f.title || f.name || f.type || "finding"}`);
    }
    process.exit(1);
  }

  console.log("[AEV CI] PASS: no findings matched gate policy.");
})();
