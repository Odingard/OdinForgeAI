/**
 * AEV CI Backend Runner (Phase 7)
 * - Triggers POST /api/aev/evaluate
 * - Polls GET /api/evaluations/:id until status === "completed" or "failed"
 * - Writes normalized findings JSON to --out
 * - Writes PR summary markdown to artifacts/aev-summary.md
 * - Uses a policy file (aev-gate-policy.json) when present
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
  console.error(
    "Usage: node scripts/aev-ci-backend.js --backend <url> --target <target> [--targetType domain|url] [--scanType full|...] [--out file]"
  );
  process.exit(2);
}

const timeoutSeconds = Number(process.env.AEV_TIMEOUT_SECONDS || 600);
const pollIntervalMs = Number(process.env.AEV_POLL_INTERVAL_MS || 3000);

function loadPolicy() {
  const policyPath = path.resolve(process.cwd(), "aev-gate-policy.json");
  let policy = null;

  if (fs.existsSync(policyPath)) {
    try {
      policy = JSON.parse(fs.readFileSync(policyPath, "utf-8"));
    } catch (e) {
      console.error("[AEV CI] WARNING: Failed to parse aev-gate-policy.json:", e);
    }
  }

  const envFailExploit = process.env.AEV_FAIL_ON_EXPLOITABLE;
  const envFailSev = process.env.AEV_FAIL_ON_SEVERITIES;

  const failOnExploitability =
    envFailExploit != null
      ? String(envFailExploit).toLowerCase() === "true"
      : policy?.failOnExploitability ?? true;

  const failOnSeverities =
    envFailSev != null
      ? String(envFailSev)
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean)
      : (policy?.failOnSeverities || ["critical", "high"]).map((s) =>
          String(s).toLowerCase()
        );

  const maxSummaryFindings = Number(policy?.maxSummaryFindings ?? 10);

  return { failOnExploitability, failOnSeverities, maxSummaryFindings };
}

const policy = loadPolicy();

async function httpJson(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: {
      "content-type": "application/json",
      ...(opts.headers || {}),
    },
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    const msg = `HTTP ${res.status} ${res.statusText} -> ${url}\n${String(text).slice(
      0,
      800
    )}`;
    throw new Error(msg);
  }
  return json;
}

function normalizeFindings(rawEval) {
  const candidates = [
    rawEval?.findings,
    rawEval?.results?.findings,
    rawEval?.results,
    rawEval?.report?.findings,
    rawEval?.data?.findings,
  ];
  for (const c of candidates) {
    if (Array.isArray(c)) return c;
  }
  return [];
}

function severityOf(f) {
  return String(f?.severity || f?.level || f?.risk || "").toLowerCase();
}

function exploitableOf(f) {
  if (typeof f?.exploitable === "boolean") return f.exploitable;
  if (typeof f?.isExploitable === "boolean") return f.isExploitable;

  if (typeof f?.exploitability === "string") {
    const v = f.exploitability.toLowerCase();
    return v === "exploitable" || v === "true" || v === "yes";
  }

  if (typeof f?.exploitability === "number") return f.exploitability >= 1;
  return false;
}

function titleOf(f) {
  return f?.title || f?.name || f?.type || "finding";
}

function idOf(f) {
  return f?.id || f?.findingId || f?.cve || f?.ruleId || f?.signature || "";
}

function groupCounts(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
    exploitable: 0,
  };
  for (const f of findings) {
    const sev = severityOf(f) || "unknown";
    if (counts[sev] == null) counts.unknown++;
    else counts[sev]++;
    if (exploitableOf(f)) counts.exploitable++;
  }
  return counts;
}

function shouldFailFinding(f) {
  const sev = severityOf(f);
  const isExpl = exploitableOf(f);
  if (policy.failOnExploitability && isExpl) return true;
  return policy.failOnSeverities.includes(sev);
}

function renderSummaryMd(meta, findings, status) {
  const counts = groupCounts(findings);
  const failing = findings.filter(shouldFailFinding);

  const lines = [];
  lines.push(`## OdinForge AEV CI Summary`);
  lines.push(`- **Status:** \`${status || "unknown"}\``);
  lines.push(`- **Target:** \`${meta.target}\``);
  lines.push(`- **Evaluation ID:** \`${meta.evaluationId}\``);
  lines.push(
    `- **Gate:** severities=${policy.failOnSeverities.join(
      ", "
    )} | failOnExploitability=${policy.failOnExploitability}`
  );
  lines.push("");
  lines.push(`### Counts`);
  lines.push(`- Critical: **${counts.critical}**`);
  lines.push(`- High: **${counts.high}**`);
  lines.push(`- Medium: ${counts.medium}`);
  lines.push(`- Low: ${counts.low}`);
  lines.push(`- Info: ${counts.info}`);
  lines.push(`- Unknown: ${counts.unknown}`);
  lines.push(`- Exploitable flagged: **${counts.exploitable}**`);
  lines.push("");

  if (failing.length === 0) {
    lines.push(`### Gate Result`);
    lines.push(`✅ **PASS** — No findings matched the gate policy.`);
  } else {
    lines.push(`### Gate Result`);
    lines.push(`❌ **FAIL** — ${failing.length} finding(s) matched the gate policy.`);
    lines.push("");
    lines.push(`### Top Findings (up to ${policy.maxSummaryFindings})`);
    for (const f of failing.slice(0, policy.maxSummaryFindings)) {
      const sev = severityOf(f) || "unknown";
      const exp = exploitableOf(f);
      const t = titleOf(f);
      const fid = idOf(f);
      lines.push(
        `- **${sev.toUpperCase()}** | exploitable=\`${exp}\` | ${t}${
          fid ? ` (\`${fid}\`)` : ""
        }`
      );
    }
  }

  lines.push("");
  lines.push(`📎 Artifacts: \`artifacts/aev-findings.json\`, \`artifacts/aev-summary.md\``);

  return lines.join("\n");
}

(async () => {
  console.log(
    `[AEV CI] Triggering evaluation: target=${target} targetType=${targetType} scanType=${scanType}`
  );

  const trigger = await httpJson(`${backend}/api/aev/evaluate`, {
    method: "POST",
    body: JSON.stringify({ target, targetType, scanType }),
  });

  const evaluationId =
    trigger?.evaluationId ||
    trigger?.id ||
    trigger?.data?.evaluationId ||
    trigger?.data?.id;

  if (!evaluationId) {
    console.error("[AEV CI] Could not find evaluationId in response:", trigger);
    process.exit(2);
  }

  console.log(`[AEV CI] evaluationId=${evaluationId}`);

  const start = Date.now();
  let last = null;

  while ((Date.now() - start) / 1000 < timeoutSeconds) {
    last = await httpJson(`${backend}/api/evaluations/${evaluationId}`, { method: "GET" });

    const status = String(last?.status || "").toLowerCase();
    const elapsed = Math.round((Date.now() - start) / 1000);

    console.log(`[AEV CI] status=${status || "(missing)"} elapsed=${elapsed}s`);

    if (status === "failed" || status === "completed") break;
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }

  const finalStatus = String(last?.status || "").toLowerCase();
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
      gate: policy,
    },
    status: finalStatus || null,
    findings,
  };

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(artifact, null, 2), "utf-8");

  const summaryPath = path.resolve(path.dirname(out), "aev-summary.md");
  fs.writeFileSync(summaryPath, renderSummaryMd(artifact.meta, findings, artifact.status), "utf-8");

  console.log(`[AEV CI] Wrote ${out} (findings=${findings.length})`);
  console.log(`[AEV CI] Wrote ${summaryPath}`);

  if (finalStatus !== "completed") {
    console.error(
      `[AEV CI] FAIL: evaluation did not complete. finalStatus=${finalStatus || "missing"}`
    );
    process.exit(1);
  }

  const failing = findings.filter(shouldFailFinding);
  if (failing.length > 0) {
    console.error(`[AEV CI] FAIL: ${failing.length} finding(s) matched gate policy.`);
    process.exit(1);
  }

  console.log("[AEV CI] PASS");
})().catch((err) => {
  console.error("[AEV CI] ERROR:", err?.stack || err);
  process.exit(1);
});
