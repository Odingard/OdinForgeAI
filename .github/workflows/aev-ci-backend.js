/**
 * AEV CI Backend Runner
 * - Triggers POST /api/aev/evaluate
 * - Polls GET /api/evaluations/:id until status === "completed" or "failed"
 * - Writes a normalized findings JSON artifact
 * - Fails CI on:
 *    - status === "failed"
 *    - timeout / never reaches "completed"
 *    - findings that match gate policy (severity and/or exploitable)
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

const failOnExploit =
  String(process.env.AEV_FAIL_ON_EXPLOITABLE || "true").toLowerCase() === "true";

const failSev = String(process.env.AEV_FAIL_ON_SEVERITIES || "critical,high")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

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
  // Best-effort extraction across possible shapes.
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

  if (typeof f?.exploitability === "number") {
    return f.exploitability >= 1;
  }

  return false;
}

function summarizeFinding(f) {
  const title = f?.title || f?.name || f?.type || "finding";
  const sev = severityOf(f) || "unknown";
  const exp = exploitableOf(f);
  const id = f?.id || f?.findingId || f?.cve || f?.ruleId || "";
  return { title, sev, exploitable: exp, id };
}

(async () => {
  console.log(
    `[AEV CI] Triggering evaluation: target=${target} targetType=${targetType} scanType=${scanType}`
  );

  // 1) Trigger job
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

  // 2) Poll job status (exact values: pending, in_progress, completed, failed)
  const start = Date.now();
  let last = null;

  while ((Date.now() - start) / 1000 < timeoutSeconds) {
    last = await httpJson(`${backend}/api/evaluations/${evaluationId}`, {
      method: "GET",
    });

    const status = String(last?.status || "").toLowerCase();
    const elapsed = Math.round((Date.now() - start) / 1000);

    console.log(`[AEV CI] status=${status || "(missing)"} elapsed=${elapsed}s`);

    if (status === "failed") {
      console.error("[AEV CI] Evaluation failed:", last);
      break;
    }

    if (status === "completed") {
      break;
    }

    // pending / in_progress => keep polling
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }

  const finalStatus = String(last?.status || "").toLowerCase();

  // 3) Always write artifact for debugging
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
      gate: {
        failOnExploit,
        failSev,
      },
    },
    status: finalStatus || null,
    findings,
  };

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(artifact, null, 2), "utf-8");
  console.log(`[AEV CI] Wrote ${out} (findings=${findings.length})`);

  // 4) Fail fast if not completed (failed / timeout / missing status)
  if (finalStatus !== "completed") {
    console.error(
      `[AEV CI] FAIL: evaluation did not complete successfully. finalStatus=${
        finalStatus || "missing"
      }`
    );
    process.exit(1);
  }

  // 5) Gate on findings
  let failing = findings;

  if (failOnExploit) {
    failing = failing.filter(
      (f) => exploitableOf(f) === true || failSev.includes(severityOf(f))
    );
  } else {
    failing = failing.filter((f) => failSev.includes(severityOf(f)));
  }

  if (failing.length > 0) {
    console.error(
      `[AEV CI] FAIL: ${failing.length} finding(s) matched gate policy (severities=${failSev.join(
        ","
      )}, exploitable=${failOnExploit}).`
    );

    // Print up to 20 summarized findings for CI logs
    for (const f of failing.slice(0, 20)) {
      const s = summarizeFinding(f);
      console.error(
        `- severity=${s.sev} exploitable=${s.exploitable} title="${s.title}" ${
          s.id ? `id=${s.id}` : ""
        }`
      );
    }

    process.exit(1);
  }

  console.log("[AEV CI] PASS: no findings matched gate policy.");
})().catch((err) => {
  console.error("[AEV CI] ERROR:", err?.stack || err);
  process.exit(1);
});
