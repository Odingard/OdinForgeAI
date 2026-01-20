/**
 * AEV Smoke Test
 * - Purpose: verify wiring and basic behavior
 * - Must NOT do aggressive scanning
 * - Should be deterministic + fast
 */

const https = require("https");

const targets = [
  "https://example.com",
  "https://badssl.com" // TLS behavior sanity check (should be reachable)
];

function head(url) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: "HEAD" }, (res) => {
      resolve({ url, status: res.statusCode, headers: res.headers });
    });
    req.on("error", reject);
    req.setTimeout(15000, () => req.destroy(new Error("timeout")));
    req.end();
  });
}

(async () => {
  console.log(`[AEV Smoke] mode=${process.env.AEV_MODE}`);
  const results = [];
  for (const t of targets) {
    const r = await head(t);
    results.push(r);
    console.log(`[AEV Smoke] ${t} -> ${r.status}`);
  }

  // Basic expectations: reachable + sane HTTP responses
  const bad = results.filter(r => !r.status || r.status >= 600);
  if (bad.length) {
    console.error("[AEV Smoke] failed:", bad);
    process.exit(1);
  }

  console.log("[AEV Smoke] OK");
})();
