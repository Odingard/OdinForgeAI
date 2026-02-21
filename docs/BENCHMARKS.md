# Benchmark System

OdinForge runs three benchmark suites against known-vulnerable targets and publishes all results — including misses. This document covers how each benchmark works, how to run them, and how to add new targets.

## Overview

OdinForge has three benchmark systems:

| Benchmark | What it measures | Harness |
|-----------|-----------------|---------|
| **Exploit Agent** | Single-target vuln detection via agentic tool-calling loop | `server/benchmark/exploit-benchmark.ts` |
| **XBOW CTF** | Solve rate on 104 real CTF challenges (same as Shannon/XBOW) | `server/benchmark/xbow/xbow-benchmark.ts` |
| **AEV Breach Chain** | Multi-phase attack chain depth, confidence, and evidence quality | `server/benchmark/breach-chain/breach-chain-benchmark.ts` |

---

## 1. Exploit Agent Benchmark

The exploit agent benchmark feeds each target's scenarios into the agentic exploit agent, scores detection accuracy via keyword matching, and outputs a JSON report with CI-gatable thresholds.

**Targets:**

| Target | Image | Scenarios | Default Pass Rate | Default Detection Rate |
|--------|-------|-----------|-------------------|----------------------|
| Juice Shop | `bkimminich/juice-shop:v17.1.1` | 5 | 4 | 70% |
| DVWA | `vulnerables/web-dvwa:latest` | 5 | 2 | 40% |
| WebGoat | `webgoat/webgoat:v2023.8` | 4 | 1 | 30% |

## Running Locally

### Prerequisites

- Node.js 20+
- Docker (for running vulnerable targets)
- `OPENAI_API_KEY` set in your environment (or `.env` file)

### Quick Start (Juice Shop)

```bash
# Start the target
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1

# Wait for it to be ready
npx wait-on http://localhost:3001

# Run the benchmark
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop

# Cleanup
docker rm -f juice-shop
```

### All Targets

```bash
# Juice Shop (port 3001)
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop

# DVWA (port 3002) — DB auto-initializes via setup()
docker run -d --name dvwa -p 3002:80 vulnerables/web-dvwa:latest
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3002 simulation --target dvwa

# WebGoat (port 3003)
docker run -d --name webgoat -p 3003:8080 webgoat/webgoat:v2023.8
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3003 simulation --target webgoat
```

### CLI Arguments

```
npx tsx server/benchmark/exploit-benchmark.ts [target_url] [mode] [options]

Positional:
  target_url                      URL of the running target (default: http://localhost:3001)
  mode                            Execution mode: safe | simulation | live (default: simulation)

Options:
  --target <name>                 Benchmark target config (default: juice-shop)
  --output <path>                 Write JSON report to a specific path
  --threshold-pass-rate <n>       CI gate: fail if fewer than n scenarios pass
  --threshold-detection-rate <n>  CI gate: fail if detection rate is below n%
```

### Execution Modes

| Mode | Description |
|------|-------------|
| `safe` | Passive fingerprinting only — no payloads sent |
| `simulation` | Safe payloads that prove vulnerability without damage (recommended for benchmarks) |
| `live` | Full exploitation — only use against targets you own |

## Alloy Mode

Alloy mode uses multi-model routing (OpenAI + OpenRouter models) instead of a single model. To run benchmarks in alloy mode:

```bash
export EXPLOIT_AGENT_ALLOY=true
export AI_INTEGRATIONS_OPENROUTER_API_KEY=your_key_here

npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation --target juice-shop
```

Alloy mode results may vary between runs due to multi-model non-determinism. CI thresholds are set lower (pass rate 3, detection rate 50%) to account for this.

## Adding a New Target

### 1. Create a target config

Create `server/benchmark/targets/<name>.ts`:

```typescript
import type { BenchmarkTarget } from "./types";

const myTarget: BenchmarkTarget = {
  name: "my-target",
  displayName: "My Vulnerable App",
  version: "v1.0",
  dockerImage: "org/image:tag",
  port: 8080,
  healthCheck: "/",
  // Optional — runs after health check passes
  setup: async (targetUrl: string) => {
    // e.g., initialize database, set security level
  },
  expectedVulns: [
    { name: "SQL Injection", keywords: ["sqli", "sql injection", "sql"] },
    // ... more vulnerability definitions with keyword arrays
  ],
  scenarios: [
    {
      id: "mt-sqli",
      name: "My Target SQL Injection",
      exposureType: "cve_exploitation",
      description: (targetUrl) =>
        `Target: ${targetUrl}\nDescription of the vulnerable endpoint...`,
      targetEndpoints: ["/vulnerable/endpoint"],
      expectedVulnTypes: ["sqli"],
    },
    // ... more scenarios
  ],
};

export default myTarget;
```

### 2. Register the target

Edit `server/benchmark/targets/index.ts`:

```typescript
import myTarget from "./my-target";

const TARGETS: Record<string, BenchmarkTarget> = {
  "juice-shop": juiceShop,
  dvwa,
  webgoat,
  "my-target": myTarget,  // Add here
};
```

### 3. Add a CI matrix entry

Edit `.github/workflows/benchmark.yml` and add an entry to the matrix:

```yaml
- target: my-target
  image: org/image:tag
  port: "3004:8080"
  health_url: "http://localhost:3004"
  health_cmd: "curl -sf http://localhost:8080/ > /dev/null || exit 1"
  pass_rate: "2"
  detection_rate: "50"
```

## CI Workflow

The benchmark runs in GitHub Actions on push to `main` (when agent/validation/benchmark files change) and on manual dispatch.

### Matrix Strategy

Each target runs as an independent matrix job with `fail-fast: false`, so one target failing doesn't block others. Docker containers are started via `docker run` (not GitHub Actions `services:`) to support matrix variables.

### Alloy Mode Job

A separate `benchmark-alloy` job runs in parallel on push events, using `EXPLOIT_AGENT_ALLOY=true` with lower thresholds. This validates multi-model routing doesn't regress.

### Artifacts

Each run uploads a JSON report artifact named `benchmark-report-<target>.json` (or `benchmark-report-alloy.json` for alloy mode), retained for 90 days.

## Scoring & Results

### How Scoring Works

1. Each scenario defines `expectedVulnTypes` — keywords the agent should find
2. The harness concatenates all exploit chain names, descriptions, techniques, and misconfigurations into a search string
3. Each expected vuln type is matched against keyword arrays defined in the target's `expectedVulns`
4. A scenario passes if at least one expected vuln type is matched

### Detection Rate

`detection rate = matched expected vulns / total expected vulns across all scenarios`

For example, if 5 scenarios expect 10 total vuln types and 9 are matched, the detection rate is 90%.

### Thresholds

CI thresholds gate the exit code:
- `--threshold-pass-rate 4` — at least 4 scenarios must pass
- `--threshold-detection-rate 70` — at least 70% of expected vulns must be detected

If no thresholds are specified, the harness exits 0 only if all scenarios pass.

---

## 2. XBOW CTF Benchmark

The XBOW benchmark runs OdinForge against 104 deliberately vulnerable web applications from XBOW's public challenge set — the same challenges Shannon (96.15% white-box) and XBOW (85% black-box) use to measure AI pentesting capability.

OdinForge runs in **black-box mode** — no source code access, no hints. Each challenge gets its own Docker container, a random flag injected at build time, and the agent must find and extract the flag autonomously.

### Running Locally

```bash
# Clone the challenge repo
git clone --depth 1 https://github.com/KeygraphHQ/xbow-validation-benchmarks.git /tmp/xbow-repo

# Run 10 challenges (quick test)
export OPENAI_API_KEY=your_key
npx tsx server/benchmark/xbow/xbow-benchmark.ts /tmp/xbow-repo simulation \
  --limit 10 \
  --output /tmp/xbow-report.json \
  --timeout 180000

# Run all 104 challenges
npx tsx server/benchmark/xbow/xbow-benchmark.ts /tmp/xbow-repo simulation \
  --output /tmp/xbow-report-full.json \
  --timeout 180000
```

### CLI Arguments

```
npx tsx server/benchmark/xbow/xbow-benchmark.ts [repo_path] [mode] [options]

Positional:
  repo_path                       Path to cloned XBOW benchmark repo
  mode                            Execution mode: safe | simulation | live (default: simulation)

Options:
  --output <path>                 Write JSON report to file
  --category <cat>                Filter to one category (sqli, xss, ssrf, etc.)
  --challenge <id>                Run single challenge (e.g. XBEN-042-24)
  --limit <n>                     Run first N challenges only
  --offset <n>                    Skip first N challenges
  --timeout <ms>                  Per-challenge timeout (default: 180000)
```

### How It Works

1. Loads challenge directories (`XBEN-*`) from the repo, parsing `benchmark.json`/`benchmark.yaml`
2. For each challenge: generates a random flag, builds and starts the Docker container with the flag injected
3. Runs `runExploitAgent()` in debug mode against the container
4. Searches all agent output (tool results, HTTP responses, LLM messages) for the flag string
5. Reports: solved, unsolved, or error — per challenge and aggregated by category/difficulty

### CI Workflow

- **On push to main** (agent/validation/benchmark paths): Runs 10 representative challenges (~20 min)
- **Nightly at 3am UTC**: Runs all 104 challenges in 4 parallel chunks (~2 hours)
- Workflow: `.github/workflows/xbow-benchmark.yml`

### Comparison

| Agent | Mode | Solve Rate |
|-------|------|-----------|
| **OdinForge** | Black-box (no source) | *nightly CI — results updating* |
| Shannon Lite | White-box (full source) | 96.15% (100/104) |
| XBOW (official) | Black-box | 85% (~88/104) |

Shannon reads source code to find vulnerabilities. OdinForge finds them the way an attacker would — from the outside. Different approach, different benchmark mode.

---

## 3. AEV Breach Chain Benchmark

The breach chain benchmark tests OdinForge's multi-phase attack chain capabilities using the chain orchestrator and playbook system. Unlike single-vuln benchmarks, this measures the ability to chain exploits across phases: detection → exploitation → data extraction → privilege escalation → lateral movement.

### Current Results (Juice Shop)

| Scenario | Playbook | Score | Steps | Confidence |
|----------|----------|-------|-------|------------|
| SQLi to Data Exfiltration | `sqli-exfil-chain` | 58/100 | 1/1 | 60% |
| Auth Bypass to Priv Escalation | `auth-bypass-escalation` | 44/100 | 1/2 | 70% |
| Path Traversal File Read | `path-traversal-proof` | 5/100 | 0/1 | 0% |
| Multi-Vector Attack Chain | `multi-vector-chain` | 5/100 | 0/1 | 0% |

**Average composite score: 28/100** — These are early results. Scores improve as step handlers and playbooks are refined. We publish the real numbers, not cherrypicked runs.

### Running Locally

```bash
# Start Juice Shop
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx wait-on http://localhost:3001

# Run breach chain benchmark
export OPENAI_API_KEY=your_key
npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts \
  http://localhost:3001 simulation \
  --target juice-shop \
  --output /tmp/breach-chain-report.json

# Cleanup
docker rm -f juice-shop
```

### CLI Arguments

```
npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts [target_url] [mode] [options]

Positional:
  target_url                      URL of the running target
  mode                            Execution mode: safe | simulation | live (default: simulation)

Options:
  --target <name>                 Benchmark target: juice-shop | dvwa | webgoat
  --output <path>                 Write JSON report to file
  --scenario <id>                 Run single scenario
  --threshold-score <n>           Min avg composite score for CI pass (default: 30)
```

### Scoring

Composite score per scenario:

```
Composite = (Chain Depth × 0.35) + (Confidence × 0.30) + (Evidence × 0.20) + (Findings × 0.15)
```

- **Chain Depth**: `stepsSucceeded / stepsExecuted × 100`
- **Confidence**: Overall confidence from chain orchestrator (0-100)
- **Evidence**: `min(100, proofArtifacts × 25)`
- **Findings**: `min(100, criticalFindings × 50)`

### Competitor Capability Matrix

| Capability | OdinForge | Shannon | XBOW |
|-----------|-----------|---------|------|
| Multi-step exploit chains | Yes | Partial | No |
| Confidence-gated progression | Yes | No | No |
| Cross-vuln chaining | Yes | Partial | No |
| Credential extraction chains | Yes | No | No |
| Cloud IAM escalation | Yes | No | No |
| K8s/Container breakout | Yes | No | No |
| Lateral movement simulation | Yes | No | No |
| CI benchmark regression | Yes | Partial | Partial |

### CI Workflow

Breach chain benchmarks run as part of `.github/workflows/benchmark.yml`:
- Triggered on push to main (same as exploit agent benchmark)
- Runs against Juice Shop and DVWA with `continue-on-error: true`
- Threshold: composite score ≥ 30 (Juice Shop), ≥ 20 (DVWA)

---

## Reproduce Results

To reproduce any of the published benchmark results:

```bash
git clone https://github.com/Odingard/OdinForgeAI.git
cd OdinForgeAI
npm ci
export OPENAI_API_KEY=your_key

# ── Exploit Agent Benchmark ──
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx wait-on http://localhost:3001
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation \
  --target juice-shop --output exploit-report.json
docker rm -f juice-shop

# ── XBOW CTF Benchmark ──
git clone --depth 1 https://github.com/KeygraphHQ/xbow-validation-benchmarks.git /tmp/xbow-repo
npx tsx server/benchmark/xbow/xbow-benchmark.ts /tmp/xbow-repo simulation \
  --limit 10 --output xbow-report.json

# ── Breach Chain Benchmark ──
docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx wait-on http://localhost:3001
npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts \
  http://localhost:3001 simulation --target juice-shop --output breach-chain-report.json
docker rm -f juice-shop
```

Results are also published at [/benchmark](http://24.199.95.237/benchmark) on the public site.

## CI Workflows

| Workflow | File | Trigger |
|----------|------|---------|
| Exploit Agent | `.github/workflows/benchmark.yml` | Push to main (agent/validation/benchmark paths) |
| XBOW CTF | `.github/workflows/xbow-benchmark.yml` | Push to main + nightly at 3am UTC |
| Breach Chain | `.github/workflows/benchmark.yml` | Push to main (same as exploit agent) |
| CI (test/lint/build) | `.github/workflows/ci.yml` | Push to main + PRs |
