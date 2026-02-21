# Benchmark System

OdinForge runs its exploit agent against known-vulnerable targets and publishes the results. This document covers how benchmarks work, how to run them, and how to add new targets.

## Overview

The benchmark harness (`server/benchmark/exploit-benchmark.ts`) feeds each target's scenarios into the agentic exploit agent, scores detection accuracy via keyword matching, and outputs a JSON report with CI-gatable thresholds.

**Current targets:**

| Target | Image | Scenarios | Default Pass Rate | Default Detection Rate |
|--------|-------|-----------|-------------------|----------------------|
| Juice Shop | `bkimminich/juice-shop:v17.1.1` | 5 | 4 | 70% |
| DVWA | `vulnerables/web-dvwa:latest` | 5 | 3 | 60% |
| WebGoat | `webgoat/webgoat:v2023.8` | 4 | 2 | 50% |

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

## Reproduce Results

To reproduce the published benchmark results:

```bash
git clone https://github.com/OdinForge/OdinForge-AI.git
cd OdinForge-AI
npm ci

docker run -d --name juice-shop -p 3001:3000 bkimminich/juice-shop:v17.1.1
npx wait-on http://localhost:3001

export OPENAI_API_KEY=your_key
npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation \
  --target juice-shop \
  --output benchmark-report.json

cat benchmark-report.json | jq '.meta'
docker rm -f juice-shop
```

Results are also published at [/benchmark](https://odinforge.ai/benchmark) on the public site.
