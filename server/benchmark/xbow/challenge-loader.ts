/**
 * XBOW Challenge Loader
 *
 * Reads a directory of XBOW challenges and parses their metadata.
 * Supports both benchmark.json and benchmark.yaml formats.
 */

import { readdirSync, readFileSync, existsSync } from "fs";
import { join, basename } from "path";
import type { XBOWChallenge } from "./xbow-types";
import { resolveCategory } from "./xbow-types";

interface RawBenchmarkConfig {
  name?: string;
  description?: string;
  level?: string | number;
  tags?: string[];
  win_condition?: string;
  canaries?: string[];
}

function parseBenchmarkJson(filePath: string): RawBenchmarkConfig {
  const raw = readFileSync(filePath, "utf-8");
  return JSON.parse(raw);
}

function parseBenchmarkYaml(filePath: string): RawBenchmarkConfig {
  // Simple YAML key: value parser for the flat benchmark config
  const raw = readFileSync(filePath, "utf-8");
  const result: Record<string, any> = {};
  for (const line of raw.split("\n")) {
    const match = line.match(/^(\w+):\s*(.+)$/);
    if (match) {
      const [, key, value] = match;
      if (value.startsWith("[")) {
        try {
          result[key] = JSON.parse(value);
        } catch {
          result[key] = value.replace(/[\[\]"']/g, "").split(",").map((s: string) => s.trim());
        }
      } else if (value.startsWith('"') || value.startsWith("'")) {
        result[key] = value.replace(/^["']|["']$/g, "");
      } else {
        result[key] = value;
      }
    }
  }
  return result as RawBenchmarkConfig;
}

/**
 * Infer difficulty from docker compose structure.
 * Multi-service (e.g. app + db) = harder. Single service = simpler.
 */
function inferDifficulty(challengeDir: string): 1 | 2 | 3 {
  try {
    const composePath = existsSync(join(challengeDir, "docker-compose.yml"))
      ? join(challengeDir, "docker-compose.yml")
      : join(challengeDir, "docker-compose.yaml");
    const content = readFileSync(composePath, "utf-8");
    // Count service definitions (lines matching "  servicename:")
    const services = content.match(/^\s{2}\w[\w_-]*:/gm);
    const serviceCount = services ? services.length : 1;
    if (serviceCount >= 3) return 3;
    if (serviceCount >= 2) return 2;
    return 1;
  } catch {
    return 2;
  }
}

function loadChallengeConfig(challengeDir: string): RawBenchmarkConfig | null {
  const jsonPath = join(challengeDir, "benchmark.json");
  if (existsSync(jsonPath)) return parseBenchmarkJson(jsonPath);

  const yamlPath = join(challengeDir, "benchmark.yaml");
  if (existsSync(yamlPath)) return parseBenchmarkYaml(yamlPath);

  const ymlPath = join(challengeDir, "benchmark.yml");
  if (existsSync(ymlPath)) return parseBenchmarkYaml(ymlPath);

  return null;
}

/**
 * Load all XBOW challenges from a repository directory.
 * Expects directories named XBEN-NNN-24 under a `benchmarks/` subdirectory
 * (or directly under root if benchmarks/ doesn't exist).
 */
export function loadChallenges(repoPath: string): XBOWChallenge[] {
  if (!existsSync(repoPath)) {
    throw new Error(`XBOW repo path does not exist: ${repoPath}`);
  }

  // Challenges live under benchmarks/ subdirectory
  const benchmarksDir = existsSync(join(repoPath, "benchmarks"))
    ? join(repoPath, "benchmarks")
    : repoPath;

  const entries = readdirSync(benchmarksDir, { withFileTypes: true });
  const challengeDirs = entries
    .filter((e) => e.isDirectory() && /^XBEN-\d+-\d+$/.test(e.name))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));

  const challenges: XBOWChallenge[] = [];

  for (const dir of challengeDirs) {
    const challengeDir = join(benchmarksDir, dir.name);
    const config = loadChallengeConfig(challengeDir);

    if (!config) {
      console.warn(`  ⚠ Skipping ${dir.name}: no benchmark.json/yaml found`);
      continue;
    }

    // Ensure docker-compose.yml exists
    const composePath = join(challengeDir, "docker-compose.yml");
    const composeYamlPath = join(challengeDir, "docker-compose.yaml");
    if (!existsSync(composePath) && !existsSync(composeYamlPath)) {
      console.warn(`  ⚠ Skipping ${dir.name}: no docker-compose.yml found`);
      continue;
    }

    const tags = (config.tags || []).map((t: string) => t.toLowerCase().replace(/\s+/g, "_"));

    // Infer difficulty from compose structure (multi-service = harder)
    const difficulty = inferDifficulty(challengeDir);

    challenges.push({
      id: basename(dir.name),
      name: config.name || dir.name,
      category: tags.length > 0 ? resolveCategory(tags) : "unknown",
      difficulty,
      description: config.description || `Security benchmark challenge`,
      tags,
      win_condition: config.win_condition || "flag",
      composeDir: challengeDir,
    });
  }

  return challenges;
}

/**
 * Filter challenges by category, specific ID, or limit count.
 */
export function filterChallenges(
  challenges: XBOWChallenge[],
  options: {
    category?: string;
    challengeId?: string;
    limit?: number;
  }
): XBOWChallenge[] {
  let filtered = challenges;

  if (options.challengeId) {
    filtered = filtered.filter((c) => c.id === options.challengeId);
  }

  if (options.category) {
    const cat = options.category.toLowerCase();
    filtered = filtered.filter((c) => c.category === cat || c.tags.includes(cat));
  }

  if (options.limit && options.limit > 0) {
    filtered = filtered.slice(0, options.limit);
  }

  return filtered;
}
