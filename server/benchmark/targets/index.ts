import type { BenchmarkTarget } from "./types";
import juiceShop from "./juice-shop";
import dvwa from "./dvwa";
import webgoat from "./webgoat";
import brokenCrystals from "./broken-crystals";

export type { BenchmarkTarget, BenchmarkScenario, ExpectedVuln } from "./types";

const TARGETS: Record<string, BenchmarkTarget> = {
  "juice-shop": juiceShop,
  dvwa,
  webgoat,
  "broken-crystals": brokenCrystals,
};

export function getTarget(name: string): BenchmarkTarget {
  const target = TARGETS[name];
  if (!target) {
    const available = Object.keys(TARGETS).join(", ");
    throw new Error(`Unknown benchmark target "${name}". Available: ${available}`);
  }
  return target;
}

export function listTargets(): string[] {
  return Object.keys(TARGETS);
}
