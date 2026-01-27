#!/usr/bin/env npx tsx
import { execSync } from "child_process";

console.log("\n🔒 Pre-Deployment Validation for OdinForge\n");
console.log("=".repeat(50));

function runCheck(name: string, command: string): boolean {
  console.log(`\n▶ ${name}...`);
  try {
    execSync(command, { stdio: "inherit" });
    console.log(`  ✅ ${name} passed`);
    return true;
  } catch {
    console.error(`  ❌ ${name} failed`);
    return false;
  }
}

function detectEnvironment(): string {
  if (process.env.REPLIT_DEPLOYMENT === "1") {
    return "production";
  }
  if (process.env.REPLIT_DEPLOYMENT_PREVIEW === "1") {
    return "preview";
  }
  return "development";
}

const env = detectEnvironment();
console.log(`Environment: ${env}`);
console.log(`Database URL: ${process.env.DATABASE_URL ? "configured" : "NOT SET"}`);

if (env === "production") {
  console.log("\n⚠️  Running in production - read-only validation mode");
}

const checks: Array<{ name: string; command: string; required: boolean }> = [
  {
    name: "TypeScript type checking",
    command: "npx tsc --noEmit",
    required: true,
  },
  {
    name: "Drizzle schema validation",
    command: "npx drizzle-kit check",
    required: true,
  },
];

let allPassed = true;
const results: Array<{ name: string; passed: boolean; required: boolean }> = [];

for (const check of checks) {
  const passed = runCheck(check.name, check.command);
  results.push({ name: check.name, passed, required: check.required });
  if (!passed && check.required) {
    allPassed = false;
  }
}

console.log("\n" + "=".repeat(50));
console.log("Validation Summary:");
console.log("=".repeat(50));

for (const result of results) {
  const status = result.passed ? "✅" : result.required ? "❌" : "⚠️";
  console.log(`${status} ${result.name}`);
}

console.log("\n");

if (!allPassed) {
  console.error("❌ Pre-deployment validation FAILED");
  console.error("   Fix the issues above before publishing to production");
  process.exit(1);
} else {
  console.log("✅ Pre-deployment validation PASSED");
  console.log("   Safe to proceed with deployment");
  process.exit(0);
}
