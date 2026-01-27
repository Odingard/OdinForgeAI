#!/usr/bin/env npx tsx
import { execSync } from "child_process";
import { existsSync, readdirSync } from "fs";
import { join } from "path";

const MIGRATIONS_DIR = "./migrations";

type Command = "generate" | "push" | "validate" | "status" | "help";

function runCommand(cmd: string, silent = false): string {
  try {
    const result = execSync(cmd, { 
      encoding: "utf-8",
      stdio: silent ? "pipe" : "inherit"
    });
    return result || "";
  } catch (error: unknown) {
    if (error instanceof Error && 'stdout' in error) {
      return (error as { stdout: string }).stdout || "";
    }
    throw error;
  }
}

function checkDatabaseUrl(): void {
  if (!process.env.DATABASE_URL) {
    console.error("Error: DATABASE_URL environment variable is not set");
    console.error("Make sure you have provisioned a database in Replit");
    process.exit(1);
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

function getMigrationCount(): number {
  if (!existsSync(MIGRATIONS_DIR)) {
    return 0;
  }
  const files = readdirSync(MIGRATIONS_DIR);
  return files.filter(f => f.endsWith(".sql")).length;
}

function generate(name?: string): void {
  console.log("\n📦 Generating new migration...\n");
  checkDatabaseUrl();
  
  const migrationName = name || `migration_${Date.now()}`;
  const beforeCount = getMigrationCount();
  
  try {
    runCommand(`npx drizzle-kit generate --name=${migrationName}`);
    
    const afterCount = getMigrationCount();
    if (afterCount > beforeCount) {
      console.log(`\n✅ Migration generated: ${migrationName}`);
      console.log(`   Location: ${MIGRATIONS_DIR}/`);
    } else {
      console.log("\n⚠️  No schema changes detected - no migration created");
    }
  } catch (error) {
    console.error("\n❌ Failed to generate migration");
    throw error;
  }
}

function push(force = false): void {
  const env = detectEnvironment();
  console.log(`\n🚀 Pushing schema changes to ${env} database...\n`);
  checkDatabaseUrl();
  
  if (env === "production" && !force) {
    console.error("⛔ Cannot push directly to production without --force flag");
    console.error("   Use: npx tsx scripts/db-migrate.ts push --force");
    console.error("   Or deploy through Replit's publish flow for safe migrations");
    process.exit(1);
  }
  
  if (env === "preview" && !force) {
    console.log("⚠️  Running in preview environment - changes are temporary");
  }
  
  try {
    const cmd = force ? "npx drizzle-kit push --force" : "npx drizzle-kit push";
    runCommand(cmd);
    console.log(`\n✅ Schema pushed to ${env} database`);
  } catch (error) {
    console.error(`\n❌ Failed to push schema to ${env}`);
    throw error;
  }
}

function validate(): void {
  console.log("\n🔍 Validating schema...\n");
  checkDatabaseUrl();
  
  const env = detectEnvironment();
  console.log(`Environment: ${env}`);
  console.log(`Database URL: ${process.env.DATABASE_URL?.substring(0, 30)}...`);
  
  try {
    runCommand("npx drizzle-kit check");
    console.log("\n✅ Schema validation passed");
  } catch (error) {
    console.error("\n❌ Schema validation failed");
    console.error("   Fix the issues above before deploying");
    process.exit(1);
  }
}

function status(): void {
  console.log("\n📊 Migration Status\n");
  
  const env = detectEnvironment();
  const migrationCount = getMigrationCount();
  
  console.log(`Environment: ${env}`);
  console.log(`Database configured: ${process.env.DATABASE_URL ? "Yes" : "No"}`);
  console.log(`Migrations directory: ${MIGRATIONS_DIR}`);
  console.log(`Migration files: ${migrationCount}`);
  
  if (existsSync(MIGRATIONS_DIR)) {
    const files = readdirSync(MIGRATIONS_DIR)
      .filter(f => f.endsWith(".sql"))
      .sort();
    
    if (files.length > 0) {
      console.log("\nMigration files:");
      files.forEach(f => console.log(`  - ${f}`));
    }
  }
}

function help(): void {
  console.log(`
OdinForge Database Migration Tool

Usage: npx tsx scripts/db-migrate.ts <command> [options]

Commands:
  generate [name]  Generate a new migration from schema changes
  push             Push schema changes to database (dev only by default)
  push --force     Force push to any environment (use with caution)
  validate         Validate schema consistency
  status           Show migration status and environment info
  help             Show this help message

Examples:
  npx tsx scripts/db-migrate.ts generate add_user_preferences
  npx tsx scripts/db-migrate.ts push
  npx tsx scripts/db-migrate.ts validate

Environment:
  DATABASE_URL              Database connection string (required)
  REPLIT_DEPLOYMENT         Set to "1" in production deployments
  REPLIT_DEPLOYMENT_PREVIEW Set to "1" in preview deployments

Note: Production pushes are blocked by default. Use Replit's publish
flow to safely migrate production databases with automatic rollback.
`);
}

const args = process.argv.slice(2);
const command = (args[0] || "help") as Command;
const options = args.slice(1);

switch (command) {
  case "generate":
    generate(options[0]);
    break;
  case "push":
    push(options.includes("--force"));
    break;
  case "validate":
    validate();
    break;
  case "status":
    status();
    break;
  case "help":
  default:
    help();
    break;
}
