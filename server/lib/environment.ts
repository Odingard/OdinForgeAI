export type DeploymentEnvironment = "development" | "production" | "preview";

export interface EnvironmentConfig {
  environment: DeploymentEnvironment;
  isDevelopment: boolean;
  isProduction: boolean;
  isPreview: boolean;
  databaseUrl: string;
  nodeEnv: string;
}

/**
 * Detects the deployment environment
 * Uses NODE_ENV and DEPLOYMENT_ENV environment variables
 */
function detectEnvironment(): DeploymentEnvironment {
  // Allow explicit override via DEPLOYMENT_ENV
  const deploymentEnv = process.env.DEPLOYMENT_ENV?.toLowerCase();
  if (deploymentEnv === "production" || deploymentEnv === "preview" || deploymentEnv === "development") {
    return deploymentEnv;
  }

  // Fall back to NODE_ENV
  const nodeEnv = process.env.NODE_ENV?.toLowerCase();
  if (nodeEnv === "production") {
    return "production";
  }

  if (nodeEnv === "preview" || nodeEnv === "staging") {
    return "preview";
  }

  return "development";
}

function getEnvironmentConfig(): EnvironmentConfig {
  const environment = detectEnvironment();

  return {
    environment,
    isDevelopment: environment === "development",
    isProduction: environment === "production",
    isPreview: environment === "preview",
    databaseUrl: process.env.DATABASE_URL || "",
    nodeEnv: process.env.NODE_ENV || "development",
  };
}

export const envConfig = getEnvironmentConfig();

/**
 * Gets environment-specific secret value
 * Looks for {SECRET_NAME}_{ENVIRONMENT} first, then falls back to {SECRET_NAME}
 *
 * Example: For "OPENAI_API_KEY" in production:
 * - First checks OPENAI_API_KEY_PRODUCTION
 * - Falls back to OPENAI_API_KEY
 */
export function getSecretForEnvironment(baseName: string): string | undefined {
  const { environment } = envConfig;

  const envSpecificKey = `${baseName}_${environment.toUpperCase()}`;
  if (process.env[envSpecificKey]) {
    return process.env[envSpecificKey];
  }

  return process.env[baseName];
}

/**
 * Requires a secret to be set, throws if missing
 */
export function requireSecret(name: string): string {
  const value = getSecretForEnvironment(name);
  if (!value) {
    throw new Error(
      `Required secret "${name}" not found. ` +
      `Looked for: ${name}_${envConfig.environment.toUpperCase()}, ${name}`
    );
  }
  return value;
}

/**
 * Logs environment information on startup
 */
export function logEnvironmentInfo(): void {
  console.log(`[Environment] Detected: ${envConfig.environment}`);
  console.log(`[Environment] NODE_ENV: ${envConfig.nodeEnv}`);
  console.log(`[Environment] Database: ${envConfig.databaseUrl ? "configured" : "NOT configured"}`);

  if (envConfig.isProduction) {
    console.log(`[Environment] Running in PRODUCTION mode`);
  } else if (envConfig.isPreview) {
    console.log(`[Environment] Running in PREVIEW/STAGING mode (testing before production)`);
  } else {
    console.log(`[Environment] Running in DEVELOPMENT mode`);
  }
}
