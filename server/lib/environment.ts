export type DeploymentEnvironment = "development" | "production" | "preview";

export interface EnvironmentConfig {
  environment: DeploymentEnvironment;
  isDevelopment: boolean;
  isProduction: boolean;
  isPreview: boolean;
  databaseUrl: string;
  replitDeployment: string | undefined;
  replitDevDomain: string | undefined;
  replitDomains: string | undefined;
}

function detectEnvironment(): DeploymentEnvironment {
  const replitDeployment = process.env.REPLIT_DEPLOYMENT;
  const replitPreview = process.env.REPLIT_DEPLOYMENT_PREVIEW;
  
  if (replitDeployment === "1") {
    return "production";
  }
  
  if (replitPreview === "1") {
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
    replitDeployment: process.env.REPLIT_DEPLOYMENT,
    replitDevDomain: process.env.REPLIT_DEV_DOMAIN,
    replitDomains: process.env.REPLIT_DOMAINS,
  };
}

export const envConfig = getEnvironmentConfig();

export function getSecretForEnvironment(baseName: string): string | undefined {
  const { environment } = envConfig;
  
  const envSpecificKey = `${baseName}_${environment.toUpperCase()}`;
  if (process.env[envSpecificKey]) {
    return process.env[envSpecificKey];
  }
  
  return process.env[baseName];
}

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

export function logEnvironmentInfo(): void {
  console.log(`[Environment] Detected: ${envConfig.environment}`);
  console.log(`[Environment] Database: ${envConfig.databaseUrl ? "configured" : "NOT configured"}`);
  
  if (envConfig.isProduction) {
    console.log(`[Environment] Production domains: ${envConfig.replitDomains || "not set"}`);
  } else if (envConfig.isPreview) {
    console.log(`[Environment] Preview deployment (testing before production)`);
    console.log(`[Environment] Preview domains: ${envConfig.replitDomains || "using dev domain"}`);
  } else {
    console.log(`[Environment] Dev domain: ${envConfig.replitDevDomain || "not set"}`);
  }
}
