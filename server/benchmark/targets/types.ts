export interface ExpectedVuln {
  name: string;
  keywords: string[];
}

export interface BenchmarkScenario {
  id: string;
  name: string;
  exposureType: string;
  description: string | ((targetUrl: string) => string);
  targetEndpoints: string[];
  expectedVulnTypes: string[];
}

export interface BenchmarkTarget {
  name: string;
  displayName: string;
  version: string;
  dockerImage: string;
  port: number;
  healthCheck: string;
  /** Optional async setup function called after health check passes (e.g., DVWA DB init). */
  setup?: (targetUrl: string) => Promise<void>;
  scenarios: BenchmarkScenario[];
  expectedVulns: ExpectedVuln[];
}
