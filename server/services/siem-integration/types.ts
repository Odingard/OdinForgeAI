/**
 * SIEM Provider Adapter Interface
 *
 * Each SIEM provider (Elastic, Splunk, Sentinel) implements this interface
 * to normalize alert querying across platforms.
 */

export interface SiemAlert {
  id: string;
  timestamp: string;
  ruleName: string;
  severity: string;
  mitreAttackId?: string;
  mitreTactic?: string;
  description?: string;
  sourceIp?: string;
  destIp?: string;
  rawData?: Record<string, any>;
}

export interface SiemQueryParams {
  /** Start of time window (usually attack start time) */
  from: Date;
  /** End of time window (usually attack end + alertQueryWindow) */
  to: Date;
  /** MITRE ATT&CK technique ID to filter on (e.g. T1059) */
  mitreAttackId?: string;
  /** MITRE tactic to filter on (e.g. execution) */
  mitreTactic?: string;
  /** Target IP/hostname to filter alerts for */
  targetHost?: string;
  /** Max alerts to return */
  limit?: number;
}

export interface SiemQueryResult {
  alerts: SiemAlert[];
  totalCount: number;
  queryTimeMs: number;
}

export interface SiemProviderAdapter {
  /** Validate that credentials and connection work */
  testConnection(): Promise<{ success: boolean; message: string }>;
  /** Query for alerts matching the given parameters */
  queryAlerts(params: SiemQueryParams): Promise<SiemQueryResult>;
}

export interface SiemConnectionConfig {
  provider: string;
  apiEndpoint: string;
  apiPort?: number | null;
  // Elastic
  elasticIndex?: string | null;
  elasticApiKey?: string | null;
  elasticCloudId?: string | null;
  // Splunk
  splunkToken?: string | null;
  splunkIndex?: string | null;
  // Sentinel
  sentinelWorkspaceId?: string | null;
  sentinelTenantId?: string | null;
  sentinelClientId?: string | null;
  sentinelClientSecret?: string | null;
}
