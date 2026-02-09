/**
 * Microsoft Sentinel SIEM Adapter
 *
 * Queries Azure Log Analytics (KQL) against SecurityAlert table.
 */

import type { SiemProviderAdapter, SiemConnectionConfig, SiemQueryParams, SiemQueryResult, SiemAlert } from "./types";

export class SentinelAdapter implements SiemProviderAdapter {
  private workspaceId: string;
  private tenantId: string;
  private clientId: string;
  private clientSecret: string;
  private tokenCache: { token: string; expiresAt: number } | null = null;

  constructor(config: SiemConnectionConfig) {
    this.workspaceId = config.sentinelWorkspaceId || "";
    this.tenantId = config.sentinelTenantId || "";
    this.clientId = config.sentinelClientId || "";
    this.clientSecret = config.sentinelClientSecret || "";
  }

  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      const token = await this.getAccessToken();
      if (!token) return { success: false, message: "Failed to acquire Azure AD token" };

      // Test with a simple query
      const res = await fetch(
        `https://api.loganalytics.io/v1/workspaces/${this.workspaceId}/query`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ query: "SecurityAlert | take 1" }),
        }
      );

      if (!res.ok) {
        return { success: false, message: `HTTP ${res.status}: ${await res.text()}` };
      }

      return { success: true, message: `Connected to Sentinel workspace: ${this.workspaceId}` };
    } catch (err: any) {
      return { success: false, message: err.message || "Connection failed" };
    }
  }

  async queryAlerts(params: SiemQueryParams): Promise<SiemQueryResult> {
    const start = Date.now();
    const token = await this.getAccessToken();
    if (!token) throw new Error("Failed to acquire Azure AD token");

    // Build KQL query
    let kql = `SecurityAlert
| where TimeGenerated between (datetime(${params.from.toISOString()}) .. datetime(${params.to.toISOString()}))`;

    if (params.mitreAttackId) {
      kql += `\n| where ExtendedProperties has "${params.mitreAttackId}" or Tactics has "${params.mitreAttackId}"`;
    }

    if (params.mitreTactic) {
      kql += `\n| where Tactics has_cs "${params.mitreTactic}"`;
    }

    if (params.targetHost) {
      kql += `\n| where CompromisedEntity == "${params.targetHost}" or ExtendedProperties has "${params.targetHost}"`;
    }

    kql += `\n| take ${params.limit || 100}`;
    kql += `\n| order by TimeGenerated asc`;

    try {
      const res = await fetch(
        `https://api.loganalytics.io/v1/workspaces/${this.workspaceId}/query`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ query: kql }),
        }
      );

      if (!res.ok) {
        throw new Error(`Sentinel query failed: HTTP ${res.status}`);
      }

      const data = await res.json();
      const columns: string[] = data.tables?.[0]?.columns?.map((c: any) => c.name) || [];
      const rows: any[][] = data.tables?.[0]?.rows || [];

      const alerts: SiemAlert[] = rows.map((row, i) => {
        const obj: Record<string, any> = {};
        columns.forEach((col, ci) => { obj[col] = row[ci]; });

        return {
          id: obj.SystemAlertId || `sentinel-${i}`,
          timestamp: obj.TimeGenerated || "",
          ruleName: obj.AlertName || obj.DisplayName || "Unknown",
          severity: (obj.AlertSeverity || "unknown").toLowerCase(),
          mitreAttackId: this.extractMitreId(obj.ExtendedProperties || ""),
          mitreTactic: obj.Tactics || undefined,
          description: obj.Description,
          sourceIp: obj.CompromisedEntity,
          rawData: obj,
        };
      });

      return {
        alerts,
        totalCount: alerts.length,
        queryTimeMs: Date.now() - start,
      };
    } catch (err: any) {
      throw new Error(`Sentinel query error: ${err.message}`);
    }
  }

  private async getAccessToken(): Promise<string | null> {
    if (this.tokenCache && Date.now() < this.tokenCache.expiresAt - 60000) {
      return this.tokenCache.token;
    }

    try {
      const res = await fetch(
        `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            client_id: this.clientId,
            client_secret: this.clientSecret,
            scope: "https://api.loganalytics.io/.default",
          }),
        }
      );

      if (!res.ok) return null;
      const data = await res.json();
      this.tokenCache = {
        token: data.access_token,
        expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
      };
      return data.access_token;
    } catch {
      return null;
    }
  }

  private extractMitreId(extProps: string): string | undefined {
    const match = extProps.match(/T\d{4}(?:\.\d{3})?/);
    return match ? match[0] : undefined;
  }
}
