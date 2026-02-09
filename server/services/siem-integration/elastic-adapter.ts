/**
 * Elasticsearch / Elastic Security SIEM Adapter
 *
 * Queries .alerts-* index for security alerts matching ATT&CK techniques.
 */

import type { SiemProviderAdapter, SiemConnectionConfig, SiemQueryParams, SiemQueryResult, SiemAlert } from "./types";

export class ElasticAdapter implements SiemProviderAdapter {
  private endpoint: string;
  private apiKey: string;
  private index: string;

  constructor(config: SiemConnectionConfig) {
    const port = config.apiPort || 9200;
    this.endpoint = config.apiEndpoint.replace(/\/$/, "");
    if (!this.endpoint.includes(":") || this.endpoint.split(":").length === 2) {
      // Add port if not already in URL (and not a full URL with protocol)
      const url = new URL(this.endpoint.startsWith("http") ? this.endpoint : `https://${this.endpoint}`);
      if (!url.port) url.port = String(port);
      this.endpoint = url.toString().replace(/\/$/, "");
    }
    this.apiKey = config.elasticApiKey || "";
    this.index = config.elasticIndex || ".alerts-security.alerts-*";
  }

  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      const res = await fetch(`${this.endpoint}/_cluster/health`, {
        headers: this.headers(),
      });
      if (!res.ok) {
        return { success: false, message: `HTTP ${res.status}: ${await res.text()}` };
      }
      const data = await res.json();
      return { success: true, message: `Cluster: ${data.cluster_name}, Status: ${data.status}` };
    } catch (err: any) {
      return { success: false, message: err.message || "Connection failed" };
    }
  }

  async queryAlerts(params: SiemQueryParams): Promise<SiemQueryResult> {
    const start = Date.now();
    const must: any[] = [
      { range: { "@timestamp": { gte: params.from.toISOString(), lte: params.to.toISOString() } } },
    ];

    if (params.mitreAttackId) {
      must.push({
        bool: {
          should: [
            { match: { "threat.technique.id": params.mitreAttackId } },
            { match: { "kibana.alert.rule.threat.technique.id": params.mitreAttackId } },
          ],
          minimum_should_match: 1,
        },
      });
    }

    if (params.mitreTactic) {
      must.push({
        bool: {
          should: [
            { match: { "threat.tactic.name": params.mitreTactic } },
            { match: { "kibana.alert.rule.threat.tactic.name": params.mitreTactic } },
          ],
          minimum_should_match: 1,
        },
      });
    }

    if (params.targetHost) {
      must.push({
        bool: {
          should: [
            { match: { "destination.ip": params.targetHost } },
            { match: { "host.ip": params.targetHost } },
            { match: { "host.name": params.targetHost } },
          ],
          minimum_should_match: 1,
        },
      });
    }

    const body = {
      size: params.limit || 100,
      query: { bool: { must } },
      sort: [{ "@timestamp": "asc" }],
    };

    try {
      const res = await fetch(`${this.endpoint}/${this.index}/_search`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        throw new Error(`Elastic query failed: HTTP ${res.status}`);
      }

      const data = await res.json();
      const hits = data.hits?.hits || [];

      const alerts: SiemAlert[] = hits.map((hit: any) => {
        const src = hit._source || {};
        return {
          id: hit._id,
          timestamp: src["@timestamp"] || "",
          ruleName: src.kibana?.alert?.rule?.name || src.rule?.name || "Unknown",
          severity: src.kibana?.alert?.severity || src.event?.severity || "unknown",
          mitreAttackId: src.threat?.technique?.id?.[0] || src.kibana?.alert?.rule?.threat?.technique?.id?.[0],
          mitreTactic: src.threat?.tactic?.name?.[0] || src.kibana?.alert?.rule?.threat?.tactic?.name?.[0],
          description: src.kibana?.alert?.reason || src.message,
          sourceIp: src.source?.ip,
          destIp: src.destination?.ip,
          rawData: src,
        };
      });

      return {
        alerts,
        totalCount: data.hits?.total?.value || alerts.length,
        queryTimeMs: Date.now() - start,
      };
    } catch (err: any) {
      throw new Error(`Elastic query error: ${err.message}`);
    }
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h["Authorization"] = `ApiKey ${this.apiKey}`;
    return h;
  }
}
