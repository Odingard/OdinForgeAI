/**
 * Splunk SIEM Adapter
 *
 * Queries Splunk REST API for notable events / security alerts.
 */

import type { SiemProviderAdapter, SiemConnectionConfig, SiemQueryParams, SiemQueryResult, SiemAlert } from "./types";

export class SplunkAdapter implements SiemProviderAdapter {
  private endpoint: string;
  private token: string;
  private index: string;

  constructor(config: SiemConnectionConfig) {
    const port = config.apiPort || 8089;
    const base = config.apiEndpoint.replace(/\/$/, "");
    this.endpoint = base.startsWith("http") ? base : `https://${base}:${port}`;
    this.token = config.splunkToken || "";
    this.index = config.splunkIndex || "notable";
  }

  async testConnection(): Promise<{ success: boolean; message: string }> {
    try {
      const res = await fetch(`${this.endpoint}/services/server/info?output_mode=json`, {
        headers: this.headers(),
      });
      if (!res.ok) {
        return { success: false, message: `HTTP ${res.status}: ${await res.text()}` };
      }
      const data = await res.json();
      const serverName = data.entry?.[0]?.content?.serverName || "unknown";
      return { success: true, message: `Connected to Splunk: ${serverName}` };
    } catch (err: any) {
      return { success: false, message: err.message || "Connection failed" };
    }
  }

  async queryAlerts(params: SiemQueryParams): Promise<SiemQueryResult> {
    const start = Date.now();

    // Build SPL query
    let spl = `search index=${this.index} earliest="${this.toSplunkTime(params.from)}" latest="${this.toSplunkTime(params.to)}"`;

    if (params.mitreAttackId) {
      spl += ` (mitre_attack_id="${params.mitreAttackId}" OR annotations.mitre_attack.mitre_technique_id="${params.mitreAttackId}")`;
    }

    if (params.mitreTactic) {
      spl += ` (mitre_tactic="${params.mitreTactic}" OR annotations.mitre_attack.mitre_tactic="${params.mitreTactic}")`;
    }

    if (params.targetHost) {
      spl += ` (dest="${params.targetHost}" OR dest_ip="${params.targetHost}" OR src="${params.targetHost}")`;
    }

    spl += ` | head ${params.limit || 100}`;

    try {
      // Create search job
      const jobRes = await fetch(`${this.endpoint}/services/search/jobs`, {
        method: "POST",
        headers: { ...this.headers(), "Content-Type": "application/x-www-form-urlencoded" },
        body: `search=${encodeURIComponent(spl)}&output_mode=json&exec_mode=oneshot&count=${params.limit || 100}`,
      });

      if (!jobRes.ok) {
        throw new Error(`Splunk search failed: HTTP ${jobRes.status}`);
      }

      const data = await jobRes.json();
      const results = data.results || [];

      const alerts: SiemAlert[] = results.map((r: any, i: number) => ({
        id: r.event_id || r._cd || `splunk-${i}`,
        timestamp: r._time || "",
        ruleName: r.search_name || r.rule_name || r.source || "Unknown",
        severity: r.urgency || r.severity || "unknown",
        mitreAttackId: r.mitre_attack_id || r.annotations?.mitre_attack?.mitre_technique_id?.[0],
        mitreTactic: r.mitre_tactic || r.annotations?.mitre_attack?.mitre_tactic?.[0],
        description: r.description || r.search_name,
        sourceIp: r.src || r.src_ip,
        destIp: r.dest || r.dest_ip,
        rawData: r,
      }));

      return {
        alerts,
        totalCount: alerts.length,
        queryTimeMs: Date.now() - start,
      };
    } catch (err: any) {
      throw new Error(`Splunk query error: ${err.message}`);
    }
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/json",
    };
  }

  private toSplunkTime(d: Date): string {
    return d.toISOString().replace("T", " ").replace("Z", "");
  }
}
