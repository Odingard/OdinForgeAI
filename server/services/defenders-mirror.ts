/**
 * Defender's Mirror
 *
 * Every attack OdinForge executes generates corresponding detection rules —
 * simultaneously. Transforms OdinForge from an adversary emulation tool into
 * a complete security feedback loop.
 *
 * Produces per technique:
 *   - Sigma Rule (YAML) — Elastic, Splunk, Sentinel, Chronicle
 *   - YARA Rule — EDR platforms, memory/file scanning
 *   - Splunk SPL Query — paste-and-run in Splunk environments
 *   - MITRE ATT&CK Tag — maps each rule to corresponding TTP
 *
 * Rule generation is DETERMINISTIC (template-based, not LLM-based).
 */

import { randomUUID } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AttackEvidence {
  id: string;
  engagementId: string;
  phase: string;
  techniqueCategory: string;
  targetService?: string;
  targetUrl?: string;
  networkProtocol?: string;
  payload?: string;
  responseIndicators?: Record<string, any>;
  statusCode?: number;
  success: boolean;
}

export interface MITRETag {
  id: string;
  name: string;
  url: string;
}

export interface DetectionRuleSet {
  id: string;
  attackEvidenceRef: string;
  engagementId: string;
  phase: string;
  techniqueCategory: string;
  mitreAttackId: string;
  mitreAttackName: string;
  mitreAttackUrl: string;
  sigmaRule: string;
  yaraRule: string;
  splunkSPL: string;
  generatedAt: string;
}

// ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────

const MITRE_MAP: Record<string, MITRETag> = {
  sqli:                { id: "T1190",     name: "Exploit Public-Facing Application",    url: "https://attack.mitre.org/techniques/T1190/" },
  xss:                 { id: "T1059.007", name: "Command and Scripting: JavaScript",    url: "https://attack.mitre.org/techniques/T1059/007/" },
  ssrf:                { id: "T1090",     name: "Proxy",                                url: "https://attack.mitre.org/techniques/T1090/" },
  cmdi:                { id: "T1059",     name: "Command and Scripting Interpreter",    url: "https://attack.mitre.org/techniques/T1059/" },
  command_injection:   { id: "T1059",     name: "Command and Scripting Interpreter",    url: "https://attack.mitre.org/techniques/T1059/" },
  jwt_abuse:           { id: "T1550",     name: "Use Alternate Authentication Material",url: "https://attack.mitre.org/techniques/T1550/" },
  smb_pivot:           { id: "T1021.002", name: "Remote Services: SMB/Windows Admin",   url: "https://attack.mitre.org/techniques/T1021/002/" },
  rdp_pivot:           { id: "T1021.001", name: "Remote Services: RDP",                 url: "https://attack.mitre.org/techniques/T1021/001/" },
  ssh_pivot:           { id: "T1021.004", name: "Remote Services: SSH",                 url: "https://attack.mitre.org/techniques/T1021/004/" },
  iam_abuse:           { id: "T1078.004", name: "Valid Accounts: Cloud Accounts",       url: "https://attack.mitre.org/techniques/T1078/004/" },
  k8s_api_abuse:       { id: "T1613",     name: "Container and Resource Discovery",     url: "https://attack.mitre.org/techniques/T1613/" },
  ssti:                { id: "T1059",     name: "Command and Scripting Interpreter",    url: "https://attack.mitre.org/techniques/T1059/" },
  path_traversal:      { id: "T1083",     name: "File and Directory Discovery",         url: "https://attack.mitre.org/techniques/T1083/" },
  idor:                { id: "T1530",     name: "Data from Cloud Storage Object",       url: "https://attack.mitre.org/techniques/T1530/" },
  auth_bypass:         { id: "T1548",     name: "Abuse Elevation Control Mechanism",    url: "https://attack.mitre.org/techniques/T1548/" },
  data_exfiltration:   { id: "T1048",     name: "Exfiltration Over Alternative Protocol",url: "https://attack.mitre.org/techniques/T1048/" },
  credential_reuse:    { id: "T1078",     name: "Valid Accounts",                       url: "https://attack.mitre.org/techniques/T1078/" },
  api_abuse:           { id: "T1106",     name: "Native API",                           url: "https://attack.mitre.org/techniques/T1106/" },
  business_logic:      { id: "T1190",     name: "Exploit Public-Facing Application",    url: "https://attack.mitre.org/techniques/T1190/" },
};

const DEFAULT_MITRE: MITRETag = { id: "T1190", name: "Exploit Public-Facing Application", url: "https://attack.mitre.org/techniques/T1190/" };

// ─── Defender's Mirror ────────────────────────────────────────────────────────

export class DefendersMirror {
  private ruleStore: DetectionRuleSet[] = [];

  /**
   * Generate Sigma, YARA, and Splunk SPL rules from a single attack evidence item.
   * Each rule type is generated independently — individual failures don't block others.
   */
  generateFromEvidence(evidence: AttackEvidence): DetectionRuleSet {
    const mitre = MITRE_MAP[evidence.techniqueCategory] || DEFAULT_MITRE;
    const ruleId = `dm-${randomUUID().slice(0, 12)}`;

    let sigmaRule: string;
    let yaraRule: string;
    let splunkSPL: string;

    try {
      sigmaRule = this.generateSigmaRule(evidence, mitre, ruleId);
    } catch {
      sigmaRule = `# Sigma rule generation failed for ${evidence.techniqueCategory}`;
    }

    try {
      yaraRule = this.generateYARARule(evidence, mitre, ruleId);
    } catch {
      yaraRule = `/* YARA rule generation failed for ${evidence.techniqueCategory} */`;
    }

    try {
      splunkSPL = this.generateSplunkSPL(evidence, mitre);
    } catch {
      splunkSPL = `| comment "SPL generation failed for ${evidence.techniqueCategory}"`;
    }

    const ruleSet: DetectionRuleSet = {
      id: ruleId,
      attackEvidenceRef: evidence.id,
      engagementId: evidence.engagementId,
      phase: evidence.phase,
      techniqueCategory: evidence.techniqueCategory,
      mitreAttackId: mitre.id,
      mitreAttackName: mitre.name,
      mitreAttackUrl: mitre.url,
      sigmaRule,
      yaraRule,
      splunkSPL,
      generatedAt: new Date().toISOString(),
    };

    this.ruleStore.push(ruleSet);
    return ruleSet;
  }

  /**
   * Generate rules for a batch of evidence items.
   */
  generateBatch(evidenceList: AttackEvidence[]): DetectionRuleSet[] {
    return evidenceList.map(e => this.generateFromEvidence(e));
  }

  /**
   * Get all generated rule sets.
   */
  getRules(): DetectionRuleSet[] {
    return this.ruleStore;
  }

  /**
   * Get rules for a specific engagement.
   */
  getRulesForEngagement(engagementId: string): DetectionRuleSet[] {
    return this.ruleStore.filter(r => r.engagementId === engagementId);
  }

  // ── Sigma Rule Generation ─────────────────────────────────────────────────

  private generateSigmaRule(evidence: AttackEvidence, mitre: MITRETag, ruleId: string): string {
    const category = evidence.techniqueCategory;
    const service = evidence.targetService || "web-application";
    const protocol = evidence.networkProtocol || "http";

    const detectionBlock = this.getSigmaDetection(category, evidence);

    return [
      `title: OdinForge Detection — ${mitre.name}`,
      `id: ${ruleId}`,
      `status: experimental`,
      `description: Detects ${category} attack technique (${mitre.id}) identified by OdinForge AEV engagement ${evidence.engagementId}`,
      `references:`,
      `  - ${mitre.url}`,
      `author: OdinForge Defender's Mirror`,
      `date: ${new Date().toISOString().slice(0, 10)}`,
      `tags:`,
      `  - attack.${mitre.id.toLowerCase()}`,
      `  - attack.${this.getMITRETactic(category)}`,
      `logsource:`,
      `  category: ${this.getSigmaLogCategory(category)}`,
      `  product: ${this.getSigmaProduct(protocol)}`,
      `  service: ${service}`,
      `detection:`,
      ...detectionBlock.map(l => `  ${l}`),
      `  condition: selection`,
      `falsepositives:`,
      `  - Legitimate ${category} patterns in application testing`,
      `  - Automated security scanning tools`,
      `level: ${evidence.success ? "high" : "medium"}`,
    ].join("\n");
  }

  private getSigmaDetection(category: string, evidence: AttackEvidence): string[] {
    const payload = evidence.payload ? this.escapeYaml(evidence.payload) : "";
    const target = evidence.targetUrl || "*";

    switch (category) {
      case "sqli":
        return [
          "selection:",
          "  cs-uri-query|contains:",
          `    - "' OR"`,
          `    - "UNION SELECT"`,
          `    - "1=1"`,
          `    - "DROP TABLE"`,
          `    - "' --"`,
        ];
      case "xss":
        return [
          "selection:",
          "  cs-uri-query|contains:",
          `    - "<script>"`,
          `    - "javascript:"`,
          `    - "onerror="`,
          `    - "onload="`,
          `    - "alert("`,
        ];
      case "ssrf":
        return [
          "selection:",
          "  cs-uri-query|contains:",
          `    - "http://169.254.169.254"`,
          `    - "http://localhost"`,
          `    - "http://127.0.0.1"`,
          `    - "file://"`,
        ];
      case "cmdi":
      case "command_injection":
        return [
          "selection:",
          "  cs-uri-query|contains:",
          `    - "; id"`,
          `    - "| whoami"`,
          `    - "\`id\`"`,
          `    - "$(whoami)"`,
          `    - "; cat /etc/passwd"`,
        ];
      case "ssti":
        return [
          "selection:",
          "  cs-body|contains:",
          `    - "{{7*7}}"`,
          `    - "{{= 7*7 }}"`,
          `    - "\${7*7}"`,
          `    - "#{7*7}"`,
        ];
      case "path_traversal":
        return [
          "selection:",
          "  cs-uri|contains:",
          `    - "../"`,
          `    - "..%2f"`,
          `    - "/etc/passwd"`,
          `    - "\\\\..\\\\..\\\\windows"`,
        ];
      case "jwt_abuse":
        return [
          "selection:",
          "  cs-uri-header|contains:",
          `    - '"alg":"none"'`,
          `    - '"alg": "none"'`,
          `    - '"alg":"HS256"'`,
        ];
      case "auth_bypass":
        return [
          "selection:",
          "  cs-uri|contains:",
          `    - "/admin"`,
          `    - "/api/admin"`,
          "  cs-status:",
          `    - 200`,
          `    - 302`,
        ];
      case "smb_pivot":
        return [
          "selection:",
          "  EventID:",
          `    - 4624`,
          `    - 4625`,
          "  LogonType: 3",
          `  TargetServerName|contains: "${evidence.targetUrl || "*"}"`,
        ];
      case "rdp_pivot":
        return [
          "selection:",
          "  EventID:",
          `    - 4624`,
          `    - 4625`,
          "  LogonType: 10",
        ];
      case "ssh_pivot":
        return [
          "selection:",
          "  sshd|contains:",
          `    - "Accepted password"`,
          `    - "Accepted publickey"`,
          `    - "Failed password"`,
        ];
      case "iam_abuse":
        return [
          "selection:",
          "  eventSource: iam.amazonaws.com",
          "  eventName|contains:",
          `    - "CreateRole"`,
          `    - "AttachRolePolicy"`,
          `    - "PutRolePolicy"`,
          `    - "AssumeRole"`,
        ];
      case "k8s_api_abuse":
        return [
          "selection:",
          `  verb|contains:`,
          `    - "list"`,
          `    - "get"`,
          `    - "create"`,
          `  objectRef.resource|contains:`,
          `    - "secrets"`,
          `    - "pods"`,
          `    - "serviceaccounts"`,
        ];
      default:
        return [
          "selection:",
          `  cs-uri|contains: "${target}"`,
          `  cs-method: "*"`,
        ];
    }
  }

  // ── YARA Rule Generation ──────────────────────────────────────────────────

  private generateYARARule(evidence: AttackEvidence, mitre: MITRETag, ruleId: string): string {
    const ruleName = `odinforge_${evidence.techniqueCategory}_${ruleId.replace(/-/g, "_")}`;
    const strings = this.getYARAStrings(evidence.techniqueCategory, evidence);

    return [
      `rule ${ruleName}`,
      `{`,
      `    meta:`,
      `        description = "Detects ${mitre.name} (${mitre.id}) — OdinForge AEV"`,
      `        author = "OdinForge Defender's Mirror"`,
      `        date = "${new Date().toISOString().slice(0, 10)}"`,
      `        mitre_attack = "${mitre.id}"`,
      `        engagement_id = "${evidence.engagementId}"`,
      `        reference = "${mitre.url}"`,
      `        severity = "${evidence.success ? "high" : "medium"}"`,
      ``,
      `    strings:`,
      ...strings.map(s => `        ${s}`),
      ``,
      `    condition:`,
      `        any of them`,
      `}`,
    ].join("\n");
  }

  private getYARAStrings(category: string, evidence: AttackEvidence): string[] {
    switch (category) {
      case "sqli":
        return [
          `$sqli1 = "' OR 1=1" nocase ascii wide`,
          `$sqli2 = "UNION SELECT" nocase ascii wide`,
          `$sqli3 = "' OR '1'='1" nocase ascii wide`,
          `$sqli4 = "; DROP TABLE" nocase ascii wide`,
        ];
      case "xss":
        return [
          `$xss1 = "<script>" nocase ascii wide`,
          `$xss2 = "javascript:" nocase ascii wide`,
          `$xss3 = "onerror=" nocase ascii wide`,
          `$xss4 = "document.cookie" nocase ascii wide`,
        ];
      case "ssrf":
        return [
          `$ssrf1 = "169.254.169.254" ascii`,
          `$ssrf2 = "http://localhost" nocase ascii`,
          `$ssrf3 = "file://" ascii`,
          `$ssrf4 = "http://127.0.0.1" ascii`,
        ];
      case "cmdi":
      case "command_injection":
        return [
          `$cmd1 = "; id" ascii`,
          `$cmd2 = "| whoami" ascii`,
          `$cmd3 = "$(whoami)" ascii`,
          `$cmd4 = "/etc/passwd" ascii`,
        ];
      case "ssti":
        return [
          `$ssti1 = "{{7*7}}" ascii`,
          `$ssti2 = "{{= 7*7 }}" ascii`,
          `$ssti3 = "${7*7}" ascii`,
        ];
      case "jwt_abuse":
        return [
          `$jwt1 = "alg\":\"none" ascii`,
          `$jwt2 = "alg\": \"none" ascii`,
          `$jwt3 = "alg\":\"HS256" ascii`,
        ];
      case "path_traversal":
        return [
          `$pt1 = "../../../" ascii`,
          `$pt2 = "..%2f..%2f" nocase ascii`,
          `$pt3 = "/etc/passwd" ascii`,
          `$pt4 = "\\\\..\\\\..\\\\windows" ascii`,
        ];
      case "smb_pivot":
        return [
          `$smb1 = "IPC$" ascii wide`,
          `$smb2 = "ADMIN$" ascii wide`,
          `$smb3 = "\\x00\\x00\\x00\\x45\\xff\\x53\\x4d\\x42" // SMB header`,
        ];
      case "rdp_pivot":
        return [
          `$rdp1 = { 03 00 00 ?? 02 f0 80 } // X.224 TPDU`,
          `$rdp2 = "mstshash=" ascii`,
        ];
      case "ssh_pivot":
        return [
          `$ssh1 = "SSH-2.0-" ascii`,
          `$ssh2 = "diffie-hellman" ascii`,
        ];
      case "iam_abuse":
        return [
          `$iam1 = "CreateRole" ascii`,
          `$iam2 = "AttachRolePolicy" ascii`,
          `$iam3 = "AssumeRole" ascii`,
          `$iam4 = "sts.amazonaws.com" ascii`,
        ];
      case "k8s_api_abuse":
        return [
          `$k8s1 = "/api/v1/secrets" ascii`,
          `$k8s2 = "/api/v1/pods" ascii`,
          `$k8s3 = "serviceaccount" ascii`,
        ];
      default:
        return [
          `$generic1 = "${evidence.targetUrl || "attack-indicator"}" ascii`,
        ];
    }
  }

  // ── Splunk SPL Generation ─────────────────────────────────────────────────

  private generateSplunkSPL(evidence: AttackEvidence, mitre: MITRETag): string {
    const category = evidence.techniqueCategory;
    const comment = `\`comment("OdinForge Defender's Mirror — ${mitre.id} ${mitre.name}")\``;

    switch (category) {
      case "sqli":
        return `index=web sourcetype=access_combined\n| where match(uri_query, "(?i)(union\\s+select|'\\s+or\\s+|1=1|drop\\s+table|'\\s*--)")\n| stats count by src_ip, uri_path, status\n| where count > 3\n| sort -count`;

      case "xss":
        return `index=web sourcetype=access_combined\n| where match(uri_query, "(?i)(<script|javascript:|onerror=|onload=|alert\\()")\n| stats count by src_ip, uri_path, uri_query\n| sort -count`;

      case "ssrf":
        return `index=web sourcetype=access_combined\n| where match(uri_query, "(169\\.254\\.169\\.254|http://localhost|http://127\\.0\\.0\\.1|file://)")\n| stats count by src_ip, uri_path, uri_query\n| sort -count`;

      case "cmdi":
      case "command_injection":
        return `index=web sourcetype=access_combined\n| where match(uri_query, "(?i)(;\\s*id|\\|\\s*whoami|\\$\\(whoami\\)|/etc/passwd)")\n| stats count by src_ip, uri_path\n| sort -count`;

      case "ssti":
        return `index=web sourcetype=access_combined\n| where match(form_data, "(\\{\\{7\\*7\\}\\}|\\{\\{=\\s*7\\*7\\s*\\}\\}|\\$\\{7\\*7\\})")\n| stats count by src_ip, uri_path\n| sort -count`;

      case "path_traversal":
        return `index=web sourcetype=access_combined\n| where match(uri_path, "(\\.\\./|\\.\\.\\.%2[fF]|/etc/passwd)")\n| stats count by src_ip, uri_path, status\n| sort -count`;

      case "jwt_abuse":
        return `index=web sourcetype=access_combined\n| where match(http_authorization, "(?i)(alg.*none|eyJ)")\n| stats count by src_ip, uri_path, http_authorization\n| sort -count`;

      case "auth_bypass":
        return `index=web sourcetype=access_combined uri_path="/admin*" OR uri_path="/api/admin*"\n| where status=200 OR status=302\n| stats count by src_ip, uri_path, status\n| where count > 5\n| sort -count`;

      case "smb_pivot":
        return `index=wineventlog source="WinEventLog:Security" EventCode=4624 OR EventCode=4625 Logon_Type=3\n| stats count by src_ip, dest, Account_Name, EventCode\n| where count > 3\n| sort -count`;

      case "rdp_pivot":
        return `index=wineventlog source="WinEventLog:Security" EventCode=4624 OR EventCode=4625 Logon_Type=10\n| stats count by src_ip, dest, Account_Name, EventCode\n| sort -count`;

      case "ssh_pivot":
        return `index=os sourcetype=syslog "sshd"\n| where match(_raw, "(Accepted|Failed)\\s+(password|publickey)")\n| stats count by src_ip, dest, user\n| sort -count`;

      case "iam_abuse":
        return `index=aws sourcetype=aws:cloudtrail eventSource="iam.amazonaws.com"\n| where match(eventName, "(CreateRole|AttachRolePolicy|PutRolePolicy|AssumeRole)")\n| stats count by sourceIPAddress, userIdentity.arn, eventName\n| sort -count`;

      case "k8s_api_abuse":
        return `index=kubernetes sourcetype=kube:apiserver\n| where match(requestURI, "(/api/v1/secrets|/api/v1/pods|serviceaccounts)")\n| stats count by sourceIPs, verb, requestURI, user.username\n| sort -count`;

      default:
        return `index=web sourcetype=access_combined\n| where uri_path="*${evidence.targetUrl || ""}*"\n| stats count by src_ip, uri_path, status, method\n| sort -count`;
    }
  }

  // ── Utility helpers ───────────────────────────────────────────────────────

  private getSigmaLogCategory(category: string): string {
    if (["smb_pivot", "rdp_pivot"].includes(category)) return "authentication";
    if (category === "ssh_pivot") return "sshd";
    if (category === "iam_abuse") return "cloudtrail";
    if (category === "k8s_api_abuse") return "kubernetes_audit";
    return "webserver";
  }

  private getSigmaProduct(protocol: string): string {
    if (protocol === "smb" || protocol === "rdp") return "windows";
    if (protocol === "ssh") return "linux";
    return "generic";
  }

  private getMITRETactic(category: string): string {
    if (["sqli", "xss", "ssrf", "cmdi", "ssti", "auth_bypass", "command_injection", "business_logic"].includes(category)) return "initial_access";
    if (["smb_pivot", "rdp_pivot", "ssh_pivot"].includes(category)) return "lateral_movement";
    if (["iam_abuse"].includes(category)) return "privilege_escalation";
    if (["k8s_api_abuse"].includes(category)) return "discovery";
    if (category === "data_exfiltration") return "exfiltration";
    if (category === "path_traversal") return "discovery";
    return "initial_access";
  }

  private escapeYaml(value: string): string {
    return value.replace(/"/g, '\\"').replace(/\n/g, "\\n");
  }
}

// ─── Convenience exports ──────────────────────────────────────────────────────

export const defendersMirror = new DefendersMirror();

export function generateBatchRules(evidenceList: AttackEvidence[]): DetectionRuleSet[] {
  return defendersMirror.generateBatch(evidenceList);
}
