import YAML from "yaml";
import { ContainerSecurityFinding, K8sManifest, containerSecurityScanner } from "./container-scanner";

export interface NetworkPolicyFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  namespace: string;
  podSelector: string;
  evidence: string;
  recommendation: string;
  cisControl?: string;
}

export interface RbacFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  resource: string;
  resourceType: "ClusterRole" | "Role" | "ClusterRoleBinding" | "RoleBinding" | "ServiceAccount";
  subject?: string;
  evidence: string;
  recommendation: string;
  mitreAttackId?: string;
  cisControl?: string;
}

export interface K8sAnalysisResult {
  containerFindings: ContainerSecurityFinding[];
  networkPolicyFindings: NetworkPolicyFinding[];
  rbacFindings: RbacFinding[];
  summary: {
    totalManifests: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    namespaces: string[];
    workloadTypes: Record<string, number>;
  };
}

class K8sManifestAnalyzer {
  private dangerousVerbs = ["*", "create", "delete", "patch", "update", "deletecollection"];
  private dangerousResources = [
    "secrets",
    "configmaps",
    "pods",
    "pods/exec",
    "pods/attach",
    "deployments",
    "daemonsets",
    "nodes",
    "persistentvolumes",
    "clusterroles",
    "clusterrolebindings",
    "roles",
    "rolebindings",
    "serviceaccounts",
    "namespaces",
  ];

  private privilegedRoles = [
    "cluster-admin",
    "admin",
    "edit",
  ];

  parseManifests(content: string): K8sManifest[] {
    const manifests: K8sManifest[] = [];
    
    const documents = content.split(/^---$/m).filter(doc => doc.trim());
    
    for (const doc of documents) {
      try {
        let parsed: any;
        
        if (doc.trim().startsWith("{")) {
          parsed = JSON.parse(doc);
        } else {
          parsed = YAML.parse(doc);
        }

        if (parsed && parsed.kind && parsed.apiVersion) {
          manifests.push(parsed as K8sManifest);
        }

        if (parsed && parsed.items && Array.isArray(parsed.items)) {
          for (const item of parsed.items) {
            if (item.kind && item.apiVersion) {
              manifests.push(item as K8sManifest);
            }
          }
        }
      } catch (error) {
        continue;
      }
    }

    return manifests;
  }

  analyzeManifests(manifests: K8sManifest[]): K8sAnalysisResult {
    const containerFindings: ContainerSecurityFinding[] = [];
    const networkPolicyFindings: NetworkPolicyFinding[] = [];
    const rbacFindings: RbacFinding[] = [];
    const namespaces = new Set<string>();
    const workloadTypes: Record<string, number> = {};

    const workloadKinds = ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"];
    const rbacKinds = ["ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding", "ServiceAccount"];

    for (const manifest of manifests) {
      const kind = manifest.kind;
      const namespace = manifest.metadata?.namespace || "default";
      namespaces.add(namespace);

      if (workloadKinds.includes(kind)) {
        workloadTypes[kind] = (workloadTypes[kind] || 0) + 1;
        const findings = containerSecurityScanner.scanManifest(manifest);
        containerFindings.push(...findings);
      }

      if (kind === "NetworkPolicy") {
        const findings = this.analyzeNetworkPolicy(manifest);
        networkPolicyFindings.push(...findings);
      }

      if (rbacKinds.includes(kind)) {
        const findings = this.analyzeRbacResource(manifest);
        rbacFindings.push(...findings);
      }
    }

    const allNamespacesWithWorkloads = new Set<string>();
    for (const manifest of manifests) {
      if (workloadKinds.includes(manifest.kind)) {
        allNamespacesWithWorkloads.add(manifest.metadata?.namespace || "default");
      }
    }

    const namespacesWithNetPol = new Set<string>();
    for (const manifest of manifests) {
      if (manifest.kind === "NetworkPolicy") {
        namespacesWithNetPol.add(manifest.metadata?.namespace || "default");
      }
    }

    for (const ns of Array.from(allNamespacesWithWorkloads)) {
      if (!namespacesWithNetPol.has(ns)) {
        networkPolicyFindings.push({
          id: `netpol-missing-${ns}`,
          severity: "high",
          title: `No NetworkPolicy in Namespace ${ns}`,
          description: `Namespace ${ns} has workloads but no NetworkPolicy defined`,
          namespace: ns,
          podSelector: "*",
          evidence: "No NetworkPolicy resources found for this namespace",
          recommendation: "Create NetworkPolicy to restrict ingress/egress traffic.",
          cisControl: "CIS 5.3.2",
        });
      }
    }

    const allFindings = [
      ...containerFindings,
      ...networkPolicyFindings,
      ...rbacFindings,
    ];

    return {
      containerFindings,
      networkPolicyFindings,
      rbacFindings,
      summary: {
        totalManifests: manifests.length,
        criticalIssues: allFindings.filter(f => f.severity === "critical").length,
        highIssues: allFindings.filter(f => f.severity === "high").length,
        mediumIssues: allFindings.filter(f => f.severity === "medium").length,
        lowIssues: allFindings.filter(f => f.severity === "low").length,
        namespaces: Array.from(namespaces),
        workloadTypes,
      },
    };
  }

  private analyzeNetworkPolicy(manifest: K8sManifest): NetworkPolicyFinding[] {
    const findings: NetworkPolicyFinding[] = [];
    const name = manifest.metadata.name;
    const namespace = manifest.metadata.namespace || "default";
    const spec = manifest.spec || {};

    const podSelector = spec.podSelector || {};
    const selectorStr = JSON.stringify(podSelector.matchLabels || {});

    if (spec.ingress) {
      for (const rule of spec.ingress) {
        if (!rule.from || rule.from.length === 0) {
          findings.push({
            id: `netpol-${name}-open-ingress`,
            severity: "high",
            title: "Open Ingress Policy",
            description: "NetworkPolicy allows ingress from all sources",
            namespace,
            podSelector: selectorStr,
            evidence: "ingress[].from is empty or not specified",
            recommendation: "Restrict ingress sources to specific namespaces or pods.",
            cisControl: "CIS 5.3.2",
          });
        }

        for (const from of rule.from || []) {
          if (from.namespaceSelector && Object.keys(from.namespaceSelector).length === 0) {
            findings.push({
              id: `netpol-${name}-all-namespaces`,
              severity: "medium",
              title: "Ingress from All Namespaces",
              description: "NetworkPolicy allows ingress from all namespaces",
              namespace,
              podSelector: selectorStr,
              evidence: "ingress[].from[].namespaceSelector: {}",
              recommendation: "Restrict to specific namespaces using matchLabels.",
            });
          }
        }
      }
    }

    if (spec.egress) {
      for (const rule of spec.egress) {
        if (!rule.to || rule.to.length === 0) {
          findings.push({
            id: `netpol-${name}-open-egress`,
            severity: "medium",
            title: "Open Egress Policy",
            description: "NetworkPolicy allows egress to all destinations",
            namespace,
            podSelector: selectorStr,
            evidence: "egress[].to is empty or not specified",
            recommendation: "Restrict egress to specific destinations.",
          });
        }

        for (const to of rule.to || []) {
          if (to.ipBlock) {
            if (to.ipBlock.cidr === "0.0.0.0/0") {
              findings.push({
                id: `netpol-${name}-egress-all-ips`,
                severity: "medium",
                title: "Egress to All IPs",
                description: "NetworkPolicy allows egress to any IP address",
                namespace,
                podSelector: selectorStr,
                evidence: "egress[].to[].ipBlock.cidr: 0.0.0.0/0",
                recommendation: "Restrict egress CIDR to required destinations.",
              });
            }
          }
        }
      }
    }

    const policyTypes = spec.policyTypes || [];
    if (!policyTypes.includes("Ingress")) {
      findings.push({
        id: `netpol-${name}-no-ingress-policy`,
        severity: "low",
        title: "Ingress Policy Not Specified",
        description: "NetworkPolicy does not explicitly define Ingress in policyTypes",
        namespace,
        podSelector: selectorStr,
        evidence: "policyTypes does not include 'Ingress'",
        recommendation: "Explicitly specify policyTypes for clarity.",
      });
    }
    if (!policyTypes.includes("Egress")) {
      findings.push({
        id: `netpol-${name}-no-egress-policy`,
        severity: "low",
        title: "Egress Policy Not Specified",
        description: "NetworkPolicy does not explicitly define Egress in policyTypes",
        namespace,
        podSelector: selectorStr,
        evidence: "policyTypes does not include 'Egress'",
        recommendation: "Add Egress to policyTypes to control outbound traffic.",
      });
    }

    return findings;
  }

  private analyzeRbacResource(manifest: K8sManifest): RbacFinding[] {
    const findings: RbacFinding[] = [];
    const kind = manifest.kind;
    const name = manifest.metadata.name;
    const namespace = manifest.metadata.namespace || "cluster-wide";

    if (kind === "ClusterRole" || kind === "Role") {
      const rules = manifest.spec?.rules || [];
      
      for (const rule of rules) {
        const resources = rule.resources || [];
        const verbs = rule.verbs || [];
        const apiGroups = rule.apiGroups || [];

        if (resources.includes("*") && verbs.includes("*")) {
          findings.push({
            id: `rbac-${name}-wildcard-all`,
            severity: "critical",
            title: "Wildcard Access to All Resources",
            description: `${kind} grants all permissions on all resources`,
            resource: `${namespace}/${name}`,
            resourceType: kind as RbacFinding["resourceType"],
            evidence: `resources: ["*"], verbs: ["*"]`,
            recommendation: "Replace wildcards with explicit resources and verbs.",
            mitreAttackId: "T1078.004",
            cisControl: "CIS 5.1.1",
          });
        }

        for (const resource of resources) {
          if (this.dangerousResources.includes(resource)) {
            const hasDangerousVerb = verbs.some((v: any) => this.dangerousVerbs.includes(v));
            
            if (hasDangerousVerb) {
              const severity = ["secrets", "pods/exec", "clusterroles", "clusterrolebindings"].includes(resource)
                ? "critical"
                : "high";

              findings.push({
                id: `rbac-${name}-dangerous-${resource}`,
                severity,
                title: `Dangerous Access to ${resource}`,
                description: `${kind} grants ${verbs.join(", ")} on ${resource}`,
                resource: `${namespace}/${name}`,
                resourceType: kind as RbacFinding["resourceType"],
                evidence: `resources: ["${resource}"], verbs: [${verbs.map((v: any) => `"${v}"`).join(", ")}]`,
                recommendation: `Review necessity of ${verbs.join("/")} permissions on ${resource}.`,
                mitreAttackId: resource === "secrets" ? "T1552.007" : "T1078.004",
                cisControl: "CIS 5.1.3",
              });
            }
          }
        }

        if (resources.includes("serviceaccounts") && 
            (verbs.includes("impersonate") || verbs.includes("*"))) {
          findings.push({
            id: `rbac-${name}-impersonate`,
            severity: "critical",
            title: "ServiceAccount Impersonation",
            description: `${kind} allows impersonating service accounts`,
            resource: `${namespace}/${name}`,
            resourceType: kind as RbacFinding["resourceType"],
            evidence: `resources: ["serviceaccounts"], verbs include "impersonate"`,
            recommendation: "Remove impersonation permission unless absolutely required.",
            mitreAttackId: "T1550.001",
            cisControl: "CIS 5.1.5",
          });
        }
      }
    }

    if (kind === "ClusterRoleBinding" || kind === "RoleBinding") {
      const roleRef = (manifest as any).roleRef || {};
      const subjects = (manifest as any).subjects || [];

      if (this.privilegedRoles.includes(roleRef.name)) {
        for (const subject of subjects) {
          const subjectStr = `${subject.kind}:${subject.namespace || ""}/${subject.name}`;
          
          findings.push({
            id: `rbac-${name}-privileged-binding`,
            severity: "high",
            title: `Binding to Privileged Role: ${roleRef.name}`,
            description: `${kind} grants ${roleRef.name} to ${subjectStr}`,
            resource: `${namespace}/${name}`,
            resourceType: kind as RbacFinding["resourceType"],
            subject: subjectStr,
            evidence: `roleRef.name: ${roleRef.name}, subject: ${subjectStr}`,
            recommendation: `Review if ${subjectStr} requires ${roleRef.name} role.`,
            mitreAttackId: "T1078.004",
            cisControl: "CIS 5.1.1",
          });
        }
      }

      for (const subject of subjects) {
        if (subject.kind === "Group" && 
            (subject.name === "system:unauthenticated" || subject.name === "system:authenticated")) {
          findings.push({
            id: `rbac-${name}-anonymous-binding`,
            severity: "critical",
            title: "Binding to Anonymous/All Users",
            description: `${kind} grants access to ${subject.name}`,
            resource: `${namespace}/${name}`,
            resourceType: kind as RbacFinding["resourceType"],
            subject: subject.name,
            evidence: `subject.kind: Group, subject.name: ${subject.name}`,
            recommendation: "Remove bindings to unauthenticated or all authenticated users.",
            mitreAttackId: "T1078.001",
            cisControl: "CIS 5.1.5",
          });
        }
      }
    }

    if (kind === "ServiceAccount") {
      const automount = (manifest as any).automountServiceAccountToken;
      
      if (automount !== false && namespace !== "kube-system") {
        findings.push({
          id: `rbac-sa-${name}-automount`,
          severity: "low",
          title: "ServiceAccount Token Auto-mounted",
          description: `ServiceAccount ${name} does not disable token automount`,
          resource: `${namespace}/${name}`,
          resourceType: "ServiceAccount",
          evidence: "automountServiceAccountToken not set to false",
          recommendation: "Set automountServiceAccountToken: false for unused service accounts.",
          cisControl: "CIS 5.1.6",
        });
      }
    }

    return findings;
  }

  generateReport(result: K8sAnalysisResult): string {
    const lines: string[] = [
      "# Kubernetes Security Analysis Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Manifests | ${result.summary.totalManifests} |`,
      `| Namespaces | ${result.summary.namespaces.join(", ")} |`,
      `| Critical Issues | ${result.summary.criticalIssues} |`,
      `| High Issues | ${result.summary.highIssues} |`,
      `| Medium Issues | ${result.summary.mediumIssues} |`,
      `| Low Issues | ${result.summary.lowIssues} |`,
      "",
      "### Workloads Analyzed",
      "",
      "| Type | Count |",
      "|------|-------|",
    ];

    for (const [type, count] of Object.entries(result.summary.workloadTypes)) {
      lines.push(`| ${type} | ${count} |`);
    }
    lines.push("");

    const criticalContainer = result.containerFindings.filter(f => f.severity === "critical");
    const criticalRbac = result.rbacFindings.filter(f => f.severity === "critical");
    const criticalNetPol = result.networkPolicyFindings.filter(f => f.severity === "critical");

    if (criticalContainer.length + criticalRbac.length + criticalNetPol.length > 0) {
      lines.push("## Critical Findings", "");
      
      for (const finding of [...criticalContainer, ...criticalRbac, ...criticalNetPol]) {
        lines.push(`### ${finding.title}`);
        lines.push(`- **Resource:** ${(finding as any).resource || (finding as any).namespace}`);
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
        lines.push(`- **Recommendation:** ${finding.recommendation}`);
        lines.push("");
      }
    }

    if (result.rbacFindings.length > 0) {
      lines.push("## RBAC Findings", "");
      lines.push("| Resource | Issue | Severity |");
      lines.push("|----------|-------|----------|");
      for (const f of result.rbacFindings) {
        lines.push(`| ${f.resource} | ${f.title} | ${f.severity} |`);
      }
      lines.push("");
    }

    if (result.networkPolicyFindings.length > 0) {
      lines.push("## Network Policy Findings", "");
      lines.push("| Namespace | Issue | Severity |");
      lines.push("|-----------|-------|----------|");
      for (const f of result.networkPolicyFindings) {
        lines.push(`| ${f.namespace} | ${f.title} | ${f.severity} |`);
      }
      lines.push("");
    }

    if (result.containerFindings.length > 0) {
      lines.push("## Container Security Findings", "");
      lines.push("| Resource | Issue | Severity |");
      lines.push("|----------|-------|----------|");
      for (const f of result.containerFindings) {
        lines.push(`| ${f.resource} | ${f.title} | ${f.severity} |`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }
}

export const k8sManifestAnalyzer = new K8sManifestAnalyzer();
