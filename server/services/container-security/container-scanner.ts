export interface ContainerSecurityFinding {
  id: string;
  category: ContainerSecurityCategory;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  resource: string;
  resourceType: "container" | "pod" | "deployment" | "daemonset" | "statefulset" | "job";
  evidence: string;
  recommendation: string;
  mitreAttackId?: string;
  cwe?: string;
  cisControl?: string;
}

export type ContainerSecurityCategory =
  | "privileged_container"
  | "dangerous_capabilities"
  | "host_namespace"
  | "host_path_mount"
  | "run_as_root"
  | "writable_rootfs"
  | "resource_limits"
  | "security_context"
  | "sensitive_mount"
  | "service_account"
  | "image_security";

export interface ContainerConfig {
  name: string;
  image: string;
  command?: string[];
  args?: string[];
  env?: Array<{ name: string; value?: string; valueFrom?: any }>;
  ports?: Array<{ containerPort: number; hostPort?: number; protocol?: string }>;
  volumeMounts?: Array<{ name: string; mountPath: string; readOnly?: boolean }>;
  securityContext?: {
    privileged?: boolean;
    runAsUser?: number;
    runAsGroup?: number;
    runAsNonRoot?: boolean;
    readOnlyRootFilesystem?: boolean;
    allowPrivilegeEscalation?: boolean;
    capabilities?: {
      add?: string[];
      drop?: string[];
    };
    seccompProfile?: { type: string };
    seLinuxOptions?: any;
  };
  resources?: {
    limits?: { cpu?: string; memory?: string };
    requests?: { cpu?: string; memory?: string };
  };
}

export interface PodSpec {
  containers: ContainerConfig[];
  initContainers?: ContainerConfig[];
  volumes?: Array<{
    name: string;
    hostPath?: { path: string; type?: string };
    emptyDir?: any;
    secret?: { secretName: string };
    configMap?: { name: string };
    persistentVolumeClaim?: { claimName: string };
  }>;
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  serviceAccountName?: string;
  automountServiceAccountToken?: boolean;
  securityContext?: {
    runAsUser?: number;
    runAsGroup?: number;
    runAsNonRoot?: boolean;
    fsGroup?: number;
    seccompProfile?: { type: string };
  };
  nodeName?: string;
  nodeSelector?: Record<string, string>;
  tolerations?: any[];
}

export interface K8sManifest {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  spec: any;
}

class ContainerSecurityScanner {
  private dangerousCapabilities = [
    "SYS_ADMIN",
    "NET_ADMIN", 
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "NET_RAW",
    "SYS_RAWIO",
    "MKNOD",
    "SETUID",
    "SETGID",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETFCAP",
    "LINUX_IMMUTABLE",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "SYS_BOOT",
    "SYS_CHROOT",
    "SYS_NICE",
    "SYS_PACCT",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "AUDIT_CONTROL",
    "AUDIT_READ",
    "AUDIT_WRITE",
    "BLOCK_SUSPEND",
    "IPC_LOCK",
    "IPC_OWNER",
    "LEASE",
    "SETPCAP",
    "SYSLOG",
    "WAKE_ALARM",
  ];

  private sensitiveHostPaths = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/kubernetes",
    "/var/run/docker.sock",
    "/var/run/crio.sock",
    "/var/run/containerd.sock",
    "/var/lib/kubelet",
    "/var/lib/etcd",
    "/root",
    "/home",
    "/proc",
    "/sys",
    "/dev",
    "/",
  ];

  private sensitiveEnvVars = [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "MYSQL_ROOT_PASSWORD",
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "API_KEY",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "JWT_SECRET",
    "TOKEN",
  ];

  scanManifest(manifest: K8sManifest): ContainerSecurityFinding[] {
    const findings: ContainerSecurityFinding[] = [];
    const kind = manifest.kind;
    const name = manifest.metadata.name;
    const namespace = manifest.metadata.namespace || "default";

    let podSpec: PodSpec | null = null;

    switch (kind) {
      case "Pod":
        podSpec = manifest.spec;
        break;
      case "Deployment":
      case "DaemonSet":
      case "StatefulSet":
      case "ReplicaSet":
      case "Job":
        podSpec = manifest.spec?.template?.spec;
        break;
      case "CronJob":
        podSpec = manifest.spec?.jobTemplate?.spec?.template?.spec;
        break;
    }

    if (podSpec) {
      findings.push(...this.scanPodSpec(podSpec, name, namespace, kind.toLowerCase() as any));
    }

    return findings;
  }

  scanPodSpec(
    podSpec: PodSpec,
    resourceName: string,
    namespace: string,
    resourceType: ContainerSecurityFinding["resourceType"]
  ): ContainerSecurityFinding[] {
    const findings: ContainerSecurityFinding[] = [];

    if (podSpec.hostNetwork) {
      findings.push({
        id: `${resourceName}-host-network`,
        category: "host_namespace",
        severity: "high",
        title: "Host Network Namespace Sharing",
        description: "Container shares the host's network namespace, potentially exposing host network traffic",
        resource: `${namespace}/${resourceName}`,
        resourceType,
        evidence: "hostNetwork: true",
        recommendation: "Remove hostNetwork unless absolutely required. Use CNI networking instead.",
        mitreAttackId: "T1610",
        cisControl: "CIS 5.2.4",
      });
    }

    if (podSpec.hostPID) {
      findings.push({
        id: `${resourceName}-host-pid`,
        category: "host_namespace",
        severity: "high",
        title: "Host PID Namespace Sharing",
        description: "Container can see and interact with host processes",
        resource: `${namespace}/${resourceName}`,
        resourceType,
        evidence: "hostPID: true",
        recommendation: "Remove hostPID. Containers should not access host process list.",
        mitreAttackId: "T1611",
        cisControl: "CIS 5.2.2",
      });
    }

    if (podSpec.hostIPC) {
      findings.push({
        id: `${resourceName}-host-ipc`,
        category: "host_namespace",
        severity: "high",
        title: "Host IPC Namespace Sharing",
        description: "Container can access host's inter-process communication resources",
        resource: `${namespace}/${resourceName}`,
        resourceType,
        evidence: "hostIPC: true",
        recommendation: "Remove hostIPC unless required for specific workloads.",
        mitreAttackId: "T1611",
        cisControl: "CIS 5.2.3",
      });
    }

    if (podSpec.volumes) {
      for (const volume of podSpec.volumes) {
        if (volume.hostPath) {
          const hostPath = volume.hostPath.path;
          const isSensitive = this.sensitiveHostPaths.some(
            p => hostPath === p || hostPath.startsWith(p + "/")
          );

          const severity = isSensitive ? "critical" : "high";
          
          findings.push({
            id: `${resourceName}-hostpath-${volume.name}`,
            category: "host_path_mount",
            severity,
            title: `Host Path Mount: ${hostPath}`,
            description: isSensitive
              ? `Sensitive host path "${hostPath}" is mounted into container`
              : `Host path "${hostPath}" is mounted into container`,
            resource: `${namespace}/${resourceName}`,
            resourceType,
            evidence: `volumes[${volume.name}].hostPath.path: ${hostPath}`,
            recommendation: "Use persistent volumes or ConfigMaps/Secrets instead of hostPath mounts.",
            mitreAttackId: "T1611",
            cisControl: "CIS 5.2.10",
          });

          if (hostPath.includes("docker.sock") || hostPath.includes("containerd.sock")) {
            findings.push({
              id: `${resourceName}-container-socket`,
              category: "sensitive_mount",
              severity: "critical",
              title: "Container Runtime Socket Mounted",
              description: "Container runtime socket is mounted, allowing container escape",
              resource: `${namespace}/${resourceName}`,
              resourceType,
              evidence: `hostPath: ${hostPath}`,
              recommendation: "Never mount container runtime sockets. Use alternative patterns for container management.",
              mitreAttackId: "T1611",
              cwe: "CWE-269",
            });
          }
        }
      }
    }

    if (podSpec.automountServiceAccountToken !== false) {
      findings.push({
        id: `${resourceName}-service-account-token`,
        category: "service_account",
        severity: "medium",
        title: "Service Account Token Auto-mounted",
        description: "Service account token is automatically mounted, potentially allowing API access",
        resource: `${namespace}/${resourceName}`,
        resourceType,
        evidence: "automountServiceAccountToken not explicitly set to false",
        recommendation: "Set automountServiceAccountToken: false unless Kubernetes API access is required.",
        mitreAttackId: "T1528",
        cisControl: "CIS 5.1.6",
      });
    }

    const allContainers = [
      ...(podSpec.containers || []),
      ...(podSpec.initContainers || []),
    ];

    for (const container of allContainers) {
      findings.push(...this.scanContainer(container, resourceName, namespace, resourceType));
    }

    return findings;
  }

  scanContainer(
    container: ContainerConfig,
    resourceName: string,
    namespace: string,
    resourceType: ContainerSecurityFinding["resourceType"]
  ): ContainerSecurityFinding[] {
    const findings: ContainerSecurityFinding[] = [];
    const ctx = container.securityContext || {};

    if (ctx.privileged === true) {
      findings.push({
        id: `${resourceName}-${container.name}-privileged`,
        category: "privileged_container",
        severity: "critical",
        title: "Privileged Container",
        description: "Container runs in privileged mode with full host access",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: "securityContext.privileged: true",
        recommendation: "Remove privileged mode. Grant only necessary capabilities instead.",
        mitreAttackId: "T1611",
        cwe: "CWE-250",
        cisControl: "CIS 5.2.1",
      });
    }

    if (ctx.capabilities?.add) {
      for (const cap of ctx.capabilities.add) {
        const upperCap = cap.toUpperCase();
        if (this.dangerousCapabilities.includes(upperCap)) {
          const severity = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"].includes(upperCap)
            ? "critical"
            : "high";

          findings.push({
            id: `${resourceName}-${container.name}-cap-${cap}`,
            category: "dangerous_capabilities",
            severity,
            title: `Dangerous Capability: ${cap}`,
            description: `Container has dangerous Linux capability ${cap} added`,
            resource: `${namespace}/${resourceName}/${container.name}`,
            resourceType,
            evidence: `securityContext.capabilities.add: [${cap}]`,
            recommendation: `Remove ${cap} capability unless absolutely required. Consider dropping all capabilities.`,
            mitreAttackId: "T1611",
            cisControl: "CIS 5.2.8",
          });
        }
      }
    }

    if (!ctx.capabilities?.drop?.includes("ALL") && !ctx.capabilities?.drop?.includes("all")) {
      findings.push({
        id: `${resourceName}-${container.name}-caps-not-dropped`,
        category: "dangerous_capabilities",
        severity: "medium",
        title: "Capabilities Not Dropped",
        description: "Container does not drop all capabilities",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: "capabilities.drop does not include 'ALL'",
        recommendation: "Drop ALL capabilities and add back only those required.",
        cisControl: "CIS 5.2.7",
      });
    }

    if (ctx.runAsUser === 0 || (ctx.runAsNonRoot !== true && ctx.runAsUser === undefined)) {
      findings.push({
        id: `${resourceName}-${container.name}-run-as-root`,
        category: "run_as_root",
        severity: ctx.runAsUser === 0 ? "high" : "medium",
        title: "Container May Run as Root",
        description: ctx.runAsUser === 0
          ? "Container explicitly runs as root (UID 0)"
          : "Container does not enforce non-root execution",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: ctx.runAsUser === 0 
          ? "securityContext.runAsUser: 0" 
          : "securityContext.runAsNonRoot not set to true",
        recommendation: "Set runAsNonRoot: true and specify a non-root runAsUser.",
        mitreAttackId: "T1611",
        cisControl: "CIS 5.2.6",
      });
    }

    if (ctx.allowPrivilegeEscalation !== false) {
      findings.push({
        id: `${resourceName}-${container.name}-priv-escalation`,
        category: "security_context",
        severity: "medium",
        title: "Privilege Escalation Not Prevented",
        description: "Container allows privilege escalation via setuid binaries",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: "allowPrivilegeEscalation not set to false",
        recommendation: "Set allowPrivilegeEscalation: false to prevent privilege escalation.",
        mitreAttackId: "T1611",
        cisControl: "CIS 5.2.5",
      });
    }

    if (ctx.readOnlyRootFilesystem !== true) {
      findings.push({
        id: `${resourceName}-${container.name}-writable-rootfs`,
        category: "writable_rootfs",
        severity: "low",
        title: "Writable Root Filesystem",
        description: "Container has a writable root filesystem",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: "readOnlyRootFilesystem not set to true",
        recommendation: "Set readOnlyRootFilesystem: true and use emptyDir for writable paths.",
        cisControl: "CIS 5.2.4",
      });
    }

    if (!container.resources?.limits?.cpu || !container.resources?.limits?.memory) {
      findings.push({
        id: `${resourceName}-${container.name}-no-limits`,
        category: "resource_limits",
        severity: "medium",
        title: "Missing Resource Limits",
        description: "Container does not have CPU and/or memory limits defined",
        resource: `${namespace}/${resourceName}/${container.name}`,
        resourceType,
        evidence: "resources.limits not fully defined",
        recommendation: "Set both CPU and memory limits to prevent resource exhaustion attacks.",
        cisControl: "CIS 5.4.1",
      });
    }

    if (container.ports) {
      for (const port of container.ports) {
        if (port.hostPort) {
          findings.push({
            id: `${resourceName}-${container.name}-hostport-${port.hostPort}`,
            category: "host_namespace",
            severity: "medium",
            title: `Host Port Binding: ${port.hostPort}`,
            description: "Container binds directly to a host port",
            resource: `${namespace}/${resourceName}/${container.name}`,
            resourceType,
            evidence: `ports[].hostPort: ${port.hostPort}`,
            recommendation: "Use Services or NodePort instead of hostPort.",
            cisControl: "CIS 5.2.13",
          });
        }
      }
    }

    if (container.env) {
      for (const env of container.env) {
        if (env.value && this.sensitiveEnvVars.some(s => 
          env.name.toUpperCase().includes(s)
        )) {
          findings.push({
            id: `${resourceName}-${container.name}-sensitive-env-${env.name}`,
            category: "security_context",
            severity: "high",
            title: `Sensitive Environment Variable: ${env.name}`,
            description: "Sensitive value may be hardcoded in environment variable",
            resource: `${namespace}/${resourceName}/${container.name}`,
            resourceType,
            evidence: `env[${env.name}].value is set directly`,
            recommendation: "Use Secrets or external secret managers for sensitive values.",
            mitreAttackId: "T1552.001",
            cwe: "CWE-798",
          });
        }
      }
    }

    if (container.image) {
      if (container.image.includes(":latest") || !container.image.includes(":")) {
        findings.push({
          id: `${resourceName}-${container.name}-latest-tag`,
          category: "image_security",
          severity: "medium",
          title: "Using Latest or No Tag",
          description: "Container uses 'latest' tag or no tag, leading to unpredictable deployments",
          resource: `${namespace}/${resourceName}/${container.name}`,
          resourceType,
          evidence: `image: ${container.image}`,
          recommendation: "Use specific image tags or digests for reproducible deployments.",
          cisControl: "CIS 5.5.1",
        });
      }
    }

    return findings;
  }

  scanDockerfile(dockerfileContent: string, imageName: string): ContainerSecurityFinding[] {
    const findings: ContainerSecurityFinding[] = [];
    const lines = dockerfileContent.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const lineNum = i + 1;

      if (line.match(/^USER\s+root/i)) {
        findings.push({
          id: `dockerfile-${imageName}-user-root-${lineNum}`,
          category: "run_as_root",
          severity: "medium",
          title: "Dockerfile USER root",
          description: `Dockerfile explicitly sets USER to root at line ${lineNum}`,
          resource: imageName,
          resourceType: "container",
          evidence: `Line ${lineNum}: ${line}`,
          recommendation: "Add a non-root USER instruction at the end of the Dockerfile.",
        });
      }

      if (line.match(/^RUN.*chmod\s+777/i)) {
        findings.push({
          id: `dockerfile-${imageName}-chmod-777-${lineNum}`,
          category: "security_context",
          severity: "high",
          title: "World-Writable Permissions",
          description: `Dockerfile sets world-writable permissions at line ${lineNum}`,
          resource: imageName,
          resourceType: "container",
          evidence: `Line ${lineNum}: ${line}`,
          recommendation: "Use minimal required permissions instead of 777.",
          cwe: "CWE-732",
        });
      }

      if (line.match(/^(ENV|ARG).*(PASSWORD|SECRET|KEY|TOKEN)/i) && line.includes("=")) {
        findings.push({
          id: `dockerfile-${imageName}-hardcoded-secret-${lineNum}`,
          category: "security_context",
          severity: "critical",
          title: "Hardcoded Secret in Dockerfile",
          description: `Potential hardcoded secret at line ${lineNum}`,
          resource: imageName,
          resourceType: "container",
          evidence: `Line ${lineNum}: ${line.slice(0, 50)}...`,
          recommendation: "Use build secrets or runtime environment variables instead of hardcoded values.",
          mitreAttackId: "T1552.001",
          cwe: "CWE-798",
        });
      }

      if (line.match(/^RUN.*curl.*\|.*sh/i) || line.match(/^RUN.*wget.*\|.*sh/i)) {
        findings.push({
          id: `dockerfile-${imageName}-curl-pipe-${lineNum}`,
          category: "image_security",
          severity: "high",
          title: "Curl Pipe to Shell",
          description: `Downloading and executing script directly at line ${lineNum}`,
          resource: imageName,
          resourceType: "container",
          evidence: `Line ${lineNum}: ${line}`,
          recommendation: "Download scripts, verify checksums, then execute.",
        });
      }

      if (line.match(/^ADD\s+https?:/i)) {
        findings.push({
          id: `dockerfile-${imageName}-add-url-${lineNum}`,
          category: "image_security",
          severity: "medium",
          title: "ADD from URL",
          description: `ADD instruction fetches from URL at line ${lineNum}`,
          resource: imageName,
          resourceType: "container",
          evidence: `Line ${lineNum}: ${line}`,
          recommendation: "Use COPY with verified local files, or RUN with curl/wget to verify checksums.",
        });
      }

      if (line.match(/^RUN.*apt-get.*-y/i) && !line.match(/apt-get\s+update/i)) {
        if (line.match(/install/i)) {
          findings.push({
            id: `dockerfile-${imageName}-apt-install-${lineNum}`,
            category: "image_security",
            severity: "low",
            title: "Package Install Without Version Pin",
            description: `Package installation may not be reproducible at line ${lineNum}`,
            resource: imageName,
            resourceType: "container",
            evidence: `Line ${lineNum}: ${line}`,
            recommendation: "Pin package versions for reproducible builds.",
          });
        }
      }
    }

    const hasUserInstruction = lines.some(l => l.trim().match(/^USER\s+(?!root)/i));
    if (!hasUserInstruction) {
      findings.push({
        id: `dockerfile-${imageName}-no-user`,
        category: "run_as_root",
        severity: "medium",
        title: "No Non-Root USER Instruction",
        description: "Dockerfile does not specify a non-root user",
        resource: imageName,
        resourceType: "container",
        evidence: "No USER instruction found",
        recommendation: "Add USER instruction with a non-root user.",
        cisControl: "CIS 4.1",
      });
    }

    return findings;
  }

  generateReport(findings: ContainerSecurityFinding[]): string {
    const lines: string[] = [
      "# Container Security Scan Report",
      "",
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "",
      `| Metric | Value |`,
      `|--------|-------|`,
      `| Total Findings | ${findings.length} |`,
      `| Critical | ${findings.filter(f => f.severity === "critical").length} |`,
      `| High | ${findings.filter(f => f.severity === "high").length} |`,
      `| Medium | ${findings.filter(f => f.severity === "medium").length} |`,
      `| Low | ${findings.filter(f => f.severity === "low").length} |`,
      "",
    ];

    const criticals = findings.filter(f => f.severity === "critical");
    if (criticals.length > 0) {
      lines.push("## Critical Findings", "");
      for (const finding of criticals) {
        lines.push(`### ${finding.title}`);
        lines.push(`- **Resource:** ${finding.resource}`);
        lines.push(`- **Category:** ${finding.category.replace(/_/g, " ")}`);
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
        if (finding.mitreAttackId) lines.push(`- **MITRE ATT&CK:** ${finding.mitreAttackId}`);
        if (finding.cisControl) lines.push(`- **CIS Control:** ${finding.cisControl}`);
        lines.push(`- **Recommendation:** ${finding.recommendation}`);
        lines.push("");
      }
    }

    const highs = findings.filter(f => f.severity === "high");
    if (highs.length > 0) {
      lines.push("## High Severity Findings", "");
      for (const finding of highs) {
        lines.push(`### ${finding.title}`);
        lines.push(`- **Resource:** ${finding.resource}`);
        lines.push(`- **Evidence:** \`${finding.evidence}\``);
        lines.push(`- **Recommendation:** ${finding.recommendation}`);
        lines.push("");
      }
    }

    lines.push("## All Findings by Category", "");
    
    const byCategory = new Map<string, ContainerSecurityFinding[]>();
    for (const finding of findings) {
      if (!byCategory.has(finding.category)) {
        byCategory.set(finding.category, []);
      }
      byCategory.get(finding.category)!.push(finding);
    }

    for (const [category, categoryFindings] of Array.from(byCategory)) {
      lines.push(`### ${category.replace(/_/g, " ").toUpperCase()}`);
      lines.push("");
      lines.push("| Resource | Title | Severity |");
      lines.push("|----------|-------|----------|");
      for (const f of categoryFindings) {
        lines.push(`| ${f.resource} | ${f.title} | ${f.severity} |`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }
}

export const containerSecurityScanner = new ContainerSecurityScanner();
