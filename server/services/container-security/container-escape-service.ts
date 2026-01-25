import { randomUUID } from "crypto";

export interface ContainerEscapeTestResult {
  id: string;
  containerId: string;
  containerName: string;
  containerImage: string;
  testDate: Date;
  escapeVectors: EscapeVector[];
  privilegeEscalations: PrivilegeEscalation[];
  securityMisconfigurations: ContainerMisconfiguration[];
  riskScore: number;
  recommendations: string[];
  mitreAttackMappings: MitreMapping[];
  evidence: Record<string, unknown>;
}

export interface EscapeVector {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  exploitability: "trivial" | "easy" | "moderate" | "difficult";
  technique: string;
  preconditions: string[];
  exploitSteps: string[];
  impact: string;
  remediation: string;
  mitreId: string;
  cveId?: string;
  tested: boolean;
  vulnerable: boolean;
}

export interface PrivilegeEscalation {
  id: string;
  name: string;
  fromPrivilege: string;
  toPrivilege: string;
  method: string;
  severity: "critical" | "high" | "medium" | "low";
  exploitable: boolean;
  mitreId: string;
}

export interface ContainerMisconfiguration {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  currentValue: string;
  recommendedValue: string;
  remediation: string;
  mitreId?: string;
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
}

export interface ContainerConfig {
  containerId: string;
  containerName: string;
  image: string;
  privileged?: boolean;
  capabilities?: string[];
  securityOpt?: string[];
  user?: string;
  readonlyRootfs?: boolean;
  pidMode?: string;
  ipcMode?: string;
  networkMode?: string;
  cgroupParent?: string;
  mounts?: ContainerMount[];
  devices?: string[];
  sysctls?: Record<string, string>;
}

export interface ContainerMount {
  type: string;
  source: string;
  destination: string;
  mode?: string;
  readOnly?: boolean;
}

const ESCAPE_VECTORS: Omit<EscapeVector, "id" | "tested" | "vulnerable">[] = [
  {
    name: "Privileged Container Escape",
    description: "Container running with --privileged flag allows full host access",
    severity: "critical",
    exploitability: "trivial",
    technique: "Mount host filesystem via /dev and escape to host",
    preconditions: ["Container running with --privileged flag"],
    exploitSteps: [
      "List block devices: fdisk -l",
      "Mount host root: mount /dev/sda1 /mnt",
      "Chroot to host: chroot /mnt",
      "Execute commands as root on host",
    ],
    impact: "Full host system compromise, access to all containers",
    remediation: "Never run containers with --privileged flag in production",
    mitreId: "T1611",
  },
  {
    name: "Docker Socket Mount Escape",
    description: "Mounted Docker socket allows container to control Docker daemon",
    severity: "critical",
    exploitability: "trivial",
    technique: "Use Docker socket to spawn privileged container",
    preconditions: ["/var/run/docker.sock mounted in container"],
    exploitSteps: [
      "Install Docker CLI or use curl",
      "Create privileged container: docker run --privileged -v /:/host ...",
      "Access host filesystem through new container",
      "Execute arbitrary commands on host",
    ],
    impact: "Full control over Docker daemon and host system",
    remediation: "Never mount Docker socket into application containers",
    mitreId: "T1611",
    cveId: "CVE-2019-5736",
  },
  {
    name: "CAP_SYS_ADMIN Escape",
    description: "SYS_ADMIN capability allows cgroup escape",
    severity: "critical",
    exploitability: "easy",
    technique: "Abuse cgroup release_agent for container escape",
    preconditions: ["CAP_SYS_ADMIN capability granted", "Cgroup v1 filesystem"],
    exploitSteps: [
      "Mount cgroup filesystem",
      "Create new cgroup",
      "Write payload to release_agent",
      "Trigger cgroup cleanup to execute payload on host",
    ],
    impact: "Code execution on host system",
    remediation: "Drop CAP_SYS_ADMIN capability unless absolutely required",
    mitreId: "T1611",
    cveId: "CVE-2022-0492",
  },
  {
    name: "CAP_SYS_PTRACE Escape",
    description: "PTRACE capability allows process injection into host processes",
    severity: "high",
    exploitability: "moderate",
    technique: "Inject code into host processes via ptrace",
    preconditions: ["CAP_SYS_PTRACE capability", "Host PID namespace (--pid=host)"],
    exploitSteps: [
      "Identify host process with PID namespace access",
      "Attach to host process using ptrace",
      "Inject shellcode or modify process execution",
    ],
    impact: "Code execution in host process context",
    remediation: "Drop CAP_SYS_PTRACE and avoid host PID namespace",
    mitreId: "T1055.008",
  },
  {
    name: "Host PID Namespace Escape",
    description: "Shared PID namespace allows access to host processes",
    severity: "high",
    exploitability: "easy",
    technique: "Access host process memory and environment",
    preconditions: ["--pid=host flag used"],
    exploitSteps: [
      "List all host processes: ps aux",
      "Access process environment: cat /proc/1/environ",
      "Access process memory: cat /proc/1/mem",
      "Extract secrets from process memory",
    ],
    impact: "Access to host process information and secrets",
    remediation: "Do not use host PID namespace for application containers",
    mitreId: "T1611",
  },
  {
    name: "Host Network Namespace Escape",
    description: "Shared network namespace exposes host network stack",
    severity: "medium",
    exploitability: "easy",
    technique: "Access host network interfaces and services",
    preconditions: ["--network=host flag used"],
    exploitSteps: [
      "List all network interfaces: ip addr",
      "Access localhost services on host",
      "Sniff host network traffic",
      "Bind to host ports",
    ],
    impact: "Access to host network and internal services",
    remediation: "Use isolated network namespaces for containers",
    mitreId: "T1557",
  },
  {
    name: "Writable /proc/sys Escape",
    description: "Writable /proc/sys allows kernel parameter modification",
    severity: "high",
    exploitability: "moderate",
    technique: "Modify kernel parameters to enable escape",
    preconditions: ["CAP_SYS_ADMIN capability", "Writable /proc/sys"],
    exploitSteps: [
      "Modify kernel parameters via /proc/sys",
      "Enable core patterns or other escape vectors",
      "Trigger kernel mechanism for code execution",
    ],
    impact: "Kernel parameter modification, potential code execution",
    remediation: "Mount /proc as read-only, drop unnecessary capabilities",
    mitreId: "T1611",
  },
  {
    name: "Sensitive Host Mount Escape",
    description: "Sensitive host paths mounted into container",
    severity: "critical",
    exploitability: "trivial",
    technique: "Modify host files through mounted paths",
    preconditions: ["Sensitive host paths mounted (/, /etc, /var)"],
    exploitSteps: [
      "Access mounted host filesystem",
      "Modify /etc/passwd or /etc/shadow",
      "Add SSH keys to root authorized_keys",
      "Schedule cron job for persistence",
    ],
    impact: "Direct host filesystem access and modification",
    remediation: "Only mount necessary paths with read-only flag",
    mitreId: "T1611",
  },
];

const CAPABILITY_RISKS: Record<string, { severity: "critical" | "high" | "medium" | "low"; risk: string; mitreId: string }> = {
  "CAP_SYS_ADMIN": { severity: "critical", risk: "Allows cgroup escape and mount operations", mitreId: "T1611" },
  "CAP_SYS_PTRACE": { severity: "high", risk: "Allows process injection attacks", mitreId: "T1055.008" },
  "CAP_NET_ADMIN": { severity: "high", risk: "Allows network configuration changes", mitreId: "T1557" },
  "CAP_NET_RAW": { severity: "medium", risk: "Allows raw socket operations and sniffing", mitreId: "T1040" },
  "CAP_SYS_RAWIO": { severity: "critical", risk: "Allows raw I/O port access", mitreId: "T1611" },
  "CAP_SYS_MODULE": { severity: "critical", risk: "Allows kernel module loading", mitreId: "T1547.006" },
  "CAP_DAC_READ_SEARCH": { severity: "high", risk: "Bypasses file read permission checks", mitreId: "T1083" },
  "CAP_DAC_OVERRIDE": { severity: "high", risk: "Bypasses all file permission checks", mitreId: "T1548" },
  "CAP_CHOWN": { severity: "medium", risk: "Allows changing file ownership", mitreId: "T1222" },
  "CAP_SETUID": { severity: "high", risk: "Allows setting arbitrary user IDs", mitreId: "T1548.001" },
  "CAP_SETGID": { severity: "high", risk: "Allows setting arbitrary group IDs", mitreId: "T1548.001" },
};

class ContainerEscapeService {
  async testContainerEscape(config: ContainerConfig): Promise<ContainerEscapeTestResult> {
    const id = `container-escape-${randomUUID().slice(0, 8)}`;
    const escapeVectors: EscapeVector[] = [];
    const privilegeEscalations: PrivilegeEscalation[] = [];
    const misconfigurations: ContainerMisconfiguration[] = [];
    const mitreAttackMappings: MitreMapping[] = [];

    if (config.privileged) {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[0], true, true);
      escapeVectors.push(vector);
      
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Privileged Mode",
        severity: "critical",
        description: "Container running in privileged mode",
        currentValue: "privileged: true",
        recommendedValue: "privileged: false",
        remediation: "Remove --privileged flag and use specific capabilities if needed",
        mitreId: "T1611",
      });
    }

    if (config.mounts?.some(m => m.source === "/var/run/docker.sock")) {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[1], true, true);
      escapeVectors.push(vector);
      
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Docker Socket Mount",
        severity: "critical",
        description: "Docker socket mounted into container",
        currentValue: "/var/run/docker.sock mounted",
        recommendedValue: "No Docker socket mount",
        remediation: "Remove Docker socket mount; use Docker API proxy with limited permissions if needed",
        mitreId: "T1611",
      });
    }

    const hasSysAdmin = config.capabilities?.includes("CAP_SYS_ADMIN") || config.capabilities?.includes("SYS_ADMIN");
    if (hasSysAdmin) {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[2], true, true);
      escapeVectors.push(vector);
    }

    const hasSysPtrace = config.capabilities?.includes("CAP_SYS_PTRACE") || config.capabilities?.includes("SYS_PTRACE");
    const hasHostPid = config.pidMode === "host";
    if (hasSysPtrace && hasHostPid) {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[3], true, true);
      escapeVectors.push(vector);
    }

    if (hasHostPid) {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[4], true, true);
      escapeVectors.push(vector);
      
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Host PID Namespace",
        severity: "high",
        description: "Container shares host PID namespace",
        currentValue: "pid: host",
        recommendedValue: "Isolated PID namespace",
        remediation: "Remove --pid=host flag",
        mitreId: "T1611",
      });
    }

    if (config.networkMode === "host") {
      const vector = this.createEscapeVector(ESCAPE_VECTORS[5], true, true);
      escapeVectors.push(vector);
      
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Host Network Namespace",
        severity: "medium",
        description: "Container shares host network namespace",
        currentValue: "network: host",
        recommendedValue: "Isolated network namespace",
        remediation: "Use bridge or custom network instead of host network",
        mitreId: "T1557",
      });
    }

    const sensitiveMounts = config.mounts?.filter(m => 
      m.source === "/" || 
      m.source.startsWith("/etc") || 
      m.source.startsWith("/var") ||
      m.source.startsWith("/root") ||
      m.source.startsWith("/home")
    ) || [];

    for (const mount of sensitiveMounts) {
      if (!mount.readOnly) {
        const vector = this.createEscapeVector(ESCAPE_VECTORS[7], true, true);
        vector.description = `Writable mount of ${mount.source}`;
        escapeVectors.push(vector);
        
        misconfigurations.push({
          id: `misconfig-${randomUUID().slice(0, 8)}`,
          type: "Sensitive Host Mount",
          severity: "critical",
          description: `Sensitive host path ${mount.source} mounted with write access`,
          currentValue: `${mount.source}:${mount.destination}:rw`,
          recommendedValue: "Remove mount or make read-only",
          remediation: "Add :ro flag to mount or remove sensitive host mounts",
          mitreId: "T1611",
        });
      }
    }

    for (const cap of config.capabilities || []) {
      const normalizedCap = cap.startsWith("CAP_") ? cap : `CAP_${cap}`;
      const riskInfo = CAPABILITY_RISKS[normalizedCap];
      
      if (riskInfo) {
        privilegeEscalations.push({
          id: `privesc-${randomUUID().slice(0, 8)}`,
          name: `${normalizedCap} Capability`,
          fromPrivilege: "Container user",
          toPrivilege: riskInfo.severity === "critical" ? "Host root" : "Elevated container",
          method: riskInfo.risk,
          severity: riskInfo.severity,
          exploitable: true,
          mitreId: riskInfo.mitreId,
        });
      }
    }

    if (!config.user || config.user === "root" || config.user === "0") {
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Root User",
        severity: "medium",
        description: "Container running as root user",
        currentValue: config.user || "root",
        recommendedValue: "Non-root user (e.g., 1000:1000)",
        remediation: "Add USER directive to Dockerfile or use --user flag",
        mitreId: "T1078",
      });
    }

    if (!config.readonlyRootfs) {
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "Writable Root Filesystem",
        severity: "low",
        description: "Container root filesystem is writable",
        currentValue: "readonlyRootfs: false",
        recommendedValue: "readonlyRootfs: true",
        remediation: "Use --read-only flag with tmpfs for writable paths",
      });
    }

    if (!config.securityOpt?.includes("no-new-privileges")) {
      misconfigurations.push({
        id: `misconfig-${randomUUID().slice(0, 8)}`,
        type: "New Privileges Allowed",
        severity: "medium",
        description: "Container can gain new privileges via setuid/setgid",
        currentValue: "no-new-privileges: false",
        recommendedValue: "no-new-privileges: true",
        remediation: "Add --security-opt=no-new-privileges flag",
        mitreId: "T1548",
      });
    }

    for (const vector of escapeVectors) {
      if (!mitreAttackMappings.some(m => m.techniqueId === vector.mitreId)) {
        mitreAttackMappings.push({
          techniqueId: vector.mitreId,
          techniqueName: vector.name,
          tactic: "privilege-escalation",
          description: vector.description,
        });
      }
    }

    const riskScore = this.calculateRiskScore(escapeVectors, privilegeEscalations, misconfigurations);
    const recommendations = this.generateRecommendations(escapeVectors, privilegeEscalations, misconfigurations);

    return {
      id,
      containerId: config.containerId,
      containerName: config.containerName,
      containerImage: config.image,
      testDate: new Date(),
      escapeVectors,
      privilegeEscalations,
      securityMisconfigurations: misconfigurations,
      riskScore,
      recommendations,
      mitreAttackMappings,
      evidence: {
        escapeVectorsFound: escapeVectors.length,
        privilegeEscalationsFound: privilegeEscalations.length,
        misconfigurationsFound: misconfigurations.length,
        privilegedMode: config.privileged || false,
        capabilitiesCount: config.capabilities?.length || 0,
        mountsCount: config.mounts?.length || 0,
      },
    };
  }

  private createEscapeVector(
    template: Omit<EscapeVector, "id" | "tested" | "vulnerable">,
    tested: boolean,
    vulnerable: boolean
  ): EscapeVector {
    return {
      ...template,
      id: `escape-${randomUUID().slice(0, 8)}`,
      tested,
      vulnerable,
    };
  }

  private calculateRiskScore(
    escapeVectors: EscapeVector[],
    privilegeEscalations: PrivilegeEscalation[],
    misconfigurations: ContainerMisconfiguration[]
  ): number {
    let score = 0;

    for (const vector of escapeVectors) {
      if (vector.vulnerable) {
        score += vector.severity === "critical" ? 30 : vector.severity === "high" ? 20 : 10;
      }
    }

    for (const pe of privilegeEscalations) {
      if (pe.exploitable) {
        score += pe.severity === "critical" ? 15 : pe.severity === "high" ? 10 : 5;
      }
    }

    for (const m of misconfigurations) {
      score += m.severity === "critical" ? 10 : m.severity === "high" ? 7 : m.severity === "medium" ? 4 : 2;
    }

    return Math.min(100, score);
  }

  private generateRecommendations(
    escapeVectors: EscapeVector[],
    privilegeEscalations: PrivilegeEscalation[],
    misconfigurations: ContainerMisconfiguration[]
  ): string[] {
    const recs: string[] = [];

    if (escapeVectors.some(v => v.name.includes("Privileged"))) {
      recs.push("CRITICAL: Remove --privileged flag immediately");
      recs.push("Use specific Linux capabilities instead of privileged mode");
    }

    if (escapeVectors.some(v => v.name.includes("Docker Socket"))) {
      recs.push("CRITICAL: Remove Docker socket mount from container");
      recs.push("Use a Docker API proxy with limited permissions if Docker access is required");
    }

    if (privilegeEscalations.some(p => p.name.includes("SYS_ADMIN"))) {
      recs.push("Drop CAP_SYS_ADMIN capability unless absolutely required");
    }

    if (misconfigurations.some(m => m.type === "Root User")) {
      recs.push("Run containers as non-root user");
      recs.push("Add USER directive to Dockerfile");
    }

    if (misconfigurations.some(m => m.type === "Host PID Namespace")) {
      recs.push("Remove --pid=host flag");
    }

    if (misconfigurations.some(m => m.type === "Host Network Namespace")) {
      recs.push("Use bridge or overlay network instead of host network");
    }

    recs.push("Enable seccomp profile to restrict system calls");
    recs.push("Use AppArmor or SELinux for additional confinement");
    recs.push("Implement container runtime security monitoring");

    return recs;
  }
}

export const containerEscapeService = new ContainerEscapeService();
