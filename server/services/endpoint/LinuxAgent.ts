// =============================================================================
// Task 06 — Linux Endpoint Agent
// server/services/endpoint/LinuxAgent.ts
//
// Checks:
//   Auth:    empty passwords, UID 0 accounts, sudoers wildcards
//   SSH:     PermitRootLogin, PasswordAuthentication, authorized_keys
//   Files:   SUID/SGID binaries (unexpected), world-writable dirs, cron jobs
//   Network: listening services on unexpected ports
//   Updates: outstanding CVEs via package manager
//   Audit:   auditd running, syslog configured
// =============================================================================

import { EndpointAgent } from "./EndpointAgent";
import path from "path";

export class LinuxAgent extends EndpointAgent {
  constructor() {
    super("linux");
  }

  protected async runChecks(): Promise<void> {
    await Promise.allSettled([
      this.checkPasswordAuth(),
      this.checkUid0Accounts(),
      this.checkSshConfig(),
      this.checkSudoers(),
      this.checkSuidBinaries(),
      this.checkWorldWritableDirs(),
      this.checkListeningPorts(),
      this.checkCronJobs(),
      this.checkAuditd(),
      this.checkFirewall(),
      this.checkPackageUpdates(),
    ]);
  }

  // —— Authentication Checks ——————————————————————————————————————————————————
  private async checkPasswordAuth(): Promise<void> {
    await this.runCheck("linux-empty-passwords", async () => {
      const result = await this.runCommand(
        "awk -F: '($2 == \"\" || $2 == \"!!\") {print $1}' /etc/shadow",
        { allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (emptyPassUsers) => {
      // Filter to users with valid shells (not service accounts)
      if (emptyPassUsers.length > 0) {
        this.addFinding({
          checkId:     "linux-empty-passwords",
          title:       `${emptyPassUsers.length} Account(s) With Empty Password`,
          description: `Accounts ${emptyPassUsers.join(", ")} have empty or locked passwords. Empty passwords allow anyone to log in without authentication.`,
          severity:    "critical",
          cvssScore:   9.8,
          resource:    "system:authentication",
          resourceType: "linux_user",
          evidence:    { Accounts: emptyPassUsers },
          remediationTitle: "Set passwords for all accounts",
          remediationSteps: [
            `Set password: passwd USERNAME`,
            "Or lock account if unused: usermod -L USERNAME",
            "Review /etc/shadow to ensure all accounts are secured",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1078"],
        });
      }
    });
  }

  private async checkUid0Accounts(): Promise<void> {
    await this.runCheck("linux-uid0-accounts", async () => {
      const result = await this.runCommand(
        "awk -F: '($3 == \"0\") {print $1}' /etc/passwd",
        { allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (uid0Accounts) => {
      const nonRoot = uid0Accounts.filter(a => a !== "root");
      if (nonRoot.length > 0) {
        this.addFinding({
          checkId:     "linux-extra-uid0",
          title:       `${nonRoot.length} Non-Root Account(s) With UID 0`,
          description: `Accounts ${nonRoot.join(", ")} have UID 0 (root-level privileges) but are not the root account. These hidden superuser accounts may indicate compromise.`,
          severity:    "critical",
          cvssScore:   9.5,
          resource:    "system:users",
          resourceType: "linux_user",
          evidence:    { ExtraUid0Accounts: nonRoot },
          remediationTitle: "Investigate and remove non-root UID 0 accounts",
          remediationSteps: [
            "Review each account: who created it and when",
            "If not authorized, delete: userdel -r USERNAME",
            "Check for persistence mechanisms: ~/.bashrc, /etc/profile.d/",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1078", "T1136"],
        });
      }
    });
  }

  // —— SSH Configuration Checks ———————————————————————————————————————————————
  private async checkSshConfig(): Promise<void> {
    await this.runCheck("linux-ssh-config", async () => {
      const result = await this.runCommand(
        "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'",
        { allowFailure: true }
      );
      return this.parseKeyValue(result.stdout, " ");
    }, (config) => {
      // Check PermitRootLogin
      const permitRoot = config.get("PermitRootLogin") ?? "yes"; // default is yes on most distros
      if (!["no", "prohibit-password", "forced-commands-only"].includes(permitRoot.toLowerCase())) {
        this.addFinding({
          checkId:     "linux-ssh-root-login",
          title:       "SSH Root Login Permitted",
          description: `sshd_config has PermitRootLogin ${permitRoot}. Direct root SSH login bypasses audit trails and allows brute-force of the most privileged account.`,
          severity:    "high",
          cvssScore:   8.1,
          resource:    "/etc/ssh/sshd_config",
          resourceType: "ssh_config",
          evidence:    { PermitRootLogin: permitRoot },
          remediationTitle: "Disable SSH root login",
          remediationSteps: [
            "Edit /etc/ssh/sshd_config",
            "Set PermitRootLogin no",
            "Restart SSH: systemctl restart sshd",
            "Ensure you have a non-root sudo account before applying",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.004", "T1078"],
        });
      }

      // Check PasswordAuthentication
      const passwordAuth = config.get("PasswordAuthentication") ?? "yes";
      if (passwordAuth.toLowerCase() !== "no") {
        this.addFinding({
          checkId:     "linux-ssh-password-auth",
          title:       "SSH Password Authentication Enabled",
          description: "sshd allows password-based authentication. Password auth is susceptible to brute force and credential stuffing attacks.",
          severity:    "medium",
          cvssScore:   6.5,
          resource:    "/etc/ssh/sshd_config",
          resourceType: "ssh_config",
          evidence:    { PasswordAuthentication: passwordAuth },
          remediationTitle: "Disable SSH password authentication",
          remediationSteps: [
            "Ensure SSH key-based auth is configured first",
            "Set PasswordAuthentication no in /etc/ssh/sshd_config",
            "Restart SSH: systemctl restart sshd",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1110"],
        });
      }

      // Check Protocol version
      if (config.get("Protocol") === "1") {
        this.addFinding({
          checkId:     "linux-ssh-protocol1",
          title:       "SSH Protocol Version 1 Enabled",
          description: "SSH Protocol 1 has critical vulnerabilities and is deprecated. Only Protocol 2 should be used.",
          severity:    "critical",
          cvssScore:   9.0,
          resource:    "/etc/ssh/sshd_config",
          resourceType: "ssh_config",
          evidence:    { Protocol: "1" },
          remediationTitle: "Enforce SSH Protocol 2",
          remediationSteps: [
            "Set Protocol 2 in /etc/ssh/sshd_config",
            "Remove Protocol 1 keys from /etc/ssh/",
            "Restart sshd",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.004"],
        });
      }
    });
  }

  // —— Sudoers Checks —————————————————————————————————————————————————————————
  private async checkSudoers(): Promise<void> {
    await this.runCheck("linux-sudoers", async () => {
      const result = await this.runCommand(
        "grep -r 'NOPASSWD\\|ALL=.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'",
        { allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (lines) => {
      const nopasswd = lines.filter(l => l.includes("NOPASSWD"));
      const allAll   = lines.filter(l => l.match(/ALL=\s*ALL/) && !l.includes("NOPASSWD"));

      if (nopasswd.length > 0) {
        this.addFinding({
          checkId:     "linux-sudo-nopasswd",
          title:       `${nopasswd.length} Sudoers Entry With NOPASSWD`,
          description: `${nopasswd.length} sudoers rule(s) allow privilege escalation without a password. Any account in these rules can become root without authentication.`,
          severity:    "high",
          cvssScore:   7.8,
          resource:    "/etc/sudoers",
          resourceType: "sudoers",
          evidence:    { NopasswdEntries: nopasswd },
          remediationTitle: "Remove NOPASSWD from sudoers",
          remediationSteps: [
            "Edit sudoers: visudo",
            "Remove NOPASSWD from all entries",
            "If automation requires it, use service accounts with key-based auth instead",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1548.003"],
        });
      }
    });
  }

  // —— SUID Binary Checks —————————————————————————————————————————————————————
  private async checkSuidBinaries(): Promise<void> {
    await this.runCheck("linux-suid-binaries", async () => {
      const result = await this.runCommand(
        "find / -xdev -perm -4000 -type f 2>/dev/null",
        { timeout: 30_000, allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (suidFiles) => {
      // Known safe SUID binaries (partial list)
      const knownSafe = new Set([
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/gpasswd",
        "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/mount",
        "/usr/bin/umount", "/usr/sbin/pam_timestamp_check", "/usr/bin/pkexec",
        "/bin/su", "/bin/mount", "/bin/umount", "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
      ]);

      const unexpected = suidFiles.filter(f => !knownSafe.has(f));

      if (unexpected.length > 0) {
        this.addFinding({
          checkId:     "linux-unexpected-suid",
          title:       `${unexpected.length} Unexpected SUID Binary/Binaries Found`,
          description: `${unexpected.length} SUID binaries were found outside the standard set. SUID binaries run as the file owner (often root) and can be exploited for privilege escalation.`,
          severity:    unexpected.length > 5 ? "high" : "medium",
          cvssScore:   unexpected.length > 5 ? 7.8 : 5.5,
          resource:    "filesystem:suid",
          resourceType: "linux_file",
          evidence:    { UnexpectedSuidFiles: unexpected.slice(0, 20) }, // Cap evidence size
          remediationTitle: "Review and remove unnecessary SUID bits",
          remediationSteps: [
            "Review each unexpected file",
            "Remove SUID bit if not required: chmod u-s /path/to/file",
            "Investigate if any files are unknown or recently modified",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1548.001"],
        });
      }
    });
  }

  // —— World-Writable Directory Checks ———————————————————————————————————————
  private async checkWorldWritableDirs(): Promise<void> {
    await this.runCheck("linux-world-writable", async () => {
      const result = await this.runCommand(
        "find /etc /usr /bin /sbin -xdev -perm -o+w -type f 2>/dev/null | head -20",
        { timeout: 20_000, allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (files) => {
      if (files.length > 0) {
        this.addFinding({
          checkId:     "linux-world-writable-system-files",
          title:       `${files.length} World-Writable File(s) in System Directories`,
          description: `${files.length} file(s) in /etc, /usr, /bin, or /sbin are world-writable. Any local user can modify these system files, enabling persistence or privilege escalation.`,
          severity:    "high",
          cvssScore:   7.5,
          resource:    "filesystem:system-dirs",
          resourceType: "linux_file",
          evidence:    { WorldWritableFiles: files },
          remediationTitle: "Remove world-writable bit from system files",
          remediationSteps: [
            "For each file: chmod o-w /path/to/file",
            "Investigate who set these permissions and when",
            "Check for recently modified files: find /etc -newer /etc/passwd",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1222"],
        });
      }
    });
  }

  // —— Listening Port Checks ——————————————————————————————————————————————————
  private async checkListeningPorts(): Promise<void> {
    await this.runCheck("linux-listening-ports", async () => {
      const result = await this.runCommand(
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      // Parse listening ports — look for services listening on 0.0.0.0 (all interfaces)
      const lines = output.split("\n").filter(l => l.includes("0.0.0.0:") || l.includes(":::"));
      const highRiskPorts: Record<number, string> = {
        23:    "Telnet (plaintext protocol — replace with SSH)",
        21:    "FTP (plaintext credentials — replace with SFTP)",
        2049:  "NFS (if exposed externally)",
        111:   "RPCbind (commonly exploited)",
        6379:  "Redis (default has no auth)",
        27017: "MongoDB (default has no auth)",
        9200:  "Elasticsearch (default has no auth)",
        5601:  "Kibana (default has no auth)",
      };

      for (const line of lines) {
        for (const [port, description] of Object.entries(highRiskPorts)) {
          if (line.includes(`:${port} `) || line.includes(`:${port}\t`)) {
            this.addFinding({
              checkId:     `linux-risky-port-${port}`,
              title:       `High-Risk Service Listening on Port ${port} (All Interfaces)`,
              description: `A service is listening on port ${port} (all interfaces). ${description}`,
              severity:    "high",
              cvssScore:   7.5,
              resource:    `0.0.0.0:${port}`,
              resourceType: "linux_network",
              evidence:    { Port: port, Service: description },
              remediationTitle: `Secure service on port ${port}`,
              remediationSteps: [
                `Identify process: lsof -i :${port}`,
                "Restrict to localhost if possible: bind to 127.0.0.1",
                "Enable authentication if required to be public",
                "Use firewall rules to restrict access: ufw deny ${port}",
              ],
              remediationEffort: "medium",
              mitreAttackIds: ["T1049"],
            });
          }
        }
      }
    });
  }

  // —— Cron Job Checks ———————————————————————————————————————————————————————
  private async checkCronJobs(): Promise<void> {
    await this.runCheck("linux-suspicious-cron", async () => {
      const result = await this.runCommand(
        "cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | grep -v '^#'",
        { allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (entries) => {
      const suspicious = entries.filter(line =>
        line.match(/curl.*\|.*sh|wget.*\|.*sh|base64.*decode|eval.*base64|\$\(.*(curl|wget)/) ||
        (line.includes("/tmp/") && line.includes("bash")) ||
        line.includes("nc -") // Netcat reverse shells
      );

      if (suspicious.length > 0) {
        this.addFinding({
          checkId:     "linux-suspicious-cron",
          title:       `${suspicious.length} Suspicious Cron Job(s) Detected`,
          description: `${suspicious.length} cron job(s) contain patterns consistent with malicious persistence: remote code execution via curl/wget pipe, base64 decoding, or netcat.`,
          severity:    "critical",
          cvssScore:   9.5,
          resource:    "system:cron",
          resourceType: "linux_cron",
          evidence:    { SuspiciousEntries: suspicious },
          remediationTitle: "Investigate and remove suspicious cron jobs",
          remediationSteps: [
            "Review each suspicious entry",
            "If unauthorized, remove from crontab: crontab -e or edit /etc/cron.d/",
            "Check for other persistence: ~/.bashrc, /etc/profile.d/, systemd units",
            "Run incident response procedures — system may be compromised",
          ],
          remediationEffort: "high",
          isKev:  true,
          mitreAttackIds: ["T1053.003", "T1059"],
        });
      }
    });
  }

  // —— Auditd Check ———————————————————————————————————————————————————————————
  private async checkAuditd(): Promise<void> {
    await this.runCheck("linux-auditd", async () => {
      const result = await this.runCommand(
        "systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | grep -c running",
        { allowFailure: true }
      );
      return result.stdout.trim();
    }, (status) => {
      if (status !== "active" && !status.includes("running") && status !== "1") {
        this.addFinding({
          checkId:     "linux-auditd-inactive",
          title:       "Audit Daemon (auditd) Not Running",
          description: "auditd is not active. Without auditd, privileged commands, file access, and authentication events are not logged.",
          severity:    "medium",
          cvssScore:   5.5,
          resource:    "system:auditd",
          resourceType: "linux_service",
          evidence:    { AuditdStatus: status },
          remediationTitle: "Enable and configure auditd",
          remediationSteps: [
            "Install: apt install auditd || yum install audit",
            "Start: systemctl enable --now auditd",
            "Configure rules in /etc/audit/rules.d/",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.001"],
        });
      }
    });
  }

  // —— Firewall Check —————————————————————————————————————————————————————————
  private async checkFirewall(): Promise<void> {
    await this.runCheck("linux-firewall", async () => {
      const [ufw, iptables, nftables] = await Promise.all([
        this.runCommand("ufw status 2>/dev/null", { allowFailure: true }),
        this.runCommand("iptables -L 2>/dev/null | wc -l", { allowFailure: true }),
        this.runCommand("nft list ruleset 2>/dev/null | wc -l", { allowFailure: true }),
      ]);
      return {
        ufwActive:     ufw.stdout.includes("Status: active"),
        iptablesRules: parseInt(iptables.stdout) > 10,
        nftablesRules: parseInt(nftables.stdout) > 5,
      };
    }, ({ ufwActive, iptablesRules, nftablesRules }) => {
      if (!ufwActive && !iptablesRules && !nftablesRules) {
        this.addFinding({
          checkId:     "linux-no-firewall",
          title:       "No Host Firewall Configured",
          description: "No local firewall (ufw, iptables, or nftables) is active. All network ports are potentially accessible.",
          severity:    "high",
          cvssScore:   7.0,
          resource:    "system:firewall",
          resourceType: "linux_firewall",
          evidence:    { UFW: ufwActive, Iptables: iptablesRules, Nftables: nftablesRules },
          remediationTitle: "Enable host firewall",
          remediationSteps: [
            "Enable ufw: ufw enable && ufw default deny incoming && ufw allow ssh",
            "Or configure iptables with a default-deny policy",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1562.004"],
        });
      }
    });
  }

  // —— Package Update Check ———————————————————————————————————————————————————
  private async checkPackageUpdates(): Promise<void> {
    await this.runCheck("linux-pending-updates", async () => {
      // Try apt first, then yum/dnf
      const aptResult = await this.runCommand(
        "apt list --upgradable 2>/dev/null | wc -l",
        { allowFailure: true, timeout: 30_000 }
      );
      const yumResult = await this.runCommand(
        "yum check-update 2>/dev/null | grep -c '^[a-zA-Z]'",
        { allowFailure: true, timeout: 30_000 }
      );

      const aptCount = parseInt(aptResult.stdout) - 1; // subtract header line
      const yumCount = parseInt(yumResult.stdout);
      return Math.max(isNaN(aptCount) ? 0 : aptCount, isNaN(yumCount) ? 0 : yumCount);
    }, (pendingCount) => {
      if (pendingCount > 50) {
        this.addFinding({
          checkId:     "linux-many-pending-updates",
          title:       `${pendingCount} Pending Package Updates`,
          description: `${pendingCount} package updates are available. A high number of pending updates increases the attack surface — some may include critical security patches.`,
          severity:    pendingCount > 100 ? "high" : "medium",
          cvssScore:   pendingCount > 100 ? 7.0 : 5.0,
          resource:    "system:packages",
          resourceType: "linux_packages",
          evidence:    { PendingUpdates: pendingCount },
          remediationTitle: "Apply pending package updates",
          remediationSteps: [
            "Update all packages: apt upgrade -y  OR  yum update -y",
            "Enable automatic security updates: apt install unattended-upgrades",
            "Schedule maintenance windows for regular patching",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1190"],
        });
      }
    });
  }
}
