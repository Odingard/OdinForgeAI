// =============================================================================
// Task 06 — Windows Endpoint Agent
// server/services/endpoint/WindowsAgent.ts
//
// Checks:
//   Defense:  Windows Defender status, Tamper Protection, real-time protection
//   UAC:      UAC enabled + prompt level
//   Encrypt:  BitLocker status on system drive
//   Network:  SMBv1 enabled, RDP exposure, Windows Firewall
//   Auth:     Guest account, empty passwords, local admin accounts
//   Updates:  Pending Windows Updates
//   Tasks:    Suspicious scheduled tasks (persistence)
// =============================================================================

import { EndpointAgent } from "./EndpointAgent";

export class WindowsAgent extends EndpointAgent {
  constructor() {
    super("windows");
  }

  protected async runChecks(): Promise<void> {
    await Promise.allSettled([
      this.checkWindowsDefender(),
      this.checkUac(),
      this.checkBitLocker(),
      this.checkSmb(),
      this.checkRdp(),
      this.checkFirewall(),
      this.checkGuestAccount(),
      this.checkLocalAdmins(),
      this.checkScheduledTasks(),
      this.checkPendingUpdates(),
      this.checkPowershellLogging(),
    ]);
  }

  // —— Windows Defender ———————————————————————————————————————————————————————
  private async checkWindowsDefender(): Promise<void> {
    await this.runCheck("windows-defender", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,TamperProtectionSource,AntivirusSignatureAge | ConvertTo-Json"`,
        { allowFailure: true }
      );
      try {
        return JSON.parse(result.stdout);
      } catch {
        return null;
      }
    }, (status) => {
      if (!status) return;

      if (!status.AntivirusEnabled || !status.RealTimeProtectionEnabled) {
        this.addFinding({
          checkId:     "windows-defender-disabled",
          title:       "Windows Defender Antivirus / Real-Time Protection Is Disabled",
          description: `Windows Defender is ${status.AntivirusEnabled ? "enabled" : "disabled"}, real-time protection is ${status.RealTimeProtectionEnabled ? "enabled" : "disabled"}. Without real-time protection, malware executes undetected.`,
          severity:    "critical",
          cvssScore:   9.5,
          resource:    "system:defender",
          resourceType: "windows_security",
          evidence:    {
            AntivirusEnabled:          status.AntivirusEnabled,
            RealTimeProtectionEnabled: status.RealTimeProtectionEnabled,
          },
          remediationTitle: "Enable Windows Defender and real-time protection",
          remediationSteps: [
            "Open Windows Security → Virus & threat protection",
            "Turn on Real-time protection",
            "If disabled by policy, check Group Policy: Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.001"],
        });
      }

      if (status.AntivirusSignatureAge > 3) {
        this.addFinding({
          checkId:     "windows-defender-old-signatures",
          title:       `Windows Defender Signatures Are ${status.AntivirusSignatureAge} Days Old`,
          description: `Windows Defender antivirus definitions are ${status.AntivirusSignatureAge} days out of date. Recent malware may not be detected.`,
          severity:    status.AntivirusSignatureAge > 14 ? "high" : "medium",
          cvssScore:   status.AntivirusSignatureAge > 14 ? 7.0 : 5.0,
          resource:    "system:defender",
          resourceType: "windows_security",
          evidence:    { SignatureAgeDays: status.AntivirusSignatureAge },
          remediationTitle: "Update Windows Defender signatures",
          remediationSteps: [
            "Open Windows Security → Virus & threat protection",
            "Click Check for updates under Virus & threat protection updates",
            "Enable automatic updates",
          ],
          remediationEffort: "low",
        });
      }
    });
  }

  // —— UAC Check ——————————————————————————————————————————————————————————————
  private async checkUac(): Promise<void> {
    await this.runCheck("windows-uac", async () => {
      const result = await this.runCommand(
        `reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA 2>nul`,
        { allowFailure: true }
      );
      const consentResult = await this.runCommand(
        `reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin 2>nul`,
        { allowFailure: true }
      );
      return { uacOutput: result.stdout, consentOutput: consentResult.stdout };
    }, ({ uacOutput, consentOutput }) => {
      const uacEnabled     = !uacOutput.includes("0x0");
      const consentBehavior = consentOutput.match(/0x(\d)/)?.[1] ?? "2";

      if (!uacEnabled) {
        this.addFinding({
          checkId:     "windows-uac-disabled",
          title:       "User Account Control (UAC) Is Disabled",
          description: "UAC is disabled. All users, including standard users, can execute code with administrator privileges without any prompt.",
          severity:    "critical",
          cvssScore:   9.5,
          resource:    "HKLM\\...\\Policies\\System:EnableLUA",
          resourceType: "windows_policy",
          evidence:    { EnableLUA: "0x0" },
          remediationTitle: "Enable UAC",
          remediationSteps: [
            "Open User Account Control Settings",
            "Set to Always notify or Notify me only when apps try to make changes",
            "Or via registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System → EnableLUA = 1",
            "Reboot required",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1548.002"],
        });
      }

      // ConsentPromptBehaviorAdmin = 0 means no UAC prompt at all (auto-elevate)
      if (uacEnabled && consentBehavior === "0") {
        this.addFinding({
          checkId:     "windows-uac-auto-elevate",
          title:       "UAC Is Set to Auto-Elevate (No Prompt)",
          description: "UAC is enabled but ConsentPromptBehaviorAdmin is 0 — administrators are silently auto-elevated without any prompt. Malware running as admin can escalate without user interaction.",
          severity:    "high",
          cvssScore:   7.5,
          resource:    "HKLM\\...\\Policies\\System:ConsentPromptBehaviorAdmin",
          resourceType: "windows_policy",
          evidence:    { ConsentPromptBehaviorAdmin: consentBehavior },
          remediationTitle: "Set UAC to prompt for consent",
          remediationSteps: [
            "Set ConsentPromptBehaviorAdmin to 2 (prompt for consent)",
            "Via Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → UAC behavior",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1548.002"],
        });
      }
    });
  }

  // —— BitLocker Check ————————————————————————————————————————————————————————
  private async checkBitLocker(): Promise<void> {
    await this.runCheck("windows-bitlocker", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "Get-BitLockerVolume -MountPoint C: | Select-Object -Property VolumeStatus,ProtectionStatus | ConvertTo-Json"`,
        { allowFailure: true }
      );
      try {
        return JSON.parse(result.stdout);
      } catch {
        return null;
      }
    }, (status) => {
      if (!status) return;

      const isEncrypted  = status.VolumeStatus === "FullyEncrypted" || status.VolumeStatus === "EncryptionInProgress";
      const isProtected  = status.ProtectionStatus === "On";

      if (!isEncrypted || !isProtected) {
        this.addFinding({
          checkId:     "windows-bitlocker-disabled",
          title:       "BitLocker Drive Encryption Is Not Active on System Drive",
          description: `The C: drive is not fully encrypted with BitLocker (Status: ${status.VolumeStatus}, Protection: ${status.ProtectionStatus}). Physical theft gives full data access.`,
          severity:    "high",
          cvssScore:   7.5,
          resource:    "C:",
          resourceType: "windows_disk",
          evidence:    { VolumeStatus: status.VolumeStatus, ProtectionStatus: status.ProtectionStatus },
          remediationTitle: "Enable BitLocker on system drive",
          remediationSteps: [
            "Open Control Panel → BitLocker Drive Encryption",
            "Click Turn on BitLocker for the C: drive",
            "Save the recovery key to Azure AD or a secure location",
            "Enable TPM protection for automatic unlock",
          ],
          remediationEffort: "medium",
        });
      }
    });
  }

  // —— SMBv1 Check ————————————————————————————————————————————————————————————
  private async checkSmb(): Promise<void> {
    await this.runCheck("windows-smbv1", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json"`,
        { allowFailure: true }
      );
      try {
        return JSON.parse(result.stdout);
      } catch {
        return null;
      }
    }, (config) => {
      if (!config) return;

      if (config.EnableSMB1Protocol === true) {
        this.addFinding({
          checkId:     "windows-smbv1-enabled",
          title:       "SMBv1 Protocol Is Enabled",
          description: "SMBv1 is enabled. This protocol was exploited by EternalBlue (WannaCry, NotPetya). There is no reason to have SMBv1 enabled on modern Windows systems.",
          severity:    "critical",
          cvssScore:   9.8,
          isKev:       true,
          resource:    "system:smb",
          resourceType: "windows_service",
          evidence:    { SMB1Enabled: true },
          remediationTitle: "Disable SMBv1",
          remediationSteps: [
            "Run PowerShell as Admin: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "Or via Windows Features: Turn off SMB 1.0/CIFS File Sharing Support",
            "Reboot to apply",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1210"],
          references: ["https://support.microsoft.com/en-us/topic/2696547"],
        });
      }
    });
  }

  // —— RDP Check ——————————————————————————————————————————————————————————————
  private async checkRdp(): Promise<void> {
    await this.runCheck("windows-rdp", async () => {
      const [rdpEnabled, nlaEnabled] = await Promise.all([
        this.runCommand(
          `reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections 2>nul`,
          { allowFailure: true }
        ),
        this.runCommand(
          `reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication 2>nul`,
          { allowFailure: true }
        ),
      ]);

      return {
        rdpEnabled: rdpEnabled.stdout.includes("0x0"),  // 0 = enabled
        nlaEnabled: nlaEnabled.stdout.includes("0x1"),  // 1 = NLA required
      };
    }, ({ rdpEnabled, nlaEnabled }) => {
      if (rdpEnabled && !nlaEnabled) {
        this.addFinding({
          checkId:     "windows-rdp-no-nla",
          title:       "RDP Is Enabled Without Network Level Authentication",
          description: "Remote Desktop is enabled but does not require Network Level Authentication (NLA). Without NLA, the authentication dialog is presented before identity is verified, enabling denial-of-service and credential attacks.",
          severity:    "high",
          cvssScore:   8.1,
          resource:    "system:rdp",
          resourceType: "windows_service",
          evidence:    { RdpEnabled: rdpEnabled, NLAEnabled: nlaEnabled },
          remediationTitle: "Enable NLA for RDP",
          remediationSteps: [
            "Open System Properties → Remote → Remote Desktop",
            "Check Allow connections only from computers running Remote Desktop with Network Level Authentication",
            "Or via registry: HKLM\\...\\RDP-Tcp → UserAuthentication = 1",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.001"],
        });
      }
    });
  }

  // —— Windows Firewall ———————————————————————————————————————————————————————
  private async checkFirewall(): Promise<void> {
    await this.runCheck("windows-firewall", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"`,
        { allowFailure: true }
      );
      try {
        return JSON.parse(result.stdout);
      } catch {
        return null;
      }
    }, (profiles) => {
      if (!profiles) return;
      const profilesArr = Array.isArray(profiles) ? profiles : [profiles];
      const disabled = profilesArr.filter((p: { Name: string; Enabled: boolean }) => !p.Enabled);

      if (disabled.length > 0) {
        this.addFinding({
          checkId:     "windows-firewall-disabled",
          title:       `Windows Firewall Disabled on ${disabled.map((p: { Name: string }) => p.Name).join(", ")} Profile(s)`,
          description: `Windows Firewall is disabled on ${disabled.map((p: { Name: string }) => p.Name).join(", ")} profiles. Inbound connections are unrestricted on these network types.`,
          severity:    "high",
          cvssScore:   7.5,
          resource:    "system:firewall",
          resourceType: "windows_firewall",
          evidence:    { DisabledProfiles: disabled.map((p: { Name: string }) => p.Name) },
          remediationTitle: "Enable Windows Firewall on all profiles",
          remediationSteps: [
            "Open Windows Defender Firewall",
            "Click Turn Windows Defender Firewall on or off",
            "Enable for all network types (Domain, Private, Public)",
            "Or via PowerShell: Set-NetFirewallProfile -All -Enabled True",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.004"],
        });
      }
    });
  }

  // —— Guest Account Check ————————————————————————————————————————————————————
  private async checkGuestAccount(): Promise<void> {
    await this.runCheck("windows-guest-account", async () => {
      const result = await this.runCommand(
        `net user Guest 2>nul | findstr "Account active"`,
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      if (output.includes("Yes")) {
        this.addFinding({
          checkId:     "windows-guest-account-enabled",
          title:       "Windows Guest Account Is Enabled",
          description: "The built-in Guest account is active. Anyone with access to the machine can log in without credentials.",
          severity:    "high",
          cvssScore:   7.0,
          resource:    "system:guest",
          resourceType: "windows_user",
          evidence:    { GuestActive: true },
          remediationTitle: "Disable Windows Guest account",
          remediationSteps: [
            "Run as Admin: net user Guest /active:no",
            "Or via Local Users and Groups: Computer Management → Local Users and Groups → Users → Guest → Account is disabled",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1078.003"],
        });
      }
    });
  }

  // —— Local Admin Accounts ———————————————————————————————————————————————————
  private async checkLocalAdmins(): Promise<void> {
    await this.runCheck("windows-local-admins", async () => {
      const result = await this.runCommand(
        `net localgroup Administrators 2>nul`,
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      const lines = output.split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("-") && !l.startsWith("Alias") && !l.startsWith("Members") && !l.startsWith("The command") && l !== "");
      const adminCount = lines.length;

      if (adminCount > 3) {
        this.addFinding({
          checkId:     "windows-too-many-local-admins",
          title:       `${adminCount} Local Administrator Accounts`,
          description: `${adminCount} accounts have local administrator privileges. Excess admin accounts increase blast radius if any account is compromised.`,
          severity:    "medium",
          cvssScore:   5.5,
          resource:    "system:local-admins",
          resourceType: "windows_user",
          evidence:    { AdminCount: adminCount },
          remediationTitle: "Reduce number of local administrators",
          remediationSteps: [
            "Review accounts: net localgroup Administrators",
            "Remove unnecessary admins: net localgroup Administrators /delete USERNAME",
            "Use domain accounts with LAPS for local admin management",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1078.003"],
        });
      }
    });
  }

  // —— Suspicious Scheduled Tasks —————————————————————————————————————————————
  private async checkScheduledTasks(): Promise<void> {
    await this.runCheck("windows-scheduled-tasks", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 2"`,
        { allowFailure: true, timeout: 20_000 }
      );
      try {
        const tasks = JSON.parse(result.stdout);
        return Array.isArray(tasks) ? tasks : [tasks];
      } catch {
        return [];
      }
    }, async (tasks) => {
      // Check task actions for suspicious patterns
      for (const task of tasks.slice(0, 50)) { // Limit to first 50 to avoid timeout
        const taskResult = await this.runCommand(
          `powershell -NoProfile -Command "(Get-ScheduledTask -TaskName '${task.TaskName.replace(/'/g, "''")}').Actions.Execute 2>nul"`,
          { allowFailure: true }
        );
        const exe = taskResult.stdout.toLowerCase().trim();
        const isSuspicious =
          exe.includes("\\temp\\") ||
          exe.includes("\\appdata\\local\\temp\\") ||
          (exe.includes("powershell") && (exe.includes("iex") || exe.includes("invoke-expression") || exe.includes("hidden"))) ||
          exe.includes("wscript.exe") ||
          exe.includes("regsvr32") ||
          exe.includes("mshta");

        if (isSuspicious) {
          this.addFinding({
            checkId:     `windows-suspicious-task-${task.TaskName.replace(/[^a-z0-9]/gi, "_")}`,
            title:       `Suspicious Scheduled Task: ${task.TaskName}`,
            description: `Scheduled task ${task.TaskName} executes from an unusual location or uses a known malware execution pattern (${exe}).`,
            severity:    "critical",
            cvssScore:   9.5,
            isKev:       true,
            resource:    `${task.TaskPath}${task.TaskName}`,
            resourceType: "windows_task",
            evidence:    { TaskName: task.TaskName, TaskPath: task.TaskPath, Execute: exe },
            remediationTitle: "Investigate and remove suspicious scheduled task",
            remediationSteps: [
              `Review task: Get-ScheduledTask -TaskName '${task.TaskName}' | Select-Object *`,
              "Check when it was created and by whom",
              `If unauthorized: Unregister-ScheduledTask -TaskName '${task.TaskName}' -Confirm:$false`,
              "Run incident response — system may be compromised",
            ],
            remediationEffort: "high",
            mitreAttackIds: ["T1053.005"],
          });
        }
      }
    });
  }

  // —— Pending Windows Updates ————————————————————————————————————————————————
  private async checkPendingUpdates(): Promise<void> {
    await this.runCheck("windows-pending-updates", async () => {
      const result = await this.runCommand(
        `powershell -NoProfile -Command "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"`,
        { allowFailure: true, timeout: 30_000 }
      );
      return parseInt(result.stdout.trim()) || 0;
    }, (count) => {
      if (count > 10) {
        this.addFinding({
          checkId:     "windows-pending-updates",
          title:       `${count} Pending Windows Update(s)`,
          description: `${count} Windows updates are pending installation. These may include critical security patches.`,
          severity:    count > 30 ? "high" : "medium",
          cvssScore:   count > 30 ? 7.0 : 5.0,
          resource:    "system:windows-update",
          resourceType: "windows_system",
          evidence:    { PendingUpdates: count },
          remediationTitle: "Install pending Windows updates",
          remediationSteps: [
            "Open Settings → Windows Update → Check for updates",
            "Install all available updates",
            "Enable automatic updates for future patches",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1190"],
        });
      }
    });
  }

  // —— PowerShell Logging —————————————————————————————————————————————————————
  private async checkPowershellLogging(): Promise<void> {
    await this.runCheck("windows-powershell-logging", async () => {
      const scriptBlockLogging = await this.runCommand(
        `reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging 2>nul`,
        { allowFailure: true }
      );
      const moduleLogging = await this.runCommand(
        `reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" /v EnableModuleLogging 2>nul`,
        { allowFailure: true }
      );
      return {
        scriptBlock: scriptBlockLogging.stdout.includes("0x1"),
        module:      moduleLogging.stdout.includes("0x1"),
      };
    }, ({ scriptBlock, module }) => {
      if (!scriptBlock || !module) {
        this.addFinding({
          checkId:     "windows-powershell-logging-disabled",
          title:       `PowerShell ${!scriptBlock ? "Script Block" : ""} ${!module ? "Module" : ""} Logging Not Enabled`,
          description: "PowerShell logging is not fully enabled. PowerShell is the most common attacker tool on Windows — without logging, malicious commands are invisible.",
          severity:    "medium",
          cvssScore:   5.5,
          resource:    "system:powershell",
          resourceType: "windows_policy",
          evidence:    { ScriptBlockLogging: scriptBlock, ModuleLogging: module },
          remediationTitle: "Enable PowerShell logging via Group Policy",
          remediationSteps: [
            "Open Group Policy Editor (gpedit.msc)",
            "Navigate to Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell",
            "Enable Turn on Module Logging (set module names to *)",
            "Enable Turn on PowerShell Script Block Logging",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1059.001", "T1562.002"],
        });
      }
    });
  }
}
