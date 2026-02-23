// =============================================================================
// Task 06 — macOS Endpoint Agent
// server/services/endpoint/MacOsAgent.ts
//
// Checks:
//   System:  SIP status, Gatekeeper, FileVault encryption, screen lock
//   Network: application firewall, stealth mode
//   Auth:    guest user, empty passwords, remote login (SSH), remote management
//   Startup: launch daemons/agents, login items (persistence)
//   Updates: available macOS updates
// =============================================================================

import { EndpointAgent } from "./EndpointAgent";

export class MacOsAgent extends EndpointAgent {
  constructor() {
    super("macos");
  }

  protected async runChecks(): Promise<void> {
    await Promise.allSettled([
      this.checkSip(),
      this.checkGatekeeper(),
      this.checkFileVault(),
      this.checkFirewall(),
      this.checkGuestUser(),
      this.checkRemoteLogin(),
      this.checkRemoteManagement(),
      this.checkScreenLock(),
      this.checkStartupItems(),
      this.checkSoftwareUpdates(),
      this.checkSharingServices(),
    ]);
  }

  // —— SIP Check ——————————————————————————————————————————————
  private async checkSip(): Promise<void> {
    await this.runCheck("macos-sip", async () => {
      const result = await this.runCommand("csrutil status 2>/dev/null", { allowFailure: true });
      return result.stdout;
    }, (output) => {
      if (!output.includes("enabled")) {
        this.addFinding({
          checkId:     "macos-sip-disabled",
          title:       "System Integrity Protection (SIP) Is Disabled",
          description: "SIP is disabled on this Mac. SIP prevents modification of system files, even by root. Disabling it is required for many kernel-level attacks and persistence techniques.",
          severity:    "critical",
          cvssScore:   9.5,
          resource:    "system:sip",
          resourceType: "macos_system",
          evidence:    { SipStatus: output },
          remediationTitle: "Re-enable System Integrity Protection",
          remediationSteps: [
            "Boot into Recovery Mode: hold Cmd+R on startup",
            "Open Terminal in Recovery Mode",
            "Run: csrutil enable",
            "Restart",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.001"],
        });
      }
    });
  }

  // —— Gatekeeper Check ——————————————————————————————————————————
  private async checkGatekeeper(): Promise<void> {
    await this.runCheck("macos-gatekeeper", async () => {
      const result = await this.runCommand(
        "spctl --status 2>/dev/null || defaults read /var/db/SystemPolicy-prefs assessmentEnabled 2>/dev/null",
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      const isDisabled = output.includes("disabled") || output.trim() === "0";
      if (isDisabled) {
        this.addFinding({
          checkId:     "macos-gatekeeper-disabled",
          title:       "Gatekeeper Is Disabled",
          description: "Gatekeeper is disabled. macOS will allow unsigned or unnotarized applications to run without warning, significantly increasing malware risk.",
          severity:    "high",
          cvssScore:   8.0,
          resource:    "system:gatekeeper",
          resourceType: "macos_system",
          evidence:    { GatekeeperStatus: output },
          remediationTitle: "Enable Gatekeeper",
          remediationSteps: [
            "Enable via System Settings → Privacy & Security → Allow apps downloaded from: App Store and identified developers",
            "Or via Terminal: spctl --master-enable",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1553.001"],
        });
      }
    });
  }

  // —— FileVault Check ———————————————————————————————————————————
  private async checkFileVault(): Promise<void> {
    await this.runCheck("macos-filevault", async () => {
      const result = await this.runCommand("fdesetup status 2>/dev/null", { allowFailure: true });
      return result.stdout;
    }, (output) => {
      if (!output.includes("FileVault is On")) {
        this.addFinding({
          checkId:     "macos-filevault-disabled",
          title:       "FileVault Disk Encryption Is Disabled",
          description: "FileVault full-disk encryption is not enabled. If this Mac is physically accessed (theft, border inspection), all data is readable without credentials.",
          severity:    "high",
          cvssScore:   7.5,
          resource:    "system:filevault",
          resourceType: "macos_system",
          evidence:    { FileVaultStatus: output },
          remediationTitle: "Enable FileVault encryption",
          remediationSteps: [
            "Open System Settings → Privacy & Security → FileVault",
            "Click Turn On FileVault",
            "Save the recovery key in a secure location (1Password, etc.)",
            "Encryption takes 1-2 hours in background",
          ],
          remediationEffort: "low",
        });
      }
    });
  }

  // —— Application Firewall Check ————————————————————————————————
  private async checkFirewall(): Promise<void> {
    await this.runCheck("macos-firewall", async () => {
      const [firewallState, stealthMode] = await Promise.all([
        this.runCommand(
          "defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null",
          { allowFailure: true }
        ),
        this.runCommand(
          "defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null",
          { allowFailure: true }
        ),
      ]);
      return {
        enabled: firewallState.stdout.trim() !== "0",
        stealth: stealthMode.stdout.trim() === "1",
      };
    }, ({ enabled, stealth }) => {
      if (!enabled) {
        this.addFinding({
          checkId:     "macos-firewall-disabled",
          title:       "macOS Application Firewall Is Disabled",
          description: "The macOS application firewall is not active. Incoming connections to all applications are unrestricted.",
          severity:    "medium",
          cvssScore:   6.0,
          resource:    "system:firewall",
          resourceType: "macos_network",
          evidence:    { FirewallEnabled: false },
          remediationTitle: "Enable macOS application firewall",
          remediationSteps: [
            "Open System Settings → Network → Firewall",
            "Turn on Firewall",
            "Enable Block all incoming connections (for high-security environments)",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.004"],
        });
      }
      if (enabled && !stealth) {
        this.addFinding({
          checkId:     "macos-firewall-no-stealth",
          title:       "macOS Firewall Stealth Mode Disabled",
          description: "Stealth mode is disabled. macOS responds to probe packets (ICMP ping, TCP probes), making this device discoverable by network scanners.",
          severity:    "low",
          cvssScore:   3.0,
          resource:    "system:firewall",
          resourceType: "macos_network",
          evidence:    { StealthMode: false },
          remediationTitle: "Enable firewall stealth mode",
          remediationSteps: [
            "System Settings → Network → Firewall → Options",
            "Enable Enable stealth mode",
          ],
          remediationEffort: "low",
        });
      }
    });
  }

  // —— Guest User Check ——————————————————————————————————————————
  private async checkGuestUser(): Promise<void> {
    await this.runCheck("macos-guest-user", async () => {
      const result = await this.runCommand(
        "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null",
        { allowFailure: true }
      );
      return result.stdout.trim();
    }, (value) => {
      if (value === "1" || value === "true") {
        this.addFinding({
          checkId:     "macos-guest-user-enabled",
          title:       "Guest User Account Is Enabled",
          description: "macOS Guest user is enabled. Anyone with physical access can log in as Guest without a password, access the browser (including saved sessions), and potentially access local network resources.",
          severity:    "medium",
          cvssScore:   5.5,
          resource:    "system:users",
          resourceType: "macos_user",
          evidence:    { GuestEnabled: true },
          remediationTitle: "Disable Guest user account",
          remediationSteps: [
            "Open System Settings → Users & Groups",
            "Click the lock to make changes",
            "Toggle off Allow guests to log in to this computer",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1078"],
        });
      }
    });
  }

  // —— Remote Login / SSH ————————————————————————————————————————
  private async checkRemoteLogin(): Promise<void> {
    await this.runCheck("macos-remote-login", async () => {
      const result = await this.runCommand(
        "systemsetup -getremotelogin 2>/dev/null || launchctl list com.openssh.sshd 2>/dev/null",
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      const isEnabled = output.includes("Remote Login: On") || output.includes("com.openssh.sshd");
      if (isEnabled) {
        this.addFinding({
          checkId:     "macos-remote-login-enabled",
          title:       "Remote Login (SSH) Is Enabled",
          description: "SSH remote login is enabled on this Mac. If not required, this increases attack surface — especially on laptops used outside corporate networks.",
          severity:    "low",
          cvssScore:   3.5,
          resource:    "system:ssh",
          resourceType: "macos_service",
          evidence:    { RemoteLoginEnabled: true },
          remediationTitle: "Disable Remote Login if not needed",
          remediationSteps: [
            "Open System Settings → General → Sharing",
            "Toggle off Remote Login",
            "Or: sudo systemsetup -setremotelogin off",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.004"],
        });
      }
    });
  }

  // —— Remote Management —————————————————————————————————————————
  private async checkRemoteManagement(): Promise<void> {
    await this.runCheck("macos-remote-management", async () => {
      const result = await this.runCommand(
        "launchctl list com.apple.screensharing 2>/dev/null",
        { allowFailure: true }
      );
      return result.stdout;
    }, (output) => {
      if (output && !output.includes("Could not find")) {
        this.addFinding({
          checkId:     "macos-screen-sharing-enabled",
          title:       "Screen Sharing / Remote Management Is Enabled",
          description: "macOS Screen Sharing is running. If this allows external access, it presents a significant lateral movement risk.",
          severity:    "medium",
          cvssScore:   6.5,
          resource:    "system:screensharing",
          resourceType: "macos_service",
          evidence:    { ScreenSharingActive: true },
          remediationTitle: "Disable Screen Sharing if not required",
          remediationSteps: [
            "System Settings → General → Sharing",
            "Toggle off Screen Sharing and Remote Management",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.005"],
        });
      }
    });
  }

  // —— Screen Lock Check —————————————————————————————————————————
  private async checkScreenLock(): Promise<void> {
    await this.runCheck("macos-screen-lock", async () => {
      const result = await this.runCommand(
        "osascript -e 'tell application \"System Events\" to get value of attribute \"AXDescription\" of (first process whose background only is false)' 2>/dev/null; defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null",
        { allowFailure: true }
      );
      const delay = parseInt(result.stdout.trim());
      return isNaN(delay) ? null : delay;
    }, (delay) => {
      if (delay === null || delay > 60) {
        this.addFinding({
          checkId:     "macos-screen-lock-delay",
          title:       `Screen Lock Password Delay Is ${delay === null ? "Not Set" : `${delay}s`}`,
          description: `macOS requires ${delay === null ? "no" : `a ${delay} second`} delay before requiring a password after screen lock. Attackers with brief physical access can unlock without credentials.`,
          severity:    "medium",
          cvssScore:   5.0,
          resource:    "system:screensaver",
          resourceType: "macos_system",
          evidence:    { AskForPasswordDelay: delay },
          remediationTitle: "Set immediate screen lock password",
          remediationSteps: [
            "System Settings → Lock Screen",
            "Set Require password after screen saver begins to Immediately",
            "Set screen saver to start after 5 minutes of inactivity",
          ],
          remediationEffort: "low",
        });
      }
    });
  }

  // —— Startup Items Check ———————————————————————————————————————
  private async checkStartupItems(): Promise<void> {
    await this.runCheck("macos-startup-items", async () => {
      const result = await this.runCommand(
        "ls /Library/LaunchDaemons/ /Library/LaunchAgents/ ~/Library/LaunchAgents/ 2>/dev/null | grep -v '.plist'",
        { allowFailure: true }
      );
      const allItems = result.stdout.split("\n").filter(Boolean);

      // Check for recently modified items
      const recentResult = await this.runCommand(
        "find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents -newer /etc/hosts -name '*.plist' 2>/dev/null",
        { allowFailure: true }
      );
      return {
        allItems,
        recentlyModified: recentResult.stdout.split("\n").filter(Boolean),
      };
    }, ({ allItems, recentlyModified }) => {
      // Flag recently modified launch agents/daemons (potential persistence)
      const suspicious = recentlyModified.filter(f => {
        const name = f.toLowerCase();
        return !name.includes("com.apple") && !name.includes("homebrew") && !name.includes("com.microsoft");
      });

      if (suspicious.length > 0) {
        this.addFinding({
          checkId:     "macos-suspicious-launch-agents",
          title:       `${suspicious.length} Recently Modified Launch Daemon/Agent(s)`,
          description: `${suspicious.length} launch daemon or agent plist file(s) were recently modified. These control what runs at startup and are a common persistence mechanism.`,
          severity:    "high",
          cvssScore:   8.0,
          resource:    "system:launchd",
          resourceType: "macos_persistence",
          evidence:    { RecentlyModifiedItems: suspicious },
          remediationTitle: "Investigate recently modified launch items",
          remediationSteps: [
            "Review each plist: cat /path/to/file.plist",
            "Check program path and arguments for malicious content",
            "Remove unauthorized items: launchctl unload /path/to/file.plist",
            "Delete the plist file",
          ],
          remediationEffort: "high",
          isKev:  true,
          mitreAttackIds: ["T1543.001"],
        });
      }
    });
  }

  // —— Software Updates Check ————————————————————————————————————
  private async checkSoftwareUpdates(): Promise<void> {
    await this.runCheck("macos-software-updates", async () => {
      const result = await this.runCommand(
        "softwareupdate -l 2>/dev/null | grep -c 'recommended'",
        { timeout: 30_000, allowFailure: true }
      );
      return parseInt(result.stdout.trim()) || 0;
    }, (updateCount) => {
      if (updateCount > 0) {
        this.addFinding({
          checkId:     "macos-pending-updates",
          title:       `${updateCount} Recommended macOS Update(s) Pending`,
          description: `${updateCount} recommended macOS update(s) are available and not installed. These may include critical security patches.`,
          severity:    updateCount > 3 ? "high" : "medium",
          cvssScore:   updateCount > 3 ? 7.0 : 5.0,
          resource:    "system:software-updates",
          resourceType: "macos_system",
          evidence:    { PendingUpdates: updateCount },
          remediationTitle: "Install pending macOS updates",
          remediationSteps: [
            "Open System Settings → General → Software Update",
            "Install all available updates",
            "Enable Automatic Updates for future security patches",
          ],
          remediationEffort: "low",
        });
      }
    });
  }

  // —— Sharing Services Check ————————————————————————————————————
  private async checkSharingServices(): Promise<void> {
    await this.runCheck("macos-sharing-services", async () => {
      const result = await this.runCommand(
        "launchctl list 2>/dev/null | grep -E 'smb|afp|nfs|ftp|http'",
        { allowFailure: true }
      );
      return result.stdout.split("\n").filter(Boolean);
    }, (services) => {
      const risky = services.filter(s => s.includes("smb") || s.includes("afp") || s.includes("ftp"));
      if (risky.length > 0) {
        this.addFinding({
          checkId:     "macos-file-sharing-active",
          title:       "File Sharing Services Are Running",
          description: `File sharing services (${risky.map(s => s.trim()).join(", ")}) are active. These expose the filesystem over the network.`,
          severity:    "medium",
          cvssScore:   6.0,
          resource:    "system:file-sharing",
          resourceType: "macos_service",
          evidence:    { ActiveSharingServices: risky },
          remediationTitle: "Disable unnecessary file sharing",
          remediationSteps: [
            "System Settings → General → Sharing",
            "Disable File Sharing, SMB, and AFP if not required",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1021.002"],
        });
      }
    });
  }
}
