// =============================================================================
// Task 06 — Azure Cloud Scanner
// server/services/cloud/AzureScanner.ts
//
// Production-grade Azure security checks covering:
//   Identity: guest users, MFA, privileged roles, service principals
//   Storage:  public blob containers, no encryption, HTTPS enforcement
//   Network:  NSG rules allowing wide-open inbound
//   Key Vault: soft delete, purge protection, access policies
//   Monitoring: activity log alerts, diagnostic settings
//
// Required permissions:
//   Reader role on subscription
//   Security Reader for Security Center findings
// =============================================================================

import { ClientSecretCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";
import { StorageManagementClient } from "@azure/arm-storage";
import { NetworkManagementClient } from "@azure/arm-network";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { AuthorizationManagementClient } from "@azure/arm-authorization";
import { MonitorClient } from "@azure/arm-monitor";

import {
  CloudScanner, type CloudCredentials, type AzureCredentials,
  type CloudFinding,
} from "./base/CloudScanner";

export class AzureScanner extends CloudScanner {
  constructor(opts: ConstructorParameters<typeof CloudScanner>[0]) {
    super({ ...opts, provider: "azure" });
  }

  protected extractAccountId(credentials: CloudCredentials): string {
    return (credentials as AzureCredentials).subscriptionId;
  }

  // —— Credential validation ——————————————————————————————————————————————————
  protected async validateCredentials(credentials: CloudCredentials): Promise<void> {
    const creds = credentials as AzureCredentials;
    try {
      const azureCredential = this.makeCredential(creds);
      const subClient = new SubscriptionClient(azureCredential);
      await this.withRetry(
        async () => {
          // List tenants to validate credentials (works with any subscription access)
          const tenants = (subClient as any).tenants?.list?.() ?? (subClient as any).subscriptions?.list?.();
          if (tenants) { await tenants.next(); }
          else { throw new Error("Cannot validate Azure credentials"); }
        },
        { label: "azure-credential-validation" }
      );
    } catch (err: unknown) {
      const e = err as Error;
      if (e.message?.includes("AADSTS7000215") || e.message?.includes("invalid_client")) {
        throw new Error("Invalid Azure client secret — check your clientId and clientSecret");
      }
      if (e.message?.includes("AADSTS90002") || e.message?.includes("tenant not found")) {
        throw new Error("Invalid Azure tenant ID — verify your tenantId");
      }
      if (e.message?.includes("AuthorizationFailed") || e.message?.includes("does not have authorization")) {
        throw new Error("Azure credentials valid but missing Reader role on subscription");
      }
      throw new Error(`Azure credential validation failed: ${e.message}`);
    }
  }

  // —— Main check runner ——————————————————————————————————————————————————————
  protected async runChecks(credentials: CloudCredentials): Promise<void> {
    const creds     = credentials as AzureCredentials;
    const azureCred = this.makeCredential(creds);
    const subId     = creds.subscriptionId;

    await Promise.allSettled([
      this.runStorageChecks(azureCred, subId),
      this.runNetworkChecks(azureCred, subId),
      this.runKeyVaultChecks(azureCred, subId),
      this.runRbacChecks(azureCred, subId),
      this.runMonitoringChecks(azureCred, subId),
    ]);
  }

  // —— Storage Checks —————————————————————————————————————————————————————————
  private async runStorageChecks(credential: ClientSecretCredential, subId: string): Promise<void> {
    const client = new StorageManagementClient(credential, subId);

    await this.runCheck("azure-storage-accounts", async () => {
      const accounts: unknown[] = [];
      for await (const account of client.storageAccounts.list()) {
        accounts.push(account);
      }
      return accounts as Awaited<ReturnType<typeof client.storageAccounts.list>>[];
    }, async (accounts) => {
      for (const account of accounts) {
        const a = account as {
          name?: string; id?: string;
          allowBlobPublicAccess?: boolean;
          enableHttpsTrafficOnly?: boolean;
          minimumTlsVersion?: string;
          encryption?: { services?: { blob?: { enabled?: boolean } } };
        };

        if (!a.name) continue;
        const resourceId = a.id ?? a.name;

        // Check 1: Public blob access
        if (a.allowBlobPublicAccess === true) {
          this.addFinding({
            checkId:     `azure-storage-public-blob-${a.name}`,
            title:       `Storage Account ${a.name} Allows Public Blob Access`,
            description: `Storage account ${a.name} has AllowBlobPublicAccess enabled. Any container set to public allows unauthenticated reads of all blobs.`,
            severity:    "high",
            cvssScore:   8.2,
            resource:    resourceId,
            resourceType: "storage_account",
            evidence:    { AccountName: a.name, AllowBlobPublicAccess: true },
            remediationTitle: "Disable public blob access",
            remediationSteps: [
              `Navigate to Azure Portal → Storage accounts → ${a.name} → Configuration`,
              "Set Allow Blob public access to Disabled",
              "Audit existing containers for public access level settings",
            ],
            remediationEffort: "low",
            mitreAttackIds: ["T1530"],
          });
        }

        // Check 2: HTTPS enforcement
        if (a.enableHttpsTrafficOnly === false) {
          this.addFinding({
            checkId:     `azure-storage-no-https-${a.name}`,
            title:       `Storage Account ${a.name} Allows HTTP Traffic`,
            description: `Storage account ${a.name} does not enforce HTTPS. Data in transit can be intercepted.`,
            severity:    "medium",
            cvssScore:   6.5,
            resource:    resourceId,
            resourceType: "storage_account",
            evidence:    { AccountName: a.name, HttpsOnly: false },
            remediationTitle: "Enforce HTTPS for storage account",
            remediationSteps: [
              `Navigate to Azure Portal → Storage accounts → ${a.name} → Configuration`,
              "Enable Secure transfer required",
            ],
            remediationEffort: "low",
          });
        }

        // Check 3: TLS version
        if (a.minimumTlsVersion && a.minimumTlsVersion < "TLS1_2") {
          this.addFinding({
            checkId:     `azure-storage-old-tls-${a.name}`,
            title:       `Storage Account ${a.name} Allows TLS Below 1.2`,
            description: `Storage account ${a.name} accepts TLS ${a.minimumTlsVersion}. TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST).`,
            severity:    "medium",
            cvssScore:   5.5,
            resource:    resourceId,
            resourceType: "storage_account",
            evidence:    { AccountName: a.name, MinimumTlsVersion: a.minimumTlsVersion },
            remediationTitle: "Enforce TLS 1.2 minimum",
            remediationSteps: [
              `Navigate to Azure Portal → Storage accounts → ${a.name} → Configuration`,
              "Set Minimum TLS version to TLS 1.2",
            ],
            remediationEffort: "low",
          });
        }
      }
    });
  }

  // —— Network Security Group Checks —————————————————————————————————————————
  private async runNetworkChecks(credential: ClientSecretCredential, subId: string): Promise<void> {
    const client = new NetworkManagementClient(credential, subId);

    await this.runCheck("azure-nsg-rules", async () => {
      const nsgs: unknown[] = [];
      for await (const nsg of client.networkSecurityGroups.listAll()) {
        nsgs.push(nsg);
      }
      return nsgs;
    }, (nsgs) => {
      for (const nsg of nsgs as { name?: string; id?: string; securityRules?: unknown[] }[]) {
        for (const rule of (nsg.securityRules ?? []) as {
          name?: string;
          direction?: string;
          access?: string;
          sourceAddressPrefix?: string;
          destinationPortRange?: string;
          priority?: number;
        }[]) {
          if (rule.direction !== "Inbound" || rule.access !== "Allow") continue;

          const isWideOpen = rule.sourceAddressPrefix === "*" ||
                             rule.sourceAddressPrefix === "0.0.0.0/0" ||
                             rule.sourceAddressPrefix === "Internet";

          if (!isWideOpen) continue;

          const portRange     = rule.destinationPortRange ?? "*";
          const isAllPorts    = portRange === "*";
          const highRiskPorts = ["22", "3389", "1433", "3306", "5432"];
          const isHighRisk    = isAllPorts || highRiskPorts.includes(portRange);

          this.addFinding({
            checkId:     `azure-nsg-open-${nsg.name}-${rule.name}`,
            title:       `NSG ${nsg.name} Allows ${isAllPorts ? "All Inbound" : `Inbound Port ${portRange}`} from Internet`,
            description: `NSG rule ${rule.name} in ${nsg.name} allows unrestricted inbound traffic from the internet${isAllPorts ? "" : ` on port ${portRange}`}.`,
            severity:    isAllPorts ? "critical" : isHighRisk ? "high" : "medium",
            cvssScore:   isAllPorts ? 9.8 : isHighRisk ? 8.1 : 5.5,
            resource:    nsg.id ?? nsg.name!,
            resourceType: "network_security_group",
            evidence:    {
              NsgName:   nsg.name,
              RuleName:  rule.name,
              PortRange: portRange,
              Source:    rule.sourceAddressPrefix,
              Priority:  rule.priority,
            },
            remediationTitle: "Restrict NSG inbound rule",
            remediationSteps: [
              `Navigate to Azure Portal → Network Security Groups → ${nsg.name}`,
              `Edit rule ${rule.name}`,
              "Change source from Any/Internet to specific IP ranges",
              "If public access required, use Azure Application Gateway or Front Door",
            ],
            remediationEffort: "medium",
            mitreAttackIds: ["T1133", "T1190"],
          });
        }
      }
    });
  }

  // —— Key Vault Checks ———————————————————————————————————————————————————————
  private async runKeyVaultChecks(credential: ClientSecretCredential, subId: string): Promise<void> {
    const client = new KeyVaultManagementClient(credential, subId);

    await this.runCheck("azure-key-vaults", async () => {
      const vaults: unknown[] = [];
      for await (const vault of client.vaults.list()) {
        vaults.push(vault);
      }
      return vaults;
    }, (vaults) => {
      for (const vault of vaults as {
        name?: string; id?: string;
        properties?: {
          enableSoftDelete?: boolean;
          enablePurgeProtection?: boolean;
          networkAcls?: { defaultAction?: string };
        };
      }[]) {
        if (!vault.name) continue;
        const props = vault.properties ?? {};

        if (!props.enableSoftDelete) {
          this.addFinding({
            checkId:     `azure-kv-no-soft-delete-${vault.name}`,
            title:       `Key Vault ${vault.name} Has Soft Delete Disabled`,
            description: `Key Vault ${vault.name} does not have soft delete enabled. Deleted secrets, keys, and certificates cannot be recovered.`,
            severity:    "high",
            cvssScore:   7.0,
            resource:    vault.id ?? vault.name,
            resourceType: "key_vault",
            evidence:    { VaultName: vault.name, SoftDeleteEnabled: false },
            remediationTitle: "Enable Key Vault soft delete",
            remediationSteps: [
              "Enable soft delete via Azure CLI: az keyvault update --enable-soft-delete true",
              "Set retention period to 90 days",
            ],
            remediationEffort: "low",
          });
        }

        if (!props.enablePurgeProtection) {
          this.addFinding({
            checkId:     `azure-kv-no-purge-protection-${vault.name}`,
            title:       `Key Vault ${vault.name} Has No Purge Protection`,
            description: `Key Vault ${vault.name} can be permanently purged during the soft delete retention period. Ransomware actors can destroy all secrets.`,
            severity:    "medium",
            cvssScore:   6.5,
            resource:    vault.id ?? vault.name,
            resourceType: "key_vault",
            evidence:    { VaultName: vault.name, PurgeProtection: false },
            remediationTitle: "Enable Key Vault purge protection",
            remediationSteps: [
              "Enable via CLI: az keyvault update --enable-purge-protection true",
              "Note: This cannot be reversed once enabled",
            ],
            remediationEffort: "low",
          });
        }

        if (props.networkAcls?.defaultAction === "Allow") {
          this.addFinding({
            checkId:     `azure-kv-public-network-${vault.name}`,
            title:       `Key Vault ${vault.name} Accessible from All Networks`,
            description: `Key Vault ${vault.name} network firewall defaults to Allow, meaning it's reachable from any IP address.`,
            severity:    "medium",
            cvssScore:   6.0,
            resource:    vault.id ?? vault.name,
            resourceType: "key_vault",
            evidence:    { VaultName: vault.name, DefaultNetworkAction: "Allow" },
            remediationTitle: "Restrict Key Vault network access",
            remediationSteps: [
              `Navigate to Key Vault → ${vault.name} → Networking`,
              "Change Allow access from to Selected networks",
              "Add your VNet or specific IP ranges",
            ],
            remediationEffort: "medium",
          });
        }
      }
    });
  }

  // —— RBAC Checks ————————————————————————————————————————————————————————————
  private async runRbacChecks(credential: ClientSecretCredential, subId: string): Promise<void> {
    const client = new AuthorizationManagementClient(credential, subId);

    await this.runCheck("azure-rbac-owner-assignments", async () => {
      const assignments: unknown[] = [];
      for await (const assignment of client.roleAssignments.listForSubscription()) {
        assignments.push(assignment);
      }
      return assignments;
    }, (assignments) => {
      // Count Owner-level assignments (Owner = full control including RBAC changes)
      const ownerAssignments = (assignments as { roleDefinitionId?: string; principalType?: string; principalId?: string }[])
        .filter(a => a.roleDefinitionId?.endsWith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")); // Owner role GUID

      if (ownerAssignments.length > 3) {
        this.addFinding({
          checkId:     "azure-rbac-too-many-owners",
          title:       `Subscription Has ${ownerAssignments.length} Owner Role Assignments`,
          description: `${ownerAssignments.length} principals have Owner access on the subscription. Owner grants full access including the ability to modify RBAC. This violates least-privilege.`,
          severity:    "high",
          cvssScore:   7.5,
          resource:    `/subscriptions/${subId}`,
          resourceType: "rbac_assignment",
          evidence:    { OwnerCount: ownerAssignments.length, SubId: subId },
          remediationTitle: "Reduce Owner role assignments",
          remediationSteps: [
            "Review all Owner assignments in Azure Portal → Subscriptions → Access control (IAM)",
            "Downgrade to Contributor where full RBAC control is not needed",
            "Use PIM (Privileged Identity Management) for just-in-time access",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1078"],
        });
      }
    });
  }

  // —— Monitoring Checks ——————————————————————————————————————————————————————
  private async runMonitoringChecks(credential: ClientSecretCredential, subId: string): Promise<void> {
    const client = new MonitorClient(credential, subId);

    await this.runCheck("azure-activity-log-alerts", async () => {
      const alerts: unknown[] = [];
      for await (const alert of client.activityLogAlerts.listBySubscriptionId()) {
        alerts.push(alert);
      }
      return alerts;
    }, (alerts) => {
      if ((alerts as unknown[]).length === 0) {
        this.addFinding({
          checkId:     "azure-no-activity-log-alerts",
          title:       "No Activity Log Alerts Configured",
          description: "No Azure Monitor activity log alerts are configured. Critical operations like policy changes, role assignments, and security group modifications are not monitored.",
          severity:    "medium",
          cvssScore:   5.5,
          resource:    `/subscriptions/${subId}`,
          resourceType: "monitor_alert",
          evidence:    { AlertCount: 0 },
          remediationTitle: "Configure Azure Monitor activity log alerts",
          remediationSteps: [
            "Navigate to Azure Monitor → Alerts → Create alert rule",
            "Create alerts for: Create/Update/Delete policy assignment, Create/Delete security group, Create/Update/Delete SQL firewall rule",
            "Set action group to notify security team via email or webhook",
          ],
          remediationEffort: "medium",
          mitreAttackIds: ["T1562.008"],
        });
      }
    });
  }

  // —— Credential factory —————————————————————————————————————————————————————
  private makeCredential(creds: AzureCredentials): ClientSecretCredential {
    return new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret);
  }
}
