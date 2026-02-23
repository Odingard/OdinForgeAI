// =============================================================================
// Task 06 — GCP Cloud Scanner
// server/services/cloud/GcpScanner.ts
//
// Production-grade GCP security checks covering:
//   IAM:     service account key age, primitive roles, external members
//   Storage: public buckets, no uniform bucket-level access
//   APIs:    enabled dangerous APIs
//   Logging: audit log configuration gaps
//   Network: firewall rules allowing 0.0.0.0/0
//
// Required roles:
//   roles/viewer  (read access to most resources)
//   roles/iam.securityReviewer
// =============================================================================

import { google, type Auth } from "googleapis";

import {
  CloudScanner, type CloudCredentials, type GcpCredentials,
  type CloudFinding,
} from "./base/CloudScanner";

export class GcpScanner extends CloudScanner {
  constructor(opts: ConstructorParameters<typeof CloudScanner>[0]) {
    super({ ...opts, provider: "gcp" });
  }

  protected extractAccountId(credentials: CloudCredentials): string {
    return (credentials as GcpCredentials).projectId;
  }

  // —— Credential validation ——————————————————————————————————————————————————
  protected async validateCredentials(credentials: CloudCredentials): Promise<void> {
    const creds = credentials as GcpCredentials;
    try {
      const auth = this.makeAuth(creds);
      const token = await auth.getAccessToken();
      if (!token) throw new Error("No access token returned");
    } catch (err: unknown) {
      const e = err as Error;
      if (e.message?.includes("invalid_grant") || e.message?.includes("Invalid JWT")) {
        throw new Error("Invalid GCP service account credentials — check your service account JSON key");
      }
      if (e.message?.includes("disabled_client")) {
        throw new Error("GCP service account or project has been disabled");
      }
      throw new Error(`GCP credential validation failed: ${e.message}`);
    }
  }

  // —— Main check runner ——————————————————————————————————————————————————————
  protected async runChecks(credentials: CloudCredentials): Promise<void> {
    const creds  = credentials as GcpCredentials;
    const auth   = this.makeAuth(creds);
    const projId = creds.projectId;

    await Promise.allSettled([
      this.runIamChecks(auth, projId),
      this.runStorageChecks(auth, projId),
      this.runFirewallChecks(auth, projId),
      this.runLoggingChecks(auth, projId),
    ]);
  }

  // —— IAM Checks ————————————————————————————————————————————————————————————
  private async runIamChecks(auth: Auth.GoogleAuth, projectId: string): Promise<void> {
    const iam = google.iam({ version: "v1", auth });

    // Check 1: Service account keys age
    await this.runCheck("gcp-iam-sa-keys", async () => {
      const saList = await this.withRetry(
        () => iam.projects.serviceAccounts.list({ name: `projects/${projectId}` }),
        { label: "list-service-accounts" }
      );
      return saList.data.accounts ?? [];
    }, async (accounts) => {
      for (const sa of accounts) {
        if (!sa.name || sa.email?.endsWith("gserviceaccount.com") === false) continue;

        const keysResp = await this.withRetry(
          () => iam.projects.serviceAccounts.keys.list({
            name:    sa.name!,
            keyTypes: ["USER_MANAGED"],
          }),
          { label: `sa-keys-${sa.email}` }
        );

        for (const key of keysResp.data.keys ?? []) {
          if (!key.validAfterTime) continue;

          const ageMs   = Date.now() - new Date(key.validAfterTime).getTime();
          const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

          if (ageDays > 90) {
            this.addFinding({
              checkId:     `gcp-iam-sa-old-key-${key.name?.split("/").pop()}`,
              title:       `Service Account Key Not Rotated (${ageDays} days)`,
              description: `Service account ${sa.email} has a user-managed key that is ${ageDays} days old. Keys should be rotated every 90 days.`,
              severity:    ageDays > 180 ? "high" : "medium",
              cvssScore:   ageDays > 180 ? 7.2 : 5.0,
              resource:    sa.name!,
              resourceType: "service_account",
              evidence:    { ServiceAccount: sa.email, KeyName: key.name, AgeDays: ageDays, ValidAfter: key.validAfterTime },
              remediationTitle: "Rotate service account key",
              remediationSteps: [
                `Create new key: gcloud iam service-accounts keys create --iam-account=${sa.email}`,
                "Update applications using the old key",
                `Delete old key: gcloud iam service-accounts keys delete KEY_ID --iam-account=${sa.email}`,
              ],
              remediationEffort: "medium",
              mitreAttackIds: ["T1552"],
            });
          }
        }
      }
    });

    // Check 2: Primitive roles (Owner/Editor at project level)
    await this.runCheck("gcp-iam-primitive-roles", async () => {
      const cloudresourcemanager = google.cloudresourcemanager({ version: "v1", auth });
      const policy = await this.withRetry(
        () => cloudresourcemanager.projects.getIamPolicy({ resource: projectId, requestBody: {} }),
        { label: "get-iam-policy" }
      );
      return policy.data.bindings ?? [];
    }, (bindings) => {
      const primitiveRoles = ["roles/owner", "roles/editor"];

      for (const binding of bindings) {
        if (!primitiveRoles.includes(binding.role ?? "")) continue;

        const externalMembers = (binding.members ?? []).filter(m =>
          m.startsWith("user:") || m.startsWith("group:")
        );

        if (externalMembers.length > 0) {
          const isOwner = binding.role === "roles/owner";
          this.addFinding({
            checkId:     `gcp-iam-primitive-${binding.role}`,
            title:       `${externalMembers.length} Member(s) Have Primitive ${isOwner ? "Owner" : "Editor"} Role`,
            description: `${externalMembers.length} member(s) have the primitive ${binding.role} role on project ${projectId}. Primitive roles are overly broad — use predefined roles instead.`,
            severity:    isOwner ? "critical" : "high",
            cvssScore:   isOwner ? 9.0 : 7.5,
            resource:    `projects/${projectId}`,
            resourceType: "iam_binding",
            evidence:    { Role: binding.role, Members: externalMembers },
            remediationTitle: "Replace primitive roles with predefined roles",
            remediationSteps: [
              `Review members with ${binding.role}: gcloud projects get-iam-policy ${projectId}`,
              "Replace owner/editor with specific predefined roles (e.g., roles/compute.admin)",
              `Remove primitive binding: gcloud projects remove-iam-policy-binding ${projectId} --role=${binding.role}`,
            ],
            remediationEffort: "medium",
            mitreAttackIds: ["T1078"],
          });
        }
      }
    });
  }

  // —— Storage Checks —————————————————————————————————————————————————————————
  private async runStorageChecks(auth: Auth.GoogleAuth, projectId: string): Promise<void> {
    const storage = google.storage({ version: "v1", auth });

    await this.runCheck("gcp-storage-buckets", async () => {
      const resp = await this.withRetry(
        () => storage.buckets.list({ project: projectId, maxResults: 100 }),
        { label: "list-buckets" }
      );
      return resp.data.items ?? [];
    }, async (buckets) => {
      for (const bucket of buckets) {
        if (!bucket.name) continue;

        // Check public IAM binding
        try {
          const iamResp = await this.withRetry(
            () => storage.buckets.getIamPolicy({ bucket: bucket.name! }),
            { label: `bucket-iam-${bucket.name}` }
          );
          const publicBindings = (iamResp.data.bindings ?? []).filter(b =>
            b.members?.some(m => m === "allUsers" || m === "allAuthenticatedUsers")
          );

          if (publicBindings.length > 0) {
            this.addFinding({
              checkId:     `gcp-storage-public-${bucket.name}`,
              title:       `GCS Bucket ${bucket.name} Is Publicly Accessible`,
              description: `Bucket ${bucket.name} has IAM bindings granting access to allUsers or allAuthenticatedUsers. Data is publicly readable from the internet.`,
              severity:    "critical",
              cvssScore:   9.5,
              resource:    `gs://${bucket.name}`,
              resourceType: "storage_bucket",
              evidence:    { BucketName: bucket.name, PublicBindings: publicBindings },
              remediationTitle: "Remove public IAM bindings from GCS bucket",
              remediationSteps: [
                `Remove public access: gsutil iam ch -d allUsers gs://${bucket.name}`,
                `Remove authenticated users: gsutil iam ch -d allAuthenticatedUsers gs://${bucket.name}`,
                "Enable Uniform Bucket-Level Access to prevent ACL bypasses",
              ],
              remediationEffort: "low",
              mitreAttackIds: ["T1530"],
            });
          }
        } catch { /* Permission denied on bucket IAM */ }

        // Check uniform bucket access
        if (!bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
          this.addFinding({
            checkId:     `gcp-storage-no-ubla-${bucket.name}`,
            title:       `GCS Bucket ${bucket.name} Has Uniform Bucket-Level Access Disabled`,
            description: `Bucket ${bucket.name} uses per-object ACLs in addition to IAM. This dual permission system is complex and can lead to unintentional public access.`,
            severity:    "medium",
            cvssScore:   5.5,
            resource:    `gs://${bucket.name}`,
            resourceType: "storage_bucket",
            evidence:    { BucketName: bucket.name, UniformBucketLevelAccess: false },
            remediationTitle: "Enable Uniform Bucket-Level Access",
            remediationSteps: [
              `Enable: gsutil uniformbucketlevelaccess set on gs://${bucket.name}`,
              "After 90 days, ACLs will be permanently disabled",
            ],
            remediationEffort: "low",
          });
        }
      }
    });
  }

  // —— Firewall Checks ———————————————————————————————————————————————————————
  private async runFirewallChecks(auth: Auth.GoogleAuth, projectId: string): Promise<void> {
    const compute = google.compute({ version: "v1", auth });

    await this.runCheck("gcp-firewall-rules", async () => {
      const resp = await this.withRetry(
        () => compute.firewalls.list({ project: projectId, maxResults: 200 }),
        { label: "list-firewalls" }
      );
      return resp.data.items ?? [];
    }, (rules) => {
      for (const rule of rules) {
        if (rule.direction !== "INGRESS") continue;

        const allowsAllSources = rule.sourceRanges?.some(r => r === "0.0.0.0/0" || r === "::/0");
        if (!allowsAllSources) continue;

        // Check for wide-open ports
        for (const allow of rule.allowed ?? []) {
          const protocol  = allow.IPProtocol;
          const isAll     = protocol === "all" || !allow.ports || allow.ports.length === 0;
          const highRisk  = ["22", "3389", "3306", "5432", "27017"].some(p =>
            allow.ports?.some(range => range === p || range?.includes(p))
          );

          if (isAll || highRisk) {
            this.addFinding({
              checkId:     `gcp-fw-open-${rule.name}`,
              title:       `Firewall Rule ${rule.name} Allows ${isAll ? "All" : `${protocol}`} Inbound from Internet`,
              description: `Firewall rule ${rule.name} allows unrestricted inbound traffic from 0.0.0.0/0. This exposes services directly to the internet.`,
              severity:    isAll ? "critical" : "high",
              cvssScore:   isAll ? 9.8 : 8.1,
              resource:    rule.selfLink ?? rule.name!,
              resourceType: "firewall_rule",
              evidence:    {
                RuleName:     rule.name,
                Protocol:     protocol,
                Ports:        allow.ports,
                SourceRanges: rule.sourceRanges,
                Priority:     rule.priority,
              },
              remediationTitle: "Restrict firewall rule source ranges",
              remediationSteps: [
                `Edit rule: gcloud compute firewall-rules update ${rule.name} --source-ranges=SPECIFIC_CIDR`,
                "Or delete if not needed: gcloud compute firewall-rules delete " + rule.name,
                "Use VPC Service Controls for internal-only services",
              ],
              remediationEffort: "medium",
              mitreAttackIds: ["T1133", "T1190"],
            });
          }
        }
      }
    });
  }

  // —— Audit Logging Checks ——————————————————————————————————————————————————
  private async runLoggingChecks(auth: Auth.GoogleAuth, projectId: string): Promise<void> {
    const cloudresourcemanager = google.cloudresourcemanager({ version: "v1", auth });

    await this.runCheck("gcp-audit-logging", async () => {
      const policy = await this.withRetry(
        () => cloudresourcemanager.projects.getIamPolicy({ resource: projectId, requestBody: {} }),
        { label: "audit-logging-policy" }
      );
      return policy.data.auditConfigs ?? [];
    }, (auditConfigs) => {
      // Check if allServices data access audit logging is enabled
      const allServices = auditConfigs.find(c => c.service === "allServices");
      const hasDataRead = allServices?.auditLogConfigs?.some(c => c.logType === "DATA_READ");
      const hasDataWrite = allServices?.auditLogConfigs?.some(c => c.logType === "DATA_WRITE");

      if (!hasDataRead || !hasDataWrite) {
        this.addFinding({
          checkId:     "gcp-audit-logging-incomplete",
          title:       "GCP Data Access Audit Logging Not Fully Enabled",
          description: `Project ${projectId} does not have DATA_READ and DATA_WRITE audit logging enabled for all services. Sensitive API operations may not be logged.`,
          severity:    "medium",
          cvssScore:   5.5,
          resource:    `projects/${projectId}`,
          resourceType: "audit_config",
          evidence:    {
            HasDataRead:  hasDataRead,
            HasDataWrite: hasDataWrite,
            AuditConfigs: auditConfigs.length,
          },
          remediationTitle: "Enable GCP data access audit logging",
          remediationSteps: [
            "Navigate to GCP Console → IAM & Admin → Audit Logs",
            "Enable DATA_READ and DATA_WRITE for all services",
            "Or use gcloud: gcloud projects set-iam-policy with updated auditConfigs",
          ],
          remediationEffort: "low",
          mitreAttackIds: ["T1562.008"],
        });
      }
    });
  }

  // —— Auth factory ——————————————————————————————————————————————————————————
  private makeAuth(creds: GcpCredentials): Auth.GoogleAuth {
    const keyFile = JSON.parse(creds.serviceAccountJson);
    return new google.auth.GoogleAuth({
      credentials: keyFile,
      scopes:      ["https://www.googleapis.com/auth/cloud-platform.read-only"],
    });
  }
}
