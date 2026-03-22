import { useState, lazy, Suspense } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import {
  Settings as SettingsIcon,
  Building2,
  Shield,
  Bell,
  Key,
  AlertTriangle,
  Save,
  RefreshCw,
  Lock,
  Mail,
  Phone,
  Clock,
  KeyRound,
  Webhook,
  Activity,
  Gauge,
  Users,
  CreditCard,
  Plug,
  ShieldAlert,
  FileText,
  Loader2
} from "lucide-react";

const UserManagementPanel = lazy(() => import("@/pages/UserManagement"));
const BillingPanel = lazy(() => import("@/pages/BillingPage"));
const IntegrationsPanel = lazy(() => import("@/pages/Infrastructure"));
const GovernancePanel = lazy(() => import("@/pages/Governance"));
const AuditLogsPanel = lazy(() => import("@/pages/AuditLogs"));

const PanelFallback = () => (
  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256 }}>
    <Loader2 className="h-8 w-8 animate-spin" style={{ color: "var(--falcon-t4)" }} />
  </div>
);

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  background: "var(--falcon-panel)",
  border: "1px solid var(--falcon-border)",
  borderRadius: 6,
  color: "var(--falcon-t1)",
  fontSize: 12,
};

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 600,
  color: "var(--falcon-t1)",
};

const labelNormalStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 400,
  color: "var(--falcon-t1)",
};

const hintStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--falcon-t4)",
  marginTop: 4,
};

const separatorStyle: React.CSSProperties = {
  height: 1,
  background: "var(--falcon-border)",
  margin: "16px 0",
};

interface OrganizationSettings {
  organizationName: string;
  organizationDescription: string;
  contactEmail: string;
  contactPhone: string;
  sessionTimeoutMinutes: number;
  mfaRequired: boolean;
  mfaGracePeriodDays: number;
  passwordMinLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireNumbers: boolean;
  passwordRequireSpecial: boolean;
  passwordExpiryDays: number;
  emailNotificationsEnabled: boolean;
  emailCriticalAlerts: boolean;
  emailHighAlerts: boolean;
  emailMediumAlerts: boolean;
  emailLowAlerts: boolean;
  emailDailyDigest: boolean;
  alertThresholdCritical: number;
  alertThresholdHigh: number;
  alertThresholdMedium: number;
  apiRateLimitPerMinute: number;
  apiRateLimitPerHour: number;
  apiRateLimitPerDay: number;
  apiLoggingEnabled: boolean;
  webhooksEnabled: boolean;
  webhookUrl: string;
}

export default function Settings() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canManageSettings = hasPermission("org:manage_settings");
  const canManageUsers = hasPermission("org:manage_users");

  const [activeTab, setActiveTab] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("tab") || "organization";
  });

  const { data: settings, isLoading } = useQuery<OrganizationSettings>({
    queryKey: ["/api/organization/settings"],
  });

  const [localSettings, setLocalSettings] = useState<Partial<OrganizationSettings>>({});

  const mergedSettings = { ...settings, ...localSettings };

  const updateSettingsMutation = useMutation({
    mutationFn: async (updates: Partial<OrganizationSettings>) => {
      const response = await apiRequest("PATCH", "/api/organization/settings", updates);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Settings Saved",
        description: "Your settings have been updated successfully.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/organization/settings"] });
      setLocalSettings({});
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Save",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleSaveChanges = () => {
    if (Object.keys(localSettings).length > 0) {
      updateSettingsMutation.mutate(localSettings);
    }
  };

  const handleReset = () => {
    setLocalSettings({});
    toast({
      title: "Changes Reset",
      description: "All unsaved changes have been discarded.",
    });
  };

  const updateSetting = <K extends keyof OrganizationSettings>(key: K, value: OrganizationSettings[K]) => {
    setLocalSettings(prev => ({ ...prev, [key]: value }));
  };

  const hasUnsavedChanges = Object.keys(localSettings).length > 0;

  if (!canManageSettings && !canManageUsers) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
        <div style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 12,
          padding: "14px 16px",
          background: "rgba(239, 68, 68, 0.08)",
          border: "1px solid rgba(239, 68, 68, 0.25)",
          borderRadius: 8,
          color: "var(--falcon-red)",
          fontSize: 12,
        }}>
          <AlertTriangle className="h-4 w-4" style={{ flexShrink: 0, marginTop: 1 }} />
          <span>
            You do not have permission to manage organization settings. Contact your administrator for access.
          </span>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256 }}>
        <RefreshCw className="h-8 w-8 animate-spin" style={{ color: "var(--falcon-t4)" }} />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Settings</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>// organization and platform configuration</p>
        </div>
        {hasUnsavedChanges && (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button
              className="f-btn f-btn-ghost"
              onClick={handleReset}
              data-testid="btn-reset-changes"
            >
              <RefreshCw className="h-4 w-4" style={{ marginRight: 8 }} />
              Reset
            </button>
            <button
              className="f-btn f-btn-primary"
              onClick={handleSaveChanges}
              disabled={updateSettingsMutation.isPending}
              data-testid="btn-save-changes"
            >
              <Save className="h-4 w-4" style={{ marginRight: 8 }} />
              {updateSettingsMutation.isPending ? "Saving..." : "Save Changes"}
            </button>
          </div>
        )}
      </div>

      <div className="f-tab-bar">
        <button className={`f-tab ${activeTab === "organization" ? "active" : ""}`} onClick={() => setActiveTab("organization")} data-testid="tab-organization">
          <Building2 className="h-4 w-4" />
          <span className="hidden sm:inline">Organization</span>
        </button>
        <button className={`f-tab ${activeTab === "security" ? "active" : ""}`} onClick={() => setActiveTab("security")} data-testid="tab-security">
          <Shield className="h-4 w-4" />
          <span className="hidden sm:inline">Security</span>
        </button>
        <button className={`f-tab ${activeTab === "notifications" ? "active" : ""}`} onClick={() => setActiveTab("notifications")} data-testid="tab-notifications">
          <Bell className="h-4 w-4" />
          <span className="hidden sm:inline">Notifications</span>
        </button>
        <button className={`f-tab ${activeTab === "api" ? "active" : ""}`} onClick={() => setActiveTab("api")} data-testid="tab-api">
          <Key className="h-4 w-4" />
          <span className="hidden sm:inline">API</span>
        </button>
        {canManageUsers && (
          <button className={`f-tab ${activeTab === "users" ? "active" : ""}`} onClick={() => setActiveTab("users")} data-testid="tab-users">
            <Users className="h-4 w-4" />
            <span className="hidden sm:inline">Users</span>
          </button>
        )}
        <button className={`f-tab ${activeTab === "billing" ? "active" : ""}`} onClick={() => setActiveTab("billing")} data-testid="tab-billing">
          <CreditCard className="h-4 w-4" />
          <span className="hidden sm:inline">Billing</span>
        </button>
        <button className={`f-tab ${activeTab === "integrations" ? "active" : ""}`} onClick={() => setActiveTab("integrations")} data-testid="tab-integrations">
          <Plug className="h-4 w-4" />
          <span className="hidden sm:inline">Integrations</span>
        </button>
        <button className={`f-tab ${activeTab === "governance" ? "active" : ""}`} onClick={() => setActiveTab("governance")} data-testid="tab-governance">
          <ShieldAlert className="h-4 w-4" />
          <span className="hidden sm:inline">Governance</span>
        </button>
        <button className={`f-tab ${activeTab === "audit-logs" ? "active" : ""}`} onClick={() => setActiveTab("audit-logs")} data-testid="tab-audit-logs">
          <FileText className="h-4 w-4" />
          <span className="hidden sm:inline">Audit Logs</span>
        </button>
      </div>

      {/* Organization Tab */}
      {activeTab === "organization" && (
        <div>
          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Organization Details</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor="orgName" style={labelStyle}>Organization Name</label>
                <input
                  id="orgName"
                  style={inputStyle}
                  value={mergedSettings.organizationName || ""}
                  onChange={(e) => updateSetting("organizationName", e.target.value)}
                  placeholder="Enter organization name"
                  data-testid="input-org-name"
                />
                <p style={hintStyle}>
                  The name displayed throughout the platform
                </p>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor="orgDescription" style={labelStyle}>Description</label>
                <textarea
                  id="orgDescription"
                  style={{ ...inputStyle, minHeight: 72, resize: "vertical" }}
                  value={mergedSettings.organizationDescription || ""}
                  onChange={(e) => updateSetting("organizationDescription", e.target.value)}
                  placeholder="Brief description of your organization"
                  rows={3}
                  data-testid="input-org-description"
                />
                <p style={hintStyle}>
                  A brief description for internal reference
                </p>
              </div>
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Contact Information</div>
            </div>
            <div style={{ padding: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label htmlFor="contactEmail" style={labelStyle}>Contact Email</label>
                  <input
                    id="contactEmail"
                    type="email"
                    style={inputStyle}
                    value={mergedSettings.contactEmail || ""}
                    onChange={(e) => updateSetting("contactEmail", e.target.value)}
                    placeholder="security@example.com"
                    data-testid="input-contact-email"
                  />
                  <p style={hintStyle}>
                    Primary email for security communications
                  </p>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label htmlFor="contactPhone" style={labelStyle}>Contact Phone</label>
                  <input
                    id="contactPhone"
                    type="tel"
                    style={inputStyle}
                    value={mergedSettings.contactPhone || ""}
                    onChange={(e) => updateSetting("contactPhone", e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    data-testid="input-contact-phone"
                  />
                  <p style={hintStyle}>
                    Emergency contact number
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Security Tab */}
      {activeTab === "security" && (
        <div>
          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Session Settings</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor="sessionTimeout" style={labelStyle}>Session Timeout (minutes)</label>
                <input
                  id="sessionTimeout"
                  type="number"
                  min={5}
                  max={480}
                  style={inputStyle}
                  value={mergedSettings.sessionTimeoutMinutes || 30}
                  onChange={(e) => updateSetting("sessionTimeoutMinutes", parseInt(e.target.value) || 30)}
                  data-testid="input-session-timeout"
                />
                <p style={hintStyle}>
                  Inactive users will be logged out after this duration (5-480 minutes)
                </p>
              </div>
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Multi-Factor Authentication</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <label style={labelStyle}>Require MFA for All Users</label>
                  <p style={hintStyle}>
                    Enforce multi-factor authentication for all platform users
                  </p>
                </div>
                <button
                  className={`f-switch ${mergedSettings.mfaRequired ? "on" : ""}`}
                  onClick={() => updateSetting("mfaRequired", !mergedSettings.mfaRequired)}
                  data-testid="switch-mfa-required"
                />
              </div>

              {mergedSettings.mfaRequired && (
                <div style={{ display: "flex", flexDirection: "column", gap: 6, paddingLeft: 16, borderLeft: "2px solid var(--falcon-border)" }}>
                  <label htmlFor="mfaGracePeriod" style={labelStyle}>Grace Period (days)</label>
                  <input
                    id="mfaGracePeriod"
                    type="number"
                    min={0}
                    max={30}
                    style={inputStyle}
                    value={mergedSettings.mfaGracePeriodDays || 7}
                    onChange={(e) => updateSetting("mfaGracePeriodDays", parseInt(e.target.value) || 7)}
                    data-testid="input-mfa-grace-period"
                  />
                  <p style={hintStyle}>
                    Days users have to set up MFA before being locked out
                  </p>
                </div>
              )}
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Password Policy</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor="passwordMinLength" style={labelStyle}>Minimum Password Length</label>
                <input
                  id="passwordMinLength"
                  type="number"
                  min={8}
                  max={128}
                  style={inputStyle}
                  value={mergedSettings.passwordMinLength || 12}
                  onChange={(e) => updateSetting("passwordMinLength", parseInt(e.target.value) || 12)}
                  data-testid="input-password-min-length"
                />
                <p style={hintStyle}>
                  Minimum characters required (8-128)
                </p>
              </div>

              <div style={separatorStyle} />

              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <label style={{ ...labelStyle, fontSize: 13 }}>Character Requirements</label>

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <label style={labelNormalStyle}>Require Uppercase Letters</label>
                    <p style={hintStyle}>At least one A-Z character</p>
                  </div>
                  <button
                    className={`f-switch ${mergedSettings.passwordRequireUppercase ?? true ? "on" : ""}`}
                    onClick={() => updateSetting("passwordRequireUppercase", !(mergedSettings.passwordRequireUppercase ?? true))}
                    data-testid="switch-password-uppercase"
                  />
                </div>

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <label style={labelNormalStyle}>Require Lowercase Letters</label>
                    <p style={hintStyle}>At least one a-z character</p>
                  </div>
                  <button
                    className={`f-switch ${mergedSettings.passwordRequireLowercase ?? true ? "on" : ""}`}
                    onClick={() => updateSetting("passwordRequireLowercase", !(mergedSettings.passwordRequireLowercase ?? true))}
                    data-testid="switch-password-lowercase"
                  />
                </div>

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <label style={labelNormalStyle}>Require Numbers</label>
                    <p style={hintStyle}>At least one 0-9 digit</p>
                  </div>
                  <button
                    className={`f-switch ${mergedSettings.passwordRequireNumbers ?? true ? "on" : ""}`}
                    onClick={() => updateSetting("passwordRequireNumbers", !(mergedSettings.passwordRequireNumbers ?? true))}
                    data-testid="switch-password-numbers"
                  />
                </div>

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div>
                    <label style={labelNormalStyle}>Require Special Characters</label>
                    <p style={hintStyle}>At least one special character (!@#$%^&*)</p>
                  </div>
                  <button
                    className={`f-switch ${mergedSettings.passwordRequireSpecial ?? true ? "on" : ""}`}
                    onClick={() => updateSetting("passwordRequireSpecial", !(mergedSettings.passwordRequireSpecial ?? true))}
                    data-testid="switch-password-special"
                  />
                </div>
              </div>

              <div style={separatorStyle} />

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label htmlFor="passwordExpiry" style={labelStyle}>Password Expiry (days)</label>
                <input
                  id="passwordExpiry"
                  type="number"
                  min={0}
                  max={365}
                  style={inputStyle}
                  value={mergedSettings.passwordExpiryDays || 90}
                  onChange={(e) => updateSetting("passwordExpiryDays", parseInt(e.target.value) || 90)}
                  data-testid="input-password-expiry"
                />
                <p style={hintStyle}>
                  Days before users must change their password (0 = never expires)
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Notifications Tab */}
      {activeTab === "notifications" && (
        <div>
          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Email Notifications</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <label style={labelStyle}>Enable Email Notifications</label>
                  <p style={hintStyle}>
                    Send email alerts for security findings
                  </p>
                </div>
                <button
                  className={`f-switch ${mergedSettings.emailNotificationsEnabled ?? true ? "on" : ""}`}
                  onClick={() => updateSetting("emailNotificationsEnabled", !(mergedSettings.emailNotificationsEnabled ?? true))}
                  data-testid="switch-email-notifications"
                />
              </div>

              {mergedSettings.emailNotificationsEnabled && (
                <>
                  <div style={separatorStyle} />

                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <label style={{ ...labelStyle, fontSize: 13 }}>Alert Levels</label>

                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <label style={{ ...labelNormalStyle, color: "var(--falcon-red)" }}>Critical Alerts</label>
                        <p style={hintStyle}>Immediate notification for critical findings</p>
                      </div>
                      <button
                        className={`f-switch ${mergedSettings.emailCriticalAlerts ?? true ? "on" : ""}`}
                        onClick={() => updateSetting("emailCriticalAlerts", !(mergedSettings.emailCriticalAlerts ?? true))}
                        data-testid="switch-email-critical"
                      />
                    </div>

                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <label style={{ ...labelNormalStyle, color: "var(--falcon-orange)" }}>High Alerts</label>
                        <p style={hintStyle}>Notification for high-severity findings</p>
                      </div>
                      <button
                        className={`f-switch ${mergedSettings.emailHighAlerts ?? true ? "on" : ""}`}
                        onClick={() => updateSetting("emailHighAlerts", !(mergedSettings.emailHighAlerts ?? true))}
                        data-testid="switch-email-high"
                      />
                    </div>

                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <label style={{ ...labelNormalStyle, color: "var(--falcon-yellow)" }}>Medium Alerts</label>
                        <p style={hintStyle}>Notification for medium-severity findings</p>
                      </div>
                      <button
                        className={`f-switch ${mergedSettings.emailMediumAlerts ?? false ? "on" : ""}`}
                        onClick={() => updateSetting("emailMediumAlerts", !(mergedSettings.emailMediumAlerts ?? false))}
                        data-testid="switch-email-medium"
                      />
                    </div>

                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <div>
                        <label style={{ ...labelNormalStyle, color: "var(--falcon-blue-hi)" }}>Low Alerts</label>
                        <p style={hintStyle}>Notification for low-severity findings</p>
                      </div>
                      <button
                        className={`f-switch ${mergedSettings.emailLowAlerts ?? false ? "on" : ""}`}
                        onClick={() => updateSetting("emailLowAlerts", !(mergedSettings.emailLowAlerts ?? false))}
                        data-testid="switch-email-low"
                      />
                    </div>
                  </div>

                  <div style={separatorStyle} />

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div>
                      <label style={labelStyle}>Daily Digest</label>
                      <p style={hintStyle}>
                        Receive a daily summary email of all security activities
                      </p>
                    </div>
                    <button
                      className={`f-switch ${mergedSettings.emailDailyDigest ?? true ? "on" : ""}`}
                      onClick={() => updateSetting("emailDailyDigest", !(mergedSettings.emailDailyDigest ?? true))}
                      data-testid="switch-email-digest"
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Alert Thresholds</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 24 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <label style={{ ...labelStyle, color: "var(--falcon-red)" }}>Critical Threshold</label>
                  <span style={{
                    fontSize: 12,
                    fontFamily: "var(--font-mono)",
                    background: "var(--falcon-panel-2)",
                    padding: "2px 8px",
                    borderRadius: 4,
                    color: "var(--falcon-t1)",
                  }} data-testid="text-threshold-critical">
                    {mergedSettings.alertThresholdCritical || 90}+
                  </span>
                </div>
                <input
                  type="range"
                  className="f-range"
                  value={mergedSettings.alertThresholdCritical || 90}
                  onChange={(e) => updateSetting("alertThresholdCritical", parseInt(e.target.value))}
                  min={50}
                  max={100}
                  step={5}
                  data-testid="slider-threshold-critical"
                />
                <p style={hintStyle}>
                  Scores at or above this value are classified as critical
                </p>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <label style={{ ...labelStyle, color: "var(--falcon-orange)" }}>High Threshold</label>
                  <span style={{
                    fontSize: 12,
                    fontFamily: "var(--font-mono)",
                    background: "var(--falcon-panel-2)",
                    padding: "2px 8px",
                    borderRadius: 4,
                    color: "var(--falcon-t1)",
                  }} data-testid="text-threshold-high">
                    {mergedSettings.alertThresholdHigh || 70}+
                  </span>
                </div>
                <input
                  type="range"
                  className="f-range"
                  value={mergedSettings.alertThresholdHigh || 70}
                  onChange={(e) => updateSetting("alertThresholdHigh", parseInt(e.target.value))}
                  min={30}
                  max={90}
                  step={5}
                  data-testid="slider-threshold-high"
                />
                <p style={hintStyle}>
                  Scores at or above this value are classified as high severity
                </p>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <label style={{ ...labelStyle, color: "var(--falcon-yellow)" }}>Medium Threshold</label>
                  <span style={{
                    fontSize: 12,
                    fontFamily: "var(--font-mono)",
                    background: "var(--falcon-panel-2)",
                    padding: "2px 8px",
                    borderRadius: 4,
                    color: "var(--falcon-t1)",
                  }} data-testid="text-threshold-medium">
                    {mergedSettings.alertThresholdMedium || 40}+
                  </span>
                </div>
                <input
                  type="range"
                  className="f-range"
                  value={mergedSettings.alertThresholdMedium || 40}
                  onChange={(e) => updateSetting("alertThresholdMedium", parseInt(e.target.value))}
                  min={10}
                  max={70}
                  step={5}
                  data-testid="slider-threshold-medium"
                />
                <p style={hintStyle}>
                  Scores at or above this value are classified as medium severity
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* API Tab */}
      {activeTab === "api" && (
        <div>
          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />API Rate Limits</div>
            </div>
            <div style={{ padding: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label htmlFor="rateLimitMinute" style={labelStyle}>Requests per Minute</label>
                  <input
                    id="rateLimitMinute"
                    type="number"
                    min={1}
                    max={1000}
                    style={inputStyle}
                    value={mergedSettings.apiRateLimitPerMinute || 60}
                    onChange={(e) => updateSetting("apiRateLimitPerMinute", parseInt(e.target.value) || 60)}
                    data-testid="input-rate-limit-minute"
                  />
                  <p style={hintStyle}>
                    Max requests/minute
                  </p>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label htmlFor="rateLimitHour" style={labelStyle}>Requests per Hour</label>
                  <input
                    id="rateLimitHour"
                    type="number"
                    min={60}
                    max={100000}
                    style={inputStyle}
                    value={mergedSettings.apiRateLimitPerHour || 1000}
                    onChange={(e) => updateSetting("apiRateLimitPerHour", parseInt(e.target.value) || 1000)}
                    data-testid="input-rate-limit-hour"
                  />
                  <p style={hintStyle}>
                    Max requests/hour
                  </p>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label htmlFor="rateLimitDay" style={labelStyle}>Requests per Day</label>
                  <input
                    id="rateLimitDay"
                    type="number"
                    min={1000}
                    max={1000000}
                    style={inputStyle}
                    value={mergedSettings.apiRateLimitPerDay || 10000}
                    onChange={(e) => updateSetting("apiRateLimitPerDay", parseInt(e.target.value) || 10000)}
                    data-testid="input-rate-limit-day"
                  />
                  <p style={hintStyle}>
                    Max requests/day
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />API Logging & Auditing</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <label style={labelStyle}>Enable API Request Logging</label>
                  <p style={hintStyle}>
                    Log all API requests for security auditing and compliance
                  </p>
                </div>
                <button
                  className={`f-switch ${mergedSettings.apiLoggingEnabled ?? true ? "on" : ""}`}
                  onClick={() => updateSetting("apiLoggingEnabled", !(mergedSettings.apiLoggingEnabled ?? true))}
                  data-testid="switch-api-logging"
                />
              </div>
            </div>
          </div>

          <div className="f-panel" style={{ marginBottom: 16 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Webhooks</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <label style={labelStyle}>Enable Webhooks</label>
                  <p style={hintStyle}>
                    Send real-time event notifications to external systems
                  </p>
                </div>
                <button
                  className={`f-switch ${mergedSettings.webhooksEnabled ?? false ? "on" : ""}`}
                  onClick={() => updateSetting("webhooksEnabled", !(mergedSettings.webhooksEnabled ?? false))}
                  data-testid="switch-webhooks-enabled"
                />
              </div>

              {mergedSettings.webhooksEnabled && (
                <div style={{ display: "flex", flexDirection: "column", gap: 6, paddingLeft: 16, borderLeft: "2px solid var(--falcon-border)" }}>
                  <label htmlFor="webhookUrl" style={labelStyle}>Webhook URL</label>
                  <input
                    id="webhookUrl"
                    type="url"
                    style={inputStyle}
                    value={mergedSettings.webhookUrl || ""}
                    onChange={(e) => updateSetting("webhookUrl", e.target.value)}
                    placeholder="https://your-system.com/webhook"
                    data-testid="input-webhook-url"
                  />
                  <p style={hintStyle}>
                    URL to receive webhook event payloads (HTTPS required)
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Users Tab */}
      {canManageUsers && activeTab === "users" && (
        <div>
          <Suspense fallback={<PanelFallback />}>
            <UserManagementPanel />
          </Suspense>
        </div>
      )}

      {/* Billing Tab */}
      {activeTab === "billing" && (
        <div>
          <Suspense fallback={<PanelFallback />}>
            <BillingPanel />
          </Suspense>
        </div>
      )}

      {/* Integrations Tab */}
      {activeTab === "integrations" && (
        <div>
          <Suspense fallback={<PanelFallback />}>
            <IntegrationsPanel />
          </Suspense>
        </div>
      )}

      {/* Governance Tab */}
      {activeTab === "governance" && (
        <div>
          <Suspense fallback={<PanelFallback />}>
            <GovernancePanel />
          </Suspense>
        </div>
      )}

      {/* Audit Logs Tab */}
      {activeTab === "audit-logs" && (
        <div>
          <Suspense fallback={<PanelFallback />}>
            <AuditLogsPanel />
          </Suspense>
        </div>
      )}
    </div>
  );
}
