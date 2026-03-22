import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import {
  Building2,
  Key,
  AlertTriangle,
  Save,
  RefreshCw,
} from "lucide-react";

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

const hintStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--falcon-t4)",
  marginTop: 4,
};

interface OrganizationSettings {
  organizationName: string;
  organizationDescription: string;
  contactEmail: string;
  contactPhone: string;
  apiRateLimitPerMinute: number;
  apiRateLimitPerHour: number;
  apiRateLimitPerDay: number;
  apiLoggingEnabled: boolean;
}

export default function Settings() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canManageSettings = hasPermission("org:manage_settings");

  const [activeTab, setActiveTab] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get("tab");
    return tab === "organization" || tab === "api" ? tab : "organization";
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

  if (!canManageSettings) {
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
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>// operator configuration</p>
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
        <button className={`f-tab ${activeTab === "api" ? "active" : ""}`} onClick={() => setActiveTab("api")} data-testid="tab-api">
          <Key className="h-4 w-4" />
          <span className="hidden sm:inline">API Keys</span>
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

      {/* API Keys Tab */}
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
              <div className="f-panel-title"><span className="f-panel-dot b" />API Logging</div>
            </div>
            <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <label style={labelStyle}>Enable API Request Logging</label>
                  <p style={hintStyle}>
                    Log all API requests for security auditing
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
        </div>
      )}

    </div>
  );
}
