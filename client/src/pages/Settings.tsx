import { useState, lazy, Suspense } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Slider } from "@/components/ui/slider";
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
  <div className="flex items-center justify-center h-64">
    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
  </div>
);

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
      <div className="space-y-6">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            You do not have permission to manage organization settings. Contact your administrator for access.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2" data-testid="text-page-title">
            <SettingsIcon className="h-6 w-6" />
            Settings
          </h1>
          <p className="text-muted-foreground">
            Configure organization, security, and platform settings
          </p>
        </div>
        {hasUnsavedChanges && (
          <div className="flex items-center gap-2">
            <Button 
              variant="outline" 
              onClick={handleReset}
              data-testid="btn-reset-changes"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
            <Button 
              onClick={handleSaveChanges}
              disabled={updateSettingsMutation.isPending}
              data-testid="btn-save-changes"
            >
              <Save className="h-4 w-4 mr-2" />
              {updateSettingsMutation.isPending ? "Saving..." : "Save Changes"}
            </Button>
          </div>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex w-full overflow-x-auto">
          <TabsTrigger value="organization" className="flex items-center gap-2" data-testid="tab-organization">
            <Building2 className="h-4 w-4" />
            <span className="hidden sm:inline">Organization</span>
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2" data-testid="tab-security">
            <Shield className="h-4 w-4" />
            <span className="hidden sm:inline">Security</span>
          </TabsTrigger>
          <TabsTrigger value="notifications" className="flex items-center gap-2" data-testid="tab-notifications">
            <Bell className="h-4 w-4" />
            <span className="hidden sm:inline">Notifications</span>
          </TabsTrigger>
          <TabsTrigger value="api" className="flex items-center gap-2" data-testid="tab-api">
            <Key className="h-4 w-4" />
            <span className="hidden sm:inline">API</span>
          </TabsTrigger>
          {canManageUsers && (
            <TabsTrigger value="users" className="flex items-center gap-2" data-testid="tab-users">
              <Users className="h-4 w-4" />
              <span className="hidden sm:inline">Users</span>
            </TabsTrigger>
          )}
          <TabsTrigger value="billing" className="flex items-center gap-2" data-testid="tab-billing">
            <CreditCard className="h-4 w-4" />
            <span className="hidden sm:inline">Billing</span>
          </TabsTrigger>
          <TabsTrigger value="integrations" className="flex items-center gap-2" data-testid="tab-integrations">
            <Plug className="h-4 w-4" />
            <span className="hidden sm:inline">Integrations</span>
          </TabsTrigger>
          <TabsTrigger value="governance" className="flex items-center gap-2" data-testid="tab-governance">
            <ShieldAlert className="h-4 w-4" />
            <span className="hidden sm:inline">Governance</span>
          </TabsTrigger>
          <TabsTrigger value="audit-logs" className="flex items-center gap-2" data-testid="tab-audit-logs">
            <FileText className="h-4 w-4" />
            <span className="hidden sm:inline">Audit Logs</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="organization" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                Organization Details
              </CardTitle>
              <CardDescription>
                Basic information about your organization
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="orgName">Organization Name</Label>
                <Input
                  id="orgName"
                  value={mergedSettings.organizationName || ""}
                  onChange={(e) => updateSetting("organizationName", e.target.value)}
                  placeholder="Enter organization name"
                  data-testid="input-org-name"
                />
                <p className="text-xs text-muted-foreground">
                  The name displayed throughout the platform
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="orgDescription">Description</Label>
                <Textarea
                  id="orgDescription"
                  value={mergedSettings.organizationDescription || ""}
                  onChange={(e) => updateSetting("organizationDescription", e.target.value)}
                  placeholder="Brief description of your organization"
                  rows={3}
                  data-testid="input-org-description"
                />
                <p className="text-xs text-muted-foreground">
                  A brief description for internal reference
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                Contact Information
              </CardTitle>
              <CardDescription>
                Primary contact details for your organization
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="contactEmail">Contact Email</Label>
                  <Input
                    id="contactEmail"
                    type="email"
                    value={mergedSettings.contactEmail || ""}
                    onChange={(e) => updateSetting("contactEmail", e.target.value)}
                    placeholder="security@example.com"
                    data-testid="input-contact-email"
                  />
                  <p className="text-xs text-muted-foreground">
                    Primary email for security communications
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contactPhone">Contact Phone</Label>
                  <Input
                    id="contactPhone"
                    type="tel"
                    value={mergedSettings.contactPhone || ""}
                    onChange={(e) => updateSetting("contactPhone", e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    data-testid="input-contact-phone"
                  />
                  <p className="text-xs text-muted-foreground">
                    Emergency contact number
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Session Settings
              </CardTitle>
              <CardDescription>
                Configure user session behavior and timeouts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
                <Input
                  id="sessionTimeout"
                  type="number"
                  min={5}
                  max={480}
                  value={mergedSettings.sessionTimeoutMinutes || 30}
                  onChange={(e) => updateSetting("sessionTimeoutMinutes", parseInt(e.target.value) || 30)}
                  data-testid="input-session-timeout"
                />
                <p className="text-xs text-muted-foreground">
                  Inactive users will be logged out after this duration (5-480 minutes)
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="h-5 w-5" />
                Multi-Factor Authentication
              </CardTitle>
              <CardDescription>
                Enforce additional authentication for enhanced security
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Require MFA for All Users</Label>
                  <p className="text-xs text-muted-foreground">
                    Enforce multi-factor authentication for all platform users
                  </p>
                </div>
                <Switch
                  checked={mergedSettings.mfaRequired || false}
                  onCheckedChange={(checked) => updateSetting("mfaRequired", checked)}
                  data-testid="switch-mfa-required"
                />
              </div>
              
              {mergedSettings.mfaRequired && (
                <div className="space-y-2 pl-4 border-l-2 border-muted">
                  <Label htmlFor="mfaGracePeriod">Grace Period (days)</Label>
                  <Input
                    id="mfaGracePeriod"
                    type="number"
                    min={0}
                    max={30}
                    value={mergedSettings.mfaGracePeriodDays || 7}
                    onChange={(e) => updateSetting("mfaGracePeriodDays", parseInt(e.target.value) || 7)}
                    data-testid="input-mfa-grace-period"
                  />
                  <p className="text-xs text-muted-foreground">
                    Days users have to set up MFA before being locked out
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Password Policy
              </CardTitle>
              <CardDescription>
                Define password requirements for user accounts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="passwordMinLength">Minimum Password Length</Label>
                <Input
                  id="passwordMinLength"
                  type="number"
                  min={8}
                  max={128}
                  value={mergedSettings.passwordMinLength || 12}
                  onChange={(e) => updateSetting("passwordMinLength", parseInt(e.target.value) || 12)}
                  data-testid="input-password-min-length"
                />
                <p className="text-xs text-muted-foreground">
                  Minimum characters required (8-128)
                </p>
              </div>

              <Separator />

              <div className="space-y-3">
                <Label className="text-sm font-medium">Character Requirements</Label>
                
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="font-normal">Require Uppercase Letters</Label>
                    <p className="text-xs text-muted-foreground">At least one A-Z character</p>
                  </div>
                  <Switch
                    checked={mergedSettings.passwordRequireUppercase ?? true}
                    onCheckedChange={(checked) => updateSetting("passwordRequireUppercase", checked)}
                    data-testid="switch-password-uppercase"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label className="font-normal">Require Lowercase Letters</Label>
                    <p className="text-xs text-muted-foreground">At least one a-z character</p>
                  </div>
                  <Switch
                    checked={mergedSettings.passwordRequireLowercase ?? true}
                    onCheckedChange={(checked) => updateSetting("passwordRequireLowercase", checked)}
                    data-testid="switch-password-lowercase"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label className="font-normal">Require Numbers</Label>
                    <p className="text-xs text-muted-foreground">At least one 0-9 digit</p>
                  </div>
                  <Switch
                    checked={mergedSettings.passwordRequireNumbers ?? true}
                    onCheckedChange={(checked) => updateSetting("passwordRequireNumbers", checked)}
                    data-testid="switch-password-numbers"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label className="font-normal">Require Special Characters</Label>
                    <p className="text-xs text-muted-foreground">At least one special character (!@#$%^&*)</p>
                  </div>
                  <Switch
                    checked={mergedSettings.passwordRequireSpecial ?? true}
                    onCheckedChange={(checked) => updateSetting("passwordRequireSpecial", checked)}
                    data-testid="switch-password-special"
                  />
                </div>
              </div>

              <Separator />

              <div className="space-y-2">
                <Label htmlFor="passwordExpiry">Password Expiry (days)</Label>
                <Input
                  id="passwordExpiry"
                  type="number"
                  min={0}
                  max={365}
                  value={mergedSettings.passwordExpiryDays || 90}
                  onChange={(e) => updateSetting("passwordExpiryDays", parseInt(e.target.value) || 90)}
                  data-testid="input-password-expiry"
                />
                <p className="text-xs text-muted-foreground">
                  Days before users must change their password (0 = never expires)
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                Email Notifications
              </CardTitle>
              <CardDescription>
                Configure email alerts for security events
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Email Notifications</Label>
                  <p className="text-xs text-muted-foreground">
                    Send email alerts for security findings
                  </p>
                </div>
                <Switch
                  checked={mergedSettings.emailNotificationsEnabled ?? true}
                  onCheckedChange={(checked) => updateSetting("emailNotificationsEnabled", checked)}
                  data-testid="switch-email-notifications"
                />
              </div>

              {mergedSettings.emailNotificationsEnabled && (
                <>
                  <Separator />
                  
                  <div className="space-y-3">
                    <Label className="text-sm font-medium">Alert Levels</Label>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label className="font-normal text-red-600 dark:text-red-400">Critical Alerts</Label>
                        <p className="text-xs text-muted-foreground">Immediate notification for critical findings</p>
                      </div>
                      <Switch
                        checked={mergedSettings.emailCriticalAlerts ?? true}
                        onCheckedChange={(checked) => updateSetting("emailCriticalAlerts", checked)}
                        data-testid="switch-email-critical"
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label className="font-normal text-orange-600 dark:text-orange-400">High Alerts</Label>
                        <p className="text-xs text-muted-foreground">Notification for high-severity findings</p>
                      </div>
                      <Switch
                        checked={mergedSettings.emailHighAlerts ?? true}
                        onCheckedChange={(checked) => updateSetting("emailHighAlerts", checked)}
                        data-testid="switch-email-high"
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label className="font-normal text-yellow-600 dark:text-yellow-400">Medium Alerts</Label>
                        <p className="text-xs text-muted-foreground">Notification for medium-severity findings</p>
                      </div>
                      <Switch
                        checked={mergedSettings.emailMediumAlerts ?? false}
                        onCheckedChange={(checked) => updateSetting("emailMediumAlerts", checked)}
                        data-testid="switch-email-medium"
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label className="font-normal text-blue-600 dark:text-blue-400">Low Alerts</Label>
                        <p className="text-xs text-muted-foreground">Notification for low-severity findings</p>
                      </div>
                      <Switch
                        checked={mergedSettings.emailLowAlerts ?? false}
                        onCheckedChange={(checked) => updateSetting("emailLowAlerts", checked)}
                        data-testid="switch-email-low"
                      />
                    </div>
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Daily Digest</Label>
                      <p className="text-xs text-muted-foreground">
                        Receive a daily summary email of all security activities
                      </p>
                    </div>
                    <Switch
                      checked={mergedSettings.emailDailyDigest ?? true}
                      onCheckedChange={(checked) => updateSetting("emailDailyDigest", checked)}
                      data-testid="switch-email-digest"
                    />
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Gauge className="h-5 w-5" />
                Alert Thresholds
              </CardTitle>
              <CardDescription>
                Configure score thresholds for alert classification
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-red-600 dark:text-red-400">Critical Threshold</Label>
                  <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded" data-testid="text-threshold-critical">
                    {mergedSettings.alertThresholdCritical || 90}+
                  </span>
                </div>
                <Slider
                  value={[mergedSettings.alertThresholdCritical || 90]}
                  onValueChange={([value]) => updateSetting("alertThresholdCritical", value)}
                  min={50}
                  max={100}
                  step={5}
                  data-testid="slider-threshold-critical"
                />
                <p className="text-xs text-muted-foreground">
                  Scores at or above this value are classified as critical
                </p>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-orange-600 dark:text-orange-400">High Threshold</Label>
                  <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded" data-testid="text-threshold-high">
                    {mergedSettings.alertThresholdHigh || 70}+
                  </span>
                </div>
                <Slider
                  value={[mergedSettings.alertThresholdHigh || 70]}
                  onValueChange={([value]) => updateSetting("alertThresholdHigh", value)}
                  min={30}
                  max={90}
                  step={5}
                  data-testid="slider-threshold-high"
                />
                <p className="text-xs text-muted-foreground">
                  Scores at or above this value are classified as high severity
                </p>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-yellow-600 dark:text-yellow-400">Medium Threshold</Label>
                  <span className="text-sm font-mono bg-muted px-2 py-0.5 rounded" data-testid="text-threshold-medium">
                    {mergedSettings.alertThresholdMedium || 40}+
                  </span>
                </div>
                <Slider
                  value={[mergedSettings.alertThresholdMedium || 40]}
                  onValueChange={([value]) => updateSetting("alertThresholdMedium", value)}
                  min={10}
                  max={70}
                  step={5}
                  data-testid="slider-threshold-medium"
                />
                <p className="text-xs text-muted-foreground">
                  Scores at or above this value are classified as medium severity
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                API Rate Limits
              </CardTitle>
              <CardDescription>
                Configure API request rate limiting to protect platform resources
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="rateLimitMinute">Requests per Minute</Label>
                  <Input
                    id="rateLimitMinute"
                    type="number"
                    min={1}
                    max={1000}
                    value={mergedSettings.apiRateLimitPerMinute || 60}
                    onChange={(e) => updateSetting("apiRateLimitPerMinute", parseInt(e.target.value) || 60)}
                    data-testid="input-rate-limit-minute"
                  />
                  <p className="text-xs text-muted-foreground">
                    Max requests/minute
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="rateLimitHour">Requests per Hour</Label>
                  <Input
                    id="rateLimitHour"
                    type="number"
                    min={60}
                    max={100000}
                    value={mergedSettings.apiRateLimitPerHour || 1000}
                    onChange={(e) => updateSetting("apiRateLimitPerHour", parseInt(e.target.value) || 1000)}
                    data-testid="input-rate-limit-hour"
                  />
                  <p className="text-xs text-muted-foreground">
                    Max requests/hour
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="rateLimitDay">Requests per Day</Label>
                  <Input
                    id="rateLimitDay"
                    type="number"
                    min={1000}
                    max={1000000}
                    value={mergedSettings.apiRateLimitPerDay || 10000}
                    onChange={(e) => updateSetting("apiRateLimitPerDay", parseInt(e.target.value) || 10000)}
                    data-testid="input-rate-limit-day"
                  />
                  <p className="text-xs text-muted-foreground">
                    Max requests/day
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                API Logging & Auditing
              </CardTitle>
              <CardDescription>
                Configure API request logging for security auditing
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable API Request Logging</Label>
                  <p className="text-xs text-muted-foreground">
                    Log all API requests for security auditing and compliance
                  </p>
                </div>
                <Switch
                  checked={mergedSettings.apiLoggingEnabled ?? true}
                  onCheckedChange={(checked) => updateSetting("apiLoggingEnabled", checked)}
                  data-testid="switch-api-logging"
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Webhook className="h-5 w-5" />
                Webhooks
              </CardTitle>
              <CardDescription>
                Configure outbound webhooks for integration with external systems
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Webhooks</Label>
                  <p className="text-xs text-muted-foreground">
                    Send real-time event notifications to external systems
                  </p>
                </div>
                <Switch
                  checked={mergedSettings.webhooksEnabled ?? false}
                  onCheckedChange={(checked) => updateSetting("webhooksEnabled", checked)}
                  data-testid="switch-webhooks-enabled"
                />
              </div>

              {mergedSettings.webhooksEnabled && (
                <div className="space-y-2 pl-4 border-l-2 border-muted">
                  <Label htmlFor="webhookUrl">Webhook URL</Label>
                  <Input
                    id="webhookUrl"
                    type="url"
                    value={mergedSettings.webhookUrl || ""}
                    onChange={(e) => updateSetting("webhookUrl", e.target.value)}
                    placeholder="https://your-system.com/webhook"
                    data-testid="input-webhook-url"
                  />
                  <p className="text-xs text-muted-foreground">
                    URL to receive webhook event payloads (HTTPS required)
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {canManageUsers && (
          <TabsContent value="users" className="mt-6">
            <Suspense fallback={<PanelFallback />}>
              <UserManagementPanel />
            </Suspense>
          </TabsContent>
        )}

        <TabsContent value="billing" className="mt-6">
          <Suspense fallback={<PanelFallback />}>
            <BillingPanel />
          </Suspense>
        </TabsContent>

        <TabsContent value="integrations" className="mt-6">
          <Suspense fallback={<PanelFallback />}>
            <IntegrationsPanel />
          </Suspense>
        </TabsContent>

        <TabsContent value="governance" className="mt-6">
          <Suspense fallback={<PanelFallback />}>
            <GovernancePanel />
          </Suspense>
        </TabsContent>

        <TabsContent value="audit-logs" className="mt-6">
          <Suspense fallback={<PanelFallback />}>
            <AuditLogsPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}
