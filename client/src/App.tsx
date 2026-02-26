import { useState, useCallback, lazy, Suspense, Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Switch, Route, useLocation, Redirect, Link } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./components/ThemeProvider";
import { UIAuthProvider, useUIAuth } from "./contexts/UIAuthContext";
import { ViewModeProvider } from "./contexts/ViewModeContext";
import { CyberToastProvider } from "@/components/ui/cyber-toast";
import { useAevOnlyMode } from "./components/AppSidebar";
import { ShieldValknut } from "./components/OdinForgeLogo";
import { NotificationsPopover } from "./components/NotificationsPopover";
import { DemoDataBanner } from "./components/DemoDataBanner";
import { TrialBanner } from "./components/TrialBanner";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/contexts/AuthContext";
import {
  LayoutDashboard,
  Zap,
  AlertCircle,
  Shield,
  Activity,
  FileText,
  Server,
  Settings,
  Calendar,
  Radar,
  Link2,
  ChevronRight,
  LogOut,
  Bell,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

// Lazy load pages
const Assets = lazy(() => import("@/pages/Assets"));
const Reports = lazy(() => import("@/pages/Reports"));
const Agents = lazy(() => import("@/pages/Agents"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const Login = lazy(() => import("@/pages/Login"));
const Signup = lazy(() => import("@/pages/Signup"));
const FullAssessment = lazy(() => import("@/pages/FullAssessment"));
const LiveScans = lazy(() => import("@/pages/LiveScans"));
const ScheduledScans = lazy(() => import("@/pages/ScheduledScans"));
const Simulations = lazy(() => import("@/pages/Simulations"));
const BreachChains = lazy(() => import("@/pages/BreachChains"));
const AssessmentWizard = lazy(() => import("@/pages/AssessmentWizard"));
const DashboardPage = lazy(() => import("@/components/Dashboard").then(m => ({ default: m.Dashboard })));
const NotFound = lazy(() => import("@/pages/not-found"));

class AppErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[AppErrorBoundary]", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background p-8">
          <div className="max-w-lg w-full space-y-4">
            <h1 className="text-2xl font-bold text-destructive">Something went wrong</h1>
            <pre className="text-sm bg-muted p-4 rounded-lg overflow-auto max-h-64 text-foreground">
              {this.state.error?.message}{"\n\n"}{this.state.error?.stack}
            </pre>
            <button onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }} className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">
              Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <div className="h-6 w-6 border-2 border-falcon-blue border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <p className="text-falcon-t3 text-xs font-mono tracking-wider">LOADING</p>
      </div>
    </div>
  );
}

function Router() {
  const isAevOnly = useAevOnlyMode();
  return (
    <AppErrorBoundary>
    <Suspense fallback={<PageLoader />}>
      <Switch>
        <Route path="/" component={DashboardPage} />
        <Route path="/login"><Redirect to="/" /></Route>
        <Route path="/signup"><Redirect to="/" /></Route>
        <Route path="/risk"><Redirect to="/" /></Route>
        <Route path="/dashboard/ciso"><Redirect to="/" /></Route>
        <Route path="/assets" component={Assets} />
        <Route path="/infrastructure"><Redirect to="/admin/settings?tab=integrations" /></Route>
        <Route path="/reports" component={Reports} />
        <Route path="/governance"><Redirect to="/admin/settings?tab=governance" /></Route>
        {!isAevOnly && <Route path="/agents" component={Agents} />}
        <Route path="/full-assessment" component={FullAssessment} />
        <Route path="/recon"><Redirect to="/full-assessment?tab=live-recon" /></Route>
        <Route path="/advanced"><Redirect to="/" /></Route>
        <Route path="/approvals"><Redirect to="/full-assessment?tab=approvals" /></Route>
        <Route path="/approvals/history"><Redirect to="/full-assessment?tab=approvals" /></Route>
        <Route path="/jobs"><Redirect to="/" /></Route>
        <Route path="/health"><Redirect to="/" /></Route>
        <Route path="/audit"><Redirect to="/admin/settings?tab=audit-logs" /></Route>
        <Route path="/sessions"><Redirect to="/scans?tab=sessions" /></Route>
        <Route path="/scans" component={LiveScans} />
        {!isAevOnly && <Route path="/scheduled-scans" component={ScheduledScans} />}
        <Route path="/sandbox"><Redirect to="/full-assessment?tab=sandbox" /></Route>
        {!isAevOnly && <Route path="/simulations" component={Simulations} />}
        <Route path="/breach-chains" component={BreachChains} />
        <Route path="/assess" component={AssessmentWizard} />
        {!isAevOnly && <Route path="/billing"><Redirect to="/admin/settings?tab=billing" /></Route>}
        <Route path="/admin/users"><Redirect to="/admin/settings?tab=users" /></Route>
        <Route path="/admin/settings" component={SettingsPage} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
    </AppErrorBoundary>
  );
}

/* ── Route labels ── */
const ROUTE_LABELS: Record<string, [string, string]> = {
  "/": ["Operations", "Dashboard"],
  "/assets": ["Intelligence", "Assets"],
  "/full-assessment": ["Operations", "Assessments"],
  "/breach-chains": ["Operations", "Breach Chains"],
  "/scans": ["Operations", "Live Scans"],
  "/scheduled-scans": ["Operations", "Scheduled Scans"],
  "/reports": ["Intelligence", "Reports"],
  "/admin/settings": ["Admin", "Settings"],
  "/assess": ["Operations", "Assessment Wizard"],
};

/* ══════════════════════════
   TOPBAR
══════════════════════════ */
function TopBar() {
  const { user: uiUser, logout } = useUIAuth();
  const [location] = useLocation();
  const { data: evaluations = [] } = useQuery<any[]>({ queryKey: ["/api/aev/evaluations"] });

  const handleLogout = async () => { await logout(); window.location.reload(); };

  const [, page] = ROUTE_LABELS[location] || ["Operations", "Page"];
  const critCount = evaluations.filter((e: any) => (e.priority || e.severity || "").toLowerCase() === "critical").length;
  const activeCount = evaluations.filter((e: any) => e.status === "in_progress").length;
  const breachCount = evaluations.filter((e: any) => e.exploitable).length;

  return (
    <div
      className="col-span-full h-[52px] flex items-center"
      style={{ background: "var(--falcon-panel)", borderBottom: "1px solid var(--falcon-border)" }}
    >
      {/* Logo block — matches sidebar width */}
      <div
        className="w-[248px] h-full flex items-center gap-[11px] px-[18px] shrink-0"
        style={{ borderRight: "1px solid var(--falcon-border)" }}
      >
        <div className="w-[30px] h-[30px] shrink-0 rounded-[6px] flex items-center justify-center" style={{ background: "var(--falcon-red)" }}>
          <ShieldValknut className="w-4 h-4 text-white" />
        </div>
        <div className="flex flex-col gap-px">
          <div className="text-[14px] font-bold tracking-[-0.01em] leading-none" style={{ color: "var(--falcon-t1)" }}>
            Odin<span style={{ color: "var(--falcon-red)" }}>Forge</span>
          </div>
          <div className="font-mono text-[8px] font-light tracking-[0.2em]" style={{ color: "var(--falcon-t4)" }}>
            AEV PLATFORM
          </div>
        </div>
      </div>

      {/* Page info */}
      <div className="flex flex-col gap-[2px] px-5">
        <div className="text-[13px] font-semibold" style={{ color: "var(--falcon-t1)" }}>{page}</div>
        <div className="text-[10px] font-mono tracking-[0.06em]" style={{ color: "var(--falcon-t3)" }}>
          Threat Operations Center
        </div>
      </div>

      {/* Alert badge */}
      {breachCount > 0 && (
        <div
          className="flex items-center gap-[7px] py-[5px] px-3 rounded cursor-pointer ml-4"
          style={{ background: "var(--falcon-red-dim)", border: "1px solid var(--falcon-red-border)" }}
        >
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--falcon-red)", animation: "f-blink 1.8s ease-in-out infinite" }} />
          <span className="font-mono text-[9.5px] font-medium tracking-[0.08em]" style={{ color: "var(--falcon-red)" }}>
            {breachCount} BREACH PATH{breachCount !== 1 ? "S" : ""} DETECTED
          </span>
        </div>
      )}

      {/* Right stats + user */}
      <div className="ml-auto flex items-stretch h-full">
        <TopBarStat value={String(activeCount)} label="Active Ops" color="var(--falcon-blue-hi)" />
        <TopBarStat value={String(critCount)} label="Critical" color={critCount > 0 ? "var(--falcon-red)" : "var(--falcon-t1)"} />
        <TopBarStat value={String(evaluations.length)} label="Exploits" color="var(--falcon-t1)" />
        <TopBarStat value="NOMINAL" label="Engine" color="var(--falcon-green)" />

        {/* Notifications */}
        <div
          className="flex items-center justify-center w-12 cursor-pointer relative transition-colors"
          style={{ borderLeft: "1px solid var(--falcon-border)", color: "var(--falcon-t3)" }}
        >
          <NotificationsPopover />
        </div>

        {/* User */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <div
              className="flex items-center gap-[10px] px-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
              style={{ borderLeft: "1px solid var(--falcon-border)" }}
              data-testid="button-user-menu"
            >
              <div
                className="w-[30px] h-[30px] rounded-full flex items-center justify-center text-[11px] font-bold"
                style={{ background: "var(--falcon-red)", color: "#fff" }}
              >
                {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
              </div>
              <div>
                <div className="text-[12px] font-medium" style={{ color: "var(--falcon-t1)" }}>
                  {uiUser?.displayName || uiUser?.email || "User"}
                </div>
                <div className="font-mono text-[9px] tracking-[0.08em]" style={{ color: "var(--falcon-t3)" }}>
                  {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
                </div>
              </div>
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            {uiUser && (
              <>
                <div className="px-3 py-2">
                  <p className="text-sm font-medium">{uiUser.displayName || uiUser.email}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{uiUser.email}</p>
                </div>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem data-testid="menu-profile">Profile</DropdownMenuItem>
            <DropdownMenuItem data-testid="menu-settings">Settings</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} data-testid="menu-logout" className="text-red-400 focus:text-red-400">
              <LogOut className="h-4 w-4 mr-2" />Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}

function TopBarStat({ value, label, color }: { value: string; label: string; color: string }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 gap-px" style={{ borderLeft: "1px solid var(--falcon-border)" }}>
      <div className="font-mono text-[14px] font-medium leading-none" style={{ color }}>{value}</div>
      <div className="text-[9px] font-normal tracking-[0.14em] uppercase" style={{ color: "var(--falcon-t3)" }}>{label}</div>
    </div>
  );
}

/* ══════════════════════════
   SIDEBAR
══════════════════════════ */
interface NavItem {
  icon: typeof LayoutDashboard;
  title: string;
  href: string;
  badge?: { count: number; style: "r" | "d" };
  aevHidden?: boolean;
}

function FalconSidebar() {
  const [location] = useLocation();
  const isAevOnly = useAevOnlyMode();
  const { hasPermission } = useAuth();
  const { user: uiUser } = useUIAuth();
  const { data: evaluations = [] } = useQuery<any[]>({ queryKey: ["/api/aev/evaluations"] });
  const { data: assets = [] } = useQuery<any[]>({ queryKey: ["/api/assets"] });

  const critCount = evaluations.filter((e: any) => (e.priority || e.severity || "").toLowerCase() === "critical").length;
  const activeCount = evaluations.filter((e: any) => e.status === "in_progress" || e.status === "pending").length;
  const breachCount = evaluations.filter((e: any) => e.exploitable).length;

  const isActive = (href: string) => {
    if (href === "/") return location === "/";
    return location.startsWith(href);
  };

  const coreItems: NavItem[] = [
    { icon: LayoutDashboard, title: "Dashboard", href: "/" },
    { icon: Server, title: "Assets", href: "/assets", badge: assets.length > 0 ? { count: assets.length, style: "d" } : undefined },
    { icon: Shield, title: "Assessments", href: "/full-assessment", badge: activeCount > 0 ? { count: activeCount, style: "d" } : undefined },
    { icon: Link2, title: "Breach Chains", href: "/breach-chains", badge: breachCount > 0 ? { count: breachCount, style: "r" } : undefined },
  ];

  const opsItems: NavItem[] = [
    { icon: Radar, title: "Live Scans", href: "/scans", badge: activeCount > 0 ? { count: activeCount, style: "d" } : undefined },
    { icon: Calendar, title: "Scheduled Scans", href: "/scheduled-scans", aevHidden: true },
    { icon: FileText, title: "Reports", href: "/reports" },
  ];

  const showSettings = hasPermission("org:manage_settings") || hasPermission("org:manage_users");

  const renderItem = (item: NavItem) => {
    if (isAevOnly && item.aevHidden) return null;
    const active = isActive(item.href);
    return (
      <Link key={item.href + item.title} href={item.href}>
        <div
          className="flex items-center gap-[11px] py-[9px] px-[18px] cursor-pointer text-[13px] transition-all select-none"
          style={{
            color: active ? "var(--falcon-t1)" : "var(--falcon-t2)",
            background: active ? "rgba(255,255,255,0.05)" : undefined,
            borderLeft: active ? "2px solid var(--falcon-red)" : "2px solid transparent",
            fontWeight: active ? 500 : 400,
          }}
          onMouseEnter={(e) => { if (!active) { e.currentTarget.style.color = "var(--falcon-t1)"; e.currentTarget.style.background = "var(--falcon-hover)"; }}}
          onMouseLeave={(e) => { if (!active) { e.currentTarget.style.color = "var(--falcon-t2)"; e.currentTarget.style.background = ""; }}}
        >
          <item.icon className="w-4 h-4 shrink-0" />
          {item.title}
          {item.badge && (
            <span className={`f-nav-badge ${item.badge.style === "r" ? "f-nb-r" : "f-nb-d"}`}>
              {item.badge.count}
            </span>
          )}
        </div>
      </Link>
    );
  };

  return (
    <div
      className="flex flex-col pt-4 overflow-hidden"
      style={{ background: "var(--falcon-nav)", borderRight: "1px solid var(--falcon-border)" }}
    >
      {/* Core section */}
      <div className="mb-1">
        <div className="font-mono text-[9px] font-normal tracking-[0.24em] uppercase px-[18px] py-[6px] pb-[5px]" style={{ color: "var(--falcon-t4)" }}>
          Core
        </div>
        {coreItems.map(renderItem)}
      </div>

      {/* Operations section */}
      <div className="mb-1">
        <div className="font-mono text-[9px] font-normal tracking-[0.24em] uppercase px-[18px] py-[6px] pb-[5px]" style={{ color: "var(--falcon-t4)" }}>
          Operations
        </div>
        {opsItems.map(renderItem)}
      </div>

      {/* Admin section */}
      {showSettings && (
        <div className="mb-1">
          <div className="font-mono text-[9px] font-normal tracking-[0.24em] uppercase px-[18px] py-[6px] pb-[5px]" style={{ color: "var(--falcon-t4)" }}>
            Admin
          </div>
          <Link href="/admin/settings">
            <div
              className="flex items-center gap-[11px] py-[9px] px-[18px] cursor-pointer text-[13px] transition-all select-none"
              style={{
                color: location.startsWith("/admin/settings") ? "var(--falcon-t1)" : "var(--falcon-t2)",
                background: location.startsWith("/admin/settings") ? "rgba(255,255,255,0.05)" : undefined,
                borderLeft: location.startsWith("/admin/settings") ? "2px solid var(--falcon-red)" : "2px solid transparent",
                fontWeight: location.startsWith("/admin/settings") ? 500 : 400,
              }}
              onMouseEnter={(e) => { if (!location.startsWith("/admin/settings")) { e.currentTarget.style.color = "var(--falcon-t1)"; e.currentTarget.style.background = "var(--falcon-hover)"; }}}
              onMouseLeave={(e) => { if (!location.startsWith("/admin/settings")) { e.currentTarget.style.color = "var(--falcon-t2)"; e.currentTarget.style.background = ""; }}}
            >
              <Settings className="w-4 h-4 shrink-0" />
              Settings
            </div>
          </Link>
        </div>
      )}

      <div className="flex-1" />

      {/* User footer */}
      <div
        className="flex items-center gap-[11px] px-[18px] py-3 cursor-pointer transition-colors"
        style={{ borderTop: "1px solid var(--falcon-border)" }}
        onMouseEnter={(e) => { e.currentTarget.style.background = "var(--falcon-hover)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}
      >
        <div
          className="w-8 h-8 rounded-full flex items-center justify-center text-[12px] font-bold shrink-0"
          style={{ background: "var(--falcon-red)", color: "#fff" }}
        >
          {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
        </div>
        <div>
          <div className="text-[12px] font-semibold" style={{ color: "var(--falcon-t1)" }}>
            {uiUser?.displayName || uiUser?.email || "User"}
          </div>
          <div className="font-mono text-[9px] tracking-[0.06em]" style={{ color: "var(--falcon-t3)" }}>
            {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ══════════════════════════
   STATUS BAR
══════════════════════════ */
function StatusBar() {
  return (
    <div
      className="col-span-full h-[26px] flex items-center px-[18px] gap-[14px] font-mono text-[9px] font-light tracking-[0.08em]"
      style={{ background: "var(--falcon-panel)", borderTop: "1px solid var(--falcon-border)", color: "var(--falcon-t4)" }}
    >
      <span className="sb">ENGINE <em className="not-italic" style={{ color: "var(--falcon-t3)" }}>Mjolnir v4.2</em></span>
      <span style={{ color: "var(--falcon-border-2)" }}>&middot;</span>
      <span className="sb">BUILD <em className="not-italic" style={{ color: "var(--falcon-t3)" }}>2026.02.26</em></span>
      <div className="ml-auto flex gap-3">
        <span style={{ color: "var(--falcon-green)" }}>&#9679; SYSTEMS NOMINAL</span>
      </div>
    </div>
  );
}

/* ══════════════════════════
   LAYOUT SHELL
══════════════════════════ */
function AppLayout() {
  return (
    <div
      className="h-screen w-full overflow-hidden"
      style={{
        display: "grid",
        gridTemplateColumns: "248px 1fr",
        gridTemplateRows: "52px 1fr 26px",
        background: "var(--falcon-bg)",
      }}
    >
      <TopBar />
      <FalconSidebar />
      <main className="flex flex-col overflow-hidden" style={{ background: "var(--falcon-bg)" }}>
        <div className="flex flex-col gap-[14px] p-5 flex-1 overflow-auto">
          <TrialBanner />
          <DemoDataBanner />
          <Router />
        </div>
      </main>
      <StatusBar />
    </div>
  );
}

function AuthenticatedApp() {
  const { isAuthenticated, isLoading } = useUIAuth();
  const [, forceUpdate] = useState(0);
  const [location] = useLocation();

  const handleAuthSuccess = useCallback(() => {
    forceUpdate(x => x + 1);
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--falcon-bg)" }}>
        <div className="text-center">
          <div className="h-6 w-6 border-2 border-falcon-blue border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="font-mono text-[10px] tracking-wider" style={{ color: "var(--falcon-t3)" }}>INITIALIZING</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    if (location === "/signup") {
      return <Signup onSignupSuccess={handleAuthSuccess} />;
    }
    return <Login onLoginSuccess={handleAuthSuccess} />;
  }

  return (
    <ViewModeProvider>
      <TooltipProvider>
        <CyberToastProvider>
          <AppLayout />
          <Toaster />
        </CyberToastProvider>
      </TooltipProvider>
    </ViewModeProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <UIAuthProvider>
          <AuthenticatedApp />
        </UIAuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
