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
import { roleMetadata } from "@shared/schema";
import {
  LayoutDashboard,
  Zap,
  AlertCircle,
  Shield,
  Activity,
  FileText,
  Search,
  Server,
  Settings,
  Calendar,
  Radar,
  Link2,
  ChevronRight,
  LogOut,
  User,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

// Lazy load pages for code splitting
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
              {this.state.error?.message}
              {"\n\n"}
              {this.state.error?.stack}
            </pre>
            <button
              onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm"
            >
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

/* ── Page name from route ── */
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

  const [group, page] = ROUTE_LABELS[location] || ["Operations", "Page"];
  const critCount = evaluations.filter((e: any) => (e.priority || e.severity || "").toLowerCase() === "critical").length;
  const activeCount = evaluations.filter((e: any) => e.status === "in_progress").length;

  return (
    <div className="col-span-full h-[52px] flex items-center" style={{ background: "var(--falcon-panel)", borderBottom: "1px solid var(--falcon-border)" }}>
      {/* Logo */}
      <div className="w-[268px] h-full flex items-center gap-[10px] px-4 shrink-0" style={{ borderRight: "1px solid var(--falcon-border)" }}>
        <div className="w-7 h-7 shrink-0 rounded-[5px] flex items-center justify-center" style={{ background: "var(--falcon-red)" }}>
          <ShieldValknut className="w-4 h-4 text-white" />
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight leading-none" style={{ color: "var(--falcon-t1)" }}>
            Odin<span style={{ color: "var(--falcon-red)" }}>Forge</span>
          </div>
          <div className="font-mono text-[8px] font-light tracking-[0.2em] mt-0.5" style={{ color: "var(--falcon-t3)" }}>
            AEV PLATFORM
          </div>
        </div>
      </div>

      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 px-4 text-xs" style={{ color: "var(--falcon-t3)" }}>
        <span>{group}</span>
        <ChevronRight className="w-3 h-3" style={{ color: "var(--falcon-t4)" }} />
        <span className="font-medium" style={{ color: "var(--falcon-t2)" }}>{page}</span>
      </div>

      {/* Alert badge */}
      {critCount > 0 && (
        <div
          className="flex items-center gap-[7px] py-[5px] px-3 rounded cursor-pointer ml-2 transition-colors"
          style={{ background: "var(--falcon-red-dim)", border: "1px solid var(--falcon-red-border)" }}
        >
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--falcon-red)", animation: "alert-pip 1.8s ease-in-out infinite" }} />
          <span className="font-mono text-[10px] font-medium tracking-wider" style={{ color: "var(--falcon-red)" }}>
            {critCount} CRITICAL FINDING{critCount !== 1 ? "S" : ""}
          </span>
        </div>
      )}

      {/* Right stats */}
      <div className="ml-auto flex items-stretch h-full">
        <TopBarStat value={String(activeCount)} label="Active Ops" color="var(--falcon-blue)" />
        <TopBarStat value={String(critCount)} label="Critical" color="var(--falcon-red)" />
        <TopBarStat value={String(evaluations.length)} label="Evaluations" color="var(--falcon-t1)" />

        {/* Notifications */}
        <div className="flex items-center px-3" style={{ borderLeft: "1px solid var(--falcon-border)" }}>
          <NotificationsPopover />
        </div>

        {/* User */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <div
              className="flex items-center gap-[9px] px-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
              style={{ borderLeft: "1px solid var(--falcon-border)" }}
              data-testid="button-user-menu"
            >
              <div
                className="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold"
                style={{ background: "var(--falcon-blue-dim)", border: "1px solid rgba(59,130,246,0.3)", color: "var(--falcon-blue)" }}
              >
                {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
              </div>
              <div>
                <div className="text-xs font-medium" style={{ color: "var(--falcon-t1)" }}>
                  {uiUser?.displayName || uiUser?.email || "User"}
                </div>
                <div className="font-mono text-[9px] tracking-wider" style={{ color: "var(--falcon-t3)" }}>
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
              <LogOut className="h-4 w-4 mr-2" />
              Log out
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
      <div className="font-mono text-[15px] font-medium leading-none" style={{ color }}>{value}</div>
      <div className="text-[9px] font-normal tracking-[0.15em] uppercase" style={{ color: "var(--falcon-t3)" }}>{label}</div>
    </div>
  );
}

/* ══════════════════════════
   ICON RAIL
══════════════════════════ */
interface RailItem {
  icon: typeof LayoutDashboard;
  href: string;
  label: string;
}

const RAIL_ITEMS: RailItem[] = [
  { icon: LayoutDashboard, href: "/", label: "Dashboard" },
  { icon: Zap, href: "/full-assessment", label: "Assessments" },
  { icon: AlertCircle, href: "/breach-chains", label: "Findings" },
  { icon: Shield, href: "/breach-chains", label: "Breach Chains" },
  { icon: Activity, href: "/scans", label: "Live Scans" },
  { icon: FileText, href: "/reports", label: "Reports" },
];

function IconRail() {
  const [location] = useLocation();

  const isActive = (href: string) => {
    if (href === "/") return location === "/";
    return location.startsWith(href);
  };

  return (
    <div
      className="flex flex-col items-center py-2 gap-0.5"
      style={{ background: "var(--falcon-nav)", borderRight: "1px solid var(--falcon-border)" }}
    >
      {RAIL_ITEMS.map((item) => (
        <Link key={item.href + item.label} href={item.href}>
          <div
            className={`w-9 h-9 flex items-center justify-center rounded-md cursor-pointer transition-all ${
              isActive(item.href) ? "text-falcon-t1 bg-white/[0.07]" : "text-falcon-t3 hover:text-falcon-t2 hover:bg-white/[0.04]"
            }`}
            title={item.label}
          >
            <item.icon className="w-4 h-4" />
          </div>
        </Link>
      ))}
      <div className="flex-1" />
      <Link href="/admin/settings">
        <div
          className="w-9 h-9 flex items-center justify-center rounded-md cursor-pointer transition-all text-falcon-t3 hover:text-falcon-t2 hover:bg-white/[0.04]"
          title="Settings"
        >
          <Settings className="w-4 h-4" />
        </div>
      </Link>
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
  badge?: { count: number; style: string };
  aevHidden?: boolean;
}

function FalconSidebar() {
  const [location] = useLocation();
  const isAevOnly = useAevOnlyMode();
  const { hasPermission } = useAuth();
  const { data: evaluations = [] } = useQuery<any[]>({ queryKey: ["/api/aev/evaluations"] });

  const critCount = evaluations.filter((e: any) => (e.priority || e.severity || "").toLowerCase() === "critical").length;
  const activeCount = evaluations.filter((e: any) => e.status === "in_progress" || e.status === "pending").length;
  const breachCount = evaluations.filter((e: any) => e.exploitable).length;

  const isActive = (href: string) => {
    if (href === "/") return location === "/";
    return location.startsWith(href);
  };

  const opsItems: NavItem[] = [
    { icon: LayoutDashboard, title: "Dashboard", href: "/" },
    { icon: Zap, title: "Assessments", href: "/full-assessment", badge: activeCount > 0 ? { count: activeCount, style: "nb-d" } : undefined },
    { icon: AlertCircle, title: "Findings", href: "/full-assessment", badge: critCount > 0 ? { count: critCount, style: "nb-r" } : undefined },
    { icon: Shield, title: "Breach Chains", href: "/breach-chains", badge: breachCount > 0 ? { count: breachCount, style: "nb-r" } : undefined },
    { icon: Radar, title: "Live Scans", href: "/scans" },
    { icon: Calendar, title: "Scheduled Scans", href: "/scheduled-scans", aevHidden: true },
  ];

  const intelItems: NavItem[] = [
    { icon: Server, title: "Assets", href: "/assets" },
    { icon: Link2, title: "Lateral Movement", href: "/breach-chains" },
    { icon: FileText, title: "Reports", href: "/reports" },
  ];

  const showSettings = hasPermission("org:manage_settings") || hasPermission("org:manage_users");

  const renderItem = (item: NavItem) => {
    if (isAevOnly && item.aevHidden) return null;
    return (
      <Link key={item.href + item.title} href={item.href}>
        <div
          className={`flex items-center gap-[9px] py-2 px-[14px] cursor-pointer text-[12.5px] transition-all ${
            isActive(item.href)
              ? "font-medium border-l-2"
              : "border-l-2 border-transparent hover:bg-white/[0.03]"
          }`}
          style={
            isActive(item.href)
              ? { color: "var(--falcon-t1)", background: "rgba(255,255,255,0.05)", borderLeftColor: "var(--falcon-red)" }
              : { color: "var(--falcon-t2)" }
          }
        >
          <item.icon className="w-[14px] h-[14px] shrink-0" />
          {item.title}
          {item.badge && (
            <span className={`ml-auto font-mono text-[9px] font-medium py-px px-1.5 rounded-[3px] ${item.badge.style === "nb-r"
              ? "text-falcon-red border border-[rgba(232,56,79,0.25)] bg-falcon-red-dim"
              : "text-falcon-t2 border border-falcon-border bg-white/5"
            }`}>
              {item.badge.count}
            </span>
          )}
        </div>
      </Link>
    );
  };

  return (
    <div
      className="flex flex-col py-3 overflow-hidden"
      style={{ background: "var(--falcon-nav)", borderRight: "1px solid var(--falcon-border)" }}
    >
      <div className="mb-0.5">
        <div className="font-mono text-[9px] font-normal tracking-[0.22em] uppercase px-[14px] py-2 pb-1" style={{ color: "var(--falcon-t4)" }}>
          Operations
        </div>
        {opsItems.map(renderItem)}
      </div>

      <div className="mt-1">
        <div className="font-mono text-[9px] font-normal tracking-[0.22em] uppercase px-[14px] py-2 pb-1" style={{ color: "var(--falcon-t4)" }}>
          Intelligence
        </div>
        {intelItems.map(renderItem)}
      </div>

      <div className="flex-1" />

      {showSettings && (
        <>
          <div className="mx-0 my-2" style={{ borderTop: "1px solid var(--falcon-border)" }} />
          <Link href="/admin/settings">
            <div
              className={`flex items-center gap-[9px] py-2 px-[14px] cursor-pointer text-[12.5px] transition-all border-l-2 ${
                location.startsWith("/admin/settings")
                  ? "font-medium"
                  : "border-transparent hover:bg-white/[0.03]"
              }`}
              style={
                location.startsWith("/admin/settings")
                  ? { color: "var(--falcon-t1)", background: "rgba(255,255,255,0.05)", borderLeftColor: "var(--falcon-red)" }
                  : { color: "var(--falcon-t2)" }
              }
            >
              <Settings className="w-[14px] h-[14px] shrink-0" />
              Settings
            </div>
          </Link>
        </>
      )}
    </div>
  );
}

/* ══════════════════════════
   FOOTER
══════════════════════════ */
function AppFooter() {
  return (
    <div
      className="col-span-full h-[26px] flex items-center px-4 gap-4 font-mono text-[9px] font-light tracking-wider"
      style={{ background: "var(--falcon-panel)", borderTop: "1px solid var(--falcon-border)", color: "var(--falcon-t4)" }}
    >
      <span>ENGINE <em className="not-italic" style={{ color: "var(--falcon-t3)" }}>Mjolnir v4.2</em></span>
      <span style={{ color: "var(--falcon-border-2)" }}>&middot;</span>
      <span>BUILD <em className="not-italic" style={{ color: "var(--falcon-t3)" }}>2026.02.26</em></span>
      <div className="ml-auto flex gap-3.5">
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
        gridTemplateColumns: "48px 220px 1fr",
        gridTemplateRows: "52px 1fr 26px",
        background: "var(--falcon-bg)",
      }}
    >
      <TopBar />
      <IconRail />
      <FalconSidebar />
      <main className="flex flex-col gap-3 overflow-auto" style={{ padding: "18px 20px", background: "var(--falcon-bg)" }}>
        <TrialBanner />
        <DemoDataBanner />
        <Router />
      </main>
      <AppFooter />
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
