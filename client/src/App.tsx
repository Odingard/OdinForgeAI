import { useState, useCallback, useEffect, lazy, Suspense, Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Switch, Route, useLocation, Redirect, Link } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./components/ThemeProvider";
import { UIAuthProvider, useUIAuth } from "./contexts/UIAuthContext";
import { ViewModeProvider } from "./contexts/ViewModeContext";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, FileText, Settings, LogOut } from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuTrigger, DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { ShieldValknut } from "./components/OdinForgeLogo";
import { NotificationsPopover } from "./components/NotificationsPopover";

const BreachChains = lazy(() => import("@/pages/BreachChains"));
const Reports      = lazy(() => import("@/pages/Reports"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const Login        = lazy(() => import("@/pages/Login"));
const Signup       = lazy(() => import("@/pages/Signup"));
const NotFound     = lazy(() => import("@/pages/not-found"));

class AppErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: ReactNode }) { super(props); this.state = { hasError: false, error: null }; }
  static getDerivedStateFromError(error: Error) { return { hasError: true, error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("[AppErrorBoundary]", error, info); }
  render() {
    if (this.state.hasError) return (
      <div className="min-h-screen flex items-center justify-center p-8" style={{ background: "var(--bg)" }}>
        <div className="max-w-lg w-full space-y-4">
          <h1 className="text-xl font-bold" style={{ color: "var(--red)" }}>Something went wrong</h1>
          <pre className="text-xs p-4 overflow-auto max-h-64" style={{ background: "var(--panel)", color: "var(--t2)", border: "1px solid var(--border)" }}>
            {this.state.error?.message}{"\n\n"}{this.state.error?.stack}
          </pre>
          <button onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }}
            className="px-4 py-2 text-sm" style={{ background: "var(--red)", color: "#fff", border: "none", cursor: "pointer" }}>
            Reload
          </button>
        </div>
      </div>
    );
    return this.props.children;
  }
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>LOADING</p>
      </div>
    </div>
  );
}

function Router() {
  return (
    <AppErrorBoundary>
      <Suspense fallback={<PageLoader />}>
        <Switch>
          <Route path="/"><Redirect to="/breach-chains" /></Route>
          <Route path="/login"><Redirect to="/breach-chains" /></Route>
          <Route path="/signup"><Redirect to="/breach-chains" /></Route>
          <Route path="/breach-chains" component={BreachChains} />
          <Route path="/reports" component={Reports} />
          <Route path="/admin/settings" component={SettingsPage} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    </AppErrorBoundary>
  );
}

const PAGE_META: Record<string, { name: string; sub: string }> = {
  "/breach-chains":   { name: "Breach Chains",  sub: "Threat Operations Center" },
  "/reports":         { name: "Reports",         sub: "Engagement deliverables"  },
  "/admin/settings":  { name: "Settings",        sub: "System configuration"     },
};

/* ── TopBar ── */
function TopBar() {
  const { user: uiUser, logout } = useUIAuth();
  const [location] = useLocation();
  const { data: chains = [] } = useQuery<any[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: (query) => {
      const data = query.state.data as any[] | undefined;
      return data?.some((c: any) => c.status === "running") ? 5000 : 30000;
    },
  });

  const handleLogout = async () => { await logout(); window.location.reload(); };
  const meta = PAGE_META[location] ?? { name: "OdinForge", sub: "AEV Platform" };

  const activeCount  = chains.filter((c: any) => c.status === "running").length;
  const critCount    = chains.reduce((s: number, c: any) =>
    s + (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length, 0);
  const breachCount  = chains.filter((c: any) =>
    (c.phaseResults || []).some((p: any) => (p.findings || []).length > 0)).length;
  const engineStatus = activeCount > 0 ? "ACTIVE" : "NOMINAL";

  const S = ({ value, label, color }: { value: string; label: string; color?: string }) => (
    <div className="flex flex-col items-center justify-center px-[14px] gap-[1px]"
      style={{ borderLeft: "1px solid var(--border)" }}>
      <div className="font-mono text-[13px] font-medium leading-none" style={{ color: color ?? "var(--t1)" }}>{value}</div>
      <div className="font-mono text-[8px] tracking-[.12em] uppercase" style={{ color: "var(--t3)" }}>{label}</div>
    </div>
  );

  return (
    <div className="flex items-center" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel)", gridColumn: "1 / -1" }}>
      {/* Logo block */}
      <div className="flex items-center gap-[10px] px-[16px] h-full flex-shrink-0"
        style={{ width: 220, borderRight: "1px solid var(--border)" }}>
        <div className="flex items-center justify-center flex-shrink-0"
          style={{ width: 28, height: 28, background: "var(--red)" }}>
          <ShieldValknut className="w-[15px] h-[15px] text-white" />
        </div>
        <div>
          <div className="text-[15px] font-bold" style={{ color: "var(--t1)", fontFamily: "var(--font-sans)" }}>
            Odin<span style={{ color: "var(--red)" }}>Forge</span>
          </div>
          <div className="font-mono text-[8px] tracking-[.18em]" style={{ color: "var(--t4)" }}>AEV PLATFORM</div>
        </div>
      </div>

      {/* Page name */}
      <div className="flex flex-col gap-[1px] px-[16px]">
        <div className="text-[13px] font-semibold" style={{ color: "var(--t1)" }}>{meta.name}</div>
        <div className="font-mono text-[9px] tracking-[.06em]" style={{ color: "var(--t3)" }}>{meta.sub}</div>
      </div>

      {/* Breach alert */}
      {breachCount > 0 && (
        <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-3"
          style={{ background: "var(--red-dim)", border: "1px solid var(--red-border)" }}>
          <div className="w-[5px] h-[5px] rounded-full" style={{ background: "var(--red)", animation: "f-blink 1.8s ease-in-out infinite" }} />
          <span className="font-mono text-[9px] tracking-[.07em]" style={{ color: "var(--red)" }}>
            {breachCount} BREACH PATH{breachCount !== 1 ? "S" : ""} DETECTED
          </span>
        </div>
      )}

      {/* Right stats */}
      <div className="ml-auto flex items-stretch h-full">
        <S value={String(activeCount)} label="Active" color={activeCount > 0 ? "var(--blue)" : undefined} />
        <S value={String(critCount)} label="Critical" color={critCount > 0 ? "var(--red)" : undefined} />
        <S value={String(breachCount)} label="Breaches" color={breachCount > 0 ? "var(--amber)" : undefined} />
        <S value={engineStatus} label="Engine" color={activeCount > 0 ? "var(--blue)" : "var(--green)"} />

        {/* Notifications */}
        <div className="flex items-center justify-center w-[44px] cursor-pointer"
          style={{ borderLeft: "1px solid var(--border)", color: "var(--t3)" }}>
          <NotificationsPopover />
        </div>

        {/* User */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <div className="flex items-center gap-[9px] px-[14px] cursor-pointer transition-colors"
              style={{ borderLeft: "1px solid var(--border)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = ""; }}
              data-testid="button-user-menu">
              <div className="w-[26px] h-[26px] rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                style={{ background: "var(--red)", color: "#fff" }}>
                {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
              </div>
              <div>
                <div className="text-[12px] font-medium" style={{ color: "var(--t1)" }}>
                  {uiUser?.displayName || uiUser?.email || "User"}
                </div>
                <div className="font-mono text-[8px] tracking-[.07em]" style={{ color: "var(--t3)" }}>
                  {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
                </div>
              </div>
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {uiUser && (
              <>
                <div className="px-3 py-2">
                  <p className="text-xs font-medium">{uiUser.displayName || uiUser.email}</p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--t3)" }}>{uiUser.email}</p>
                </div>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem>Profile</DropdownMenuItem>
            <DropdownMenuItem>Settings</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} className="text-red-400 focus:text-red-400" data-testid="menu-logout">
              <LogOut className="h-3.5 w-3.5 mr-2" />Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}

/* ── Sidebar ── */
function Sidebar() {
  const [location] = useLocation();
  const { hasPermission } = useAuth();
  const { user: uiUser, logout } = useUIAuth();
  const { data: chains = [] } = useQuery<any[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: (query) => {
      const data = query.state.data as any[] | undefined;
      return data?.some((c: any) => c.status === "running") ? 5000 : 30000;
    },
  });
  const breachCount = chains.filter((c: any) =>
    (c.phaseResults || []).some((p: any) => (p.findings || []).length > 0)).length;

  const navItem = (href: string, Icon: typeof Shield, label: string, badge?: number) => {
    const active = location.startsWith(href);
    return (
      <Link key={href} href={href}>
        <div className="flex items-center gap-[10px] py-[9px] px-[14px] text-[12px] font-medium cursor-pointer select-none transition-all"
          style={{
            color: active ? "var(--t1)" : "var(--t2)",
            background: active ? "rgba(255,255,255,.04)" : undefined,
            borderLeft: active ? "2px solid var(--red)" : "2px solid transparent",
          }}
          onMouseEnter={e => { if (!active) { (e.currentTarget as HTMLElement).style.color = "var(--t1)"; (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}}
          onMouseLeave={e => { if (!active) { (e.currentTarget as HTMLElement).style.color = "var(--t2)"; (e.currentTarget as HTMLElement).style.background = ""; }}}>
          <Icon className="w-[14px] h-[14px] flex-shrink-0" strokeWidth={1.5} />
          {label}
          {badge !== undefined && badge > 0 && (
            <span className="f-nav-badge f-nb-r ml-auto">{badge}</span>
          )}
        </div>
      </Link>
    );
  };

  const showSettings = hasPermission("org:manage_settings") || hasPermission("org:manage_users");

  return (
    <div className="flex flex-col overflow-hidden" style={{ background: "var(--nav)", borderRight: "1px solid var(--border)" }}>
      <div className="h-4" />
      <div className="flex flex-col gap-[2px] px-[10px]">
        {navItem("/breach-chains", Shield, "Breach Chains", breachCount)}
        {navItem("/reports", FileText, "Reports")}
      </div>
      <div className="flex-1" />
      {showSettings && (
        <div className="px-[10px] pb-1">
          {navItem("/admin/settings", Settings, "Settings")}
        </div>
      )}
      <div className="flex items-center gap-[10px] px-[14px] py-[10px] cursor-pointer transition-colors"
        style={{ borderTop: "1px solid var(--border)" }}
        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = ""; }}>
        <div className="w-[26px] h-[26px] rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
          style={{ background: "var(--red)", color: "#fff" }}>
          {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
        </div>
        <div>
          <div className="text-[12px] font-semibold" style={{ color: "var(--t1)" }}>
            {uiUser?.displayName || uiUser?.email || "User"}
          </div>
          <div className="font-mono text-[8px] tracking-[.06em]" style={{ color: "var(--t3)" }}>
            {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── StatusBar ── */
function StatusBar() {
  const { data: chains = [] } = useQuery<any[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: (query) => {
      const data = query.state.data as any[] | undefined;
      return data?.some((c: any) => c.status === "running") ? 5000 : 30000;
    },
  });
  const running = chains.filter((c: any) => c.status === "running");
  return (
    <div className="flex items-center px-[16px] gap-[12px] font-mono text-[9px] tracking-[.07em]"
      style={{ borderTop: "1px solid var(--border)", background: "var(--panel)", color: "var(--t4)", gridColumn: "1 / -1" }}>
      <span>engine</span><span style={{ color: "var(--t3)" }}>Mjolnir v4.2</span>
      <span style={{ color: "var(--border2)" }}>·</span>
      <span>build</span><span style={{ color: "var(--t3)" }}>2026.03.17</span>
      <span style={{ color: "var(--border2)" }}>·</span>
      <span>odingard security</span>
      <div className="ml-auto flex items-center gap-[5px]" style={{ color: running.length > 0 ? "var(--blue)" : "var(--green)" }}>
        <div className="w-[5px] h-[5px] rounded-full" style={{ background: running.length > 0 ? "var(--blue)" : "var(--green)" }} />
        {running.length > 0 ? `${running.length} chain${running.length !== 1 ? "s" : ""} active` : "systems nominal"}
      </div>
    </div>
  );
}

/* ── App Layout ── */
function AppLayout() {
  return (
    <div className="h-screen w-full overflow-hidden" style={{
      display: "grid",
      gridTemplateColumns: "220px 1fr",
      gridTemplateRows: "48px 1fr 24px",
      background: "var(--bg)",
    }}>
      <TopBar />
      <Sidebar />
      <main className="flex flex-col overflow-hidden" style={{ background: "var(--bg)" }}>
        <div className="flex flex-col gap-[14px] p-5 flex-1 overflow-auto">
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

  useEffect(() => {
    fetch("/api/flags").then(r => r.ok ? r.json() : {})
      .then((flags: Record<string, boolean>) => { (window as any).__ODINFORGE_FLAGS__ = flags; })
      .catch(() => {});
  }, []);

  const handleAuthSuccess = useCallback(() => forceUpdate(x => x + 1), []);

  if (isLoading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg)" }}>
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>INITIALIZING</p>
      </div>
    </div>
  );

  if (!isAuthenticated) {
    if (location === "/signup") return <Signup onSignupSuccess={handleAuthSuccess} />;
    return <Login onLoginSuccess={handleAuthSuccess} />;
  }

  return (
    <ViewModeProvider>
      <TooltipProvider>
        <AppLayout />
        <Toaster />
      </TooltipProvider>
    </ViewModeProvider>
  );
}

export default function App() {
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
