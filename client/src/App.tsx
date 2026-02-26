import { useState, useCallback, lazy, Suspense, Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Switch, Route, useLocation, Redirect } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";
import { UIAuthProvider, useUIAuth } from "./contexts/UIAuthContext";
import { ViewModeProvider } from "./contexts/ViewModeContext";
import { CyberToastProvider } from "@/components/ui/cyber-toast";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar, useAevOnlyMode } from "./components/AppSidebar";
import { Button } from "@/components/ui/button";
import { Moon, Sun, User, ChevronDown, LogOut } from "lucide-react";
import { NotificationsPopover } from "./components/NotificationsPopover";
import { DemoDataBanner } from "./components/DemoDataBanner";
import { TrialBanner } from "./components/TrialBanner";
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
const Settings = lazy(() => import("@/pages/Settings"));
const Login = lazy(() => import("@/pages/Login"));
const Signup = lazy(() => import("@/pages/Signup"));
const FullAssessment = lazy(() => import("@/pages/FullAssessment"));
const LiveScans = lazy(() => import("@/pages/LiveScans"));
const ScheduledScans = lazy(() => import("@/pages/ScheduledScans"));
const Simulations = lazy(() => import("@/pages/Simulations"));
const BreachChains = lazy(() => import("@/pages/BreachChains"));
const AssessmentWizard = lazy(() => import("@/pages/AssessmentWizard"));
const Dashboard = lazy(() => import("@/components/Dashboard").then(m => ({ default: m.Dashboard })));
const NotFound = lazy(() => import("@/pages/not-found"));

// Loading fallback component
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
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p className="text-muted-foreground text-sm">Loading...</p>
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
        <Route path="/" component={Dashboard} />
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
        <Route path="/admin/settings" component={Settings} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
    </AppErrorBoundary>
  );
}

function AppHeader() {
  const { theme, toggleTheme } = useTheme();
  const { user: uiUser, logout } = useUIAuth();

  const handleLogout = async () => {
    await logout();
    window.location.reload();
  };

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-40">
      <div className="h-full px-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <SidebarTrigger data-testid="button-sidebar-toggle" />
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            data-testid="button-theme-toggle"
          >
            {theme === "dark" ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
          </Button>
          
          <NotificationsPopover />
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="gap-2" data-testid="button-user-menu">
                <div className="h-7 w-7 rounded-full bg-gradient-to-br from-red-600 to-red-500 flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <span className="hidden sm:inline text-sm">{uiUser?.displayName || uiUser?.email || "User"}</span>
                <ChevronDown className="h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {uiUser && (
                <>
                  <div className="px-2 py-1.5 text-xs text-muted-foreground">{uiUser.email}</div>
                  <div className="px-2 py-1 text-xs font-medium capitalize">{uiUser.role?.name || "User"}</div>
                  <DropdownMenuSeparator />
                </>
              )}
              <DropdownMenuItem data-testid="menu-profile">Profile</DropdownMenuItem>
              <DropdownMenuItem data-testid="menu-settings">Settings</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} data-testid="menu-logout">
                <LogOut className="h-4 w-4 mr-2" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}

function AppLayout() {
  const sidebarStyle = {
    "--sidebar-width": "16rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <SidebarProvider style={sidebarStyle as React.CSSProperties}>
      <div className="flex h-screen w-full">
        <AppSidebar />
        <div className="flex flex-col flex-1 overflow-hidden">
          <AppHeader />
          <div className="px-6 pt-4 space-y-2">
            <TrialBanner />
            <DemoDataBanner />
          </div>
          <main className="flex-1 overflow-auto p-6">
            <Router />
          </main>
        </div>
      </div>
    </SidebarProvider>
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
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Loading...</p>
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
