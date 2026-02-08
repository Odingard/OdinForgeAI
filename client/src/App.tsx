import { useState, useCallback, lazy, Suspense } from "react";
import { Switch, Route, useLocation, Redirect } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";
import { AuthProvider } from "./contexts/AuthContext";
import { UIAuthProvider, useUIAuth } from "./contexts/UIAuthContext";
import { ViewModeProvider } from "./contexts/ViewModeContext";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "./components/AppSidebar";
import { Dashboard } from "./components/Dashboard";
import { Button } from "@/components/ui/button";
import { Moon, Sun, User, ChevronDown, LogOut } from "lucide-react";
import { NotificationsPopover } from "./components/NotificationsPopover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "./contexts/AuthContext";
import { roleMetadata } from "@shared/schema";

// Lazy load pages for code splitting (reduces initial bundle size by ~50%)
const RiskDashboard = lazy(() => import("@/pages/RiskDashboard"));
const Assets = lazy(() => import("@/pages/Assets"));
const Infrastructure = lazy(() => import("@/pages/Infrastructure"));
const Reports = lazy(() => import("@/pages/Reports"));
const Governance = lazy(() => import("@/pages/Governance"));
const Advanced = lazy(() => import("@/pages/Advanced"));
const Agents = lazy(() => import("@/pages/Agents"));
const Simulations = lazy(() => import("@/pages/Simulations"));
const UserManagement = lazy(() => import("@/pages/UserManagement"));
const Settings = lazy(() => import("@/pages/Settings"));
const Login = lazy(() => import("@/pages/Login"));
const Signup = lazy(() => import("@/pages/Signup"));
const FullAssessment = lazy(() => import("@/pages/FullAssessment"));
const SecurityTesting = lazy(() => import("@/pages/SecurityTesting"));
const Approvals = lazy(() => import("@/pages/Approvals"));
const ApprovalHistory = lazy(() => import("@/pages/ApprovalHistory"));
const Remediation = lazy(() => import("@/pages/Remediation"));
const LateralMovement = lazy(() => import("@/pages/LateralMovement"));
const ExternalRecon = lazy(() => import("@/components/ExternalRecon").then(m => ({ default: m.ExternalRecon })));
const Jobs = lazy(() => import("@/pages/Jobs"));
const SystemHealth = lazy(() => import("@/pages/SystemHealth"));
const AuditLogs = lazy(() => import("@/pages/AuditLogs"));
const NotFound = lazy(() => import("@/pages/not-found"));

// Loading fallback component
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
  return (
    <Suspense fallback={<PageLoader />}>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/login"><Redirect to="/" /></Route>
        <Route path="/signup"><Redirect to="/" /></Route>
        <Route path="/risk" component={RiskDashboard} />
        <Route path="/assets" component={Assets} />
        <Route path="/infrastructure" component={Infrastructure} />
        <Route path="/reports" component={Reports} />
        <Route path="/governance" component={Governance} />
        <Route path="/agents" component={Agents} />
        <Route path="/simulations" component={Simulations} />
        <Route path="/full-assessment" component={FullAssessment} />
        <Route path="/security-testing" component={SecurityTesting} />
        <Route path="/recon" component={ExternalRecon} />
        <Route path="/advanced" component={Advanced} />
        <Route path="/approvals" component={Approvals} />
        <Route path="/approvals/history" component={ApprovalHistory} />
        <Route path="/remediation" component={Remediation} />
        <Route path="/lateral-movement" component={LateralMovement} />
        <Route path="/jobs" component={Jobs} />
        <Route path="/health" component={SystemHealth} />
        <Route path="/audit" component={AuditLogs} />
        <Route path="/admin/users" component={UserManagement} />
        <Route path="/admin/settings" component={Settings} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
}

function AppHeader() {
  const { theme, toggleTheme } = useTheme();
  const { user, setUserRole, availableRoles } = useAuth();
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
                <div className="h-7 w-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <span className="hidden sm:inline text-sm">{uiUser?.displayName || uiUser?.email || user?.displayName || "User"}</span>
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
              <div className="px-2 py-1.5 text-xs text-muted-foreground">Switch Role (Demo)</div>
              {availableRoles.map(role => (
                <DropdownMenuItem 
                  key={role}
                  onClick={() => setUserRole(role)}
                  className={user?.role === role ? "bg-accent" : ""}
                  data-testid={`menu-role-${role}`}
                >
                  {roleMetadata[role]?.displayName || role}
                  {user?.role === role && <span className="ml-auto text-xs text-muted-foreground">Current</span>}
                </DropdownMenuItem>
              ))}
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
    <AuthProvider>
      <ViewModeProvider>
        <TooltipProvider>
          <AppLayout />
          <Toaster />
        </TooltipProvider>
      </ViewModeProvider>
    </AuthProvider>
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
