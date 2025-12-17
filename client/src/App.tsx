import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";
import { AuthProvider } from "./contexts/AuthContext";
import { ViewModeProvider, useViewMode } from "./contexts/ViewModeContext";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "./components/AppSidebar";
import { ViewModeToggle } from "./components/ViewModeToggle";
import { Dashboard } from "./components/Dashboard";
import RiskDashboard from "@/pages/RiskDashboard";
import Assets from "@/pages/Assets";
import Infrastructure from "@/pages/Infrastructure";
import Reports from "@/pages/Reports";
import BatchJobs from "@/pages/BatchJobs";
import Governance from "@/pages/Governance";
import Advanced from "@/pages/Advanced";
import Agents from "@/pages/Agents";
import Simulations from "@/pages/Simulations";
import UserManagement from "@/pages/UserManagement";
import Settings from "@/pages/Settings";
import NotFound from "@/pages/not-found";
import { Button } from "@/components/ui/button";
import { Moon, Sun, Bell, User, ChevronDown } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "./contexts/AuthContext";
import { roleMetadata } from "@shared/schema";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/risk" component={RiskDashboard} />
      <Route path="/assets" component={Assets} />
      <Route path="/infrastructure" component={Infrastructure} />
      <Route path="/reports" component={Reports} />
      <Route path="/batch" component={BatchJobs} />
      <Route path="/governance" component={Governance} />
      <Route path="/agents" component={Agents} />
      <Route path="/simulations" component={Simulations} />
      <Route path="/advanced" component={Advanced} />
      <Route path="/admin/users" component={UserManagement} />
      <Route path="/admin/settings" component={Settings} />
      <Route component={NotFound} />
    </Switch>
  );
}

function AppHeader() {
  const { theme, toggleTheme } = useTheme();
  const { viewMode, setViewMode } = useViewMode();
  const { user, setUserRole, availableRoles } = useAuth();

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-40">
      <div className="h-full px-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <SidebarTrigger data-testid="button-sidebar-toggle" />
        </div>

        <div className="flex items-center gap-3">
          <ViewModeToggle mode={viewMode} onChange={setViewMode} />
          
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
          
          <Button variant="ghost" size="icon" className="relative" data-testid="button-notifications">
            <Bell className="h-4 w-4" />
            <span className="absolute top-1.5 right-1.5 h-2 w-2 bg-red-500 rounded-full" />
          </Button>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="gap-2" data-testid="button-user-menu">
                <div className="h-7 w-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <span className="hidden sm:inline text-sm">{user?.displayName || user?.username || "User"}</span>
                <ChevronDown className="h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
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
              <DropdownMenuItem data-testid="menu-logout">Log out</DropdownMenuItem>
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

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <ViewModeProvider>
            <TooltipProvider>
              <AppLayout />
              <Toaster />
            </TooltipProvider>
          </ViewModeProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
