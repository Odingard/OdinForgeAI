import { Shield, Moon, Sun, User, ChevronDown, Brain, Server, Swords, LogOut, Settings as SettingsIcon, UserCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme } from "./ThemeProvider";
import { Link, useLocation } from "wouter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/contexts/AuthContext";
import { NotificationsPopover } from "./NotificationsPopover";

export function Header() {
  const { theme, toggleTheme } = useTheme();
  const [location, navigate] = useLocation();
  const { user, logout } = useAuth();

  const isActive = (path: string) => location === path;

  return (
    <header className="h-16 border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-50">
      <div className="h-full px-6 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-blue-600 blur-lg opacity-50" />
            <div className="relative p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg">
              <Shield className="h-6 w-6 text-white" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-lg font-bold tracking-tight bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              OdinForge
            </span>
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground -mt-1">
              AEV Platform
            </span>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-1">
          <Link href="/">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-dashboard"
            >
              Dashboard
            </Button>
          </Link>
          <Link href="/assets">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/assets") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-assets"
            >
              Assets
            </Button>
          </Link>
          <Link href="/infrastructure">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/infrastructure") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-integrations"
            >
              Integrations
            </Button>
          </Link>
          <Link href="/risk">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/risk") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-risk"
            >
              Risk Dashboard
            </Button>
          </Link>
          <Link href="/reports">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/reports") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-reports"
            >
              Reports
            </Button>
          </Link>
          <Link href="/batch">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/batch") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-batch"
            >
              Batch Jobs
            </Button>
          </Link>
          <Link href="/governance">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/governance") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-governance"
            >
              Governance
            </Button>
          </Link>
          <Link href="/agents">
            <Button 
              variant="ghost" 
              size="sm" 
              className={`${isActive("/agents") ? "text-foreground" : "text-muted-foreground"} gap-1`} 
              data-testid="nav-agents"
            >
              <Server className="h-3.5 w-3.5" />
              Agents
            </Button>
          </Link>
          <Link href="/simulations">
            <Button 
              variant="ghost" 
              size="sm" 
              className={`${isActive("/simulations") ? "text-foreground" : "text-muted-foreground"} gap-1`} 
              data-testid="nav-simulations"
            >
              <Swords className="h-3.5 w-3.5" />
              Simulations
            </Button>
          </Link>
          <Link href="/advanced">
            <Button 
              variant="ghost" 
              size="sm" 
              className={`${isActive("/advanced") ? "text-foreground" : "text-muted-foreground"} gap-1`} 
              data-testid="nav-advanced"
            >
              <Brain className="h-3.5 w-3.5" />
              Advanced
            </Button>
          </Link>
        </nav>

        <div className="flex items-center gap-2">
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
                  <span className="text-xs font-bold text-white">
                    {user?.displayName?.charAt(0) || user?.username?.charAt(0) || "U"}
                  </span>
                </div>
                <span className="hidden sm:inline text-sm">{user?.displayName || user?.username || "User"}</span>
                <ChevronDown className="h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <div className="px-2 py-1.5">
                <p className="text-sm font-medium">{user?.displayName || user?.username}</p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => navigate("/settings")} data-testid="menu-profile">
                <UserCircle className="h-4 w-4 mr-2" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate("/settings")} data-testid="menu-settings">
                <SettingsIcon className="h-4 w-4 mr-2" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => logout()} className="text-destructive" data-testid="menu-logout">
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
