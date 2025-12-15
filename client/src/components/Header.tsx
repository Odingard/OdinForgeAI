import { Shield, Moon, Sun, Bell, User, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme } from "./ThemeProvider";
import { Link, useLocation } from "wouter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function Header() {
  const { theme, toggleTheme } = useTheme();
  const [location] = useLocation();

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
          <Link href="/">
            <Button 
              variant="ghost" 
              size="sm" 
              className={isActive("/evaluations") ? "text-foreground" : "text-muted-foreground"} 
              data-testid="nav-evaluations"
            >
              Evaluations
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
                <span className="hidden sm:inline text-sm">Admin</span>
                <ChevronDown className="h-3 w-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem data-testid="menu-profile">Profile</DropdownMenuItem>
              <DropdownMenuItem data-testid="menu-settings">Settings</DropdownMenuItem>
              <DropdownMenuItem data-testid="menu-logout">Log out</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
