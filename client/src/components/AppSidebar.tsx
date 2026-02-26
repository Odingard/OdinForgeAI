import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  Server,
  ScanSearch,
  Link2,
  Radar,
  Calendar,
  FileText,
  Settings,
} from "lucide-react";
import { OdinForgeLogo } from "./OdinForgeLogo";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
} from "@/components/ui/sidebar";
import { useAuth } from "@/contexts/AuthContext";
import { Badge } from "@/components/ui/badge";
import { roleMetadata } from "@shared/schema";
import { useQuery } from "@tanstack/react-query";

const navItems = [
  { title: "Dashboard", href: "/", icon: LayoutDashboard },
  { title: "Assets", href: "/assets", icon: Server },
  { title: "Assessments", href: "/full-assessment", icon: ScanSearch },
  { title: "Breach Chains", href: "/breach-chains", icon: Link2 },
  { title: "Live Scans", href: "/scans", icon: Radar },
  { title: "Scheduled Scans", href: "/scheduled-scans", icon: Calendar },
  { title: "Reports", href: "/reports", icon: FileText },
];

const aevOnlyNavItems = [
  { title: "Dashboard", href: "/", icon: LayoutDashboard },
  { title: "Assets", href: "/assets", icon: Server },
  { title: "Assessments", href: "/full-assessment", icon: ScanSearch },
  { title: "Breach Chains", href: "/breach-chains", icon: Link2 },
  { title: "Live Scans", href: "/scans", icon: Radar },
  { title: "Reports", href: "/reports", icon: FileText },
];

export function useAevOnlyMode() {
  const { data } = useQuery<{ aevOnly: boolean }>({
    queryKey: ["/api/mode"],
    staleTime: Infinity,
  });
  return data?.aevOnly === true;
}

export function AppSidebar() {
  const [location] = useLocation();
  const { user, hasPermission } = useAuth();
  const isAevOnly = useAevOnlyMode();

  const isActive = (href: string) => {
    if (href === "/admin/settings") return location.startsWith("/admin/settings");
    return location === href;
  };

  const getRoleBadgeStyle = (role: string) => {
    switch (role) {
      case "platform_super_admin":
        return "bg-red-500/10 text-red-400 border-red-500/30";
      case "organization_owner":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "security_administrator":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "security_engineer":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "security_analyst":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "executive_viewer":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "compliance_officer":
        return "bg-teal-500/10 text-teal-400 border-teal-500/30";
      default:
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
    }
  };

  const displayNavItems = isAevOnly ? aevOnlyNavItems : navItems;

  return (
    <Sidebar>
      <SidebarHeader className="border-b border-border p-4">
        <OdinForgeLogo size="md" animated showIcon />
        <div className="mt-1 ml-11">
          <span className="text-[9px] uppercase tracking-widest text-muted-foreground font-medium">
            AEV Platform
          </span>
        </div>
      </SidebarHeader>

      {isAevOnly && (
        <div className="mx-3 mt-3 px-2 py-1.5 rounded border border-red-500/30 bg-red-500/10 text-center">
          <span className="text-[10px] uppercase tracking-widest font-semibold text-red-400">
            AEV-ONLY MODE
          </span>
        </div>
      )}

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {displayNavItems.map((item) => (
                <SidebarMenuItem key={item.href}>
                  <SidebarMenuButton asChild isActive={isActive(item.href)}>
                    <Link href={item.href} data-testid={`nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}>
                      <item.icon className="h-4 w-4" />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
              {(hasPermission("org:manage_settings") || hasPermission("org:manage_users")) && (
                <SidebarMenuItem>
                  <SidebarMenuButton asChild isActive={isActive("/admin/settings")}>
                    <Link href="/admin/settings" data-testid="nav-settings">
                      <Settings className="h-4 w-4" />
                      <span>Settings</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              )}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-border p-4">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-full bg-gradient-to-br from-red-600 to-red-500 flex items-center justify-center">
            <span className="text-xs font-bold text-white">
              {user?.displayName?.charAt(0) || user?.username?.charAt(0) || "U"}
            </span>
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium truncate">
              {user?.displayName || user?.username || "User"}
            </span>
            <Badge className={`text-[10px] w-fit ${getRoleBadgeStyle(user?.role || "security_analyst")}`}>
              {user?.role ? roleMetadata[user.role as keyof typeof roleMetadata]?.displayName || user.role : "Security Analyst"}
            </Badge>
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
