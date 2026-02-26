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
import { ShieldValknut } from "./OdinForgeLogo";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
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

interface NavItem {
  title: string;
  href: string;
  icon: typeof LayoutDashboard;
  aevHidden?: boolean;
}

const coreItems: NavItem[] = [
  { title: "Dashboard", href: "/", icon: LayoutDashboard },
  { title: "Assets", href: "/assets", icon: Server },
  { title: "Assessments", href: "/full-assessment", icon: ScanSearch },
  { title: "Breach Chains", href: "/breach-chains", icon: Link2 },
];

const opsItems: NavItem[] = [
  { title: "Live Scans", href: "/scans", icon: Radar },
  { title: "Scheduled Scans", href: "/scheduled-scans", icon: Calendar, aevHidden: true },
  { title: "Reports", href: "/reports", icon: FileText },
];

export function useAevOnlyMode() {
  const { data } = useQuery<{ aevOnly: boolean }>({
    queryKey: ["/api/mode"],
    staleTime: Infinity,
  });
  return data?.aevOnly === true;
}

const ROLE_BADGE_STYLES: Record<string, string> = {
  platform_super_admin: "bg-red-500/10 text-red-400 border-red-500/30",
  organization_owner: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  security_administrator: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  security_engineer: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  security_analyst: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  executive_viewer: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  compliance_officer: "bg-teal-500/10 text-teal-400 border-teal-500/30",
};

function NavGroup({ label, items }: { label: string; items: NavItem[] }) {
  const [location] = useLocation();

  const isActive = (href: string) => {
    if (href === "/") return location === "/";
    return location.startsWith(href);
  };

  return (
    <SidebarGroup>
      <SidebarGroupLabel className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 px-3 mb-1">
        {label}
      </SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.href}>
              <SidebarMenuButton asChild isActive={isActive(item.href)}>
                <Link href={item.href} data-testid={`nav-${item.title.toLowerCase().replace(/\s+/g, "-")}`}>
                  <item.icon className="h-4 w-4" />
                  <span>{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

export function AppSidebar() {
  const [location] = useLocation();
  const { user, hasPermission } = useAuth();
  const isAevOnly = useAevOnlyMode();

  const filteredOps = isAevOnly ? opsItems.filter((i) => !i.aevHidden) : opsItems;

  const showSettings =
    hasPermission("org:manage_settings") || hasPermission("org:manage_users");

  const roleBadge =
    ROLE_BADGE_STYLES[user?.role || ""] || "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";

  return (
    <Sidebar>
      <SidebarHeader className="border-b border-border px-4 py-5">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center h-9 w-9 rounded-lg bg-red-600/10 border border-red-500/20">
            <ShieldValknut className="h-6 w-6 text-red-500" />
            <div className="absolute inset-0 rounded-lg" style={{ boxShadow: "0 0 12px rgba(239,68,68,0.15)" }} />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight text-foreground">OdinForge</span>
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground/60 font-medium">
              AEV Platform
            </span>
          </div>
        </div>
      </SidebarHeader>

      {isAevOnly && (
        <div className="mx-3 mt-3 px-2 py-1.5 rounded border border-red-500/30 bg-red-500/10 text-center">
          <span className="text-[10px] uppercase tracking-widest font-semibold text-red-400">
            AEV-ONLY MODE
          </span>
        </div>
      )}

      <SidebarContent className="pt-2">
        <NavGroup label="Core" items={coreItems} />
        <NavGroup label="Operations" items={filteredOps} />

        {showSettings && (
          <SidebarGroup>
            <SidebarGroupLabel className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 px-3 mb-1">
              Admin
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild isActive={location.startsWith("/admin/settings")}>
                    <Link href="/admin/settings" data-testid="nav-settings">
                      <Settings className="h-4 w-4" />
                      <span>Settings</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
      </SidebarContent>

      <SidebarFooter className="border-t border-border p-4">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-full bg-gradient-to-br from-red-600 to-red-500 flex items-center justify-center shrink-0">
            <span className="text-sm font-bold text-white">
              {user?.displayName?.charAt(0) || user?.username?.charAt(0) || "U"}
            </span>
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium truncate text-foreground">
              {user?.displayName || user?.username || "User"}
            </span>
            <Badge className={`text-[10px] w-fit mt-0.5 ${roleBadge}`}>
              {user?.role
                ? roleMetadata[user.role as keyof typeof roleMetadata]?.displayName || user.role
                : "Security Analyst"}
            </Badge>
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
