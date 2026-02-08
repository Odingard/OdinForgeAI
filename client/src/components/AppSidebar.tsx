import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  Server,
  Building2,
  BarChart3,
  FileText,
  Shield,
  Bot,
  Brain,
  ChevronDown,
  Settings,
  Users,
  ScanSearch,
  Globe,
  FlaskConical,
  ShieldAlert,
  History,
  ListChecks,
  Activity,
  FileCheck,
  Package,
  UserCheck,
  Radar,
  Calendar,
} from "lucide-react";
import { OdinForgeLogo } from "./OdinForgeLogo";
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
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useAuth } from "@/contexts/AuthContext";
import { Badge } from "@/components/ui/badge";
import { roleMetadata } from "@shared/schema";

const mainNavItems = [
  { title: "Dashboard", href: "/", icon: LayoutDashboard },
  { title: "Assets", href: "/assets", icon: Server },
  { title: "Data Sources", href: "/infrastructure", icon: Building2 },
  { title: "Risk Dashboard", href: "/risk", icon: BarChart3 },
];

const analysisItems = [
  { title: "Full Assessment", href: "/full-assessment", icon: ScanSearch },
  { title: "Live Recon", href: "/recon", icon: Globe },
  { title: "Reports", href: "/reports", icon: FileText },
];

const systemItems = [
  { title: "Agents", href: "/agents", icon: Bot },
  { title: "Approvals", href: "/approvals", icon: ShieldAlert },
  { title: "Approval History", href: "/approvals/history", icon: History },
  { title: "Governance", href: "/governance", icon: Shield },
  { title: "Advanced", href: "/advanced", icon: Brain },
];

const operationsItems = [
  { title: "Jobs", href: "/jobs", icon: ListChecks },
  { title: "System Health", href: "/health", icon: Activity },
  { title: "Audit Logs", href: "/audit", icon: FileText },
];

const complianceItems = [
  { title: "Evidence", href: "/evidence", icon: FileCheck },
  { title: "Forensics", href: "/forensics", icon: Package },
];

const advancedItems = [
  { title: "Sessions", href: "/sessions", icon: UserCheck },
  { title: "Live Scans", href: "/scans", icon: Radar },
  { title: "Scheduled Scans", href: "/scheduled-scans", icon: Calendar },
  { title: "Sandbox", href: "/sandbox", icon: FlaskConical },
];

export function AppSidebar() {
  const [location] = useLocation();
  const { user, hasPermission } = useAuth();

  const isActive = (href: string) => location === href;

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

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {mainNavItems.map((item) => (
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

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup>
            <CollapsibleTrigger asChild>
              <SidebarGroupLabel className="cursor-pointer hover-elevate rounded-md">
                Analysis
                <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
              </SidebarGroupLabel>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {analysisItems.map((item) => (
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
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup>
            <CollapsibleTrigger asChild>
              <SidebarGroupLabel className="cursor-pointer hover-elevate rounded-md">
                System
                <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
              </SidebarGroupLabel>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {systemItems.map((item) => (
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
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup>
            <CollapsibleTrigger asChild>
              <SidebarGroupLabel className="cursor-pointer hover-elevate rounded-md">
                Operations
                <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
              </SidebarGroupLabel>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {operationsItems.map((item) => (
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
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup>
            <CollapsibleTrigger asChild>
              <SidebarGroupLabel className="cursor-pointer hover-elevate rounded-md">
                Compliance & Forensics
                <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
              </SidebarGroupLabel>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {complianceItems.map((item) => (
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
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        <Collapsible defaultOpen className="group/collapsible">
          <SidebarGroup>
            <CollapsibleTrigger asChild>
              <SidebarGroupLabel className="cursor-pointer hover-elevate rounded-md">
                Advanced
                <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
              </SidebarGroupLabel>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <SidebarGroupContent>
                <SidebarMenu>
                  {advancedItems.map((item) => (
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
            </CollapsibleContent>
          </SidebarGroup>
        </Collapsible>

        {hasPermission("org:manage_users") && (
          <SidebarGroup>
            <SidebarGroupLabel>Administration</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton asChild>
                    <Link href="/admin/users" data-testid="nav-admin-users">
                      <Users className="h-4 w-4" />
                      <span>User Management</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                {hasPermission("org:manage_settings") && (
                  <SidebarMenuItem>
                    <SidebarMenuButton asChild>
                      <Link href="/admin/settings" data-testid="nav-admin-settings">
                        <Settings className="h-4 w-4" />
                        <span>Settings</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                )}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
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
