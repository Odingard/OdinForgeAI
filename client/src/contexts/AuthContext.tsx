import { createContext, useContext, useState, useEffect } from "react";
import type { UserRole, Permission, ExecutionMode, AllRole } from "@shared/schema";
import { 
  rolePermissions, 
  roleMetadata, 
  userRoles,
  canExecuteMode as schemaCanExecuteMode,
  needsSanitizedView as schemaNeedsSanitizedView,
  isApiOnlyRole
} from "@shared/schema";

interface AuthUser {
  id: string;
  username: string;
  displayName?: string;
  email?: string;
  role: UserRole;
  permissions: Permission[];
  organizationId?: string;
}

interface AuthContextType {
  user: AuthUser | null;
  isLoading: boolean;
  hasPermission: (permission: Permission) => boolean;
  hasAnyPermission: (permissions: Permission[]) => boolean;
  hasRole: (role: UserRole) => boolean;
  hasAnyRole: (roles: UserRole[]) => boolean;
  canExecuteMode: (mode: ExecutionMode) => boolean;
  needsSanitizedView: () => boolean;
  setUserRole: (role: UserRole) => void;
  availableRoles: UserRole[];
}

const AuthContext = createContext<AuthContextType | null>(null);

// Demo user names for each role
const roleDisplayNames: Record<UserRole, string> = {
  platform_super_admin: "Platform Admin",
  organization_owner: "Sarah Mitchell",
  security_administrator: "James Chen",
  security_engineer: "Alex Rivera",
  security_analyst: "Jordan Kim",
  executive_viewer: "Dr. Emily Foster",
  compliance_officer: "Michael Okonkwo",
  automation_account: "CI/CD Pipeline",
};

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Filter to only customer-assignable roles for demo (exclude platform_super_admin)
  const availableRoles = userRoles.filter(
    role => roleMetadata[role]?.customerAssignable && roleMetadata[role]?.uiAccess
  ) as UserRole[];

  useEffect(() => {
    // DEMO MODE: Client-side role management
    // In production, replace with:
    // 1. Fetch authenticated user from /api/auth/me
    // 2. Server-side role/permission enforcement on all protected routes
    // 3. Remove localStorage role switching capability
    // 
    // Current implementation allows users to switch roles for demonstration
    // purposes only. This does NOT provide real security - all API routes
    // should independently verify permissions server-side.
    const storedRole = localStorage.getItem("odinforge_user_role") as UserRole | null;
    // Default to security_administrator for demo (good balance of capabilities)
    const role: UserRole = storedRole && userRoles.includes(storedRole) 
      ? storedRole 
      : "security_administrator";
    
    setUser({
      id: "demo-user",
      username: role,
      displayName: roleDisplayNames[role] || "Demo User",
      email: `${role.replace(/_/g, ".")}@demo.odinforge.ai`,
      role,
      permissions: rolePermissions[role] || [],
      organizationId: "demo-org",
    });
    setIsLoading(false);
  }, []);

  const hasPermission = (permission: Permission): boolean => {
    if (!user) return false;
    return user.permissions.includes(permission);
  };

  const hasAnyPermission = (perms: Permission[]): boolean => {
    if (!user) return false;
    return perms.some(p => user.permissions.includes(p));
  };

  const hasRole = (role: UserRole): boolean => {
    if (!user) return false;
    return user.role === role;
  };

  const hasAnyRole = (roles: UserRole[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  const canExecuteMode = (mode: ExecutionMode): boolean => {
    if (!user) return false;
    return schemaCanExecuteMode(user.role, mode);
  };

  const needsSanitizedView = (): boolean => {
    if (!user) return true;
    return schemaNeedsSanitizedView(user.role);
  };

  const setUserRole = (role: UserRole) => {
    localStorage.setItem("odinforge_user_role", role);
    setUser(prev => prev ? {
      ...prev,
      role,
      username: role,
      displayName: roleDisplayNames[role] || "Demo User",
      email: `${role.replace(/_/g, ".")}@demo.odinforge.ai`,
      permissions: rolePermissions[role] || [],
    } : null);
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      isLoading, 
      hasPermission, 
      hasAnyPermission,
      hasRole, 
      hasAnyRole,
      canExecuteMode,
      needsSanitizedView,
      setUserRole,
      availableRoles,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
