// Bridge module: redirects legacy useAuth() calls to the production UIAuthContext
// This allows gradual migration of components from useAuth() to useUIAuth()
import { useUIAuth } from "./UIAuthContext";
import type { Permission, ExecutionMode } from "@shared/schema";

// Re-export useUIAuth as useAuth for backward compatibility
export function useAuth() {
  const uiAuth = useUIAuth();

  return {
    user: uiAuth.user ? {
      id: uiAuth.user.id,
      username: uiAuth.user.email,
      displayName: uiAuth.user.displayName,
      email: uiAuth.user.email,
      role: uiAuth.user.roleId,
      permissions: uiAuth.permissions,
      organizationId: uiAuth.user.organizationId,
    } : null,
    isLoading: uiAuth.isLoading,
    hasPermission: uiAuth.hasPermission,
    hasAnyPermission: uiAuth.hasAnyPermission,
    hasRole: (role: string) => uiAuth.hasRole(role),
    hasAnyRole: (roles: string[]) => uiAuth.hasAnyRole(roles),
    canExecuteMode: uiAuth.canExecuteMode,
    needsSanitizedView: uiAuth.needsSanitizedView,
    // No-ops for removed demo features
    setUserRole: (_role: string) => {
      console.warn("setUserRole is deprecated. Roles are now managed server-side.");
    },
    availableRoles: [] as string[],
    logout: uiAuth.logout,
  };
}

// AuthProvider is now a pass-through — UIAuthProvider handles everything
export function AuthProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
