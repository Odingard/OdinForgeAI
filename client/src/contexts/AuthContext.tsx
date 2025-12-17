import { createContext, useContext, useState, useEffect } from "react";
import type { UserRole, Permission } from "@shared/schema";
import { rolePermissions } from "@shared/schema";

interface AuthUser {
  id: string;
  username: string;
  displayName?: string;
  role: UserRole;
  permissions: Permission[];
}

interface AuthContextType {
  user: AuthUser | null;
  isLoading: boolean;
  hasPermission: (permission: Permission) => boolean;
  hasRole: (role: UserRole) => boolean;
  setUserRole: (role: UserRole) => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

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
    const role: UserRole = storedRole || "admin";
    
    setUser({
      id: "demo-user",
      username: "admin",
      displayName: "Admin User",
      role,
      permissions: rolePermissions[role] || [],
    });
    setIsLoading(false);
  }, []);

  const hasPermission = (permission: Permission): boolean => {
    if (!user) return false;
    return user.permissions.includes(permission);
  };

  const hasRole = (role: UserRole): boolean => {
    if (!user) return false;
    return user.role === role;
  };

  const setUserRole = (role: UserRole) => {
    localStorage.setItem("odinforge_user_role", role);
    setUser(prev => prev ? {
      ...prev,
      role,
      permissions: rolePermissions[role] || [],
    } : null);
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, hasPermission, hasRole, setUserRole }}>
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
