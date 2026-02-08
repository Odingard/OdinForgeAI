import { createContext, useContext, useState, useEffect, useCallback, useRef, useMemo } from "react";
import {
  UIUser,
  getStoredTokens,
  clearAuthData,
  isTokenExpired,
  login as apiLogin,
  logout as apiLogout,
  register as apiRegister,
  refreshTokens,
  fetchSession,
} from "@/lib/uiAuth";
import type { Permission, UserRole, ExecutionMode } from "@shared/schema";
import { getPermissionsForDbRole, canExecuteMode as schemaCanExecuteMode, needsSanitizedView as schemaNeedsSanitizedView, dbRoleToSchemaRole } from "@shared/schema";

interface UIAuthContextType {
  user: UIUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName?: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
  refreshSession: () => Promise<boolean>;
  // Permission helpers
  hasPermission: (permission: Permission) => boolean;
  hasAnyPermission: (permissions: Permission[]) => boolean;
  hasRole: (roleId: string) => boolean;
  hasAnyRole: (roleIds: string[]) => boolean;
  canExecuteMode: (mode: ExecutionMode) => boolean;
  needsSanitizedView: () => boolean;
  permissions: Permission[];
}

const UIAuthContext = createContext<UIAuthContextType | null>(null);

const TOKEN_REFRESH_BUFFER = 2 * 60 * 1000; // 2 minutes before expiry

export function UIAuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UIUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const refreshTimerRef = useRef<NodeJS.Timeout | null>(null);

  const scheduleTokenRefresh = useCallback((expiresAt: Date) => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }

    const msUntilExpiry = expiresAt.getTime() - Date.now();
    const refreshIn = Math.max(msUntilExpiry - TOKEN_REFRESH_BUFFER, 10000);

    refreshTimerRef.current = setTimeout(async () => {
      const result = await refreshTokens();
      if (result) {
        setUser(result.user);
        scheduleTokenRefresh(new Date(result.accessTokenExpiresAt));
      } else {
        setUser(null);
      }
    }, refreshIn);
  }, []);

  const initializeAuth = useCallback(async () => {
    setIsLoading(true);
    try {
      const { accessToken, accessTokenExpiry, refreshToken, refreshTokenExpiry } = getStoredTokens();

      if (!accessToken || !refreshToken) {
        setUser(null);
        return;
      }

      if (isTokenExpired(accessTokenExpiry)) {
        if (isTokenExpired(refreshTokenExpiry)) {
          clearAuthData();
          setUser(null);
          return;
        }

        const result = await refreshTokens();
        if (result) {
          setUser(result.user);
          scheduleTokenRefresh(new Date(result.accessTokenExpiresAt));
        } else {
          setUser(null);
        }
        return;
      }

      const sessionUser = await fetchSession(accessToken);
      if (sessionUser) {
        setUser(sessionUser);
        if (accessTokenExpiry) {
          scheduleTokenRefresh(accessTokenExpiry);
        }
      } else {
        console.warn("Session validation failed - clearing stored auth data");
        clearAuthData();
        setUser(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [scheduleTokenRefresh]);

  useEffect(() => {
    initializeAuth();

    return () => {
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
      }
    };
  }, [initializeAuth]);

  const login = async (email: string, password: string) => {
    const result = await apiLogin(email, password);
    setUser(result.user);
    scheduleTokenRefresh(new Date(result.accessTokenExpiresAt));
  };

  const register = async (email: string, password: string, displayName?: string) => {
    const result = await apiRegister(email, password, displayName);
    setUser(result.user);
    scheduleTokenRefresh(new Date(result.accessTokenExpiresAt));
  };

  const logout = async () => {
    const { accessToken } = getStoredTokens();
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
    }
    await apiLogout(accessToken);
    setUser(null);
  };

  const getAccessToken = (): string | null => {
    const { accessToken } = getStoredTokens();
    return accessToken;
  };

  const refreshSession = async (): Promise<boolean> => {
    const result = await refreshTokens();
    if (result) {
      setUser(result.user);
      scheduleTokenRefresh(new Date(result.accessTokenExpiresAt));
      return true;
    }
    setUser(null);
    return false;
  };

  // Derive permissions from the user's role
  const permissions = useMemo<Permission[]>(() => {
    if (!user) return [];
    // Prefer server-provided permissions, fall back to schema lookup
    if (user.permissions && user.permissions.length > 0) {
      return user.permissions as Permission[];
    }
    return getPermissionsForDbRole(user.roleId);
  }, [user]);

  const hasPermission = useCallback((permission: Permission): boolean => {
    return permissions.includes(permission);
  }, [permissions]);

  const hasAnyPermission = useCallback((perms: Permission[]): boolean => {
    return perms.some(p => permissions.includes(p));
  }, [permissions]);

  const hasRole = useCallback((roleId: string): boolean => {
    return user?.roleId === roleId;
  }, [user]);

  const hasAnyRole = useCallback((roleIds: string[]): boolean => {
    return user ? roleIds.includes(user.roleId) : false;
  }, [user]);

  const canExecuteMode = useCallback((mode: ExecutionMode): boolean => {
    if (!user) return false;
    const schemaRole = dbRoleToSchemaRole[user.roleId];
    return schemaRole ? schemaCanExecuteMode(schemaRole, mode) : false;
  }, [user]);

  const needsSanitizedView = useCallback((): boolean => {
    if (!user) return true;
    const schemaRole = dbRoleToSchemaRole[user.roleId];
    return schemaRole ? schemaNeedsSanitizedView(schemaRole) : true;
  }, [user]);

  return (
    <UIAuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        getAccessToken,
        refreshSession,
        hasPermission,
        hasAnyPermission,
        hasRole,
        hasAnyRole,
        canExecuteMode,
        needsSanitizedView,
        permissions,
      }}
    >
      {children}
    </UIAuthContext.Provider>
  );
}

export function useUIAuth() {
  const context = useContext(UIAuthContext);
  if (!context) {
    throw new Error("useUIAuth must be used within a UIAuthProvider");
  }
  return context;
}
