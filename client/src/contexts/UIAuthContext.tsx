import { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import {
  UIUser,
  getStoredTokens,
  clearAuthData,
  isTokenExpired,
  login as apiLogin,
  logout as apiLogout,
  refreshTokens,
  fetchSession,
} from "@/lib/uiAuth";

interface UIAuthContextType {
  user: UIUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => string | null;
  refreshSession: () => Promise<boolean>;
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

  return (
    <UIAuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        getAccessToken,
        refreshSession,
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
