import { apiRequest } from "./queryClient";

export interface UIRole {
  id: string;
  name: string;
  description: string | null;
  canManageUsers: boolean;
  canManageRoles: boolean;
  canManageSettings: boolean;
  canManageAgents: boolean;
  canCreateEvaluations: boolean;
  canRunSimulations: boolean;
  canViewEvaluations: boolean;
  canViewReports: boolean;
  canExportData: boolean;
  canAccessAuditLogs: boolean;
  canManageCompliance: boolean;
  canUseKillSwitch: boolean;
  isSystemRole: boolean;
  hierarchyLevel: number;
}

export interface UIUser {
  id: string;
  email: string;
  displayName: string | null;
  roleId: string;
  role?: UIRole;
  tenantId: string;
  organizationId: string;
  lastLoginAt?: string;
  lastActivityAt?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

export interface LoginResponse {
  user: UIUser;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

const TOKEN_KEY = "odinforge_access_token";
const REFRESH_KEY = "odinforge_refresh_token";
const TOKEN_EXPIRY_KEY = "odinforge_token_expiry";
const REFRESH_EXPIRY_KEY = "odinforge_refresh_expiry";
const USER_KEY = "odinforge_ui_user";

export function getStoredTokens(): { accessToken: string | null; refreshToken: string | null; accessTokenExpiry: Date | null; refreshTokenExpiry: Date | null } {
  const accessToken = localStorage.getItem(TOKEN_KEY);
  const refreshToken = localStorage.getItem(REFRESH_KEY);
  const accessExpiry = localStorage.getItem(TOKEN_EXPIRY_KEY);
  const refreshExpiry = localStorage.getItem(REFRESH_EXPIRY_KEY);

  return {
    accessToken,
    refreshToken,
    accessTokenExpiry: accessExpiry ? new Date(accessExpiry) : null,
    refreshTokenExpiry: refreshExpiry ? new Date(refreshExpiry) : null,
  };
}

export function getStoredUser(): UIUser | null {
  const userStr = localStorage.getItem(USER_KEY);
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

export function storeAuthData(data: LoginResponse): void {
  localStorage.setItem(TOKEN_KEY, data.accessToken);
  localStorage.setItem(REFRESH_KEY, data.refreshToken);
  localStorage.setItem(TOKEN_EXPIRY_KEY, data.accessTokenExpiresAt);
  localStorage.setItem(REFRESH_EXPIRY_KEY, data.refreshTokenExpiresAt);
  localStorage.setItem(USER_KEY, JSON.stringify(data.user));
}

export function clearAuthData(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);
  localStorage.removeItem(REFRESH_EXPIRY_KEY);
  localStorage.removeItem(USER_KEY);
}

export function isTokenExpired(expiryDate: Date | null): boolean {
  if (!expiryDate) return true;
  return new Date() >= expiryDate;
}

export function isTokenExpiringSoon(expiryDate: Date | null, bufferMs: number = 60000): boolean {
  if (!expiryDate) return true;
  return new Date().getTime() + bufferMs >= expiryDate.getTime();
}

export async function login(email: string, password: string, tenantId: string = "default"): Promise<LoginResponse> {
  const response = await fetch("/ui/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, tenantId }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Login failed");
  }

  const data = await response.json();
  storeAuthData(data);
  return data;
}

export async function register(email: string, password: string, displayName?: string): Promise<LoginResponse> {
  const response = await fetch("/ui/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, displayName }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Registration failed");
  }

  const data = await response.json();
  storeAuthData(data);
  return data;
}

export async function refreshTokens(): Promise<LoginResponse | null> {
  const { refreshToken } = getStoredTokens();
  if (!refreshToken) return null;

  try {
    const response = await fetch("/ui/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      clearAuthData();
      return null;
    }

    const data = await response.json();
    storeAuthData(data);
    return data;
  } catch {
    clearAuthData();
    return null;
  }
}

export async function logout(accessToken?: string | null): Promise<void> {
  const { refreshToken } = getStoredTokens();
  const token = accessToken || getStoredTokens().accessToken;

  if (token && refreshToken) {
    try {
      await fetch("/ui/api/auth/logout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ refreshToken }),
      });
    } catch {
      // Ignore logout errors, still clear local data
    }
  }

  clearAuthData();
}

export async function fetchSession(accessToken: string): Promise<UIUser | null> {
  try {
    const response = await fetch("/ui/api/auth/session", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) return null;

    const data = await response.json();
    return data.user;
  } catch {
    return null;
  }
}

export async function checkBootstrapNeeded(): Promise<boolean> {
  try {
    const response = await fetch("/ui/api/auth/bootstrap", { method: "HEAD" });
    return response.status === 200;
  } catch {
    return false;
  }
}

export async function bootstrap(email: string, password: string): Promise<LoginResponse> {
  const response = await fetch("/ui/api/auth/bootstrap", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Bootstrap failed");
  }

  const data = await response.json();
  return login(email, password);
}
