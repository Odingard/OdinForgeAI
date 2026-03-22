/**
 * Engagement Configuration — controls scope, auth, execution, and safety
 * for each breach chain assessment.
 */

export interface EngagementConfig {
  target: string;

  scope: {
    allowedDomains: string[];
    excludedPaths?: string[];
  };

  auth?: {
    type: 'none' | 'basic' | 'bearer' | 'cookie' | 'form';
    credentials?: {
      username?: string;
      password?: string;
      token?: string;
      cookie?: string;
    };
    loginEndpoint?: string;
  };

  execution?: {
    maxRuntimeMs?: number;   // default 120000 (2 min)
    maxRequests?: number;    // default 500
    maxDepth?: number;       // default 6
    safeMode?: boolean;      // default false — restricts destructive actions
  };
}

export interface SessionState {
  authenticated: boolean;
  role: 'anonymous' | 'user' | 'admin';
  cookies: string[];
  tokens: string[];
  loginTimestamp?: string;
}

/** Engagement context included in sealed package */
export interface EngagementContext {
  authenticated: boolean;
  highestRoleReached: SessionState['role'];
  scopeEnforced: boolean;
  safeModeEnabled: boolean;
  totalRequests: number;
  runtimeMs: number;
}

// ── Scope Enforcement ────────────────────────────────────────────────────────

export function isInScope(url: string, config: EngagementConfig): boolean {
  try {
    const parsed = new URL(url, `https://${config.scope.allowedDomains[0]}`);
    const hostname = parsed.hostname;

    // Check allowed domains
    const domainAllowed = config.scope.allowedDomains.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );
    if (!domainAllowed) return false;

    // Check excluded paths
    if (config.scope.excludedPaths) {
      const pathname = parsed.pathname;
      for (const excluded of config.scope.excludedPaths) {
        if (pathname.startsWith(excluded) || pathname.includes(excluded)) return false;
      }
    }

    return true;
  } catch {
    // Relative URLs — check path exclusions only
    if (config.scope.excludedPaths) {
      for (const excluded of config.scope.excludedPaths) {
        if (url.startsWith(excluded) || url.includes(excluded)) return false;
      }
    }
    return true; // relative paths are in-scope by default
  }
}

// ── Safe Mode Guards ─────────────────────────────────────────────────────────

const DESTRUCTIVE_METHODS = ['DELETE', 'PATCH'];
const DESTRUCTIVE_PATHS = ['/delete', '/remove', '/destroy', '/shutdown', '/payment', '/checkout', '/unsubscribe'];

export function isSafeRequest(method: string, url: string, safeMode: boolean): { allowed: boolean; reason?: string } {
  if (!safeMode) return { allowed: true };

  const upper = method.toUpperCase();
  if (DESTRUCTIVE_METHODS.includes(upper)) {
    return { allowed: false, reason: `Safe mode: ${upper} method blocked` };
  }

  // PUT is allowed for testing but flagged
  const lower = url.toLowerCase();
  for (const path of DESTRUCTIVE_PATHS) {
    if (lower.includes(path)) {
      return { allowed: false, reason: `Safe mode: destructive path ${path} blocked` };
    }
  }

  return { allowed: true };
}

// ── Auth Application ─────────────────────────────────────────────────────────

export function buildAuthHeaders(config: EngagementConfig): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!config.auth || config.auth.type === 'none') return headers;

  switch (config.auth.type) {
    case 'basic':
      if (config.auth.credentials?.username && config.auth.credentials?.password) {
        const encoded = Buffer.from(`${config.auth.credentials.username}:${config.auth.credentials.password}`).toString('base64');
        headers['Authorization'] = `Basic ${encoded}`;
      }
      break;
    case 'bearer':
      if (config.auth.credentials?.token) {
        headers['Authorization'] = `Bearer ${config.auth.credentials.token}`;
      }
      break;
    case 'cookie':
      if (config.auth.credentials?.cookie) {
        headers['Cookie'] = config.auth.credentials.cookie;
      }
      break;
  }

  return headers;
}

// ── Config Validation ────────────────────────────────────────────────────────

export function validateEngagementConfig(config: any): { valid: boolean; error?: string } {
  if (!config?.target) return { valid: false, error: 'target is required' };
  if (!config?.scope?.allowedDomains?.length) return { valid: false, error: 'scope.allowedDomains is required' };

  // Ensure target domain is in allowed list
  try {
    const targetHost = new URL(config.target).hostname;
    const allowed = config.scope.allowedDomains.some((d: string) =>
      targetHost === d || targetHost.endsWith(`.${d}`)
    );
    if (!allowed) return { valid: false, error: `target domain ${targetHost} not in allowedDomains` };
  } catch {
    return { valid: false, error: 'target is not a valid URL' };
  }

  return { valid: true };
}
