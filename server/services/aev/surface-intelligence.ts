/**
 * Surface Intelligence Layer
 *
 * Run-local model that turns discovered endpoints into structured
 * understanding: trust zones, sensitivity, relationships, chain roles,
 * and high-value target ranking.
 *
 * This is a planning/intelligence layer only — it does NOT confirm
 * findings, loosen validation, or invent evidence. Validation remains
 * the source of truth.
 */

import type { DiscoveredEndpoint } from '../active-exploit-engine';

// ── Types ────────────────────────────────────────────────────────────────────

export type TrustZone = 'public' | 'authenticated' | 'privileged' | 'internal_like' | 'unknown';
export type Sensitivity = 'auth' | 'user_data' | 'admin' | 'config' | 'financial' | 'generic';
export type ChainRole = 'entry' | 'pivot' | 'target';
export type RelationshipType = 'auth_flow' | 'resource_family' | 'shared_identifier' | 'graphql_rest_overlap' | 'config_to_access';

export interface SurfaceEndpoint {
  url: string;
  method: string;
  trustZone: TrustZone;
  sensitivity: Sensitivity;
  chainRole: ChainRole;
  highValueScore: number;
}

export interface SurfaceRelationship {
  from: string;       // endpoint URL
  to: string;         // endpoint URL
  type: RelationshipType;
  reason: string;
}

export interface SurfaceSummary {
  totalEndpoints: number;
  trustZones: Record<TrustZone, number>;
  sensitivities: Record<Sensitivity, number>;
  chainRoles: Record<ChainRole, number>;
  highValueTargets: SurfaceEndpoint[];  // top 5
  relationships: SurfaceRelationship[];
  primaryEntryPoints: string[];
  primaryTargets: string[];
}

export interface SurfaceModel {
  endpoints: SurfaceEndpoint[];
  relationships: SurfaceRelationship[];
  trustZones: Map<string, TrustZone>;
  highValueTargets: SurfaceEndpoint[];
  summary: SurfaceSummary;
}

// ── Trust Zone Classification ────────────────────────────────────────────────

const PUBLIC_HINTS = ['/login', '/register', '/signup', '/logout', '/index', '/home', '/about', '/contact', '/docs', '/swagger', '/redoc', '/health', '/status'];
const AUTH_HINTS = ['/me', '/account', '/profile', '/api/user', '/api/me', '/api/account', '/api/profile', '/api/whoami', '/dashboard'];
const PRIV_HINTS = ['/admin', '/management', '/manage', '/internal', '/config', '/api/admin', '/api/config', '/actuator', '/debug', '/console'];
const INTERNAL_HINTS = ['169.254.', '127.0.0.1', '10.', '172.16.', '192.168.', '/server-status', '/server-info', 'metadata.google'];

export function classifyTrustZone(url: string, endpoint?: DiscoveredEndpoint): TrustZone {
  const lower = url.toLowerCase();

  if (INTERNAL_HINTS.some(h => lower.includes(h))) return 'internal_like';
  if (PRIV_HINTS.some(h => lower.includes(h))) return 'privileged';
  if (AUTH_HINTS.some(h => lower.includes(h))) return 'authenticated';
  if (PUBLIC_HINTS.some(h => lower.includes(h))) return 'public';

  // Auth-required endpoints (got 401/403 during crawl)
  if (endpoint?.authenticated) return 'authenticated';

  // GraphQL is typically authenticated but publicly reachable
  if (lower.includes('/graphql')) return 'authenticated';

  // API endpoints default to authenticated
  if (lower.includes('/api/')) return 'authenticated';

  return 'unknown';
}

// ── Sensitivity Classification ───────────────────────────────────────────────

const AUTH_SENSITIVITY = ['auth', 'login', 'token', 'session', 'password', 'jwt', 'oauth', 'signin', 'signup'];
const USER_SENSITIVITY = ['user', 'profile', 'account', 'email', 'phone', 'address', 'member', 'person'];
const ADMIN_SENSITIVITY = ['admin', 'role', 'permission', 'management', 'manage', 'privilege'];
const CONFIG_SENSITIVITY = ['config', 'env', 'secret', 'key', 'setting', 'actuator', 'debug', '.git'];
const FINANCIAL_SENSITIVITY = ['payment', 'billing', 'invoice', 'card', 'stripe', 'checkout', 'order', 'price'];

export function classifySensitivity(url: string): Sensitivity {
  const lower = url.toLowerCase();

  if (AUTH_SENSITIVITY.some(h => lower.includes(h))) return 'auth';
  if (FINANCIAL_SENSITIVITY.some(h => lower.includes(h))) return 'financial';
  if (ADMIN_SENSITIVITY.some(h => lower.includes(h))) return 'admin';
  if (CONFIG_SENSITIVITY.some(h => lower.includes(h))) return 'config';
  if (USER_SENSITIVITY.some(h => lower.includes(h))) return 'user_data';

  return 'generic';
}

// ── Chain Role Classification ────────────────────────────────────────────────

export function classifyChainRole(url: string, trustZone: TrustZone, sensitivity: Sensitivity): ChainRole {
  // Targets: privileged, admin, high-sensitivity config
  if (trustZone === 'privileged') return 'target';
  if (sensitivity === 'admin') return 'target';
  if (trustZone === 'internal_like') return 'target';

  // Entry: public-facing, auth endpoints, GraphQL, exposed config
  if (trustZone === 'public') return 'entry';
  if (sensitivity === 'auth') return 'entry';
  if (sensitivity === 'config') return 'entry'; // privileged already returned 'target' above
  if (url.toLowerCase().includes('/graphql')) return 'entry';

  // Pivot: everything in between — API endpoints, user data, resource-driven
  return 'pivot';
}

// ── Relationship Mapping ─────────────────────────────────────────────────────

export function mapRelationships(endpoints: SurfaceEndpoint[]): SurfaceRelationship[] {
  const relationships: SurfaceRelationship[] = [];

  // Auth flow: login → me/account/profile
  const authEndpoints = endpoints.filter(e => e.sensitivity === 'auth');
  const userEndpoints = endpoints.filter(e => e.sensitivity === 'user_data');
  for (const auth of authEndpoints) {
    for (const user of userEndpoints) {
      relationships.push({
        from: auth.url,
        to: user.url,
        type: 'auth_flow',
        reason: 'Auth endpoint leads to user data endpoint',
      });
    }
  }

  // Resource family: endpoints sharing path segments
  const apiEndpoints = endpoints.filter(e => e.url.includes('/api/'));
  const families = new Map<string, SurfaceEndpoint[]>();
  for (const ep of apiEndpoints) {
    const segments = ep.url.split('/').filter(Boolean);
    if (segments.length >= 3) {
      const family = segments.slice(0, 3).join('/');
      if (!families.has(family)) families.set(family, []);
      families.get(family)!.push(ep);
    }
  }
  for (const [, members] of Array.from(families.entries())) {
    if (members.length < 2) continue;
    for (let i = 0; i < members.length - 1; i++) {
      relationships.push({
        from: members[i].url,
        to: members[i + 1].url,
        type: 'resource_family',
        reason: 'Shared API path prefix',
      });
    }
  }

  // GraphQL ↔ REST overlap: GraphQL + API endpoints about the same entities
  const graphqlEndpoints = endpoints.filter(e => e.url.includes('graphql'));
  if (graphqlEndpoints.length > 0 && apiEndpoints.length > 0) {
    for (const gql of graphqlEndpoints) {
      for (const api of apiEndpoints.slice(0, 5)) {
        relationships.push({
          from: gql.url,
          to: api.url,
          type: 'graphql_rest_overlap',
          reason: 'GraphQL and REST may expose same entities',
        });
      }
    }
  }

  // Config → access: config endpoints that expose secrets used by auth endpoints
  const configEndpoints = endpoints.filter(e => e.sensitivity === 'config');
  for (const config of configEndpoints) {
    for (const auth of authEndpoints) {
      relationships.push({
        from: config.url,
        to: auth.url,
        type: 'config_to_access',
        reason: 'Config may expose credentials used by auth endpoint',
      });
    }
  }

  return relationships;
}

// ── High-Value Target Ranking ────────────────────────────────────────────────

function scoreHighValue(ep: SurfaceEndpoint): number {
  let score = 0;

  // Trust zone scoring
  if (ep.trustZone === 'privileged') score += 40;
  if (ep.trustZone === 'internal_like') score += 35;
  if (ep.trustZone === 'authenticated') score += 15;

  // Sensitivity scoring
  if (ep.sensitivity === 'admin') score += 35;
  if (ep.sensitivity === 'config') score += 25;
  if (ep.sensitivity === 'auth') score += 20;
  if (ep.sensitivity === 'financial') score += 30;
  if (ep.sensitivity === 'user_data') score += 10;

  // Chain role scoring
  if (ep.chainRole === 'target') score += 20;
  if (ep.chainRole === 'pivot') score += 10;

  return score;
}

// ── Build Surface Model ──────────────────────────────────────────────────────

export function buildSurfaceModel(discoveredEndpoints: DiscoveredEndpoint[]): SurfaceModel {
  // Classify each endpoint
  const surfaceEndpoints: SurfaceEndpoint[] = discoveredEndpoints.map(ep => {
    const trustZone = classifyTrustZone(ep.url, ep);
    const sensitivity = classifySensitivity(ep.url);
    const chainRole = classifyChainRole(ep.url, trustZone, sensitivity);
    const highValueScore = scoreHighValue({ url: ep.url, method: ep.method, trustZone, sensitivity, chainRole, highValueScore: 0 });

    return {
      url: ep.url,
      method: ep.method,
      trustZone,
      sensitivity,
      chainRole,
      highValueScore,
    };
  });

  // Map relationships
  const relationships = mapRelationships(surfaceEndpoints);

  // Build trust zone map
  const trustZones = new Map<string, TrustZone>();
  for (const ep of surfaceEndpoints) {
    trustZones.set(ep.url, ep.trustZone);
  }

  // Rank high-value targets
  const ranked = [...surfaceEndpoints].sort((a, b) => b.highValueScore - a.highValueScore);
  const highValueTargets = ranked.slice(0, 5);

  // Build summary
  const zoneCounts: Record<TrustZone, number> = { public: 0, authenticated: 0, privileged: 0, internal_like: 0, unknown: 0 };
  const sensCounts: Record<Sensitivity, number> = { auth: 0, user_data: 0, admin: 0, config: 0, financial: 0, generic: 0 };
  const roleCounts: Record<ChainRole, number> = { entry: 0, pivot: 0, target: 0 };

  for (const ep of surfaceEndpoints) {
    zoneCounts[ep.trustZone]++;
    sensCounts[ep.sensitivity]++;
    roleCounts[ep.chainRole]++;
  }

  const summary: SurfaceSummary = {
    totalEndpoints: surfaceEndpoints.length,
    trustZones: zoneCounts,
    sensitivities: sensCounts,
    chainRoles: roleCounts,
    highValueTargets,
    relationships,
    primaryEntryPoints: surfaceEndpoints.filter(e => e.chainRole === 'entry').map(e => e.url).slice(0, 5),
    primaryTargets: surfaceEndpoints.filter(e => e.chainRole === 'target').map(e => e.url).slice(0, 5),
  };

  return {
    endpoints: surfaceEndpoints,
    relationships,
    trustZones,
    highValueTargets,
    summary,
  };
}

// ── Replay Target Prioritization ─────────────────────────────────────────────

/** Reorder replay targets so privileged/auth/family endpoints come first */
export function prioritizeReplayTargets(
  targets: string[],
  surfaceModel: SurfaceModel
): string[] {
  return [...targets].sort((a, b) => {
    const aEp = surfaceModel.endpoints.find(e => e.url === a);
    const bEp = surfaceModel.endpoints.find(e => e.url === b);
    const aScore = aEp?.highValueScore || 0;
    const bScore = bEp?.highValueScore || 0;
    return bScore - aScore; // highest value first
  });
}
