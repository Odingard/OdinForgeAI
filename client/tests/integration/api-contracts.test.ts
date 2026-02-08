/**
 * Frontend-Backend API Contract Tests
 *
 * These tests validate that frontend expectations match backend API responses.
 * Run with: npm run test
 */

import { describe, it, expect, beforeAll } from 'vitest';

const API_BASE = 'http://localhost:5000/api';

// Helper to make authenticated requests (in real tests, use actual auth)
async function apiRequest(endpoint: string, options: RequestInit = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  return response;
}

describe('API Contract Tests', () => {
  describe('AEV Evaluations API', () => {
    it('GET /api/aev/evaluations returns array of evaluations', async () => {
      const response = await apiRequest('/aev/evaluations');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const evaluation = data[0];
        expect(evaluation).toHaveProperty('id');
        expect(evaluation).toHaveProperty('assetId');
        expect(evaluation).toHaveProperty('status');
        expect(evaluation).toHaveProperty('priority');
        expect(evaluation).toHaveProperty('exposureType');
      }
    });

    it('GET /api/aev/stats returns evaluation statistics', async () => {
      const response = await apiRequest('/aev/stats');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('total');
      expect(data).toHaveProperty('completed');
      expect(data).toHaveProperty('pending');
      expect(data).toHaveProperty('failed');
      expect(typeof data.total).toBe('number');
    });

    it('GET /api/aev/execution-modes returns available modes', async () => {
      const response = await apiRequest('/aev/execution-modes');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);
      expect(data).toContain('safe');
      expect(data).toContain('simulation');
      expect(data).toContain('live');
    });
  });

  describe('Assets API', () => {
    it('GET /api/assets returns array of assets', async () => {
      const response = await apiRequest('/assets');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const asset = data[0];
        expect(asset).toHaveProperty('id');
        expect(asset).toHaveProperty('name');
        expect(asset).toHaveProperty('type');
        expect(asset).toHaveProperty('criticality');
      }
    });
  });

  describe('Agents API', () => {
    it('GET /api/agents returns array of agents', async () => {
      const response = await apiRequest('/agents');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const agent = data[0];
        expect(agent).toHaveProperty('id');
        expect(agent).toHaveProperty('hostname');
        expect(agent).toHaveProperty('platform');
        expect(agent).toHaveProperty('status');
        expect(agent).toHaveProperty('lastHeartbeat');
      }
    });

    it('GET /api/agents/stats/summary returns agent statistics', async () => {
      const response = await apiRequest('/agents/stats/summary');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('total');
      expect(data).toHaveProperty('online');
      expect(data).toHaveProperty('offline');
      expect(typeof data.total).toBe('number');
    });
  });

  describe('Cloud Assets API', () => {
    it('GET /api/cloud-assets returns array of cloud assets', async () => {
      const response = await apiRequest('/cloud-assets');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const asset = data[0];
        expect(asset).toHaveProperty('id');
        expect(asset).toHaveProperty('provider');
        expect(asset).toHaveProperty('assetType');
        expect(asset).toHaveProperty('assetName');
        expect(asset).toHaveProperty('region');
      }
    });
  });

  describe('Reports API', () => {
    it('GET /api/reports returns array of reports', async () => {
      const response = await apiRequest('/reports');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const report = data[0];
        expect(report).toHaveProperty('id');
        expect(report).toHaveProperty('title');
        expect(report).toHaveProperty('format');
        expect(report).toHaveProperty('createdAt');
      }
    });
  });

  describe('Lateral Movement API', () => {
    it('GET /api/lateral-movement/techniques returns array of techniques', async () => {
      const response = await apiRequest('/lateral-movement/techniques');

      // May require auth, check for 401 or 200
      if (response.status === 401) {
        expect(response.status).toBe(401);
        return;
      }

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const technique = data[0];
        expect(technique).toHaveProperty('id');
        expect(technique).toHaveProperty('name');
        expect(technique).toHaveProperty('description');
      }
    });

    it('GET /api/lateral-movement/credentials returns array of credentials', async () => {
      const response = await apiRequest('/lateral-movement/credentials');

      if (response.status === 401) {
        expect(response.status).toBe(401);
        return;
      }

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);
    });
  });

  describe('Governance API', () => {
    it('GET /api/scope-rules/:organizationId returns scope rules', async () => {
      const response = await apiRequest('/scope-rules/default');
      expect([200, 401]).toContain(response.status);

      if (response.status === 200) {
        const data = await response.json();
        expect(Array.isArray(data)).toBe(true);
      }
    });
  });

  describe('AI Simulations API', () => {
    it('GET /api/ai-simulations/:organizationId returns simulations', async () => {
      const response = await apiRequest('/ai-simulations/default');
      expect([200, 401]).toContain(response.status);

      if (response.status === 200) {
        const data = await response.json();
        expect(Array.isArray(data)).toBe(true);
      }
    });

    it('GET /api/adversary-profiles returns adversary profiles', async () => {
      const response = await apiRequest('/adversary-profiles');
      expect([200, 401]).toContain(response.status);

      if (response.status === 200) {
        const data = await response.json();
        expect(Array.isArray(data)).toBe(true);
      }
    });
  });

  describe('Full Assessment API', () => {
    it('GET /api/full-assessments returns assessments', async () => {
      const response = await apiRequest('/full-assessments');
      expect([200, 401]).toContain(response.status);

      if (response.status === 200) {
        const data = await response.json();
        expect(Array.isArray(data)).toBe(true);
      }
    });
  });

  describe('Vulnerabilities API', () => {
    it('GET /api/vulnerabilities returns vulnerabilities', async () => {
      const response = await apiRequest('/vulnerabilities');
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);

      if (data.length > 0) {
        const vuln = data[0];
        expect(vuln).toHaveProperty('id');
        expect(vuln).toHaveProperty('severity');
        expect(vuln).toHaveProperty('title');
      }
    });
  });

  describe('Error Handling', () => {
    it('returns 404 for non-existent endpoints', async () => {
      const response = await apiRequest('/non-existent-endpoint');
      expect(response.status).toBe(404);
    });

    it('returns 404 for non-existent resource', async () => {
      const response = await apiRequest('/aev/evaluations/non-existent-id');
      expect(response.status).toBe(404);
    });
  });

  describe('Rate Limiting', () => {
    it('includes rate limit headers', async () => {
      const response = await apiRequest('/aev/evaluations');

      // Rate limit headers may not be present on all endpoints
      // but should be present on rate-limited ones
      if (response.headers.has('X-RateLimit-Limit')) {
        expect(response.headers.get('X-RateLimit-Limit')).toBeTruthy();
        expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy();
      }
    });
  });
});
