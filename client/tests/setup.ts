/**
 * Vitest Setup File
 *
 * Configures the testing environment for integration tests
 */

import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

// Mock environment variables
process.env.NODE_ENV = 'test';

// Setup global test utilities
global.testConfig = {
  apiBaseUrl: 'http://localhost:5000/api',
  testTimeout: 10000,
};

// Mock fetch if needed
if (!global.fetch) {
  global.fetch = vi.fn();
}
