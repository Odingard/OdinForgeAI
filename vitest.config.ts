import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    env: {
      OPENAI_API_KEY: "sk-test-dummy-key-for-vitest",
      DATABASE_URL: "postgresql://dummy:dummy@localhost:5432/dummy",
    },
    include: [
      'server/**/*.test.ts',
      'shared/**/*.test.ts',
    ],
    exclude: [
      'node_modules/**',
      'server/src/reportsV2/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'client/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/dist',
      ],
    },
  },
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, './shared'),
    },
  },
});
