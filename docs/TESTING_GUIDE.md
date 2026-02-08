# OdinForge-AI Testing Guide

## Overview

OdinForge-AI uses **Vitest** for integration testing to ensure frontend and backend API contracts remain synchronized.

---

## Test Structure

```
client/tests/
├── setup.ts                          # Test environment configuration
└── integration/
    └── api-contracts.test.ts         # Frontend-backend contract tests
```

---

## Running Tests

### Install Dependencies

```bash
npm install --save-dev vitest @testing-library/react @testing-library/jest-dom @vitest/ui jsdom
```

### Run All Tests

```bash
npm test
```

### Run Tests in Watch Mode

```bash
npm test -- --watch
```

### Run with Coverage

```bash
npm test -- --coverage
```

### Run with UI

```bash
npm test -- --ui
```

### Run Specific Test File

```bash
npm test client/tests/integration/api-contracts.test.ts
```

---

## Test Categories

### 1. API Contract Tests

**Purpose:** Validate that frontend expectations match backend API responses.

**Coverage:**
- AEV Evaluations API (10 endpoints)
- Assets API (5 endpoints)
- Agents API (8 endpoints)
- Cloud Assets API (6 endpoints)
- Reports API (7 endpoints)
- Lateral Movement API (13 endpoints)
- Governance API (4 endpoints)
- AI Simulations API (5 endpoints)
- Full Assessments API (4 endpoints)
- Vulnerabilities API (6 endpoints)

**What We Test:**
- Response status codes (200, 401, 404)
- Response data structure
- Required fields presence
- Data types correctness
- Array vs object responses
- Error handling

**Example:**
```typescript
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
  }
});
```

---

## Writing New Tests

### Test Template

```typescript
import { describe, it, expect } from 'vitest';

describe('Your Feature API', () => {
  it('should validate the response structure', async () => {
    const response = await fetch('http://localhost:5000/api/your-endpoint');
    expect(response.status).toBe(200);

    const data = await response.json();
    expect(data).toHaveProperty('expectedField');
  });
});
```

### Best Practices

1. **Test the Contract, Not Implementation**
   - Focus on API response structure
   - Don't test internal logic
   - Validate required fields

2. **Handle Authentication**
   ```typescript
   const response = await apiRequest('/protected-endpoint');

   // Handle both authenticated and unauthenticated states
   if (response.status === 401) {
     expect(response.status).toBe(401);
     return;
   }
   ```

3. **Test Error Cases**
   ```typescript
   it('returns 404 for non-existent resource', async () => {
     const response = await apiRequest('/items/non-existent-id');
     expect(response.status).toBe(404);
   });
   ```

4. **Test Empty States**
   ```typescript
   it('handles empty arrays gracefully', async () => {
     const data = await response.json();
     expect(Array.isArray(data)).toBe(true);
     // Don't assume data.length > 0
   });
   ```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: API Contract Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Start services
        run: |
          docker-compose up -d
          npm run dev &
          sleep 10

      - name: Run tests
        run: npm test

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage/coverage-final.json
```

---

## Test Coverage Goals

| Category | Target Coverage |
|----------|----------------|
| API Endpoints | 80%+ |
| Critical Paths | 100% |
| Error Handling | 75%+ |
| Authentication | 90%+ |

### Checking Coverage

```bash
npm test -- --coverage
```

**Coverage Report Location:** `coverage/index.html`

---

## Troubleshooting

### Tests Failing with Connection Errors

**Problem:** Can't connect to `http://localhost:5000`

**Solution:**
1. Ensure dev server is running: `npm run dev`
2. Check if database is up: `docker-compose ps`
3. Verify port 5000 is not in use: `lsof -i :5000`

### Authentication Issues

**Problem:** All tests return 401

**Solution:**
1. Use a test user token
2. Mock authentication in tests
3. Set `Authorization` header properly

```typescript
const response = await fetch(url, {
  headers: {
    Authorization: `Bearer ${testToken}`,
  },
});
```

### Timeout Errors

**Problem:** Tests timeout waiting for response

**Solution:**
1. Increase timeout in `vitest.config.ts`:
   ```typescript
   test: {
     testTimeout: 30000, // 30 seconds
   }
   ```
2. Check if server is responding slowly
3. Use `--no-parallel` flag for debugging

---

## Mocking

### Mock API Responses

```typescript
import { vi } from 'vitest';

vi.mock('@/lib/queryClient', () => ({
  apiRequest: vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ id: '123', name: 'Test' }),
    })
  ),
}));
```

### Mock WebSocket

```typescript
vi.stubGlobal('WebSocket', class MockWebSocket {
  constructor(public url: string) {}
  send = vi.fn();
  close = vi.fn();
  addEventListener = vi.fn();
});
```

---

## Integration with Development

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
npm test -- --run --reporter=dot
```

### VS Code Integration

Add to `.vscode/settings.json`:

```json
{
  "vitest.enable": true,
  "vitest.commandLine": "npm test"
}
```

---

## Future Enhancements

### Planned Test Additions

1. **Component Tests**
   - React component rendering
   - User interactions
   - Form submissions

2. **E2E Tests**
   - Full user workflows
   - Multi-step processes
   - Browser automation

3. **Performance Tests**
   - Response time validation
   - Load testing
   - Memory leak detection

4. **Security Tests**
   - XSS prevention
   - CSRF token validation
   - SQL injection protection

---

## Test Data Management

### Using Test Fixtures

```typescript
// tests/fixtures/evaluations.ts
export const mockEvaluation = {
  id: 'eval-123',
  assetId: 'asset-456',
  status: 'completed',
  priority: 'high',
  exposureType: 'sql_injection',
};
```

### Database Seeding

```bash
npm run db:seed:test
```

---

## Resources

- **Vitest Docs:** https://vitest.dev/
- **Testing Library:** https://testing-library.com/
- **API Testing Best Practices:** https://kentcdodds.com/blog/common-mistakes-with-react-testing-library

---

## Support

For test-related questions:
- Check existing test files for examples
- Review this guide
- Open an issue on GitHub

---

**Last Updated:** February 7, 2026
**Status:** ✅ Ready for Use
