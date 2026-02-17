# Contributing to OdinForge AI

Thank you for your interest in contributing. OdinForge AI is licensed under BSL 1.1 — contributions are welcome under the same license terms.

## Getting Started

### Prerequisites
- Node.js 20+
- PostgreSQL 15+ (with pgvector)
- Redis 7+
- Go 1.21+ (for agent development)

### Local Development
```bash
git clone <repository-url>
cd OdinForgeAI
npm install
cp .env.example .env
# Edit .env with your local configuration
npm run dev
```

## Development Guidelines

### Code Style
- TypeScript strict mode for all new code
- React functional components with hooks
- Server endpoints follow: `app.METHOD(path, rateLimiter, uiAuthMiddleware, requirePermission("perm"), handler)`
- Use `UIAuthenticatedRequest` with `req.uiUser` (not `req.user`)

### Commit Messages
Use descriptive commit messages with a verb prefix:
- `Add` — new feature
- `Fix` — bug fix
- `Update` — enhancement to existing feature
- `Remove` — deleted code or feature
- `Refactor` — code restructuring without behavior change

### Pull Requests
1. Create a feature branch from `main`
2. Keep PRs focused — one feature or fix per PR
3. Include tests for new functionality
4. Update documentation if you change APIs or user-facing behavior
5. Fill out the PR template

### Security
- Never commit secrets, API keys, or credentials
- Use `requirePermission()` for all new endpoints
- Validate all user input at API boundaries
- Follow OWASP secure coding practices

## Architecture Notes
- **Auth**: JWT-based via `UIAuthProvider` → `uiAuthMiddleware` → `requirePermission()`
- **Multi-tenancy**: Row-Level Security via `withTenantContext()`
- **Permissions**: 67 granular permissions (action:resource pattern), 8 roles
- **Job queue**: BullMQ with Redis for async processing

See [docs/](docs/) for detailed architecture and API documentation.

## Reporting Issues
- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for bugs
- Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) for enhancements
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
