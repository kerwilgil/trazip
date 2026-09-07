# Contributing to TRAZIP

Thank you for considering a contribution to TRAZIP.

## Prerequisites

- Go 1.26+ (toolchain 1.26.6)
- Node.js 22+
- npm 10+
- Wails v2.13+ (for development builds)

## Development Setup

```bash
# Clone and enter
git clone https://github.com/kerwilgil/trazip.git
cd trazip

# Install frontend dependencies
cd frontend && npm ci && cd ..

# Run tests
go test ./... -count=1
go vet ./...
cd frontend && npm test && cd ..

# Build frontend
cd frontend && npm run build && cd ..

# Run application (development)
wails dev
```

## Pre-Commit Checklist

Before committing, run locally:

```bash
# Go
go test ./... -count=1
go vet ./...

# Frontend
cd frontend && npm ci && npm test && npm run build && cd ..

# Security
gitleaks detect --source=. --verbose
govulncheck ./...

# Git hygiene
git diff --check
git status --short
```

## Pull Request Requirements

- All CI checks must pass (see Checks tab)
- No `git add .` or `git add -A` — stage files explicitly
- No credentials, secrets, or network captures in commits
- Network captures shared for debugging must be sanitized (remove PII, credentials)
- Active testing only against authorized targets
- Conventional commit messages preferred (e.g., `feat:`, `fix:`, `ci:`, `docs:`)

## Code Standards

- Go: standard library style, `gofmt`, `go vet` clean
- TypeScript: strict mode, ESLint + Prettier (via Vite)
- Tests: table-driven for Go, descriptive for Vitest
- Security: no hardcoded secrets, all external calls bounded/cancellable

## Security

- Report vulnerabilities via GitHub Security Advisories (not public issues)
- See [SECURITY.md](.github/SECURITY.md) for supported versions and disclosure policy
- Never commit secrets — CI will block them

## License

By contributing, you agree your contributions will be licensed under the MIT License (see LICENSE).