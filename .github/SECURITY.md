# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| 1.4.x   | :white_check_mark: (security fixes only) |
| < 1.4   | :x:                |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Please report suspected security vulnerabilities privately via:

- **GitHub Security Advisories** (preferred): Use the "Report a vulnerability" tab in the Security section of this repository
- **Email**: security@trazip.io (if available)

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any proof-of-concept code (if safe to share)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Development**: Target 30 days for critical/high, 90 days for medium/low
- **Release**: Patched version released as soon as fix is validated

## Scope

This policy covers the TRAZIP application codebase including:

- Go backend (internal/, cmd/, app.go, main.go)
- TypeScript/React frontend (frontend/)
- Build and release infrastructure
- Update mechanism (internal/update, cmd/trazip-updater)

Out of scope:

- Third-party dependencies (report to their maintainers)
- Infrastructure not controlled by this repository
- Social engineering / physical attacks

## Security Features

TRAZIP implements several security controls:

- **Local-first architecture**: No telemetry, no forced external connections
- **Scope Guard**: All active operations require explicit authorization
- **Signed updates**: Ed25519-verified updates via dedicated channel
- **Secret handling**: Windows DPAPI for credential storage
- **Dependency scanning**: Automated govulncheck and npm audit in CI
- **Secret scanning**: Gitleaks integrated in CI

## Disclosure Policy

We follow coordinated disclosure:

1. Report received privately
2. Fix developed and tested
3. Security advisory published with release
4. Credit given to reporter (unless anonymous requested)

## Contact

For security questions not related to vulnerability reporting, open a GitHub Discussion.