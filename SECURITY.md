# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PgSec, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: `security@royaltools.dev` (or the maintainer's private email)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## What We Promise

- We will acknowledge receipt within 48 hours
- We will provide an estimated timeline for a fix
- We will credit you in the release notes (unless you prefer anonymity)
- We will not take legal action against researchers acting in good faith

## Security Design Principles

PgSec follows these security practices:

### Credential Handling
- Passwords are **never** placed on command-line arguments
- SSH passwords are read via stdin or environment variable, never via `--password`
- Container environment variables with secret-like names have their **values** suppressed — only names are collected
- All evidence/report content is redacted for password/token-like values

### Authentication
- SSH unknown host keys are rejected by default
- `--accept-new-hostkey` explicitly enables trust-on-first-use (TOFU)
- SSH password mode requires the bundled `pgssh` helper; system `ssh` fallback is key-only

### File Permissions
- Output files are written with restrictive permissions (0600) where the platform permits
- Atomic writes prevent partial file exposure

### Data Collection
- Container secret environment variable **values are never collected**
- Evidence content is automatically redacted using regex patterns for passwords, tokens, and connection URIs

## Supported Versions

| Version | Supported |
|---|---|
| 1.2.x | ✅ Active |
| 1.1.x | ❌ End of life |

## CIS Benchmark Disclaimer

PgSec is an independent assessment tool. It is not endorsed, sponsored, or affiliated with CIS (Center for Internet Security). CIS PostgreSQL Benchmarks are proprietary CIS materials requiring authorized access for redistribution.
