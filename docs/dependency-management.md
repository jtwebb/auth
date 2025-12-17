# Dependency management

## Goals

- Keep dependencies minimal in the core.
- Prefer well-maintained security-critical deps (Argon2, WebAuthn) with strong ecosystems.

## Suggested practices

- Use Renovate/Dependabot for PR-based updates.
- Review changelogs for:
  - `@node-rs/argon2`
  - `@simplewebauthn/server`
  - `@simplewebauthn/browser`
- For every dependency update:
  - `npm test`
  - `npm run build`

## Audit guidance

- `npm audit` can be noisy. Treat it as a signal, not a binary gate.
- Prioritize:
  - direct dependencies
  - vulnerabilities in authentication/crypto/web layers
  - exploitable attack paths in your deployment context


