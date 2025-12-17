# Release checklist

## Pre-flight

- Confirm Node support: **Node 20+**
- Confirm package entrypoints build and resolve:
  - `@jtwebb/auth`
  - `@jtwebb/auth/core`
  - `@jtwebb/auth/react-router`
  - `@jtwebb/auth/react`
- Ensure `README.md` and `docs/production-hardening.md` match current APIs.

## Quality gates

- `npm test`
- `npm run build`
- Ensure TypeScript declarations are emitted to `dist/` and `package.json#exports` points to them.

## Security gates

- Review `docs/security-review.md`
- Ensure secrets are not committed and docs do not include real secrets.
- Confirm cookie defaults: `httpOnly`, `secure`, `sameSite`, `path=/`

## Versioning

- Use semver:
  - `MAJOR`: breaking API change (types, exports, storage interfaces)
  - `MINOR`: new functionality in a backwards compatible way
  - `PATCH`: bugfixes and docs

## Publish

- Update `package.json` version
- Publish to npm registry


