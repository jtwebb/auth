# `@jtwebb/auth`

Secure, framework-agnostic authentication building blocks for Node 20+:

- **Core**: password + passkeys (WebAuthn) + backup codes + DB-backed sessions (opaque token, hashed in DB)
- **Adapters**: React Router v7 first (`Request`/`Response` based)
- **React helpers**: passkey flows, hooks, and minimal UI components

## Install

```bash
npm i @jtwebb/auth
```

## Package entrypoints

- `@jtwebb/auth/core`
- `@jtwebb/auth/react-router`
- `@jtwebb/auth/react`

## Core usage (server)

### 1) Implement `AuthStorage`

Core is DB-agnostic. You implement `AuthStorage` against your DB. The key security properties:
- **Sessions**: store only `tokenHash` server-side (never plaintext session tokens)
- **Passwords**: store only Argon2id PHC hashes (never plaintext)
- **Passkeys**: store credential `id` (base64url), `publicKey`, and `counter`
- **Challenges + backup codes**: consume exactly once (atomic)

### 2) Create `AuthCore`

```ts
import { createAuthCore } from "@jtwebb/auth/core";

const core = createAuthCore({
  storage,
  policy: {
    passkey: {
      rpId: "example.com",
      rpName: "Example",
      origins: ["https://example.com"],
      userVerification: "preferred",
    },
  },
  // Recommended: secrets for hashing tokens/codes
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET!,
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET!,
  passwordPepper: process.env.PASSWORD_PEPPER!,
});
```

## React Router v7 adapter usage

This adapter intentionally **does not import react-router packages**. It operates on standard `Request`/`Response`
objects used by React Router actions/loaders.

```ts
import { createReactRouterAuthAdapter } from "@jtwebb/auth/react-router";

export const auth = createReactRouterAuthAdapter({
  core,
  sessionCookie: {
    name: "sid",
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  },
});
```

### Guard a loader

```ts
export async function loader({ request }: { request: Request }) {
  const { userId, headers } = await auth.requireUser(request, { redirectTo: "/login" });
  return new Response(JSON.stringify({ userId }), { headers });
}
```

### Actions

- Password login: `auth.actions.passwordLogin(request, { redirectTo: "/" })`
- Password register: `auth.actions.passwordRegister(request, { redirectTo: "/" })`
- Passkey login: `auth.actions.passkeyLoginStart(request)` then `auth.actions.passkeyLoginFinish(request, { redirectTo: "/" })`
- Logout: `auth.logout(request, { redirectTo: "/login" })`

## React helpers usage (browser)

### Passkey flow (recommended)

```ts
import { createPasskeyFlows } from "@jtwebb/auth/react";

const passkeys = createPasskeyFlows({
  registrationStartUrl: "/api/passkeys/register/start",
  registrationFinishUrl: "/api/passkeys/register/finish",
  loginStartUrl: "/api/passkeys/login/start",
  loginFinishUrl: "/api/passkeys/login/finish",
});

await passkeys.login(); // passkey-first (discoverable)
```

### Components

- `LoginForm`
- `PasskeyLoginButton`
- `PasskeyRegistrationButton`
- `BackupCodesDisplay`
- `BackupCodeRedeemForm`

## Security notes (must read)

See `SECURITY.md` and `docs/production-hardening.md`.

