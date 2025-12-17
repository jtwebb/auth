# `@jtwebb/auth`

Secure, framework-agnostic authentication building blocks for Node 20+:

- **Core**: password + passkeys (WebAuthn) + **TOTP 2FA** + backup codes + DB-backed sessions (opaque token, hashed in DB)
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
    totp: {
      issuer: "Example",
      digits: 6,
      periodSeconds: 30,
      allowedSkewSteps: 1,
    },
  },
  // Recommended: secrets for hashing tokens/codes
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET!,
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET!,
  passwordPepper: process.env.PASSWORD_PEPPER!,
  // Required for TOTP (2FA): encrypt TOTP secrets at rest
  totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY!,
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
  // Used during 2FA step-up (httpOnly cookie holding the pending token)
  totpPendingCookie: {
    name: "totp",
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAgeSeconds: 60 * 5,
  },
  twoFactorRedirectTo: "/two-factor",
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
- TOTP enrollment: `auth.actions.totpEnrollmentStart(request)` then `auth.actions.totpEnrollmentFinish(request)`
- TOTP verification (step-up): `auth.actions.totpVerify(request, { redirectTo: "/" })`

### 2FA (TOTP) flow (server)

- If TOTP is enabled for a user, **password/passkey login will redirect to** `twoFactorRedirectTo` and set an **httpOnly** `totp` cookie.
- Your `/two-factor` page should POST a form with `code` to the `totpVerify` action endpoint.

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
- `TotpSetup`
- `TotpVerifyForm`

## Security notes (must read)

See `SECURITY.md` and `docs/production-hardening.md`.

