# React Router v7 example (skeleton)

This folder shows how to wire:

- `@jtwebb/auth/core` (your storage implementation)
- `@jtwebb/auth/react-router` adapter (cookie + CSRF/origin checks)
- `@jtwebb/auth/react` helpers (passkey flow + small UI components)

It’s intentionally a **skeleton** so it doesn’t pull in framework/build dependencies in the main library repo.

## Endpoints you’ll expose

- `POST /api/auth/login` (password) → `auth.actions.passwordLogin`
- `POST /api/auth/register` (password) → `auth.actions.passwordRegister`
- `POST /api/auth/register` (password) → `auth.actions.passwordRegister`
- `POST /api/passkeys/register/start` → `auth.actions.passkeyRegistrationStart`
- `POST /api/passkeys/register/finish` → `auth.actions.passkeyRegistrationFinish`
- `POST /api/passkeys/login/start` → `auth.actions.passkeyLoginStart`
- `POST /api/passkeys/login/finish` → `auth.actions.passkeyLoginFinish`
- `POST /api/auth/logout` → `auth.logout`

## Protecting routes (loaders)

In any loader that requires auth:

- Call `auth.requireUser(request, { redirectTo: "/login" })`
- Return the loader response with the **returned headers** (so session rotation `Set-Cookie` is applied)

See `examples/react-router-v7/server/protected-loader.ts`.

## Passkey-only registration

Passkey registration requires a `userId`. For “passkey-only” signup:

- Create the user record server-side first (no password credential)
- Then start passkey registration for that user

See:

- `examples/react-router-v7/server/passkey-only-register.ts` (server flow)
- `examples/react-router-v7/routes/passkey-only-register.tsx` (UI)

## Files

- `examples/react-router-v7/server/auth.ts`: creates `AuthCore` and `createReactRouterAuthAdapter`
- `examples/react-router-v7/server/routes.ts`: request handlers for auth endpoints (illustrative)
- `examples/react-router-v7/server/protected-loader.ts`: route protection example (illustrative)
- `examples/react-router-v7/server/passkey-only-register.ts`: passkey-only signup example (illustrative)
- `examples/react-router-v7/routes/login.tsx`: UI using `LoginForm` + `PasskeyLoginButton`
- `examples/react-router-v7/routes/register.tsx`: UI showing password registration
- `examples/react-router-v7/routes/protected.tsx`: UI for a protected page
- `examples/react-router-v7/routes/passkey-only-register.tsx`: UI showing passkey-only registration
