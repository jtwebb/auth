# React Router v7 example (skeleton)

This folder shows how to wire:

- `@jtwebb/auth/core` (your storage implementation)
- `@jtwebb/auth/react-router` adapter (cookie + CSRF/origin checks)
- `@jtwebb/auth/react` helpers (passkey flow + small UI components)

It’s intentionally a **skeleton** so it doesn’t pull in framework/build dependencies in the main library repo.

## Endpoints you’ll expose

- `POST /api/auth/login` (password) → `auth.actions.passwordLogin`
- `POST /api/auth/register` (password) → `auth.actions.passwordRegister`
- `POST /api/passkeys/register/start` → `auth.actions.passkeyRegistrationStart`
- `POST /api/passkeys/register/finish` → `auth.actions.passkeyRegistrationFinish`
- `POST /api/passkeys/login/start` → `auth.actions.passkeyLoginStart`
- `POST /api/passkeys/login/finish` → `auth.actions.passkeyLoginFinish`
- `POST /api/auth/logout` → `auth.logout`

## Files

- `examples/react-router-v7/server/auth.ts`: creates `AuthCore` and `createReactRouterAuthAdapter`
- `examples/react-router-v7/routes/login.tsx`: UI using `LoginForm` + `PasskeyLoginButton`


