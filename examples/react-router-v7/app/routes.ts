import { type RouteConfig, index, route } from '@react-router/dev/routes';

export default [
  index('routes/home.tsx'),

  route('register', 'routes/register.tsx'),
  route('login', 'routes/login.tsx'),
  route('two-factor', 'routes/two-factor.tsx'),
  route('logout', 'routes/logout.tsx'),

  route('settings/security', 'routes/settings.security.tsx'),
  route('protected', 'routes/protected.tsx'),

  // JSON endpoints used by WebAuthn + settings flows (implemented as route actions).
  route('api/passkeys/register/start', 'routes/api.passkeys.register.start.ts'),
  route('api/passkeys/register/finish', 'routes/api.passkeys.register.finish.ts'),
  route('api/passkeys/login/start', 'routes/api.passkeys.login.start.ts'),
  route('api/passkeys/login/finish', 'routes/api.passkeys.login.finish.ts'),

  route('api/totp/enroll/start', 'routes/api.totp.enroll.start.ts'),
  route('api/totp/enroll/finish', 'routes/api.totp.enroll.finish.ts'),

  route('api/backup-codes/rotate', 'routes/api.backup-codes.rotate.ts')
] satisfies RouteConfig;
