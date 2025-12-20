import { createHmac, randomBytes } from 'node:crypto';
import { AuthError } from '../auth-error.js';
import type { AuthPolicy } from '../auth-policy.js';
import type { ChallengeId, CreateSessionTokenResult, UserId } from '../auth-types.js';
import type { RandomBytesFn } from '../create-auth-core.js';
import type { AuthStorage } from '../storage/auth-storage.js';
import type {
  FinishTotpEnrollmentInput,
  FinishTotpEnrollmentResult,
  StartTotpEnrollmentInput,
  StartTotpEnrollmentResult,
  VerifyTotpInput,
  VerifyTotpResult
} from './totp-types.js';
import { decryptTotpSecret, encryptTotpSecret, type TotpEncryptionKey } from './totp-crypto.js';

export async function startTotpEnrollment(ctx: {
  input: StartTotpEnrollmentInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  totpEncryptionKey: TotpEncryptionKey;
  randomBytes?: RandomBytesFn;
}): Promise<StartTotpEnrollmentResult> {
  const now = ctx.now();
  const secretBytes = (ctx.randomBytes ?? randomBytes)(20);
  const secretBase32 = base32Encode(secretBytes);

  const encryptedSecret = encryptTotpSecret({
    userId: ctx.input.userId,
    secretBase32,
    key: ctx.totpEncryptionKey,
    randomBytes: ctx.randomBytes
  });
  await ctx.storage.totp.setPending(ctx.input.userId, encryptedSecret, now);

  const otpauthUri = buildOtpAuthUri({
    issuer: ctx.policy.totp.issuer,
    accountName: normalizeAccountName(ctx.input.accountName),
    secretBase32,
    digits: ctx.policy.totp.digits,
    periodSeconds: ctx.policy.totp.periodSeconds
  });

  return { userId: ctx.input.userId, secretBase32, otpauthUri };
}

export async function finishTotpEnrollment(ctx: {
  input: FinishTotpEnrollmentInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  totpEncryptionKey: TotpEncryptionKey;
}): Promise<FinishTotpEnrollmentResult> {
  const now = ctx.now();
  const enabled = await ctx.storage.totp.getEnabled(ctx.input.userId);
  if (enabled) throw new AuthError('conflict', 'TOTP already enabled');

  const pending = await ctx.storage.totp.getPending(ctx.input.userId);
  if (!pending) throw new AuthError('not_found', 'No pending TOTP enrollment');

  const secretBase32 = decryptTotpSecret({
    userId: ctx.input.userId,
    encryptedSecret: pending.encryptedSecret,
    key: ctx.totpEncryptionKey
  });

  const ok = verifyTotpCode({
    secretBase32,
    code: ctx.input.code,
    now,
    digits: ctx.policy.totp.digits,
    periodSeconds: ctx.policy.totp.periodSeconds,
    allowedSkewSteps: ctx.policy.totp.allowedSkewSteps,
    lastUsedAt: undefined,
    lastUsedStep: undefined
  });
  if (ok === null) {
    throw new AuthError('totp_invalid', 'Invalid TOTP code', {
      publicMessage: 'Invalid code',
      status: 401
    });
  }

  await ctx.storage.totp.enableFromPending(ctx.input.userId, now);
  const updated =
    (await ctx.storage.totp.updateLastUsedStepIfGreater?.({
      userId: ctx.input.userId,
      step: ok,
      usedAt: now
    })) ?? null;
  if (updated === null) {
    // Best-effort fallback (not race-free).
    await ctx.storage.totp.updateLastUsedAt(ctx.input.userId, now);
  }
  return { enabled: true };
}

export async function createTotpPending(ctx: {
  userId: UserId;
  storage: AuthStorage;
  now: () => Date;
  randomBytes: RandomBytesFn;
  ttlMs: number;
}): Promise<ChallengeId> {
  const now = ctx.now();
  const id = randomId(ctx.randomBytes, 16) as ChallengeId;
  await ctx.storage.challenges.createChallenge({
    id,
    type: 'totp_pending',
    userId: ctx.userId,
    challenge: '',
    expiresAt: new Date(now.getTime() + ctx.ttlMs)
  });
  return id;
}

export async function verifyTotp(ctx: {
  input: VerifyTotpInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  totpEncryptionKey: TotpEncryptionKey;
  createSessionToken: () => CreateSessionTokenResult;
  hashSessionContextValue: (value: string) => string;
}): Promise<VerifyTotpResult> {
  const now = ctx.now();
  const pending = await ctx.storage.challenges.consumeChallenge(ctx.input.pendingToken);
  if (!pending || pending.type !== 'totp_pending' || !pending.userId) {
    throw new AuthError('totp_invalid', 'Invalid two-factor token', {
      publicMessage: 'Invalid code'
    });
  }
  if (pending.expiresAt.getTime() < now.getTime()) {
    throw new AuthError('challenge_expired', 'Two-factor token expired', {
      publicMessage: 'Invalid code'
    });
  }

  const totp = await ctx.storage.totp.getEnabled(pending.userId);
  if (!totp)
    throw new AuthError('totp_not_enabled', 'TOTP not enabled', { publicMessage: 'Invalid code' });

  const secretBase32 = decryptTotpSecret({
    userId: pending.userId,
    encryptedSecret: totp.encryptedSecret,
    key: ctx.totpEncryptionKey
  });
  const step = verifyTotpCode({
    secretBase32,
    code: ctx.input.code,
    now,
    digits: ctx.policy.totp.digits,
    periodSeconds: ctx.policy.totp.periodSeconds,
    allowedSkewSteps: ctx.policy.totp.allowedSkewSteps,
    lastUsedAt: totp.lastUsedAt,
    lastUsedStep: totp.lastUsedStep
  });
  if (step === null)
    throw new AuthError('totp_invalid', 'Invalid TOTP code', { publicMessage: 'Invalid code' });

  // Replay mitigation: prefer atomic step-based update if storage supports it.
  const atomicUpdated =
    (await ctx.storage.totp.updateLastUsedStepIfGreater?.({
      userId: pending.userId,
      step,
      usedAt: now
    })) ?? null;
  if (atomicUpdated === false) {
    // Another request already used this step (concurrent replay).
    throw new AuthError('totp_invalid', 'Invalid TOTP code', { publicMessage: 'Invalid code' });
  }
  if (atomicUpdated === null) {
    // Best-effort fallback (not race-free).
    await ctx.storage.totp.updateLastUsedAt(pending.userId, now);
  }

  const session = ctx.createSessionToken();
  const expiresAt = new Date(now.getTime() + ctx.policy.session.absoluteTtlMs);
  await ctx.storage.sessions.createSession({
    tokenHash: session.sessionTokenHash,
    userId: pending.userId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt,
    clientIdHash: ctx.input.sessionContext?.clientId
      ? ctx.hashSessionContextValue(ctx.input.sessionContext.clientId)
      : undefined,
    userAgentHash: ctx.input.sessionContext?.userAgent
      ? ctx.hashSessionContextValue(ctx.input.sessionContext.userAgent)
      : undefined
  });

  return { userId: pending.userId, session };
}

function buildOtpAuthUri(ctx: {
  issuer: string;
  accountName: string;
  secretBase32: string;
  digits: number;
  periodSeconds: number;
}): string {
  const issuer = encodeURIComponent(ctx.issuer);
  const label = encodeURIComponent(`${ctx.issuer}:${ctx.accountName}`);
  const secret = encodeURIComponent(ctx.secretBase32);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&digits=${ctx.digits}&period=${ctx.periodSeconds}`;
}

function normalizeAccountName(v: string): string {
  if (typeof v !== 'string') throw new AuthError('invalid_input', 'accountName must be a string');
  const t = v.trim();
  if (!t) throw new AuthError('invalid_input', 'accountName is required');
  if (t.length > 320) throw new AuthError('invalid_input', 'accountName is too long');
  return t;
}

function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(base32: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = base32.replaceAll('=', '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of cleaned) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) throw new AuthError('invalid_input', 'Invalid base32 secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function totpStep(now: Date, periodSeconds: number): number {
  return Math.floor(now.getTime() / 1000 / periodSeconds);
}

function hotp(secret: Uint8Array, counter: number, digits: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  const mod = 10 ** digits;
  return String(code % mod).padStart(digits, '0');
}

function verifyTotpCode(ctx: {
  secretBase32: string;
  code: string;
  now: Date;
  digits: number;
  periodSeconds: number;
  allowedSkewSteps: number;
  lastUsedAt?: Date;
  lastUsedStep?: number;
}): number | null {
  const code = ctx.code.trim();
  if (!/^\d{6,8}$/.test(code)) return null;

  const secret = base32Decode(ctx.secretBase32);
  const stepNow = totpStep(ctx.now, ctx.periodSeconds);
  const lastStepFromAt = ctx.lastUsedAt ? totpStep(ctx.lastUsedAt, ctx.periodSeconds) : null;
  const lastStep =
    typeof ctx.lastUsedStep === 'number'
      ? ctx.lastUsedStep
      : lastStepFromAt === null
        ? null
        : lastStepFromAt;

  for (let delta = -ctx.allowedSkewSteps; delta <= ctx.allowedSkewSteps; delta++) {
    const step = stepNow + delta;
    if (lastStep !== null && step <= lastStep) continue; // replay mitigation
    if (hotp(secret, step, ctx.digits) === code) return step;
  }
  return null;
}

function randomId(randomBytesFn: RandomBytesFn, size: number): string {
  const bytes = randomBytesFn(size);
  return Buffer.from(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}
