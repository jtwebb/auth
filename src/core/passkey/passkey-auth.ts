import type { AuthPolicy } from '../auth-policy.js';
import { AuthError } from '../auth-error.js';
import type {
  ChallengeId,
  CreateSessionTokenResult,
  UserId,
  WebAuthnCredentialId
} from '../auth-types.js';
import type { RandomBytesFn } from '../create-auth-core.js';
import type { AuthStorage } from '../storage/auth-storage.js';
import type {
  PasskeyLoginFinishInput,
  PasskeyLoginFinishResult,
  PasskeyLoginStartInput,
  PasskeyLoginStartResult,
  PasskeyRegistrationFinishInput,
  PasskeyRegistrationFinishResult,
  PasskeyRegistrationStartInput,
  PasskeyRegistrationStartResult
} from './passkey-types.js';
import type { Uint8Array_ } from '@simplewebauthn/server';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';
import { createHash } from 'node:crypto';
import { createTotpPending } from '../totp/totp.js';

export type PasskeyStartContext<I, O> = {
  input: I;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  randomBytes: RandomBytesFn;
} & O;

export async function startPasskeyRegistration(ctx: {
  input: PasskeyRegistrationStartInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  randomBytes: RandomBytesFn;
}): Promise<PasskeyRegistrationStartResult> {
  const now = ctx.now();
  const challengeId = randomId(ctx.randomBytes, 16) as ChallengeId;
  const challenge = randomId(ctx.randomBytes, 32);
  const expiresAt = new Date(now.getTime() + ctx.policy.challenge.ttlMs);

  const existing = await ctx.storage.webauthn.listCredentialsForUser(ctx.input.userId);
  const excludeCredentials = existing.map(c => ({
    id: c.credentialId,
    transports: c.transports
  }));

  const userHandle = userHandleFromUserId(ctx.input.userId);

  const options = await generateRegistrationOptions({
    rpName: ctx.policy.passkey.rpName,
    rpID: ctx.policy.passkey.rpId,
    userName: normalizeUserName(ctx.input.userName),
    userDisplayName: (ctx.input.userDisplayName ?? ctx.input.userName).trim(),
    userID: userHandle,
    challenge,
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: ctx.policy.passkey.userVerification
    },
    attestationType: 'none'
  });

  await ctx.storage.challenges.createChallenge({
    id: challengeId,
    type: 'passkey_register',
    userId: ctx.input.userId,
    challenge: options.challenge,
    expiresAt
  });

  return { challengeId, options };
}

export async function finishPasskeyRegistration(ctx: {
  input: PasskeyRegistrationFinishInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
}): Promise<PasskeyRegistrationFinishResult> {
  const now = ctx.now();
  const stored = await ctx.storage.challenges.consumeChallenge(ctx.input.challengeId);
  if (!stored || stored.type !== 'passkey_register') throw invalidPasskey();
  if (stored.userId !== ctx.input.userId) throw invalidPasskey();
  if (stored.expiresAt.getTime() < now.getTime())
    throw new AuthError('challenge_expired', 'Passkey challenge expired');

  const requireUserVerification = ctx.policy.passkey.userVerification === 'required';

  const verification = await verifyRegistrationResponse({
    response: ctx.input.response,
    expectedChallenge: stored.challenge,
    expectedOrigin: [...ctx.policy.passkey.origins],
    expectedRPID: ctx.policy.passkey.rpId,
    requireUserVerification
  });

  if (!verification.verified) throw invalidPasskey();

  const { credential, credentialBackedUp, credentialDeviceType } = verification.registrationInfo;

  const credentialId = credential.id as unknown as WebAuthnCredentialId;

  await ctx.storage.webauthn.createCredential({
    id: credentialId,
    userId: ctx.input.userId,
    credentialId: credential.id,
    publicKey: credential.publicKey.slice(),
    counter: credential.counter,
    transports: credential.transports,
    credentialDeviceType,
    credentialBackedUp,
    createdAt: now
  });

  return { userId: ctx.input.userId, credentialId };
}

export async function startPasskeyLogin(ctx: {
  input: PasskeyLoginStartInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  randomBytes: RandomBytesFn;
}): Promise<PasskeyLoginStartResult> {
  const now = ctx.now();
  const challengeId = randomId(ctx.randomBytes, 16) as ChallengeId;
  const challenge = randomId(ctx.randomBytes, 32);
  const expiresAt = new Date(now.getTime() + ctx.policy.challenge.ttlMs);

  const allowCredentials =
    ctx.input.userId !== undefined
      ? (await ctx.storage.webauthn.listCredentialsForUser(ctx.input.userId)).map(c => ({
          id: c.credentialId,
          transports: c.transports
        }))
      : undefined;

  const options = await generateAuthenticationOptions({
    rpID: ctx.policy.passkey.rpId,
    challenge,
    allowCredentials,
    userVerification: ctx.policy.passkey.userVerification
  });

  await ctx.storage.challenges.createChallenge({
    id: challengeId,
    type: 'passkey_login',
    userId: ctx.input.userId,
    challenge: options.challenge,
    expiresAt
  });

  return { challengeId, options };
}

export async function finishPasskeyLogin(ctx: {
  input: PasskeyLoginFinishInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  createSessionToken: () => CreateSessionTokenResult;
  randomBytes: RandomBytesFn;
}): Promise<PasskeyLoginFinishResult> {
  const now = ctx.now();
  const stored = await ctx.storage.challenges.consumeChallenge(ctx.input.challengeId);
  if (!stored || stored.type !== 'passkey_login') throw invalidPasskey();
  if (stored.expiresAt.getTime() < now.getTime())
    throw new AuthError('challenge_expired', 'Passkey challenge expired');

  const credentialIdB64u = ctx.input.response.id;
  const record = await ctx.storage.webauthn.getCredentialById(
    credentialIdB64u as unknown as WebAuthnCredentialId
  );
  if (!record) throw invalidPasskey();
  if (stored.userId !== undefined && stored.userId !== record.userId) throw invalidPasskey();

  const requireUserVerification = ctx.policy.passkey.userVerification === 'required';

  const verification = await verifyAuthenticationResponse({
    response: ctx.input.response,
    expectedChallenge: stored.challenge,
    expectedOrigin: [...ctx.policy.passkey.origins],
    expectedRPID: [ctx.policy.passkey.rpId],
    credential: {
      id: record.credentialId,
      publicKey: record.publicKey.slice(),
      counter: record.counter,
      transports: record.transports
    },
    requireUserVerification,
    advancedFIDOConfig: {
      userVerification: ctx.policy.passkey.userVerification
    }
  });

  if (!verification.verified) throw invalidPasskey();

  await ctx.storage.webauthn.updateCredentialCounter(
    record.id,
    verification.authenticationInfo.newCounter,
    now
  );

  const totpEnabled = await ctx.storage.totp.getEnabled(record.userId);
  if (totpEnabled) {
    const pendingToken = await createTotpPending({
      userId: record.userId,
      storage: ctx.storage,
      now: () => now,
      randomBytes: ctx.randomBytes,
      ttlMs: ctx.policy.challenge.ttlMs
    });
    return { twoFactorRequired: true, userId: record.userId, pendingToken };
  }

  const session = ctx.createSessionToken();
  const expiresAt = new Date(now.getTime() + ctx.policy.session.absoluteTtlMs);
  await ctx.storage.sessions.createSession({
    tokenHash: session.sessionTokenHash,
    userId: record.userId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt
  });

  return { userId: record.userId, session };
}

function invalidPasskey(): AuthError {
  return new AuthError('passkey_invalid', 'Invalid passkey response', {
    publicMessage: 'Unable to sign in',
    status: 401
  });
}

function randomId(randomBytes: RandomBytesFn, size: number): string {
  const bytes = randomBytes(size);
  return toBase64Url(bytes);
}

function userHandleFromUserId(userId: UserId): Uint8Array_ {
  const h = createHash('sha256');
  h.update('user-handle:');
  h.update(userId as unknown as string);
  // `.slice()` normalizes Buffer's underlying ArrayBufferLike typing to match SimpleWebAuthn's Uint8Array_ helper type.
  return h.digest().slice();
}

function normalizeUserName(userName: string): string {
  if (typeof userName !== 'string')
    throw new AuthError('invalid_input', 'userName must be a string');
  const trimmed = userName.trim();
  if (!trimmed) throw new AuthError('invalid_input', 'userName is required');
  if (trimmed.length > 320) throw new AuthError('invalid_input', 'userName is too long');
  return trimmed;
}

function toBase64Url(buf: Uint8Array): string {
  // Node 20 supports base64url encoding, but this keeps output consistent across environments.
  return Buffer.from(buf)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}
