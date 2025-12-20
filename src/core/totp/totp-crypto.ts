import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { AuthError } from '../auth-error.js';
import type { RandomBytesFn } from '../create-auth-core.js';
import type { UserId } from '../auth-types.js';

export type TotpEncryptionKeyMaterial = string | Uint8Array;
export type TotpEncryptionKeyRing = {
  /**
   * The key id used for new encryptions.
   */
  primaryKeyId: string;
  /**
   * Key material by id. Keep these in a secrets manager/KMS.
   */
  keys: Record<string, TotpEncryptionKeyMaterial>;
};

/**
 * - **Legacy**: a single key (string/bytes) encrypts/decrypts "v1" ciphertexts (no key id).
 * - **Key ring**: supports encrypting "v2" ciphertexts with a key id, while decrypting v1+v2.
 */
export type TotpEncryptionKey = TotpEncryptionKeyMaterial | TotpEncryptionKeyRing;

export function encryptTotpSecret(ctx: {
  userId: UserId;
  secretBase32: string;
  key: TotpEncryptionKey;
  randomBytes?: RandomBytesFn;
}): string {
  const iv = (ctx.randomBytes ?? randomBytes)(12);
  const userId = ctx.userId as unknown as string;

  // v2: key ring with explicit key id
  if (isKeyRing(ctx.key)) {
    const keyMaterial = ctx.key.keys[ctx.key.primaryKeyId];
    if (keyMaterial === undefined) {
      throw new AuthError('invalid_input', 'TOTP key ring missing primaryKeyId material');
    }
    const key = deriveKey(keyMaterial);
    const kid = ctx.key.primaryKeyId;
    const aad = Buffer.from(`totp-secret:v2:${userId}:${kid}`, 'utf8');

    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(ctx.secretBase32, 'utf8')),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    return `v2.${kid}.${b64u(iv)}.${b64u(tag)}.${b64u(ciphertext)}`;
  }

  // v1: legacy single-key ciphertext (no key id)
  const key = deriveKey(ctx.key);
  const aad = Buffer.from(`totp-secret:v1:${userId}`, 'utf8');

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(ctx.secretBase32, 'utf8')),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();
  return `${b64u(iv)}.${b64u(tag)}.${b64u(ciphertext)}`;
}

export function decryptTotpSecret(ctx: {
  userId: UserId;
  encryptedSecret: string;
  key: TotpEncryptionKey;
}): string {
  const userId = ctx.userId as unknown as string;
  const parts = ctx.encryptedSecret.split('.');

  // v2.<kid>.<iv>.<tag>.<ct>
  if (parts[0] === 'v2') {
    const kid = parts[1];
    const ivB64u = parts[2];
    const tagB64u = parts[3];
    const ctB64u = parts[4];
    if (!kid || !ivB64u || !tagB64u || !ctB64u || parts.length !== 5) {
      throw new AuthError('invalid_input', 'Invalid encrypted TOTP secret');
    }
    if (!isKeyRing(ctx.key)) {
      throw new AuthError('invalid_input', 'TOTP key ring is required to decrypt v2 secrets');
    }
    const material = ctx.key.keys[kid];
    if (material === undefined) {
      throw new AuthError('invalid_input', 'Unknown TOTP key id');
    }
    const iv = fromB64u(ivB64u);
    const tag = fromB64u(tagB64u);
    const ct = fromB64u(ctB64u);

    const key = deriveKey(material);
    const aad = Buffer.from(`totp-secret:v2:${userId}:${kid}`, 'utf8');
    return decryptAesGcm({ key, iv, tag, ct, aad });
  }

  // v1: <iv>.<tag>.<ct> (no key id). If a key ring is provided, try each key.
  const ivB64u = parts[0];
  const tagB64u = parts[1];
  const ctB64u = parts[2];
  if (!ivB64u || !tagB64u || !ctB64u || parts.length !== 3) {
    throw new AuthError('invalid_input', 'Invalid encrypted TOTP secret');
  }
  const iv = fromB64u(ivB64u);
  const tag = fromB64u(tagB64u);
  const ct = fromB64u(ctB64u);
  const aad = Buffer.from(`totp-secret:v1:${userId}`, 'utf8');

  if (isKeyRing(ctx.key)) {
    for (const material of Object.values(ctx.key.keys)) {
      const key = deriveKey(material);
      const out = tryDecryptAesGcm({ key, iv, tag, ct, aad });
      if (out !== null) return out;
    }
    throw new AuthError('internal_error', 'Failed to decrypt TOTP secret');
  }
  const key = deriveKey(ctx.key);
  return decryptAesGcm({ key, iv, tag, ct, aad });
}

function isKeyRing(key: TotpEncryptionKey): key is TotpEncryptionKeyRing {
  return typeof key === 'object' && key !== null && 'primaryKeyId' in key && 'keys' in key;
}

function decryptAesGcm(ctx: {
  key: Buffer;
  iv: Buffer;
  tag: Buffer;
  ct: Buffer;
  aad: Buffer;
}): string {
  const decipher = createDecipheriv('aes-256-gcm', ctx.key, ctx.iv);
  decipher.setAAD(ctx.aad);
  decipher.setAuthTag(ctx.tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ctx.ct), decipher.final()]);
    return plaintext.toString('utf8');
  } catch (cause) {
    throw new AuthError('internal_error', 'Failed to decrypt TOTP secret', { cause });
  }
}

function tryDecryptAesGcm(ctx: {
  key: Buffer;
  iv: Buffer;
  tag: Buffer;
  ct: Buffer;
  aad: Buffer;
}): string | null {
  const decipher = createDecipheriv('aes-256-gcm', ctx.key, ctx.iv);
  decipher.setAAD(ctx.aad);
  decipher.setAuthTag(ctx.tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ctx.ct), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    return null;
  }
}

function deriveKey(keyMaterial: TotpEncryptionKeyMaterial): Buffer {
  // Developer-friendly: accept string or bytes and derive a fixed 32-byte key via SHA-256.
  const buf =
    typeof keyMaterial === 'string' ? Buffer.from(keyMaterial, 'utf8') : Buffer.from(keyMaterial);
  return createHash('sha256').update(buf).digest();
}

function b64u(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

function fromB64u(s: string): Buffer {
  const padded = s.replaceAll('-', '+').replaceAll('_', '/') + '==='.slice((s.length + 3) % 4);
  return Buffer.from(padded, 'base64');
}
