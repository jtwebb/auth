import { describe, expect, it } from 'vitest';
import {
  hashPassword,
  parseEncodedHash,
  verifyPassword
} from '../../../src/core/password/password-hash.js';

describe('core/password/password-hash', () => {
  it('hashes and verifies a password', async () => {
    const encoded = await hashPassword('correct horse battery staple');
    expect(encoded.startsWith('$argon2id$')).toBe(true);

    const ok = await verifyPassword('correct horse battery staple', encoded);
    expect(ok.ok).toBe(true);
  });

  it('rejects a wrong password', async () => {
    const encoded = await hashPassword('pw-1');
    const res = await verifyPassword('pw-2', encoded);
    expect(res.ok).toBe(false);
  });

  it('pepper changes verification outcome', async () => {
    const encoded = await hashPassword('pw', { pepper: 'pep' });
    expect((await verifyPassword('pw', encoded, { pepper: 'pep' })).ok).toBe(true);
    expect((await verifyPassword('pw', encoded, { pepper: 'wrong' })).ok).toBe(false);
  });

  it('parses encoded hash', async () => {
    const encoded = await hashPassword('pw');
    const parsed = parseEncodedHash(encoded);
    expect(parsed.kind).toBe('argon2id');
    if (parsed.kind === 'argon2id') {
      expect(parsed.params.memoryCost).toBeGreaterThan(0);
    }
  });

  it('signals needsRehash when desired params are stronger', async () => {
    const encoded = await hashPassword('pw', { params: { memoryCost: 8192 } });
    const res = await verifyPassword('pw', encoded, { desiredParams: { memoryCost: 16384 } });
    expect(res.ok).toBe(true);
    expect(res.needsRehash).toBe(true);
  });
});
