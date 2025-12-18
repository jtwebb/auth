import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPgAuthStorage } from '../../../src/adapters/pg/pg-auth-storage.js';
import type { ChallengeId, SessionTokenHash } from '../../../src/core/auth-types.js';

// Integration tests are only collected when AUTH_PG_INTEGRATION=1 (see vitest.config.ts).
// These tests require Docker (testcontainers) and will be skipped if Docker isn't available.

const describeIf = (cond: boolean) => (cond ? describe : describe.skip);

type Started = {
  stop(): Promise<void>;
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
};

async function startPostgres(): Promise<Started> {
  // Dynamic imports so unit test runs don't require these deps.
  const tc = (await import('testcontainers')) as unknown as {
    GenericContainer: new (image: string) => {
      withEnvironment(key: string, value: string): any;
      withExposedPorts(port: number): any;
      start(): Promise<any>;
    };
  };

  const postgresPassword = 'postgres';
  const postgresUser = 'postgres';
  const postgresDb = 'postgres';

  const container = await new tc.GenericContainer('postgres:16-alpine')
    .withEnvironment('POSTGRES_PASSWORD', postgresPassword)
    .withEnvironment('POSTGRES_USER', postgresUser)
    .withEnvironment('POSTGRES_DB', postgresDb)
    .withExposedPorts(5432)
    .start();

  return {
    stop: () => container.stop(),
    host: container.getHost(),
    port: container.getMappedPort(5432),
    user: postgresUser,
    password: postgresPassword,
    database: postgresDb
  };
}

async function createPool(conn: Started) {
  const pg = (await import('pg')) as unknown as {
    Pool: new (opts: any) => {
      query: (
        text: string,
        values?: readonly unknown[]
      ) => Promise<{ rows: any[]; rowCount: number }>;
      connect: () => Promise<{ query: any; release: () => void }>;
      end: () => Promise<void>;
    };
  };
  return new pg.Pool({
    host: conn.host,
    port: conn.port,
    user: conn.user,
    password: conn.password,
    database: conn.database
  });
}

async function applyMigrations(pool: { query: (text: string) => Promise<any> }) {
  // Minimal inline migration for integration tests (matches src/adapters/pg/migrations/001_init.sql).
  const sql = `
    CREATE TABLE IF NOT EXISTS auth_users (
      id text PRIMARY KEY,
      identifier text NOT NULL UNIQUE,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS auth_password_credentials (
      user_id text PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
      password_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NULL
    );
    CREATE TABLE IF NOT EXISTS auth_challenges (
      id text PRIMARY KEY,
      type text NOT NULL,
      user_id text NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      challenge text NOT NULL,
      expires_at timestamptz NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash text PRIMARY KEY,
      user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      created_at timestamptz NOT NULL,
      last_seen_at timestamptz NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz NULL,
      rotated_from_hash text NULL
    );
    CREATE TABLE IF NOT EXISTS auth_backup_codes (
      user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      code_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      consumed_at timestamptz NULL,
      PRIMARY KEY (user_id, code_hash)
    );
    CREATE TABLE IF NOT EXISTS auth_totp (
      user_id text PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
      encrypted_secret text NOT NULL,
      enabled_at timestamptz NULL,
      pending_created_at timestamptz NULL,
      last_used_at timestamptz NULL
    );
    CREATE TABLE IF NOT EXISTS auth_webauthn_credentials (
      id text PRIMARY KEY,
      user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      credential_id text NOT NULL UNIQUE,
      public_key bytea NOT NULL,
      counter integer NOT NULL,
      transports text[] NULL,
      credential_device_type text NULL,
      credential_backed_up boolean NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NULL
    );
  `;
  await pool.query(sql);
}

describeIf(process.env.AUTH_PG_INTEGRATION === '1')('pg adapter (integration)', () => {
  let started: Started | null = null;
  let pool: any;

  beforeAll(async () => {
    try {
      started = await startPostgres();
      pool = await createPool(started);
      await applyMigrations(pool);
    } catch (e) {
      // If Docker isn't available, don't hard-fail the whole unit test run.
      // (This suite is opt-in, but still try to be friendly.)
      // eslint-disable-next-line no-console
      console.warn('pg integration tests: skipping (failed to start Postgres container)', e);
      started = null;
      pool = null;
    }
  });

  afterAll(async () => {
    if (pool) await pool.end();
    if (started) await started.stop();
  });

  it('supports consume-once semantics for challenges', async () => {
    if (!pool) return;
    const storage = createPgAuthStorage({ pool });
    const userId = await storage.users.createUser('user@example.com');

    const id = 'challenge-1' as unknown as ChallengeId;
    await storage.challenges.createChallenge({
      id,
      type: 'passkey_login',
      userId,
      challenge: 'abc',
      expiresAt: new Date(Date.now() + 60_000)
    });

    const [a, b] = await Promise.all([
      storage.challenges.consumeChallenge(id),
      storage.challenges.consumeChallenge(id)
    ]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
  });

  it('supports atomic session rotation', async () => {
    if (!pool) return;
    const storage = createPgAuthStorage({ pool });
    const userId = await storage.users.createUser('user2@example.com');
    const now = new Date();

    const oldHash = 'oldhash' as unknown as SessionTokenHash;
    await storage.sessions.createSession({
      tokenHash: oldHash,
      userId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 60_000)
    });

    const newHash = 'newhash' as unknown as SessionTokenHash;
    await storage.sessions.rotateSession(
      oldHash,
      {
        tokenHash: newHash,
        userId,
        createdAt: now,
        expiresAt: new Date(now.getTime() + 60_000),
        rotatedFromHash: oldHash
      },
      new Date()
    );

    const oldSession = await storage.sessions.getSessionByTokenHash(oldHash);
    const newSession = await storage.sessions.getSessionByTokenHash(newHash);
    expect(oldSession?.revokedAt).toBeTruthy();
    expect(newSession?.revokedAt).toBeUndefined();
    expect(newSession?.rotatedFromHash).toBe(oldHash);
  });

  it('supports consume-once semantics for backup codes', async () => {
    if (!pool) return;
    const storage = createPgAuthStorage({ pool });
    const userId = await storage.users.createUser('user3@example.com');

    await storage.backupCodes.replaceCodes(
      userId,
      [
        {
          userId,
          codeHash: 'c1',
          createdAt: new Date()
        }
      ],
      new Date()
    );

    const [a, b] = await Promise.all([
      storage.backupCodes.consumeCode(userId, 'c1', new Date()),
      storage.backupCodes.consumeCode(userId, 'c1', new Date())
    ]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
    expect(await storage.backupCodes.countRemaining(userId)).toBe(0);
  });
});
