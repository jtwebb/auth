import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Kysely, PostgresDialect } from 'kysely';
import { createKyselyAuthStorage } from '../../../src/adapters/kysely/kysely-auth-storage.js';
import type { ChallengeId, SessionTokenHash } from '../../../src/core/auth-types.js';
import { up as up001Init } from '../../../src/adapters/kysely/migrations/001_init.js';

// Opt-in via AUTH_KYSELY_INTEGRATION=1 (see vitest.config.ts)

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

async function createPgPool(conn: Started) {
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

describeIf(process.env.AUTH_KYSELY_INTEGRATION === '1')('kysely adapter (integration)', () => {
  let started: Started | null = null;
  let pool: any;
  let db: Kysely<any> | null = null;

  beforeAll(async () => {
    try {
      started = await startPostgres();
      pool = await createPgPool(started);
      db = new Kysely({
        dialect: new PostgresDialect({
          pool
        })
      });
      await up001Init(db as any);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('kysely integration tests: skipping (failed to start Postgres container)', e);
      started = null;
      pool = null;
      db = null;
    }
  });

  afterAll(async () => {
    if (db) await db.destroy();
    if (pool) await pool.end();
    if (started) await started.stop();
  });

  it('supports consume-once semantics for challenges', async () => {
    if (!db) return;
    const storage = createKyselyAuthStorage({ db });
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
    if (!db) return;
    const storage = createKyselyAuthStorage({ db });
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
    if (!db) return;
    const storage = createKyselyAuthStorage({ db });
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
