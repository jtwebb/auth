import { describe, expect, it } from 'vitest';
import { createPgAuthStorage } from '../../../src/adapters/pg/pg-auth-storage.js';
import type { PgClient, PgPool } from '../../../src/adapters/pg/pg-types.js';
import type { SessionTokenHash, UserId } from '../../../src/core/auth-types.js';

function createMockPool() {
  const queries: Array<{ text: string; values?: readonly unknown[] }> = [];

  const client: PgClient = {
    async query(text, values) {
      queries.push({ text, values });
      return { rows: [], rowCount: 0 };
    },
    release() {}
  };

  const pool: PgPool = {
    async query(text, values) {
      queries.push({ text, values });
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      return client;
    }
  };

  return { pool, client, queries };
}

describe('pg adapter: createPgAuthStorage', () => {
  it('uses default table names', async () => {
    const { pool, queries } = createMockPool();
    const storage = createPgAuthStorage({ pool });

    await storage.users.getUserIdByIdentifier('a@example.com');

    expect(queries[0]?.text).toContain('FROM auth_users');
  });

  it('supports schema qualification + table prefix', async () => {
    const { pool, queries } = createMockPool();
    const storage = createPgAuthStorage({ pool, schema: 'app', tablePrefix: 'x_' });

    await storage.sessions.touchSession('hash' as unknown as SessionTokenHash, new Date());

    expect(queries[0]?.text).toContain('UPDATE app.x_auth_sessions');
  });

  it('supports overriding individual table names', async () => {
    const { pool, queries } = createMockPool();
    const storage = createPgAuthStorage({
      pool,
      tables: { users: 'my_users' }
    });

    await storage.users.getUserIdByIdentifier('a@example.com');

    expect(queries[0]?.text).toContain('FROM my_users');
  });

  it('manages transactions internally for rotateSession', async () => {
    const { pool, queries } = createMockPool();
    const storage = createPgAuthStorage({ pool });

    await storage.sessions.rotateSession(
      'old' as unknown as SessionTokenHash,
      {
        tokenHash: 'new' as unknown as SessionTokenHash,
        userId: 'u' as unknown as UserId,
        createdAt: new Date(),
        expiresAt: new Date()
      },
      new Date()
    );

    expect(queries.map(q => q.text)).toEqual(expect.arrayContaining(['BEGIN', 'COMMIT']));
  });
});
