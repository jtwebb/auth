import { describe, expect, it } from 'vitest';
import { createKyselyAuthStorage } from '../../../src/adapters/kysely/kysely-auth-storage.js';
import type { KyselyDb } from '../../../src/adapters/kysely/kysely-types.js';
import type { SessionTokenHash, UserId } from '../../../src/core/auth-types.js';

function createMockDb() {
  const calls: Array<{ op: string; table: string }> = [];

  const makeChain = (op: string, table: string) => {
    calls.push({ op, table });
    const chain: any = {
      select: () => chain,
      where: () => chain,
      values: () => chain,
      onConflict: () => chain,
      doUpdateSet: () => chain,
      set: () => chain,
      returning: () => chain,
      execute: async () => ({ rows: [], numUpdatedRows: 0n }),
      executeTakeFirst: async () => undefined
    };
    return chain;
  };

  const db: KyselyDb<any> = {
    selectFrom: (table: string) => makeChain('selectFrom', table),
    insertInto: (table: string) => makeChain('insertInto', table),
    deleteFrom: (table: string) => makeChain('deleteFrom', table),
    updateTable: (table: string) => makeChain('updateTable', table),
    transaction: () => ({
      execute: async (fn: any) => fn(db)
    })
  };

  return { db, calls };
}

describe('kysely adapter: createKyselyAuthStorage (smoke)', () => {
  it('uses default table names', async () => {
    const { db, calls } = createMockDb();
    const storage = createKyselyAuthStorage({ db });

    await storage.users.getUserIdByIdentifier('a@example.com');
    expect(calls[0]).toEqual({ op: 'selectFrom', table: 'authUsers' });
  });

  it('supports tablePrefix and internal transactions', async () => {
    const { db, calls } = createMockDb();
    const storage = createKyselyAuthStorage({ db, tablePrefix: 'x_' });

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

    expect(calls.some(c => c.table === 'x_authSessions')).toBe(true);
  });
});
