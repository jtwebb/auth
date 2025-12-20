import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';
import type {
  ChallengeId,
  SessionTokenHash,
  UserId,
  WebAuthnCredentialId
} from '../../core/auth-types.js';
import type {
  AuthStorage,
  BackupCodeRecord,
  PasswordCredentialRecord,
  SessionRecord,
  StoredChallenge,
  WebAuthnCredentialRecord
} from '../../core/storage/auth-storage.js';
import type { KyselyDb, KyselyTx } from './kysely-types.js';

export type KyselyAuthTables = {
  users: string;
  passwordCredentials: string;
  webauthnCredentials: string;
  challenges: string;
  sessions: string;
  backupCodes: string;
  totp: string;
};

export type CreateKyselyAuthStorageOptions = {
  db: KyselyDb;
  /**
   * Optional table prefix applied to default table names.
   */
  tablePrefix?: string;
  /**
   * Override individual table names.
   *
   * Note: for Kysely, we keep these unqualified (no schema support here) to avoid coupling to
   * dialect-specific quoting/qualification rules. If you need schema, prefer `db.withSchema(...)`
   * before passing it in.
   */
  tables?: Partial<KyselyAuthTables>;
  now?: () => Date;
  logger?: { debug(message: string, meta?: Record<string, unknown>): void };
};

/**
 * Kysely adapter for AuthStorage.
 *
 * Notes:
 * - This implementation assumes Postgres-like support for `returning(...)` for the consume-once operations.
 * - For schema support, pass `db.withSchema('your_schema')` as `db`.
 */
export function createKyselyAuthStorage(options: CreateKyselyAuthStorageOptions): AuthStorage {
  const now = options.now ?? (() => new Date());
  const tables = resolveTables(options);

  const debug = (message: string, meta?: Record<string, unknown>) => {
    options.logger?.debug(message, meta);
  };

  const withTx = async <T>(fn: (tx: KyselyTx) => Promise<T>): Promise<T> =>
    options.db.transaction().execute(fn);

  return {
    users: {
      async getUserIdByIdentifier(identifier: string) {
        const row = await options.db
          .selectFrom(tables.users)
          .select(['id'])
          .where('identifier', '=', identifier)
          .executeTakeFirst();
        const id = toOptionalString(getField(row, 'id'));
        return id ? asUserId(id) : null;
      },

      async createUser(identifier: string) {
        const id = randomUUID();
        await options.db
          .insertInto(tables.users)
          .values({ id, identifier, createdAt: now() })
          .execute();
        return asUserId(id);
      }
    },

    passwordCredentials: {
      async getForUser(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.passwordCredentials)
          .select(['userId', 'passwordHash', 'createdAt', 'updatedAt'])
          .where('userId', '=', userId as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: PasswordCredentialRecord = {
          userId: asUserId(toString(getField(r, 'userId'))),
          passwordHash: toString(getField(r, 'passwordHash')),
          createdAt: toDate(getField(r, 'createdAt')),
          updatedAt: toOptionalDate(getField(r, 'updatedAt'))
        };
        return out;
      },

      async upsertForUser(record: PasswordCredentialRecord) {
        // Postgres: ON CONFLICT (userId) DO UPDATE ...
        await options.db
          .insertInto(tables.passwordCredentials)
          .values({
            userId: record.userId as unknown as string,
            passwordHash: record.passwordHash,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt ?? null
          })
          .onConflict(oc =>
            oc.column('userId').doUpdateSet({
              passwordHash: record.passwordHash,
              updatedAt: record.updatedAt ?? null
            })
          )
          .execute();
      }
    },

    challenges: {
      async createChallenge(ch: StoredChallenge) {
        await options.db
          .insertInto(tables.challenges)
          .values({
            id: ch.id as unknown as string,
            type: ch.type,
            userId: (ch.userId ?? null) as unknown as string | null,
            challenge: ch.challenge,
            expiresAt: ch.expiresAt
          })
          .execute();
      },

      async consumeChallenge(id: ChallengeId) {
        const r = await options.db
          .deleteFrom(tables.challenges)
          .where('id', '=', id as unknown as string)
          .returning(['id', 'type', 'userId', 'challenge', 'expiresAt'])
          .executeTakeFirst();
        if (!r) return null;
        const out: StoredChallenge = {
          id: asChallengeId(toString(getField(r, 'id'))),
          type: toString(getField(r, 'type')) as StoredChallenge['type'],
          userId: (() => {
            const uid = toOptionalString(getField(r, 'userId'));
            return uid ? asUserId(uid) : undefined;
          })(),
          challenge: toString(getField(r, 'challenge')),
          expiresAt: toDate(getField(r, 'expiresAt'))
        };
        return out;
      }
    },

    totp: {
      async getEnabled(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.totp)
          .select(['encryptedSecret', 'enabledAt', 'lastUsedAt', 'lastUsedStep'])
          .where('userId', '=', userId as unknown as string)
          .where('enabledAt', 'is not', null)
          .executeTakeFirst();
        if (!r) return null;
        return {
          encryptedSecret: toString(getField(r, 'encryptedSecret')),
          enabledAt: toDate(getField(r, 'enabledAt')),
          lastUsedAt: toOptionalDate(getField(r, 'lastUsedAt')),
          lastUsedStep: (() => {
            const v = getField(r, 'lastUsedStep');
            if (v == null) return undefined;
            const n = typeof v === 'number' ? v : Number(v);
            return Number.isFinite(n) ? n : undefined;
          })()
        };
      },

      async getPending(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.totp)
          .select(['encryptedSecret', 'pendingCreatedAt'])
          .where('userId', '=', userId as unknown as string)
          .where('enabledAt', 'is', null)
          .where('pendingCreatedAt', 'is not', null)
          .executeTakeFirst();
        if (!r) return null;
        return {
          encryptedSecret: toString(getField(r, 'encryptedSecret')),
          createdAt: toDate(getField(r, 'pendingCreatedAt'))
        };
      },

      async setPending(userId: UserId, encryptedSecret: string, createdAt: Date) {
        await options.db
          .insertInto(tables.totp)
          .values({
            userId: userId as unknown as string,
            encryptedSecret: encryptedSecret,
            enabledAt: null,
            pendingCreatedAt: createdAt,
            lastUsedAt: null,
            lastUsedStep: null
          })
          .onConflict(oc =>
            oc.column('userId').doUpdateSet({
              encryptedSecret: encryptedSecret,
              enabledAt: null,
              pendingCreatedAt: createdAt,
              lastUsedAt: null,
              lastUsedStep: null
            })
          )
          .execute();
      },

      async enableFromPending(userId: UserId, enabledAt: Date) {
        await options.db
          .updateTable(tables.totp)
          .set({ enabledAt: enabledAt, pendingCreatedAt: null })
          .where('userId', '=', userId as unknown as string)
          .where('enabledAt', 'is', null)
          .where('pendingCreatedAt', 'is not', null)
          .execute();
      },

      async disable(userId: UserId, disabledAt: Date) {
        debug('totp.disable', { userId, disabledAt: disabledAt.toISOString() });
        await options.db
          .deleteFrom(tables.totp)
          .where('userId', '=', userId as unknown as string)
          .execute();
      },

      async updateLastUsedAt(userId: UserId, lastUsedAt: Date) {
        await options.db
          .updateTable(tables.totp)
          .set({ lastUsedAt: lastUsedAt })
          .where('userId', '=', userId as unknown as string)
          .execute();
      },

      async updateLastUsedStepIfGreater({ userId, step, usedAt }) {
        const r = await options.db
          .updateTable(tables.totp)
          .set({ lastUsedStep: step, lastUsedAt: usedAt })
          .where('userId', '=', userId as unknown as string)
          .where('enabledAt', 'is not', null)
          .where(eb =>
            eb.or([eb('lastUsedStep', 'is', null), eb('lastUsedStep', '<', step as unknown as any)])
          )
          .returning(['userId'])
          .executeTakeFirst();
        return Boolean(r);
      }
    },

    sessions: {
      async createSession(s: SessionRecord) {
        await options.db
          .insertInto(tables.sessions)
          .values({
            tokenHash: s.tokenHash as unknown as string,
            userId: s.userId as unknown as string,
            createdAt: s.createdAt,
            lastSeenAt: s.lastSeenAt ?? null,
            expiresAt: s.expiresAt,
            revokedAt: s.revokedAt ?? null,
            rotatedFromHash: (s.rotatedFromHash ?? null) as unknown as string | null,
            clientIdHash: s.clientIdHash ?? null,
            userAgentHash: s.userAgentHash ?? null
          })
          .execute();
      },

      async getSessionByTokenHash(tokenHash: SessionTokenHash) {
        const r = await options.db
          .selectFrom(tables.sessions)
          .select([
            'tokenHash',
            'userId',
            'createdAt',
            'lastSeenAt',
            'expiresAt',
            'revokedAt',
            'rotatedFromHash',
            'clientIdHash',
            'userAgentHash'
          ])
          .where('tokenHash', '=', tokenHash as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: SessionRecord = {
          tokenHash: asSessionTokenHash(toString(getField(r, 'tokenHash'))),
          userId: asUserId(toString(getField(r, 'userId'))),
          createdAt: toDate(getField(r, 'createdAt')),
          lastSeenAt: toOptionalDate(getField(r, 'lastSeenAt')),
          expiresAt: toDate(getField(r, 'expiresAt')),
          revokedAt: toOptionalDate(getField(r, 'revokedAt')),
          rotatedFromHash: (() => {
            const rot = toOptionalString(getField(r, 'rotatedFromHash'));
            return rot ? asSessionTokenHash(rot) : undefined;
          })(),
          clientIdHash: toOptionalString(getField(r, 'clientIdHash')),
          userAgentHash: toOptionalString(getField(r, 'userAgentHash'))
        };
        return out;
      },

      async listSessionsForUser(userId: UserId) {
        const rows = await options.db
          .selectFrom(tables.sessions)
          .select([
            'tokenHash',
            'userId',
            'createdAt',
            'lastSeenAt',
            'expiresAt',
            'revokedAt',
            'rotatedFromHash',
            'clientIdHash',
            'userAgentHash'
          ])
          .where('userId', '=', userId as unknown as string)
          .orderBy('createdAt', 'desc')
          .execute();
        return rows.map(
          (r: unknown): SessionRecord => ({
            tokenHash: asSessionTokenHash(toString(getField(r, 'tokenHash'))),
            userId: asUserId(toString(getField(r, 'userId'))),
            createdAt: toDate(getField(r, 'createdAt')),
            lastSeenAt: toOptionalDate(getField(r, 'lastSeenAt')),
            expiresAt: toDate(getField(r, 'expiresAt')),
            revokedAt: toOptionalDate(getField(r, 'revokedAt')),
            rotatedFromHash: (() => {
              const rot = toOptionalString(getField(r, 'rotatedFromHash'));
              return rot ? asSessionTokenHash(rot) : undefined;
            })(),
            clientIdHash: toOptionalString(getField(r, 'clientIdHash')),
            userAgentHash: toOptionalString(getField(r, 'userAgentHash'))
          })
        );
      },

      async touchSession(tokenHash: SessionTokenHash, lastSeenAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ lastSeenAt })
          .where('tokenHash', '=', tokenHash as unknown as string)
          .where('revokedAt', 'is', null)
          .execute();
      },

      async revokeSession(tokenHash: SessionTokenHash, revokedAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ revokedAt })
          .where('tokenHash', '=', tokenHash as unknown as string)
          .execute();
      },

      async revokeAllUserSessions(userId: UserId, revokedAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ revokedAt })
          .where('userId', '=', userId as unknown as string)
          .execute();
      },

      async revokeAllUserSessionsExceptTokenHash(
        userId: UserId,
        exceptTokenHash: SessionTokenHash,
        revokedAt: Date
      ) {
        await options.db
          .updateTable(tables.sessions)
          .set({ revokedAt })
          .where('userId', '=', userId as unknown as string)
          .where('tokenHash', '<>', exceptTokenHash as unknown as string)
          .where('revokedAt', 'is', null)
          .execute();
      },

      async rotateSession(
        oldTokenHash: SessionTokenHash,
        newSession: SessionRecord,
        revokedAt: Date
      ) {
        await withTx(async tx => {
          await tx
            .insertInto(tables.sessions)
            .values({
              tokenHash: newSession.tokenHash as unknown as string,
              userId: newSession.userId as unknown as string,
              createdAt: newSession.createdAt,
              lastSeenAt: newSession.lastSeenAt ?? null,
              expiresAt: newSession.expiresAt,
              revokedAt: null,
              rotatedFromHash: (newSession.rotatedFromHash ?? null) as unknown as string | null,
              clientIdHash: newSession.clientIdHash ?? null,
              userAgentHash: newSession.userAgentHash ?? null
            })
            .execute();
          await tx
            .updateTable(tables.sessions)
            .set({ revokedAt })
            .where('tokenHash', '=', oldTokenHash as unknown as string)
            .execute();
        });
      }
    },

    backupCodes: {
      async replaceCodes(userId: UserId, codes: BackupCodeRecord[], rotatedAt: Date) {
        debug('backupCodes.replaceCodes', {
          userId,
          rotatedAt: rotatedAt.toISOString(),
          count: codes.length
        });
        await withTx(async tx => {
          await tx
            .deleteFrom(tables.backupCodes)
            .where('userId', '=', userId as unknown as string)
            .execute();
          for (const c of codes) {
            await tx
              .insertInto(tables.backupCodes)
              .values({
                userId: c.userId as unknown as string,
                codeHash: c.codeHash,
                createdAt: c.createdAt,
                consumedAt: null
              })
              .execute();
          }
        });
      },

      async consumeCode(userId: UserId, codeHash: string, consumedAt: Date) {
        const r = await options.db
          .updateTable(tables.backupCodes)
          .set({ consumedAt })
          .where('userId', '=', userId as unknown as string)
          .where('codeHash', '=', codeHash)
          .where('consumedAt', 'is', null)
          .returning(['userId'])
          .executeTakeFirst();
        return Boolean(r);
      },

      async countRemaining(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.backupCodes)
          .select(sql<number>`count(*)`.as('n'))
          .where('userId', '=', userId as unknown as string)
          .where('consumedAt', 'is', null)
          .executeTakeFirst();
        const n = getField(r, 'n');
        return Number(n ?? 0);
      }
    },

    webauthn: {
      async listCredentialsForUser(userId: UserId) {
        const rows = await options.db
          .selectFrom(tables.webauthnCredentials)
          .select([
            'id',
            'userId',
            'credentialId',
            'publicKey',
            'counter',
            'transports',
            'credentialDeviceType',
            'credentialBackedUp',
            'createdAt',
            'updatedAt'
          ])
          .where('userId', '=', userId as unknown as string)
          .execute();
        return rows.map(
          (r: unknown): WebAuthnCredentialRecord => ({
            id: asWebAuthnCredentialId(toString(getField(r, 'id'))),
            userId: asUserId(toString(getField(r, 'userId'))),
            credentialId: toString(getField(r, 'credentialId')),
            publicKey: toUint8Array(getField(r, 'publicKey')),
            counter: Number(getField(r, 'counter')),
            transports: (toOptionalStringArray(getField(r, 'transports')) ?? undefined) as
              | AuthenticatorTransportFuture[]
              | undefined,
            credentialDeviceType: (toOptionalString(getField(r, 'credentialDeviceType')) ??
              undefined) as CredentialDeviceType | undefined,
            credentialBackedUp: toOptionalBoolean(getField(r, 'credentialBackedUp')),
            createdAt: toDate(getField(r, 'createdAt')),
            updatedAt: toOptionalDate(getField(r, 'updatedAt'))
          })
        );
      },

      async getCredentialById(id: WebAuthnCredentialId) {
        const r = await options.db
          .selectFrom(tables.webauthnCredentials)
          .select([
            'id',
            'userId',
            'credentialId',
            'publicKey',
            'counter',
            'transports',
            'credentialDeviceType',
            'credentialBackedUp',
            'createdAt',
            'updatedAt'
          ])
          .where('id', '=', id as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: WebAuthnCredentialRecord = {
          id: asWebAuthnCredentialId(toString(getField(r, 'id'))),
          userId: asUserId(toString(getField(r, 'userId'))),
          credentialId: toString(getField(r, 'credentialId')),
          publicKey: toUint8Array(getField(r, 'publicKey')),
          counter: Number(getField(r, 'counter')),
          transports: (toOptionalStringArray(getField(r, 'transports')) ?? undefined) as
            | AuthenticatorTransportFuture[]
            | undefined,
          credentialDeviceType: (toOptionalString(getField(r, 'credentialDeviceType')) ??
            undefined) as CredentialDeviceType | undefined,
          credentialBackedUp: toOptionalBoolean(getField(r, 'credentialBackedUp')),
          createdAt: toDate(getField(r, 'createdAt')),
          updatedAt: toOptionalDate(getField(r, 'updatedAt'))
        };
        return out;
      },

      async createCredential(record: WebAuthnCredentialRecord) {
        await options.db
          .insertInto(tables.webauthnCredentials)
          .values({
            id: record.id as unknown as string,
            userId: record.userId as unknown as string,
            credentialId: record.credentialId,
            publicKey: Buffer.from(record.publicKey),
            counter: record.counter,
            transports: (record.transports ?? null) as unknown as string[] | null,
            credentialDeviceType: (record.credentialDeviceType ?? null) as unknown as string | null,
            credentialBackedUp: record.credentialBackedUp ?? null,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt ?? null
          })
          .execute();
      },

      async updateCredentialCounter(id: WebAuthnCredentialId, counter: number, updatedAt: Date) {
        await options.db
          .updateTable(tables.webauthnCredentials)
          .set({ counter, updatedAt: updatedAt })
          .where('id', '=', id as unknown as string)
          .execute();
      }
    }
  };
}

function toDate(v: unknown): Date {
  if (v instanceof Date) return v;
  if (typeof v === 'string' || typeof v === 'number') return new Date(v);
  throw new TypeError('Expected Date|string|number');
}

function toOptionalDate(v: unknown): Date | undefined {
  if (v == null) return undefined;
  return toDate(v);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function getField(row: unknown, key: string): unknown {
  if (!isRecord(row)) return undefined;
  return row[key];
}

function toString(v: unknown): string {
  return typeof v === 'string' ? v : String(v ?? '');
}

function toOptionalString(v: unknown): string | undefined {
  if (v == null) return undefined;
  return typeof v === 'string' ? v : String(v);
}

function toOptionalBoolean(v: unknown): boolean | undefined {
  if (v == null) return undefined;
  if (typeof v === 'boolean') return v;
  return undefined;
}

function toOptionalStringArray(v: unknown): string[] | undefined {
  if (v == null) return undefined;
  if (Array.isArray(v) && v.every(x => typeof x === 'string')) return v;
  return undefined;
}

function toUint8Array(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new TypeError('Expected Uint8Array/Buffer/ArrayBuffer for bytea');
}

function asUserId(v: string): UserId {
  return v as UserId;
}
function asChallengeId(v: string): ChallengeId {
  return v as ChallengeId;
}
function asSessionTokenHash(v: string): SessionTokenHash {
  return v as SessionTokenHash;
}
function asWebAuthnCredentialId(v: string): WebAuthnCredentialId {
  return v as WebAuthnCredentialId;
}

function resolveTables(options: CreateKyselyAuthStorageOptions): KyselyAuthTables {
  const prefix = options.tablePrefix ?? '';
  const defaults: KyselyAuthTables = {
    users: `${prefix}authUsers`,
    passwordCredentials: `${prefix}authPasswordCredentials`,
    webauthnCredentials: `${prefix}authWebauthnCredentials`,
    challenges: `${prefix}authChallenges`,
    sessions: `${prefix}authSessions`,
    backupCodes: `${prefix}authBackupCodes`,
    totp: `${prefix}authTotp`
  };
  return { ...defaults, ...(options.tables ?? {}) };
}
