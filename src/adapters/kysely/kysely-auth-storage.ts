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
          .values({ id, identifier, created_at: now() })
          .execute();
        return asUserId(id);
      }
    },

    passwordCredentials: {
      async getForUser(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.passwordCredentials)
          .select(['user_id', 'password_hash', 'created_at', 'updated_at'])
          .where('user_id', '=', userId as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: PasswordCredentialRecord = {
          userId: asUserId(toString(getField(r, 'user_id'))),
          passwordHash: toString(getField(r, 'password_hash')),
          createdAt: toDate(getField(r, 'created_at')),
          updatedAt: toOptionalDate(getField(r, 'updated_at'))
        };
        return out;
      },

      async upsertForUser(record: PasswordCredentialRecord) {
        // Postgres: ON CONFLICT (user_id) DO UPDATE ...
        await options.db
          .insertInto(tables.passwordCredentials)
          .values({
            user_id: record.userId as unknown as string,
            password_hash: record.passwordHash,
            created_at: record.createdAt,
            updated_at: record.updatedAt ?? null
          })
          .onConflict(oc =>
            oc.column('user_id').doUpdateSet({
              password_hash: record.passwordHash,
              updated_at: record.updatedAt ?? null
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
            user_id: (ch.userId ?? null) as unknown as string | null,
            challenge: ch.challenge,
            expires_at: ch.expiresAt
          })
          .execute();
      },

      async consumeChallenge(id: ChallengeId) {
        const r = await options.db
          .deleteFrom(tables.challenges)
          .where('id', '=', id as unknown as string)
          .returning(['id', 'type', 'user_id', 'challenge', 'expires_at'])
          .executeTakeFirst();
        if (!r) return null;
        const out: StoredChallenge = {
          id: asChallengeId(toString(getField(r, 'id'))),
          type: toString(getField(r, 'type')) as StoredChallenge['type'],
          userId: (() => {
            const uid = toOptionalString(getField(r, 'user_id'));
            return uid ? asUserId(uid) : undefined;
          })(),
          challenge: toString(getField(r, 'challenge')),
          expiresAt: toDate(getField(r, 'expires_at'))
        };
        return out;
      }
    },

    totp: {
      async getEnabled(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.totp)
          .select(['encrypted_secret', 'enabled_at', 'last_used_at'])
          .where('user_id', '=', userId as unknown as string)
          .where('enabled_at', 'is not', null)
          .executeTakeFirst();
        if (!r) return null;
        return {
          encryptedSecret: toString(getField(r, 'encrypted_secret')),
          enabledAt: toDate(getField(r, 'enabled_at')),
          lastUsedAt: toOptionalDate(getField(r, 'last_used_at'))
        };
      },

      async getPending(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.totp)
          .select(['encrypted_secret', 'pending_created_at'])
          .where('user_id', '=', userId as unknown as string)
          .where('enabled_at', 'is', null)
          .where('pending_created_at', 'is not', null)
          .executeTakeFirst();
        if (!r) return null;
        return {
          encryptedSecret: toString(getField(r, 'encrypted_secret')),
          createdAt: toDate(getField(r, 'pending_created_at'))
        };
      },

      async setPending(userId: UserId, encryptedSecret: string, createdAt: Date) {
        await options.db
          .insertInto(tables.totp)
          .values({
            user_id: userId as unknown as string,
            encrypted_secret: encryptedSecret,
            enabled_at: null,
            pending_created_at: createdAt,
            last_used_at: null
          })
          .onConflict(oc =>
            oc.column('user_id').doUpdateSet({
              encrypted_secret: encryptedSecret,
              enabled_at: null,
              pending_created_at: createdAt
            })
          )
          .execute();
      },

      async enableFromPending(userId: UserId, enabledAt: Date) {
        await options.db
          .updateTable(tables.totp)
          .set({ enabled_at: enabledAt, pending_created_at: null })
          .where('user_id', '=', userId as unknown as string)
          .where('enabled_at', 'is', null)
          .where('pending_created_at', 'is not', null)
          .execute();
      },

      async disable(userId: UserId, disabledAt: Date) {
        debug('totp.disable', { userId, disabledAt: disabledAt.toISOString() });
        await options.db
          .deleteFrom(tables.totp)
          .where('user_id', '=', userId as unknown as string)
          .execute();
      },

      async updateLastUsedAt(userId: UserId, lastUsedAt: Date) {
        await options.db
          .updateTable(tables.totp)
          .set({ last_used_at: lastUsedAt })
          .where('user_id', '=', userId as unknown as string)
          .execute();
      }
    },

    sessions: {
      async createSession(s: SessionRecord) {
        await options.db
          .insertInto(tables.sessions)
          .values({
            token_hash: s.tokenHash as unknown as string,
            user_id: s.userId as unknown as string,
            created_at: s.createdAt,
            last_seen_at: s.lastSeenAt ?? null,
            expires_at: s.expiresAt,
            revoked_at: s.revokedAt ?? null,
            rotated_from_hash: (s.rotatedFromHash ?? null) as unknown as string | null
          })
          .execute();
      },

      async getSessionByTokenHash(tokenHash: SessionTokenHash) {
        const r = await options.db
          .selectFrom(tables.sessions)
          .select([
            'token_hash',
            'user_id',
            'created_at',
            'last_seen_at',
            'expires_at',
            'revoked_at',
            'rotated_from_hash'
          ])
          .where('token_hash', '=', tokenHash as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: SessionRecord = {
          tokenHash: asSessionTokenHash(toString(getField(r, 'token_hash'))),
          userId: asUserId(toString(getField(r, 'user_id'))),
          createdAt: toDate(getField(r, 'created_at')),
          lastSeenAt: toOptionalDate(getField(r, 'last_seen_at')),
          expiresAt: toDate(getField(r, 'expires_at')),
          revokedAt: toOptionalDate(getField(r, 'revoked_at')),
          rotatedFromHash: (() => {
            const rot = toOptionalString(getField(r, 'rotated_from_hash'));
            return rot ? asSessionTokenHash(rot) : undefined;
          })()
        };
        return out;
      },

      async touchSession(tokenHash: SessionTokenHash, lastSeenAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ last_seen_at: lastSeenAt })
          .where('token_hash', '=', tokenHash as unknown as string)
          .where('revoked_at', 'is', null)
          .execute();
      },

      async revokeSession(tokenHash: SessionTokenHash, revokedAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ revoked_at: revokedAt })
          .where('token_hash', '=', tokenHash as unknown as string)
          .execute();
      },

      async revokeAllUserSessions(userId: UserId, revokedAt: Date) {
        await options.db
          .updateTable(tables.sessions)
          .set({ revoked_at: revokedAt })
          .where('user_id', '=', userId as unknown as string)
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
              token_hash: newSession.tokenHash as unknown as string,
              user_id: newSession.userId as unknown as string,
              created_at: newSession.createdAt,
              last_seen_at: newSession.lastSeenAt ?? null,
              expires_at: newSession.expiresAt,
              revoked_at: null,
              rotated_from_hash: (newSession.rotatedFromHash ?? null) as unknown as string | null
            })
            .execute();
          await tx
            .updateTable(tables.sessions)
            .set({ revoked_at: revokedAt })
            .where('token_hash', '=', oldTokenHash as unknown as string)
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
            .where('user_id', '=', userId as unknown as string)
            .execute();
          for (const c of codes) {
            await tx
              .insertInto(tables.backupCodes)
              .values({
                user_id: c.userId as unknown as string,
                code_hash: c.codeHash,
                created_at: c.createdAt,
                consumed_at: null
              })
              .execute();
          }
        });
      },

      async consumeCode(userId: UserId, codeHash: string, consumedAt: Date) {
        const r = await options.db
          .updateTable(tables.backupCodes)
          .set({ consumed_at: consumedAt })
          .where('user_id', '=', userId as unknown as string)
          .where('code_hash', '=', codeHash)
          .where('consumed_at', 'is', null)
          .returning(['user_id'])
          .executeTakeFirst();
        return Boolean(r);
      },

      async countRemaining(userId: UserId) {
        const r = await options.db
          .selectFrom(tables.backupCodes)
          .select(sql<number>`count(*)`.as('n'))
          .where('user_id', '=', userId as unknown as string)
          .where('consumed_at', 'is', null)
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
            'user_id',
            'credential_id',
            'public_key',
            'counter',
            'transports',
            'credential_device_type',
            'credential_backed_up',
            'created_at',
            'updated_at'
          ])
          .where('user_id', '=', userId as unknown as string)
          .execute();
        return rows.map(
          (r: unknown): WebAuthnCredentialRecord => ({
            id: asWebAuthnCredentialId(toString(getField(r, 'id'))),
            userId: asUserId(toString(getField(r, 'user_id'))),
            credentialId: toString(getField(r, 'credential_id')),
            publicKey: toUint8Array(getField(r, 'public_key')),
            counter: Number(getField(r, 'counter')),
            transports: (toOptionalStringArray(getField(r, 'transports')) ?? undefined) as
              | AuthenticatorTransportFuture[]
              | undefined,
            credentialDeviceType: (toOptionalString(getField(r, 'credential_device_type')) ??
              undefined) as CredentialDeviceType | undefined,
            credentialBackedUp: toOptionalBoolean(getField(r, 'credential_backed_up')),
            createdAt: toDate(getField(r, 'created_at')),
            updatedAt: toOptionalDate(getField(r, 'updated_at'))
          })
        );
      },

      async getCredentialById(id: WebAuthnCredentialId) {
        const r = await options.db
          .selectFrom(tables.webauthnCredentials)
          .select([
            'id',
            'user_id',
            'credential_id',
            'public_key',
            'counter',
            'transports',
            'credential_device_type',
            'credential_backed_up',
            'created_at',
            'updated_at'
          ])
          .where('id', '=', id as unknown as string)
          .executeTakeFirst();
        if (!r) return null;
        const out: WebAuthnCredentialRecord = {
          id: asWebAuthnCredentialId(toString(getField(r, 'id'))),
          userId: asUserId(toString(getField(r, 'user_id'))),
          credentialId: toString(getField(r, 'credential_id')),
          publicKey: toUint8Array(getField(r, 'public_key')),
          counter: Number(getField(r, 'counter')),
          transports: (toOptionalStringArray(getField(r, 'transports')) ?? undefined) as
            | AuthenticatorTransportFuture[]
            | undefined,
          credentialDeviceType: (toOptionalString(getField(r, 'credential_device_type')) ??
            undefined) as CredentialDeviceType | undefined,
          credentialBackedUp: toOptionalBoolean(getField(r, 'credential_backed_up')),
          createdAt: toDate(getField(r, 'created_at')),
          updatedAt: toOptionalDate(getField(r, 'updated_at'))
        };
        return out;
      },

      async createCredential(record: WebAuthnCredentialRecord) {
        await options.db
          .insertInto(tables.webauthnCredentials)
          .values({
            id: record.id as unknown as string,
            user_id: record.userId as unknown as string,
            credential_id: record.credentialId,
            public_key: Buffer.from(record.publicKey),
            counter: record.counter,
            transports: (record.transports ?? null) as unknown as string[] | null,
            credential_device_type: (record.credentialDeviceType ?? null) as unknown as
              | string
              | null,
            credential_backed_up: record.credentialBackedUp ?? null,
            created_at: record.createdAt,
            updated_at: record.updatedAt ?? null
          })
          .execute();
      },

      async updateCredentialCounter(id: WebAuthnCredentialId, counter: number, updatedAt: Date) {
        await options.db
          .updateTable(tables.webauthnCredentials)
          .set({ counter, updated_at: updatedAt })
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
    users: `${prefix}auth_users`,
    passwordCredentials: `${prefix}auth_password_credentials`,
    webauthnCredentials: `${prefix}auth_webauthn_credentials`,
    challenges: `${prefix}auth_challenges`,
    sessions: `${prefix}auth_sessions`,
    backupCodes: `${prefix}auth_backup_codes`,
    totp: `${prefix}auth_totp`
  };
  return { ...defaults, ...(options.tables ?? {}) };
}
