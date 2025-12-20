import { randomUUID } from 'node:crypto';
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
import type { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';
import type { PgClient, PgPool } from './pg-types.js';

export type PgAuthTables = {
  users: string;
  passwordCredentials: string;
  webauthnCredentials: string;
  challenges: string;
  sessions: string;
  backupCodes: string;
  totp: string;
};

export type CreatePgAuthStorageOptions = {
  pool: PgPool;
  /**
   * Optional DB schema/namespace (Postgres). If set, table names are qualified.
   */
  schema?: string;
  /**
   * Optional prefix applied to default table names (e.g. "app_" -> "app_auth_users").
   */
  tablePrefix?: string;
  /**
   * Override individual table names (unqualified). Applied after `tablePrefix`.
   */
  tables?: Partial<PgAuthTables>;
  /**
   * Injectable clock for tests.
   */
  now?: () => Date;
  /**
   * Optional debug logger. Never logs secrets.
   */
  logger?: { debug(message: string, meta?: Record<string, unknown>): void };
};

export function createPgAuthStorage(options: CreatePgAuthStorageOptions): AuthStorage {
  const now = options.now ?? (() => new Date());
  const tables = resolveTables(options);

  const debug = (message: string, meta?: Record<string, unknown>) => {
    options.logger?.debug(message, meta);
  };

  return {
    users: {
      async getUserIdByIdentifier(identifier: string) {
        const res = await options.pool.query<{ id: string }>(
          `SELECT id FROM ${tables.users} WHERE identifier = $1`,
          [identifier]
        );
        const id = res.rows[0]?.id;
        return id ? asUserId(id) : null;
      },

      async createUser(identifier: string) {
        const userId = randomUUID();
        await options.pool.query(
          `INSERT INTO ${tables.users} (id, identifier, created_at) VALUES ($1,$2,$3)`,
          [userId, identifier, now()]
        );
        return asUserId(userId);
      }
    },

    passwordCredentials: {
      async getForUser(userId: UserId) {
        const res = await options.pool.query<{
          user_id: string;
          password_hash: string;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT user_id, password_hash, created_at, updated_at
           FROM ${tables.passwordCredentials}
           WHERE user_id = $1`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: PasswordCredentialRecord = {
          userId: asUserId(r.user_id),
          passwordHash: r.password_hash,
          createdAt: toDate(r.created_at),
          updatedAt: toOptionalDate(r.updated_at)
        };
        return out;
      },

      async upsertForUser(record: PasswordCredentialRecord) {
        await options.pool.query(
          `INSERT INTO ${tables.passwordCredentials} (user_id, password_hash, created_at, updated_at)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (user_id)
           DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at`,
          [record.userId, record.passwordHash, record.createdAt, record.updatedAt ?? null]
        );
      }
    },

    challenges: {
      async createChallenge(ch: StoredChallenge) {
        await options.pool.query(
          `INSERT INTO ${tables.challenges} (id, type, user_id, challenge, expires_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [ch.id, ch.type, ch.userId ?? null, ch.challenge, ch.expiresAt]
        );
      },

      async consumeChallenge(id: ChallengeId) {
        const res = await options.pool.query<{
          id: string;
          type: StoredChallenge['type'];
          user_id: string | null;
          challenge: string;
          expires_at: Date | string;
        }>(
          `DELETE FROM ${tables.challenges}
           WHERE id = $1
           RETURNING id, type, user_id, challenge, expires_at`,
          [id]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: StoredChallenge = {
          id: asChallengeId(r.id),
          type: r.type,
          userId: r.user_id ? asUserId(r.user_id) : undefined,
          challenge: r.challenge,
          expiresAt: toDate(r.expires_at)
        };
        return out;
      }
    },

    totp: {
      async getEnabled(userId: UserId) {
        const res = await options.pool.query<{
          encrypted_secret: string;
          enabled_at: Date | string;
          last_used_at: Date | string | null;
          last_used_step: number | null;
        }>(
          `SELECT encrypted_secret, enabled_at, last_used_at, last_used_step
           FROM ${tables.totp}
           WHERE user_id = $1 AND enabled_at IS NOT NULL`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        return {
          encryptedSecret: r.encrypted_secret,
          enabledAt: toDate(r.enabled_at),
          lastUsedAt: toOptionalDate(r.last_used_at),
          lastUsedStep: r.last_used_step ?? undefined
        };
      },

      async getPending(userId: UserId) {
        const res = await options.pool.query<{
          encrypted_secret: string;
          pending_created_at: Date | string;
        }>(
          `SELECT encrypted_secret, pending_created_at
           FROM ${tables.totp}
           WHERE user_id = $1 AND enabled_at IS NULL AND pending_created_at IS NOT NULL`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        return { encryptedSecret: r.encrypted_secret, createdAt: toDate(r.pending_created_at) };
      },

      async setPending(userId: UserId, encryptedSecret: string, createdAt: Date) {
        await options.pool.query(
          `INSERT INTO ${tables.totp} (user_id, encrypted_secret, enabled_at, pending_created_at, last_used_at, last_used_step)
           VALUES ($1, $2, NULL, $3, NULL, NULL)
           ON CONFLICT (user_id)
           DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, enabled_at = NULL, pending_created_at = EXCLUDED.pending_created_at, last_used_at = NULL, last_used_step = NULL`,
          [userId, encryptedSecret, createdAt]
        );
      },

      async enableFromPending(userId: UserId, enabledAt: Date) {
        await options.pool.query(
          `UPDATE ${tables.totp}
           SET enabled_at = $2, pending_created_at = NULL
           WHERE user_id = $1 AND enabled_at IS NULL AND pending_created_at IS NOT NULL`,
          [userId, enabledAt]
        );
      },

      async disable(userId: UserId, disabledAt: Date) {
        debug('totp.disable', { userId, disabledAt: disabledAt.toISOString() });
        await options.pool.query(`DELETE FROM ${tables.totp} WHERE user_id = $1`, [userId]);
      },

      async updateLastUsedAt(userId: UserId, lastUsedAt: Date) {
        await options.pool.query(`UPDATE ${tables.totp} SET last_used_at = $2 WHERE user_id = $1`, [
          userId,
          lastUsedAt
        ]);
      },

      async updateLastUsedStepIfGreater({ userId, step, usedAt }) {
        const res = await options.pool.query(
          `UPDATE ${tables.totp}
           SET last_used_step = $2, last_used_at = $3
           WHERE user_id = $1
             AND enabled_at IS NOT NULL
             AND (last_used_step IS NULL OR last_used_step < $2)
           RETURNING 1`,
          [userId, step, usedAt]
        );
        return res.rowCount === 1;
      }
    },

    sessions: {
      async createSession(s: SessionRecord) {
        await options.pool.query(
          `INSERT INTO ${tables.sessions}
           (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash, client_id_hash, user_agent_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            s.tokenHash,
            s.userId,
            s.createdAt,
            s.lastSeenAt ?? null,
            s.expiresAt,
            s.revokedAt ?? null,
            s.rotatedFromHash ?? null,
            s.clientIdHash ?? null,
            s.userAgentHash ?? null
          ]
        );
      },

      async getSessionByTokenHash(tokenHash: SessionTokenHash) {
        const res = await options.pool.query<{
          token_hash: string;
          user_id: string;
          created_at: Date | string;
          last_seen_at: Date | string | null;
          expires_at: Date | string;
          revoked_at: Date | string | null;
          rotated_from_hash: string | null;
          client_id_hash: string | null;
          user_agent_hash: string | null;
        }>(
          `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash, client_id_hash, user_agent_hash
           FROM ${tables.sessions}
           WHERE token_hash = $1`,
          [tokenHash]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: SessionRecord = {
          tokenHash: asSessionTokenHash(r.token_hash),
          userId: asUserId(r.user_id),
          createdAt: toDate(r.created_at),
          lastSeenAt: toOptionalDate(r.last_seen_at),
          expiresAt: toDate(r.expires_at),
          revokedAt: toOptionalDate(r.revoked_at),
          rotatedFromHash: r.rotated_from_hash
            ? asSessionTokenHash(r.rotated_from_hash)
            : undefined,
          clientIdHash: r.client_id_hash ?? undefined,
          userAgentHash: r.user_agent_hash ?? undefined
        };
        return out;
      },

      async listSessionsForUser(userId: UserId) {
        const res = await options.pool.query<{
          token_hash: string;
          user_id: string;
          created_at: Date | string;
          last_seen_at: Date | string | null;
          expires_at: Date | string;
          revoked_at: Date | string | null;
          rotated_from_hash: string | null;
          client_id_hash: string | null;
          user_agent_hash: string | null;
        }>(
          `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash, client_id_hash, user_agent_hash
           FROM ${tables.sessions}
           WHERE user_id = $1
           ORDER BY created_at DESC`,
          [userId]
        );
        return res.rows.map(
          (r): SessionRecord => ({
            tokenHash: asSessionTokenHash(r.token_hash),
            userId: asUserId(r.user_id),
            createdAt: toDate(r.created_at),
            lastSeenAt: toOptionalDate(r.last_seen_at),
            expiresAt: toDate(r.expires_at),
            revokedAt: toOptionalDate(r.revoked_at),
            rotatedFromHash: r.rotated_from_hash
              ? asSessionTokenHash(r.rotated_from_hash)
              : undefined,
            clientIdHash: r.client_id_hash ?? undefined,
            userAgentHash: r.user_agent_hash ?? undefined
          })
        );
      },

      async touchSession(tokenHash: SessionTokenHash, lastSeenAt: Date) {
        await options.pool.query(
          `UPDATE ${tables.sessions} SET last_seen_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`,
          [tokenHash, lastSeenAt]
        );
      },

      async revokeSession(tokenHash: SessionTokenHash, revokedAt: Date) {
        await options.pool.query(
          `UPDATE ${tables.sessions} SET revoked_at = $2 WHERE token_hash = $1`,
          [tokenHash, revokedAt]
        );
      },

      async revokeAllUserSessions(userId: UserId, revokedAt: Date) {
        await options.pool.query(
          `UPDATE ${tables.sessions} SET revoked_at = $2 WHERE user_id = $1`,
          [userId, revokedAt]
        );
      },

      async revokeAllUserSessionsExceptTokenHash(
        userId: UserId,
        exceptTokenHash: SessionTokenHash,
        revokedAt: Date
      ) {
        await options.pool.query(
          `UPDATE ${tables.sessions}
           SET revoked_at = $3
           WHERE user_id = $1 AND token_hash <> $2 AND revoked_at IS NULL`,
          [userId, exceptTokenHash, revokedAt]
        );
      },

      async rotateSession(
        oldTokenHash: SessionTokenHash,
        newSession: SessionRecord,
        revokedAt: Date
      ) {
        await withTx(options.pool, async tx => {
          await tx.query(
            `INSERT INTO ${tables.sessions}
             (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash, client_id_hash, user_agent_hash)
             VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8)`,
            [
              newSession.tokenHash,
              newSession.userId,
              newSession.createdAt,
              newSession.lastSeenAt ?? null,
              newSession.expiresAt,
              newSession.rotatedFromHash ?? null,
              newSession.clientIdHash ?? null,
              newSession.userAgentHash ?? null
            ]
          );
          await tx.query(`UPDATE ${tables.sessions} SET revoked_at = $2 WHERE token_hash = $1`, [
            oldTokenHash,
            revokedAt
          ]);
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
        await withTx(options.pool, async tx => {
          await tx.query(`DELETE FROM ${tables.backupCodes} WHERE user_id = $1`, [userId]);
          for (const c of codes) {
            await tx.query(
              `INSERT INTO ${tables.backupCodes} (user_id, code_hash, created_at, consumed_at)
               VALUES ($1, $2, $3, NULL)`,
              [userId, c.codeHash, c.createdAt]
            );
          }
        });
      },

      async consumeCode(userId: UserId, codeHash: string, consumedAt: Date) {
        const res = await options.pool.query(
          `UPDATE ${tables.backupCodes}
           SET consumed_at = $3
           WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL
           RETURNING 1`,
          [userId, codeHash, consumedAt]
        );
        return res.rowCount === 1;
      },

      async countRemaining(userId: UserId) {
        const res = await options.pool.query<{ n: string | number }>(
          `SELECT COUNT(*)::int AS n
           FROM ${tables.backupCodes}
           WHERE user_id = $1 AND consumed_at IS NULL`,
          [userId]
        );
        const n = res.rows[0]?.n ?? 0;
        return typeof n === 'number' ? n : Number.parseInt(n, 10);
      }
    },

    webauthn: {
      async listCredentialsForUser(userId: UserId) {
        const res = await options.pool.query<{
          id: string;
          user_id: string;
          credential_id: string;
          public_key: Buffer;
          counter: number;
          transports: string[] | null;
          credential_device_type: string | null;
          credential_backed_up: boolean | null;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at
           FROM ${tables.webauthnCredentials}
           WHERE user_id = $1`,
          [userId]
        );
        return res.rows.map(
          (r): WebAuthnCredentialRecord => ({
            id: asWebAuthnCredentialId(r.id),
            userId: asUserId(r.user_id),
            credentialId: r.credential_id,
            publicKey: new Uint8Array(r.public_key),
            counter: r.counter,
            transports: (r.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
            credentialDeviceType: (r.credential_device_type ?? undefined) as
              | CredentialDeviceType
              | undefined,
            credentialBackedUp: r.credential_backed_up ?? undefined,
            createdAt: toDate(r.created_at),
            updatedAt: toOptionalDate(r.updated_at)
          })
        );
      },

      async getCredentialById(id: WebAuthnCredentialId) {
        const res = await options.pool.query<{
          id: string;
          user_id: string;
          credential_id: string;
          public_key: Buffer;
          counter: number;
          transports: string[] | null;
          credential_device_type: string | null;
          credential_backed_up: boolean | null;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at
           FROM ${tables.webauthnCredentials}
           WHERE id = $1`,
          [id]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: WebAuthnCredentialRecord = {
          id: asWebAuthnCredentialId(r.id),
          userId: asUserId(r.user_id),
          credentialId: r.credential_id,
          publicKey: new Uint8Array(r.public_key),
          counter: r.counter,
          transports: (r.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
          credentialDeviceType: (r.credential_device_type ?? undefined) as
            | CredentialDeviceType
            | undefined,
          credentialBackedUp: r.credential_backed_up ?? undefined,
          createdAt: toDate(r.created_at),
          updatedAt: toOptionalDate(r.updated_at)
        };
        return out;
      },

      async createCredential(record: WebAuthnCredentialRecord) {
        await options.pool.query(
          `INSERT INTO ${tables.webauthnCredentials}
           (id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            record.id,
            record.userId,
            record.credentialId,
            Buffer.from(record.publicKey),
            record.counter,
            record.transports ?? null,
            record.credentialDeviceType ?? null,
            record.credentialBackedUp ?? null,
            record.createdAt,
            record.updatedAt ?? null
          ]
        );
      },

      async updateCredentialCounter(id: WebAuthnCredentialId, counter: number, updatedAt: Date) {
        await options.pool.query(
          `UPDATE ${tables.webauthnCredentials} SET counter = $2, updated_at = $3 WHERE id = $1`,
          [id, counter, updatedAt]
        );
      }
    }
  };
}

function toDate(v: Date | string | number): Date {
  return v instanceof Date ? v : new Date(v);
}

function toOptionalDate(v: Date | string | number | null | undefined): Date | undefined {
  if (v == null) return undefined;
  return toDate(v);
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

function resolveTables(options: CreatePgAuthStorageOptions): PgAuthTables {
  const prefix = options.tablePrefix ?? '';
  const defaults: PgAuthTables = {
    users: `${prefix}auth_users`,
    passwordCredentials: `${prefix}auth_password_credentials`,
    webauthnCredentials: `${prefix}auth_webauthn_credentials`,
    challenges: `${prefix}auth_challenges`,
    sessions: `${prefix}auth_sessions`,
    backupCodes: `${prefix}auth_backup_codes`,
    totp: `${prefix}auth_totp`
  };
  const merged = { ...defaults, ...(options.tables ?? {}) };
  return {
    users: qualify(options.schema, merged.users),
    passwordCredentials: qualify(options.schema, merged.passwordCredentials),
    webauthnCredentials: qualify(options.schema, merged.webauthnCredentials),
    challenges: qualify(options.schema, merged.challenges),
    sessions: qualify(options.schema, merged.sessions),
    backupCodes: qualify(options.schema, merged.backupCodes),
    totp: qualify(options.schema, merged.totp)
  };
}

function qualify(schema: string | undefined, table: string): string {
  // Minimal identifier handling: schema/table are assumed trusted (code config, not user input).
  // Users should not pass untrusted values into `schema`/`tables`/`tablePrefix`.
  return schema ? `${schema}.${table}` : table;
}

async function withTx<T>(pool: PgPool, fn: (tx: PgClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
