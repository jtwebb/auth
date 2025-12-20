/**
 * Kysely migration: 001_init
 *
 * Creates the default auth tables used by the Kysely adapter.
 *
 * Notes:
 * - user ids are stored as TEXT (DB-agnostic).
 * - session tokens are never stored plaintext; only token_hash is stored.
 * - TOTP secrets must be encrypted at rest (encrypted_secret).
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<Record<string, Record<string, unknown>>>): Promise<void> {
  await db.schema
    .createTable('auth_users')
    .ifNotExists()
    .addColumn('id', 'text', col => col.primaryKey())
    .addColumn('identifier', 'text', col => col.notNull().unique())
    .addColumn('created_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createTable('auth_password_credentials')
    .ifNotExists()
    .addColumn('user_id', 'text', col =>
      col.primaryKey().references('auth_users.id').onDelete('cascade')
    )
    .addColumn('password_hash', 'text', col => col.notNull())
    .addColumn('created_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz')
    .execute();

  await db.schema
    .createTable('auth_webauthn_credentials')
    .ifNotExists()
    .addColumn('id', 'text', col => col.primaryKey())
    .addColumn('user_id', 'text', col =>
      col.notNull().references('auth_users.id').onDelete('cascade')
    )
    .addColumn('credential_id', 'text', col => col.notNull().unique())
    .addColumn('public_key', 'bytea', col => col.notNull())
    .addColumn('counter', 'integer', col => col.notNull())
    .addColumn('transports', sql`text[]`)
    .addColumn('credential_device_type', 'text')
    .addColumn('credential_backed_up', 'boolean')
    .addColumn('created_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz')
    .execute();

  await db.schema
    .createTable('auth_challenges')
    .ifNotExists()
    .addColumn('id', 'text', col => col.primaryKey())
    .addColumn('type', 'text', col => col.notNull())
    .addColumn('user_id', 'text', col => col.references('auth_users.id').onDelete('cascade'))
    .addColumn('challenge', 'text', col => col.notNull())
    .addColumn('expires_at', 'timestamptz', col => col.notNull())
    .addColumn('created_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex('auth_challenges_expires_at_idx')
    .ifNotExists()
    .on('auth_challenges')
    .column('expires_at')
    .execute();

  await db.schema
    .createTable('auth_sessions')
    .ifNotExists()
    .addColumn('token_hash', 'text', col => col.primaryKey())
    .addColumn('user_id', 'text', col =>
      col.notNull().references('auth_users.id').onDelete('cascade')
    )
    .addColumn('created_at', 'timestamptz', col => col.notNull())
    .addColumn('last_seen_at', 'timestamptz')
    .addColumn('expires_at', 'timestamptz', col => col.notNull())
    .addColumn('revoked_at', 'timestamptz')
    .addColumn('rotated_from_hash', 'text')
    .addColumn('client_id_hash', 'text')
    .addColumn('user_agent_hash', 'text')
    .addColumn('updated_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex('auth_sessions_user_id_idx')
    .ifNotExists()
    .on('auth_sessions')
    .column('user_id')
    .execute();
  await db.schema
    .createIndex('auth_sessions_expires_at_idx')
    .ifNotExists()
    .on('auth_sessions')
    .column('expires_at')
    .execute();

  await db.schema
    .createTable('auth_backup_codes')
    .ifNotExists()
    .addColumn('user_id', 'text', col =>
      col.notNull().references('auth_users.id').onDelete('cascade')
    )
    .addColumn('code_hash', 'text', col => col.notNull())
    .addColumn('created_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', col => col.notNull().defaultTo(sql`now()`))
    .addColumn('consumed_at', 'timestamptz')
    .addPrimaryKeyConstraint('auth_backup_codes_pkey', ['user_id', 'code_hash'])
    .execute();

  await db.schema
    .createIndex('auth_backup_codes_user_id_consumed_idx')
    .ifNotExists()
    .on('auth_backup_codes')
    .columns(['user_id', 'consumed_at'])
    .execute();

  await db.schema
    .createTable('auth_totp')
    .ifNotExists()
    .addColumn('user_id', 'text', col =>
      col.primaryKey().references('auth_users.id').onDelete('cascade')
    )
    .addColumn('encrypted_secret', 'text', col => col.notNull())
    .addColumn('enabled_at', 'timestamptz')
    .addColumn('pending_created_at', 'timestamptz')
    .addColumn('last_used_at', 'timestamptz')
    .addColumn('last_used_step', 'integer')
    .execute();
}

export async function down(db: Kysely<Record<string, Record<string, unknown>>>): Promise<void> {
  // Drop indexes first (mostly for cleanliness in Postgres).
  await db.schema.dropIndex('auth_backup_codes_user_id_consumed_idx').ifExists().execute();
  await db.schema.dropIndex('auth_sessions_expires_at_idx').ifExists().execute();
  await db.schema.dropIndex('auth_sessions_user_id_idx').ifExists().execute();
  await db.schema.dropIndex('auth_challenges_expires_at_idx').ifExists().execute();

  // Drop tables in reverse dependency order.
  await db.schema.dropTable('auth_totp').ifExists().execute();
  await db.schema.dropTable('auth_backup_codes').ifExists().execute();
  await db.schema.dropTable('auth_sessions').ifExists().execute();
  await db.schema.dropTable('auth_challenges').ifExists().execute();
  await db.schema.dropTable('auth_webauthn_credentials').ifExists().execute();
  await db.schema.dropTable('auth_password_credentials').ifExists().execute();
  await db.schema.dropTable('auth_users').ifExists().execute();
}
