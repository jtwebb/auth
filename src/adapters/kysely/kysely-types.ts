import type { Kysely, Transaction } from 'kysely';

/**
 * We intentionally accept a loosely-typed `Kysely` here because this adapter supports configurable
 * table names (prefix/overrides), which aren't representable with full compile-time
 * table/column typing in Kysely without a lot of user-supplied type machinery.
 *
 * The adapter still avoids `as any` and keeps runtime decoding localized.
 */
export type KyselyDb = Kysely<Record<string, Record<string, unknown>>>;
export type KyselyTx = Transaction<Record<string, Record<string, unknown>>>;
