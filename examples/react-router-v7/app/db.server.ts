import { CamelCasePlugin, Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/postgres'
});

export const db = new Kysely<Record<string, Record<string, unknown>>>({
  dialect: new PostgresDialect({ pool }),
  plugins: [new CamelCasePlugin()]
});
