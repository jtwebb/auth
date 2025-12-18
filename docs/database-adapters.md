# Database adapters

This project ships optional database adapters that implement `AuthStorage` for common stacks.

## `@jtwebb/auth/pg`

### Install

```bash
npm i pg
```

### Use

```ts
import { Pool } from 'pg';
import { createPgAuthStorage } from '@jtwebb/auth/pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export const storage = createPgAuthStorage({
  pool
  // Optional:
  // schema: 'public',
  // tablePrefix: 'app_',
  // tables: { users: 'my_users' },
});
```

### Migrations

The `pg` adapter ships SQL migrations in the package `dist/` output:

- `node_modules/@jtwebb/auth/dist/adapters/pg/migrations/001_init.sql`

Apply with psql, or copy into your migration system.

## `@jtwebb/auth/kysely`

### Install

```bash
npm i kysely
```

### Use

```ts
import { createKyselyAuthStorage } from '@jtwebb/auth/kysely';

export const storage = createKyselyAuthStorage({
  db
  // Optional:
  // tablePrefix: 'app_',
  // tables: { users: 'my_users' },
});
```

### Migrations (TypeScript `up`/`down`)

The Kysely adapter exports migration helpers:

```ts
import { migrations } from '@jtwebb/auth/kysely';

await migrations.up001Init(db);
// ... later ...
await migrations.down001Init(db);
```

To integrate with Kysely's `Migrator`, you can wrap these in a migration provider (app-owned).
