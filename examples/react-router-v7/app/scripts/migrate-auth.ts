import { migrations } from '@jtwebb/auth/kysely';
import { db } from '../db.server';

// Run with: `node --loader ts-node/esm app/scripts/migrate-auth.ts`
// or adapt to your app's tooling. This example keeps it simple and explicit.

await migrations.up001Init(db);
await db.destroy();
