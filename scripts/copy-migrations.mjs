import { cp, mkdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const root = path.resolve(__dirname, '..');

async function copyMigrations(adapterName) {
  const from = path.join(root, 'src', 'adapters', adapterName, 'migrations');
  const to = path.join(root, 'dist', 'adapters', adapterName, 'migrations');
  try {
    await stat(from);
  } catch {
    return;
  }
  await mkdir(to, { recursive: true });
  await cp(from, to, { recursive: true });
}

await copyMigrations('pg');
