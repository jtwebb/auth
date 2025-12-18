/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          globals: true,
          environment: 'node',
          include: ['tests/**/*.spec.{ts,tsx}'],
          exclude: ['tests/**/*.int.spec.{ts,tsx}']
        }
      },
      {
        test: {
          name: 'integration',
          globals: true,
          environment: 'node',
          include:
            process.env.AUTH_PG_INTEGRATION === '1' || process.env.AUTH_KYSELY_INTEGRATION === '1'
              ? ['tests/**/*.int.spec.ts']
              : [],
          testTimeout: 60_000
        }
      }
    ]
  }
});
