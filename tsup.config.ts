import { defineConfig } from 'tsup';

/**
 * Multi-entry build for `@authkit/permissions`.
 *
 * ESM-only across every entry — the dual-package hazard
 * (two `instanceof PermissionError` realms when CJS and ESM copies load
 * in the same process) is gone by construction.
 *
 * `treeshake: 'recommended'` enables Rollup-flavoured shaking on top of
 * esbuild so consumers that only call `definePolicy` don't pull
 * `enforcer`, `effective`, or `memo`.
 */
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'errors/index': 'src/errors/index.ts',
    'audit/index': 'src/audit/index.ts',
    'builder/index': 'src/builder/index.ts',
    'adapters/next/index': 'src/adapters/next/index.ts',
    'adapters/hono/index': 'src/adapters/hono/index.ts',
    'adapters/express/index': 'src/adapters/express/index.ts',
    'adapters/fastify/index': 'src/adapters/fastify/index.ts',
    'adapters/nestjs/index': 'src/adapters/nestjs/index.ts',
    'adapters/trpc/index': 'src/adapters/trpc/index.ts',
    'orm/prisma/index': 'src/orm/prisma/index.ts',
    'orm/drizzle/index': 'src/orm/drizzle/index.ts',
    'orm/mongoose/index': 'src/orm/mongoose/index.ts',
    'react/index': 'src/react/index.ts',
    'vue/index': 'src/vue/index.ts',
  },
  format: ['esm'],
  target: 'es2024',
  dts: true,
  splitting: false,
  treeshake: 'recommended',
  sourcemap: true,
  clean: true,
  outDir: 'dist',
  external: [
    'react',
    'react-dom',
    'vue',
    'next',
    'hono',
    'express',
    'fastify',
    '@nestjs/common',
    '@nestjs/core',
    '@trpc/server',
    '@prisma/client',
    'drizzle-orm',
    'mongoose',
  ],
});
