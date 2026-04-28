import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    typecheck: {
      enabled: false,
      tsconfig: './tsconfig.json',
      include: ['tests/**/*.test-d.ts'],
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: [
        'src/**/index.ts',
        'src/types/**',
        'src/**/*.d.ts',
      ],
      thresholds: {
        lines: 95,
        branches: 95,
        functions: 100,
      },
    },
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
  },
});
