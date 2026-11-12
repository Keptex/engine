import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    globals: false,
    // The end-to-end test runs the 100k-iteration PBKDF2 of @keptex/core.
    testTimeout: 30_000,
  },
})
