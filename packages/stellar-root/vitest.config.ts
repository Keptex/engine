import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    globals: false,
    // End-to-end tests run PBKDF2 (100k iterations) several times.
    testTimeout: 30_000,
  },
})
