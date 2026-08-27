import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        // Each package owns its tests under src/**/*.test.ts. Node environment
        // throughout: nothing here touches a DOM.
        include: ['packages/*/src/**/*.test.ts', 'apps/*/src/**/*.test.ts'],
        environment: 'node',
        // The audit chain and Cedar WASM init are I/O bound but not slow; the
        // default 5s timeout is ample and keeps a hung test from stalling CI.
        testTimeout: 15_000,
        hookTimeout: 30_000,
        coverage: {
            provider: 'v8',
            include: ['packages/*/src/**/*.ts', 'apps/*/src/**/*.ts'],
            exclude: ['**/*.test.ts', '**/dist/**', '**/index.ts']
        }
    }
});
