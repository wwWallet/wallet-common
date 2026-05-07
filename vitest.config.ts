import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		setupFiles: ['./setup-vitest.ts'],
		include: ['**/*.test.ts'],
		exclude: ['node_modules/**'],
		silent: 'passed-only',
	},
});
