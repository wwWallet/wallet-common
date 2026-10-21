import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
	{
		ignores: ['dist/**', 'build/**', 'output/**', 'coverage/**', '.nyc_output/**', 'node_modules/**'],
	},
	{
		linterOptions: {
			reportUnusedDisableDirectives: 'error',
		},
	},
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: ['**/*.{ts,mts}'],
		rules: {
			'no-undef': 'off',
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-unused-vars': 'off',
			'@typescript-eslint/ban-ts-comment': 'off',
			'prefer-const': 'off',
			'@typescript-eslint/no-empty-object-type': 'off',
			'no-useless-escape': 'off',
			'no-case-declarations': 'off',
		},
	},
	{
		files: ['src/**/*.test.ts', 'eslint.config.mjs', 'vitest.config.mts', 'setup-vitest.ts'],
		languageOptions: {
			globals: globals.node,
		},
	},
);
