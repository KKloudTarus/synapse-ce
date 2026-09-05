import babelParser from '@babel/eslint-parser'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'

/**
 * Minimal flat config, scoped to the Rules of Hooks. A component that returned
 * before its useState shipped and logged "Internal React error: Expected static
 * flag was missing" on every engagement load; nothing in the toolchain caught
 * it.
 *
 * The Babel parser is used rather than typescript-eslint because the latter
 * refuses to run against the repo's TypeScript 7. These rules only need the
 * syntax tree, not type information.
 *
 * Vendored Untitled UI sources are excluded, matching tsconfig's exclude list.
 */
export default [
  {
    ignores: [
      'dist/**',
      'public/**',
      'src/components/application/**',
      'src/components/base/**',
      'src/components/foundations/**',
      'src/components/shared-assets/**',
    ],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          babelrc: false,
          configFile: false,
          parserOpts: { plugins: ['typescript', 'jsx', 'explicitResourceManagement'] },
        },
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      globals: { ...globals.browser },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
]
