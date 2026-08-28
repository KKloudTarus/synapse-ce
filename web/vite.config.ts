import { rmSync } from 'node:fs'
import path from 'path'
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Dev server proxies API calls to the Go backend only when VITE_API_PROXY_TARGET is set.
// Without it, MSW (service worker) intercepts /api/* in the browser — no proxy needed.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_API_PROXY_TARGET

  return {
    plugins: [
      react(),
      tailwindcss(),
      // public/mockServiceWorker.js is a dev-only MSW artifact. It is inert in prod
      // (the msw client is tree-shaken, so nothing ever activates it), but shipping
      // it is needless surface — and a footgun if a browser still holds a stale
      // same-origin registration from a dev session. It is copied verbatim from
      // public/, so it has to be removed after the write rather than filtered out
      // of the bundle graph.
      {
        name: 'synapse-strip-msw-worker',
        apply: 'build' as const,
        closeBundle() {
          rmSync(path.resolve(import.meta.dirname, 'dist/mockServiceWorker.js'), { force: true })
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, './src'),
      },
    },
    server: {
      port: 5173,
      ...(apiTarget && {
        proxy: {
          '/api': apiTarget,
          '/healthz': apiTarget,
        },
      }),
    },
  }
})
