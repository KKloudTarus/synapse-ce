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
    plugins: [react(), tailwindcss()],
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
