import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'
import "./styles/globals.css";

// Apply theme BEFORE first render to prevent flash of wrong theme.
// Guarded: localStorage/matchMedia can throw when site data is blocked, and an
// exception here aborts the module before bootstrap() renders anything.
;(function initTheme() {
  try {
    const pref = localStorage.getItem('synapse-theme') || 'light'
    let resolved = pref
    if (pref === 'system') {
      resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    }
    document.documentElement.dataset.theme = resolved
    if (resolved === 'dark') document.documentElement.classList.add('dark-mode')
  } catch {
    document.documentElement.dataset.theme = 'light'
  }
})()

async function bootstrap() {
  // MSW mock mode is dev-only AND mutually exclusive with the real backend:
  // when VITE_API_PROXY_TARGET is set the dev server proxies /api to the backend,
  // so the mock worker must stay off or it would intercept those calls first.
  // VITE_PLAYGROUND builds the same mock layer into a static bundle for the hosted playground,
  // which has no backend to proxy to and must never reach one.
  const playground = import.meta.env.VITE_PLAYGROUND === '1'
  if ((import.meta.env.DEV || playground) && !import.meta.env.VITE_API_PROXY_TARGET) {
    const { worker } = await import('./mocks/browser')
    await worker.start({ onUnhandledRequest: 'bypass' })
  }

  // The playground shell is imported dynamically so a normal build never pulls it into the bundle.
  const Shell = playground ? (await import('./playground/PlaygroundShell')).PlaygroundShell : null

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <BrowserRouter>
        {Shell ? <Shell /> : null}
        <App />
      </BrowserRouter>
    </StrictMode>,
  )
}

bootstrap()
