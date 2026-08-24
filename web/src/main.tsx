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
  if (import.meta.env.DEV) {
    const { worker } = await import('./mocks/browser')
    await worker.start({ onUnhandledRequest: 'bypass' })
  }

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  )
}

bootstrap()
