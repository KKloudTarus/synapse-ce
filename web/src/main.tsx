import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'
import "./styles/globals.css";

// Apply theme BEFORE first render to prevent flash of wrong theme
;(function initTheme() {
  const pref = localStorage.getItem('synapse-theme') || 'light'
  let resolved = pref
  if (pref === 'system') {
    resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  document.documentElement.dataset.theme = resolved
  if (resolved === 'dark') document.documentElement.classList.add('dark-mode')
})()

async function bootstrap() {
  // MSW runs only in DEV and only when not explicitly disabled. Set
  // VITE_ENABLE_MSW=false (e.g. in the docker dev stack) to hit the real API
  // through the Vite proxy instead of the in-browser mock handlers.
  const mswEnabled = import.meta.env.DEV && import.meta.env.VITE_ENABLE_MSW !== 'false'
  if (mswEnabled) {
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
