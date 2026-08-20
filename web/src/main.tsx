import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

// Apply the persisted theme before the first render. The sidebar owns the toggle, but it only
// mounts once authenticated, so without this the login screen ignores a saved dark preference.
try {
  if (globalThis.localStorage?.getItem('synapse-theme') === 'dark') {
    document.documentElement.dataset.theme = 'dark'
  }
} catch {}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
