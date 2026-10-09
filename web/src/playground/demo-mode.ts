export type DemoMode = 'overview' | 'code' | 'runtime' | 'ai' | 'quality' | 'remediation' | 'intelligence' | 'policy' | 'ai-setup' | 'ci-setup'
export const DEMO_MODE_KEY = 'synapse.playground.mode'

// Dataset progress is shared by the browser; the chapter being viewed belongs to this tab.
export function readDemoMode(fallback: DemoMode): DemoMode {
  try {
    const value = sessionStorage.getItem(DEMO_MODE_KEY) ?? localStorage.getItem(DEMO_MODE_KEY)
    const mode = value && ['overview', 'code', 'runtime', 'ai', 'quality', 'remediation', 'intelligence', 'policy', 'ai-setup', 'ci-setup'].includes(value) ? value as DemoMode : fallback
    sessionStorage.setItem(DEMO_MODE_KEY, mode)
    return mode
  } catch { return fallback }
}
export function saveDemoMode(mode: DemoMode) {
  try { sessionStorage.setItem(DEMO_MODE_KEY, mode) } catch { /* Keep the in-memory view. */ }
}
