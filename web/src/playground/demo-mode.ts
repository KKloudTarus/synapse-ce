export type DemoMode = 'overview' | 'code' | 'runtime' | 'ai' | 'quality' | 'remediation' | 'intelligence' | 'policy' | 'ai-setup' | 'ci-setup'
export const DEMO_MODE_KEY = 'synapse.playground.mode'

// New tabs inherit the last chosen chapter; existing tabs keep their own selection.
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
  try { localStorage.setItem(DEMO_MODE_KEY, mode) } catch { /* New tabs cannot inherit without storage. */ }
}
