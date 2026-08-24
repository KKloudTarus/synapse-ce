import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// Under an opaque origin jsdom exposes a non-functional Web Storage object whose
// methods are missing, so tests that call localStorage.clear() throw. Install a
// minimal in-memory Storage when a working one is not already present.
function installMemoryStorage(key: 'localStorage' | 'sessionStorage') {
  const existing = (globalThis as Record<string, unknown>)[key] as Storage | undefined
  if (existing && typeof existing.clear === 'function') {
    return
  }
  const store = new Map<string, string>()
  const storage: Storage = {
    get length() {
      return store.size
    },
    clear: () => store.clear(),
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    removeItem: (k: string) => {
      store.delete(k)
    },
    setItem: (k: string, v: string) => {
      store.set(k, String(v))
    },
  }
  Object.defineProperty(globalThis, key, { configurable: true, value: storage })
}

installMemoryStorage('localStorage')
installMemoryStorage('sessionStorage')

// React Router passes jsdom's AbortSignal to Node's native Request during navigation.
// Node rejects that cross-realm signal, though jsdom never performs the request.
const NativeRequest = globalThis.Request
if (NativeRequest) {
  globalThis.Request = new Proxy(NativeRequest, {
    construct(target, [input, init]) {
      if (!init?.signal) return new target(input, init)
      const { signal: _, ...withoutSignal } = init
      return new target(input, withoutSignal)
    },
  }) as typeof Request
}

afterEach(() => {
  cleanup()
})
