import { lazy, type ComponentType } from 'react'

/**
 * Wraps a tab's dynamic import so a failed chunk fetch can recover.
 *
 * After a deploy rotates the hashed chunk filenames, an already-open session's import 404s.
 * React.lazy caches that rejection permanently, so the error boundary's Retry remounts into the
 * same rejected payload forever. Retry the import once (it covers a transient network failure),
 * then reload the page once, which fetches the current index and its chunk names. The one-shot
 * flag stops a genuinely missing chunk from turning into a reload loop, and it is cleared on the
 * next successful load.
 */
const CHUNK_RELOAD_FLAG = 'synapse.engagement-chunk-reloaded'

function readReloadFlag(): boolean {
  try {
    return sessionStorage.getItem(CHUNK_RELOAD_FLAG) === '1'
  } catch {
    // Private mode or blocked storage: treat as "not yet reloaded" and rely on the single attempt.
    return false
  }
}

function writeReloadFlag(value: boolean) {
  try {
    if (value) sessionStorage.setItem(CHUNK_RELOAD_FLAG, '1')
    else sessionStorage.removeItem(CHUNK_RELOAD_FLAG)
  } catch {
    // Storage is unavailable; the reload still happens, it just is not deduplicated.
  }
}

export function lazyTab<T extends ComponentType<any>>(load: () => Promise<{ default: T }>) {
  return lazy(async () => {
    try {
      const loaded = await load()
      writeReloadFlag(false)
      return loaded
    } catch (first) {
      try {
        const retried = await load()
        writeReloadFlag(false)
        return retried
      } catch (second) {
        if (!readReloadFlag()) {
          writeReloadFlag(true)
          window.location.reload()
        }
        throw second instanceof Error ? second : first
      }
    }
  })
}
