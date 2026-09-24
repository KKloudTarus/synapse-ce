// copyText copies text to the clipboard and resolves whether it likely succeeded.
//
// The async Clipboard API (navigator.clipboard) only exists in a SECURE context — HTTPS or localhost.
// When the app is opened over plain HTTP on a LAN/remote URL, `navigator.clipboard` is undefined, so a
// bare `navigator.clipboard.writeText(...)` throws synchronously and the copy button appears to do
// nothing. This helper guards that and falls back to a hidden-textarea + execCommand('copy'), so every
// copy button works regardless of context. Callers should still show their own copied/feedback state.
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Permission denied or not allowed in this context — fall through to the legacy path.
  }

  // The textarea briefly holds whatever is being copied, which on this app includes a freshly
  // issued API key. It is removed in a finally: execCommand throws in browsers that have dropped
  // it, and the old code's removeChild was after the throwing call, leaving the value readable in
  // document.body for the life of the tab.
  const ta = document.createElement('textarea')
  try {
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '0'
    ta.style.left = '0'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    ta.value = ''
    ta.remove()
  }
}
