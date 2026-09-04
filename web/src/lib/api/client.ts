export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

let token = ''
let csrfToken = ''
let onUnauthorized: (() => void) | null = null

export function setToken(t: string): void {
  token = t
}

// The BFF issues this token with the session; it intentionally remains in memory only.
export function setCSRFToken(t: string): void {
  csrfToken = t
}

export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn
}

export function getToken(): string {
  return token
}

export function getOnUnauthorized(): (() => void) | null {
  return onUnauthorized
}

export function newIdempotencyKey(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}

export type BFFSession = { authenticated: boolean; csrfToken: string }

function apiRequestInit(init: RequestInit = {}, json = true): RequestInit {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = {}
  const formData = typeof FormData !== 'undefined' && init.body instanceof FormData
  if (json && !formData) headers['content-type'] = 'application/json'
  if (token) headers.authorization = `Bearer ${token}`
  else if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken
  return { ...init, credentials: token ? 'omit' : 'same-origin', headers: { ...headers, ...(init.headers as Record<string, string> ?? {}) } }
}

async function errorMessage(res: Response): Promise<string> {
  try { const b = await res.json(); return b?.error ?? `HTTP ${res.status}` } catch { return `HTTP ${res.status}` }
}

export async function discoverSession(): Promise<BFFSession> {
  let res: Response
  try {
    res = await fetch('/api/auth/session', { credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  // 401/403 = not signed in; 404 = a token-only server that doesn't mount the OIDC BFF
  // (the /api/auth/* routes are registered only when OIDC is enabled). Both mean "no
  // session" — surface the login screen rather than an error.
  if (res.status === 401 || res.status === 403 || res.status === 404) return { authenticated: false, csrfToken: '' }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res))
  const body = await res.json()
  if (body?.authenticated !== true) return { authenticated: false, csrfToken: '' }
  const csrf = body?.csrf_token ?? body?.csrfToken ?? body?.csrf
  if (typeof csrf !== 'string' || csrf === '') {
    throw new ApiError(res.status, 'The sign-in session did not include a CSRF token.')
  }
  return { authenticated: true, csrfToken: csrf }
}

export async function logoutSession(): Promise<void> {
  let res: Response
  try {
    res = await fetch('/api/auth/logout', apiRequestInit({ method: 'POST' }))
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res))
}

export async function req(path: string, init?: RequestInit): Promise<any> {
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, apiRequestInit(init))
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body?.error) msg = body.error
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204) return null
  return res.json()
}

/** Fetch a SARIF/OpenVEX export with the bearer token and trigger a browser download. */
export async function blobDownload(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, apiRequestInit({}, false))
  if (res.status === 401 && onUnauthorized) onUnauthorized()
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const b = await res.json()
      if (b?.error) msg = b.error
    } catch {
      /* non-JSON */
    }
    throw new ApiError(res.status, msg)
  }
  const blob = await res.blob()
  const cd = res.headers.get('content-disposition') ?? ''
  const filename = /filename="([^"]+)"/.exec(cd)?.[1] ?? fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
