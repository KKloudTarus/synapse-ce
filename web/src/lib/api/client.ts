import { ApiError, errorFromResponse } from './errors'

export { ApiError } from './errors'

type AuthMaterial = Readonly<{ bearer: string; csrf: string; epoch: number }>

// Changing either credential creates a new epoch. Requests retain the immutable material they began
// with, so a late rejection cannot invalidate a credential installed by a newer authentication flow.
let authMaterial: AuthMaterial = { bearer: '', csrf: '', epoch: 0 }

// Called when a response says the caller is no longer authenticated. It receives the parsed error so
// it can tell a rejected credential from a missing one.
type UnauthorizedHandler = (error?: ApiError) => void
let onUnauthorized: UnauthorizedHandler | null = null

export function setToken(t: string): void {
  if (t === authMaterial.bearer) return
  authMaterial = { ...authMaterial, bearer: t, epoch: authMaterial.epoch + 1 }
}

// The BFF issues this token with the session; it intentionally remains in memory only.
export function setCSRFToken(t: string): void {
  if (t === authMaterial.csrf) return
  authMaterial = { ...authMaterial, csrf: t, epoch: authMaterial.epoch + 1 }
}

export function setUnauthorizedHandler(fn: UnauthorizedHandler): void {
  onUnauthorized = fn
}

export type AuthSnapshot = Readonly<{
  requestInit: (init?: RequestInit, json?: boolean) => RequestInit
  notifyUnauthorized: (error?: ApiError) => void
}>

/** Captures the current authentication material for one request without exposing it to React state. */
export function snapshotAuth(): AuthSnapshot {
  const snapshot = authMaterial
  return {
    requestInit: (init = {}, json = true) => apiRequestInit(snapshot, init, json),
    notifyUnauthorized: (error) => notifyUnauthorized(snapshot.epoch, error),
  }
}

export function newIdempotencyKey(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}

export type BFFSession = { authenticated: boolean; csrfToken: string }

function apiRequestInit(material: AuthMaterial, init: RequestInit = {}, json = true): RequestInit {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = {}
  const formData = typeof FormData !== 'undefined' && init.body instanceof FormData
  if (json && !formData) headers['content-type'] = 'application/json'
  if (material.bearer) headers.authorization = `Bearer ${material.bearer}`
  else if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method) && material.csrf) headers['X-CSRF-Token'] = material.csrf
  return { ...init, credentials: material.bearer ? 'omit' : 'same-origin', headers: { ...headers, ...(init.headers as Record<string, string> ?? {}) } }
}

// Only an authentication outcome for the still-current material reaches the global handler. A 503
// authentication_unavailable, a 403 of any kind or another 5xx describes a dependency or an
// authorization decision, not the credential, so it never signs the operator out.
function notifyUnauthorized(epoch: number, error?: ApiError): void {
  if (!onUnauthorized || epoch !== authMaterial.epoch) return
  if (error === undefined || error.status === 401 || error.code === 'authentication_invalid') onUnauthorized(error)
}

// Discovery rotates the session. When two tabs discover at the same moment one rotation wins and the
// other gets 409 conflict with the cookie left in place; the browser already holds the winner's
// replacement cookie, so one more attempt picks it up.
const DISCOVERY_CONFLICT_RETRY_MS = 250

async function fetchSession(): Promise<Response> {
  try {
    return await fetch('/api/auth/session', { credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
}

export async function discoverSession(): Promise<BFFSession> {
  let res = await fetchSession()
  if (res.status === 409) {
    await new Promise((resolve) => setTimeout(resolve, DISCOVERY_CONFLICT_RETRY_MS))
    res = await fetchSession()
  }
  // 401/403 = not signed in; 404 = a token-only server that doesn't mount the OIDC BFF
  // (the /api/auth/* routes are registered only when OIDC is enabled). Both mean "no
  // session" — surface the login screen rather than an error. A 503 authentication_unavailable
  // or any other failure is thrown instead: the session store could not answer, which says
  // nothing about whether the cookie is still valid.
  if (res.status === 401 || res.status === 403 || res.status === 404) return { authenticated: false, csrfToken: '' }
  if (!res.ok) throw await errorFromResponse(res)
  const body = await res.json()
  if (body?.authenticated !== true) return { authenticated: false, csrfToken: '' }
  const csrf = body?.csrf_token ?? body?.csrfToken ?? body?.csrf
  if (typeof csrf !== 'string' || csrf === '') {
    throw new ApiError(res.status, 'The sign-in session did not include a CSRF token.')
  }
  return { authenticated: true, csrfToken: csrf }
}

export async function logoutSession(): Promise<void> {
  const auth = snapshotAuth()
  let res: Response
  try {
    res = await fetch('/api/auth/logout', auth.requestInit({ method: 'POST' }))
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!res.ok) {
    const error = await errorFromResponse(res)
    auth.notifyUnauthorized(error)
    throw error
  }
}

export async function req(path: string, init?: RequestInit): Promise<any> {
  const auth = snapshotAuth()
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, auth.requestInit(init))
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!res.ok) {
    const error = await errorFromResponse(res)
    auth.notifyUnauthorized(error)
    throw error
  }
  if (res.status === 204) return null
  return res.json()
}

/** Fetch a SARIF/OpenVEX export with the bearer token and trigger a browser download. */
export async function blobDownload(path: string, fallbackName: string): Promise<void> {
  const auth = snapshotAuth()
  const res = await fetch(path, auth.requestInit({}, false))
  if (!res.ok) {
    const error = await errorFromResponse(res)
    auth.notifyUnauthorized(error)
    throw error
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
