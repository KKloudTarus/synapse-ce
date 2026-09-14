export type IdentityErrorCode =
  | 'authentication_invalid'
  | 'identity_access_denied'
  | 'identity_conflict'
  | 'dependency_unavailable'
  | 'capacity_limited'

export type ApiErrorBody = {
  error?: string
  code?: string
  request_id?: string
  retryable?: boolean
  [key: string]: unknown
}

function errorBody(value: unknown): ApiErrorBody | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as ApiErrorBody
}

export class ApiError extends Error {
  public readonly code?: string
  public readonly requestId?: string
  public readonly retryable: boolean

  constructor(
    public status: number,
    message: string,
    // The parsed JSON error body, when the server sent one. Some endpoints attach structured detail
    // alongside the message. Existing callers that inspect err.body keep working while D2 identity
    // callers can use the stable code/requestId/retryable fields directly.
    public body?: unknown,
  ) {
    super(message)
    this.name = 'ApiError'
    const structured = errorBody(body)
    this.code = typeof structured?.code === 'string' ? structured.code : undefined
    this.requestId = typeof structured?.request_id === 'string' ? structured.request_id : undefined
    this.retryable = structured?.retryable === true
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

async function responseError(res: Response): Promise<ApiError> {
  let body: unknown
  let message = `HTTP ${res.status}`
  try {
    body = await res.json()
    const parsed = errorBody(body)
    if (typeof parsed?.error === 'string' && parsed.error !== '') message = parsed.error
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, message, body)
}

// Only the explicit D2 invalid-credential code is authoritative. The status-only fallback keeps
// compatibility with older Synapse servers during rolling upgrades. Unknown future codes fail
// closed toward PRESERVING credentials rather than unexpectedly signing a user out.
export function isAuthenticationInvalid(error: ApiError): boolean {
  if (error.code === 'authentication_invalid') return true
  return error.code === undefined && error.status === 401
}

function notifyAuthenticationInvalid(error: ApiError): void {
  if (isAuthenticationInvalid(error) && onUnauthorized) onUnauthorized()
}

export async function discoverSession(): Promise<BFFSession> {
  let res: Response
  try {
    res = await fetch('/api/auth/session', { credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  // 404 = token-only server that does not mount the OIDC BFF.
  if (res.status === 404) return { authenticated: false, csrfToken: '' }
  if (!res.ok) {
    const err = await responseError(res)
    if (isAuthenticationInvalid(err)) return { authenticated: false, csrfToken: '' }
    throw err
  }
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
  if (!res.ok) throw await responseError(res)
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
  if (!res.ok) {
    const err = await responseError(res)
    notifyAuthenticationInvalid(err)
    throw err
  }
  if (res.status === 204) return null
  return res.json()
}

/** Fetch a SARIF/OpenVEX export with the bearer token and trigger a browser download. */
export async function blobDownload(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, apiRequestInit({}, false))
  if (!res.ok) {
    const err = await responseError(res)
    notifyAuthenticationInvalid(err)
    throw err
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
