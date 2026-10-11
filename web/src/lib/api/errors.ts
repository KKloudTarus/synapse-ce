// Stable error codes the API attaches to JSON error bodies alongside the human `error` text. The set
// is open: a newer server may send a code this client does not know, so callers must branch on the
// codes they understand and fall back to `status` and `retryable` for everything else.
export type KnownApiErrorCode =
  | 'authentication_required'
  | 'authentication_invalid'
  | 'authentication_unavailable'
  | 'csrf_invalid'
  | 'aup_required'
  | 'permission_denied'
  | 'access_denied'
  | 'validation_failed'
  | 'not_found'
  | 'conflict'
  | 'saturated'
  | 'internal'

export class ApiError extends Error {
  // Absent when an older server sent only `{ error }`, or when the failure never reached the server.
  readonly code?: string
  // The server's X-Request-ID for this failure, shown to operators so support can find the log line.
  readonly requestId?: string
  // Whether repeating the same request may succeed without the user changing anything.
  readonly retryable: boolean

  constructor(
    public status: number,
    message: string,
    // The parsed JSON error body, when the server sent one. Some endpoints attach structured detail
    // alongside the message (e.g. /alerts/test returns { error, outcome } on 502); callers that need it
    // read err.body, while the common `err.status === 404` checks are unaffected.
    public body?: unknown,
    headerRequestId?: string,
  ) {
    super(message)
    this.name = 'ApiError'
    const fields = contractFields(body)
    this.code = fields.code
    this.requestId = fields.requestId ?? (headerRequestId || undefined)
    this.retryable = fields.retryable ?? defaultRetryable(status)
  }
}

function contractFields(body: unknown): { code?: string; requestId?: string; retryable?: boolean } {
  if (!body || typeof body !== 'object') return {}
  const b = body as Record<string, unknown>
  return {
    code: typeof b.code === 'string' && b.code !== '' ? b.code : undefined,
    requestId: typeof b.request_id === 'string' && b.request_id !== '' ? b.request_id : undefined,
    retryable: typeof b.retryable === 'boolean' ? b.retryable : undefined,
  }
}

// Without an explicit hint, a network failure (status 0) or any 5xx may clear up on its own, while a
// 4xx describes the request itself and repeats identically. This also covers unknown future codes.
function defaultRetryable(status: number): boolean {
  return status === 0 || status >= 500
}

/** Builds an ApiError from a non-OK response, tolerating non-JSON bodies and missing headers. */
export async function errorFromResponse(res: Response, fallbackMessage?: string): Promise<ApiError> {
  let body: unknown
  try {
    body = await res.json()
  } catch {
    body = undefined
  }
  const text = body && typeof body === 'object' ? (body as { error?: unknown }).error : undefined
  const message = typeof text === 'string' && text !== '' ? text : fallbackMessage ?? `HTTP ${res.status}`
  const headerRequestId = typeof res.headers?.get === 'function' ? res.headers.get('X-Request-ID') ?? undefined : undefined
  return new ApiError(res.status, message, body, headerRequestId)
}

/**
 * Reports whether the server definitively rejected the presented credential. This is the only
 * outcome that justifies discarding a stored credential. A 401 without a code comes from a server
 * that predates error codes, where 401 always meant a rejected credential.
 */
export function isCredentialInvalid(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false
  if (e.code) return e.code === 'authentication_invalid'
  return e.status === 401
}

/** Reports whether a response means the caller is no longer authenticated at all. */
export function isUnauthenticated(e: unknown): boolean {
  return isCredentialInvalid(e) || (e instanceof ApiError && e.code === 'authentication_required')
}
