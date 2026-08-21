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
let onUnauthorized: (() => void) | null = null

export function setToken(t: string): void {
  token = t
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

export async function req(path: string, init?: RequestInit): Promise<any> {
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {}),
      },
    })
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
  const res = await fetch(path, { headers: token ? { authorization: `Bearer ${token}` } : {} })
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
