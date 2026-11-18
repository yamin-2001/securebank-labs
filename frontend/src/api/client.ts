/**
 * The API client.
 *
 * Every request goes through `request()`, which attaches the bearer token
 * when there is one. The token is kept in localStorage so a page reload
 * does not log you out — this is a lab app, and convenience beats
 * correctness here.
 */

const TOKEN_KEY = 'securebank.token'
const USER_KEY = 'securebank.user'

export interface Session {
  token: string
  username: string
  role: string
  user_id: number
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getSession(): Session | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as Session
  } catch {
    return null
  }
}

export function setSession(session: Session | null) {
  if (session) {
    localStorage.setItem(TOKEN_KEY, session.token)
    localStorage.setItem(USER_KEY, JSON.stringify(session))
  } else {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
  }
}

export class ApiError extends Error {
  status: number
  body: unknown

  constructor(status: number, body: unknown, message: string) {
    super(message)
    this.status = status
    this.body = body
  }
}

interface RequestOptions {
  method?: string
  json?: unknown
  headers?: Record<string, string>
  /** Skip the bearer token — used by the login call itself. */
  anonymous?: boolean
}

export async function request<T = unknown>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = 'GET', json, headers = {}, anonymous = false } = options

  const finalHeaders: Record<string, string> = { Accept: 'application/json', ...headers }
  const token = getToken()
  if (token && !anonymous) {
    finalHeaders.Authorization = `Bearer ${token}`
  }

  let body: BodyInit | undefined
  if (json !== undefined) {
    finalHeaders['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  }

  const res = await fetch(path, { method, headers: finalHeaders, body })

  const text = await res.text()
  let parsed: unknown = text
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    // Not JSON — keep the raw text (some lab endpoints answer with HTML).
  }

  if (!res.ok) {
    const message =
      (parsed && typeof parsed === 'object' && 'error' in parsed
        ? String((parsed as { error: unknown }).error)
        : typeof parsed === 'string'
          ? parsed
          : `HTTP ${res.status}`) || `HTTP ${res.status}`
    throw new ApiError(res.status, parsed, message)
  }

  return parsed as T
}

export const api = {
  get: <T = unknown>(path: string, headers?: Record<string, string>) =>
    request<T>(path, { method: 'GET', headers }),
  post: <T = unknown>(path: string, json?: unknown, anonymous = false) =>
    request<T>(path, { method: 'POST', json, anonymous }),
  patch: <T = unknown>(path: string, json?: unknown) =>
    request<T>(path, { method: 'PATCH', json }),
}

/** Log in and store the session. */
export async function login(username: string, password: string): Promise<Session> {
  const session = await api.post<Session>(
    '/api/auth/login',
    { username, password },
    true,
  )
  setSession(session)
  return session
}

export function logout() {
  setSession(null)
}
