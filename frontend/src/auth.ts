/** Minimal bearer-session store for real backend authentication. */

const TOKEN_KEY = 'ecdat-session-token'
const EMAIL_KEY = 'ecdat-session-email'

export interface SessionInfo {
  token: string
  email: string
}

export const authStore = {
  getToken(): string | null {
    return window.localStorage.getItem(TOKEN_KEY)
  },
  getEmail(): string | null {
    return window.localStorage.getItem(EMAIL_KEY)
  },
  isSignedIn(): boolean {
    return Boolean(window.localStorage.getItem(TOKEN_KEY))
  },
  setSession(token: string, email: string): void {
    window.localStorage.setItem(TOKEN_KEY, token)
    window.localStorage.setItem(EMAIL_KEY, email)
    window.localStorage.removeItem('ecdat-demo-session')
  },
  clear(): void {
    window.localStorage.removeItem(TOKEN_KEY)
    window.localStorage.removeItem(EMAIL_KEY)
    window.localStorage.removeItem('ecdat-demo-session')
  },
}

export function authHeaders(): Record<string, string> {
  const token = authStore.getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}
