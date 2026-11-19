import { useState } from 'react'
import { ApiError, login, type Session } from '../api/client'

interface Props {
  onLoggedIn: (session: Session) => void
}

const SEED_USERS = [
  { username: 'alice', password: 'password123', role: 'customer' },
  { username: 'bob', password: 'qwerty', role: 'customer' },
  { username: 'carol', password: 'letmein', role: 'customer' },
  // LAB 5 (fixed): the admin's password has been rotated away from the
  // shipped default, so `admin / admin` no longer signs in.
  { username: 'admin', password: 'S3cure-Admin-Passw0rd!', role: 'admin' },
]

export default function LoginPage({ onLoggedIn }: Props) {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('password123')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const session = await login(username, password)
      onLoggedIn(session)
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : 'Could not reach the server.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-xl bg-bank-500 text-lg font-bold text-white">
            S
          </div>
          <h1 className="text-xl font-semibold text-slate-100">SecureBank</h1>
          <p className="mt-1 text-sm text-ink-300">
            Sign in to your account
          </p>
        </div>

        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="label" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="label" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
              {error}
            </div>
          )}

          <button type="submit" className="btn-primary w-full" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="mt-5 rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-300">
            Seeded accounts
          </div>
          <div className="mt-2 space-y-1">
            {SEED_USERS.map((u) => (
              <button
                key={u.username}
                type="button"
                onClick={() => {
                  setUsername(u.username)
                  setPassword(u.password)
                }}
                className="flex w-full items-center justify-between rounded px-2 py-1 text-left font-mono text-xs text-ink-300 hover:bg-white/5"
              >
                <span>
                  {u.username} / {u.password}
                </span>
                <span className="text-[10px] uppercase">{u.role}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
