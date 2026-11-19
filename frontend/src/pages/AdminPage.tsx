import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'

interface AdminUser {
  id: number
  username: string
  email: string
  full_name: string
  role: string
  password_hash: string
}

interface AdminAccount {
  id: number
  account_number: string
  owner_id: number
  balance: number
}

/**
 * The admin page.
 *
 * LAB 2 (missing role check): the page is reachable by any customer, so
 * there is deliberately no role gate here in the UI either — the
 * protection is supposed to be the Spring Security matcher, and the lab is
 * that it is not.
 */
export default function AdminPage() {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [accounts, setAccounts] = useState<AdminAccount[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<AdminUser[]>('/api/admin/users')
      .then(setUsers)
      .catch((e: Error) => setError(e.message))
    api
      .get<AdminAccount[]>('/api/admin/accounts')
      .then(setAccounts)
      .catch(() => {
        // A non-admin may be refused here; the users endpoint is the
        // decisive one for Lab 2.
      })
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">
          Administration
        </h1>
        <p className="mt-1 text-sm text-ink-300">
          Every user in the system, and every account.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="card">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Users</h2>
        {users.length === 0 ? (
          <p className="text-sm text-ink-300">No users returned.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[11px] uppercase tracking-wide text-ink-300">
                  <th className="px-4 py-2 font-medium">Id</th>
                  <th className="px-4 py-2 font-medium">Username</th>
                  <th className="px-4 py-2 font-medium">Email</th>
                  <th className="px-4 py-2 font-medium">Role</th>
                  <th className="px-4 py-2 font-medium">Password hash</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="table-row">
                    <td className="px-4 py-3 font-mono text-xs">{u.id}</td>
                    <td className="px-4 py-3">{u.username}</td>
                    <td className="px-4 py-3 text-xs">{u.email}</td>
                    <td className="px-4 py-3">
                      <span className="pill bg-white/5 text-ink-300">
                        {u.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-amber-200">
                      {u.password_hash}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {accounts.length > 0 && (
        <div className="card">
          <h2 className="mb-3 text-sm font-semibold text-slate-100">
            Accounts
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[11px] uppercase tracking-wide text-ink-300">
                  <th className="px-4 py-2 font-medium">Id</th>
                  <th className="px-4 py-2 font-medium">Account number</th>
                  <th className="px-4 py-2 font-medium">Owner id</th>
                  <th className="px-4 py-2 text-right font-medium">Balance</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.id} className="table-row">
                    <td className="px-4 py-3 font-mono text-xs">{a.id}</td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {a.account_number}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{a.owner_id}</td>
                    <td className="px-4 py-3 text-right">
                      £{Number(a.balance).toLocaleString('en-GB', {
                        minimumFractionDigits: 2,
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * The operations console (Lab 5).
 *
 * It lives in its own URL space — /admin-panel — so that it cannot be
 * confused with the admin API, and so that the two labs are fixed
 * independently.
 */
export function OperationsConsole() {
  const [username, setUsername] = useState('admin')
  // LAB 5 (fixed): the admin's password has been rotated away from the
  // shipped default, so `admin / admin` no longer signs in.
  const [password, setPassword] = useState('S3cure-Admin-Passw0rd!')
  const [session, setSession] = useState<string | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSession(null)
    try {
      const res = await api.post<{ session: string }>(
        '/admin-panel/login',
        { username, password },
        true,
      )
      setSession(res.session)
      const list = await api.get<AdminUser[]>('/admin-panel/users')
      setUsers(list)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">
          Operations console
        </h1>
        <p className="mt-1 text-sm text-ink-300">
          The internal console. It has its own credential check.
        </p>
      </div>

      <form onSubmit={submit} className="card space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="panelUser">
              Username
            </label>
            <input
              id="panelUser"
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="panelPass">
              Password
            </label>
            <input
              id="panelPass"
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button type="submit" className="btn-primary">
            Sign in
          </button>
          {session && (
            <span className="text-sm text-emerald-400">
              Signed in — session {session}
            </span>
          )}
          {error && <span className="text-sm text-rose-400">{error}</span>}
        </div>
      </form>

      {users.length > 0 && (
        <div className="card">
          <h2 className="mb-3 text-sm font-semibold text-slate-100">
            Console users
          </h2>
          <div className="space-y-2">
            {users.map((u) => (
              <div
                key={u.id}
                className="rounded-lg border border-white/10 px-3 py-2 text-sm"
              >
                <div className="flex items-center justify-between">
                  <span>{u.username}</span>
                  <span className="pill bg-white/5 text-ink-300">{u.role}</span>
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-amber-200">
                  {u.password_hash}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
