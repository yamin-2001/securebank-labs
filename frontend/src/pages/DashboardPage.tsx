import { useEffect, useState } from 'react'
import { api, getSession } from '../api/client'

interface Account {
  id: number
  account_number: string
  sort_code: string
  balance: number
  currency: string
  owner_id: number
}

export default function DashboardPage() {
  const session = getSession()
  const [accounts, setAccounts] = useState<Account[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<Account[]>('/api/accounts')
      .then(setAccounts)
      .catch((e: Error) => setError(e.message))
  }, [])

  const total = accounts.reduce((sum, a) => sum + Number(a.balance ?? 0), 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">
          Welcome back, {session?.username}
        </h1>
        <p className="mt-1 text-sm text-ink-300">
          Your accounts, balances and recent activity.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-ink-300">
            Total balance
          </div>
          <div className="mt-1 text-2xl font-semibold text-slate-100">
            £{total.toLocaleString('en-GB', { minimumFractionDigits: 2 })}
          </div>
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-ink-300">
            Accounts
          </div>
          <div className="mt-1 text-2xl font-semibold text-slate-100">
            {accounts.length}
          </div>
        </div>
        <div className="card">
          <div className="text-xs uppercase tracking-wide text-ink-300">
            Role
          </div>
          <div className="mt-1 text-2xl font-semibold capitalize text-slate-100">
            {session?.role}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="card">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Your accounts</h2>
        {accounts.length === 0 ? (
          <p className="text-sm text-ink-300">No accounts to show.</p>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="text-[11px] uppercase tracking-wide text-ink-300">
                <th className="px-4 py-2 font-medium">Account</th>
                <th className="px-4 py-2 font-medium">Sort code</th>
                <th className="px-4 py-2 text-right font-medium">Balance</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id} className="table-row">
                  <td className="px-4 py-3 font-mono text-xs">
                    {a.account_number}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{a.sort_code}</td>
                  <td className="px-4 py-3 text-right font-medium">
                    £{Number(a.balance).toLocaleString('en-GB', {
                      minimumFractionDigits: 2,
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
