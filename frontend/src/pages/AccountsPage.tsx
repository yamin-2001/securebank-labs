import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'

interface Account {
  id: number
  account_number: string
  sort_code: string
  balance: number
  currency: string
  owner_id: number
}

/**
 * The accounts page.
 *
 * The account lookup at the top is deliberately a raw id field: Lab 1 is
 * "change the id and read someone else's account", so the UI has to let you
 * type an id that is not yours.
 */
export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([])
  const [lookupId, setLookupId] = useState('1')
  const [looked, setLooked] = useState<Account | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<Account[]>('/api/accounts')
      .then(setAccounts)
      .catch((e: Error) => setError(e.message))
  }, [])

  async function lookup(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLooked(null)
    try {
      const account = await api.get<Account>(`/api/accounts/${lookupId}`)
      setLooked(account)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Lookup failed.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Accounts</h1>
        <p className="mt-1 text-sm text-ink-300">
          Your accounts, and a direct lookup by account id.
        </p>
      </div>

      <div className="card">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">
          Look up an account by id
        </h2>
        <form onSubmit={lookup} className="flex flex-wrap items-end gap-3">
          <div className="w-32">
            <label className="label" htmlFor="lookupId">
              Account id
            </label>
            <input
              id="lookupId"
              className="input"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary">
            Fetch
          </button>
        </form>

        {error && (
          <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
            {error}
          </div>
        )}

        {looked && (
          <div className="mt-4 rounded-lg border border-white/10 bg-black/20 p-4">
            <div className="grid gap-2 text-sm sm:grid-cols-2">
              <Field label="Account id" value={String(looked.id)} />
              <Field label="Account number" value={looked.account_number} />
              <Field label="Sort code" value={looked.sort_code} />
              <Field label="Owner id" value={String(looked.owner_id)} />
              <Field
                label="Balance"
                value={`£${Number(looked.balance).toLocaleString('en-GB', {
                  minimumFractionDigits: 2,
                })}`}
              />
              <Field label="Currency" value={looked.currency} />
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">
          Your accounts
        </h2>
        {accounts.length === 0 ? (
          <p className="text-sm text-ink-300">No accounts to show.</p>
        ) : (
          <div className="space-y-2">
            {accounts.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => {
                  setLookupId(String(a.id))
                  setLooked(null)
                }}
                className="flex w-full items-center justify-between rounded-lg border border-white/10 px-3 py-2 text-left text-sm hover:bg-white/5"
              >
                <span className="font-mono text-xs">
                  #{a.id} · {a.account_number}
                </span>
                <span className="font-medium">
                  £{Number(a.balance).toLocaleString('en-GB', {
                    minimumFractionDigits: 2,
                  })}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-ink-300">
        {label}
      </div>
      <div className="font-mono text-xs text-slate-200">{value}</div>
    </div>
  )
}
