import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'

interface Transfer {
  id: number
  from_account_id: number
  to_account_id: number
  amount: number
  note: string | null
  created_at?: string
}

/**
 * The transfers page.
 *
 * LAB 13 (stored XSS): the note is injected with `dangerouslySetInnerHTML`.
 * That is deliberate — it matches the original lab and it is the render
 * path the fix has to cover.
 *
 * Note that this page renders the note itself; it does not go through the
 * server-side `NoteRenderer`. The API's `/api/transfers/html` endpoint uses
 * that renderer, so the two are *separate* render paths: escaping in
 * `NoteRenderer` fixes the API but leaves this page injectable. The fix
 * for this lab has to cover both.
 */
export default function TransfersPage() {
  const [transfers, setTransfers] = useState<Transfer[]>([])
  const [fromId, setFromId] = useState('1')
  const [toId, setToId] = useState('2')
  const [amount, setAmount] = useState('10.00')
  const [note, setNote] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<Transfer[]>('/api/transfers/history')
      .then(setTransfers)
      .catch((e: Error) => setError(e.message))
  }, [])

  async function send(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    setError(null)
    try {
      const res = await api.post<{ message: string; transfer: Transfer }>(
        '/api/transfers/send',
        {
          from_account_id: Number(fromId),
          to_account_id: Number(toId),
          amount: Number(amount),
          note: note || null,
        },
      )
      setMessage(res.message)
      setNote('')
      const fresh = await api.get<Transfer[]>('/api/transfers/history')
      setTransfers(fresh)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Transfer failed.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Transfers</h1>
        <p className="mt-1 text-sm text-ink-300">
          Send money between accounts and review your history.
        </p>
      </div>

      <form onSubmit={send} className="card space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <label className="label" htmlFor="fromId">
              From account id
            </label>
            <input
              id="fromId"
              className="input"
              value={fromId}
              onChange={(e) => setFromId(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="toId">
              To account id
            </label>
            <input
              id="toId"
              className="input"
              value={toId}
              onChange={(e) => setToId(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="amount">
              Amount
            </label>
            <input
              id="amount"
              className="input"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
            />
          </div>
        </div>

        <div>
          <label className="label" htmlFor="note">
            Note
          </label>
          <input
            id="note"
            className="input"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="e.g. Rent for August"
          />
        </div>

        <div className="flex items-center gap-3">
          <button type="submit" className="btn-primary">
            Send transfer
          </button>
          {message && <span className="text-sm text-emerald-400">{message}</span>}
          {error && <span className="text-sm text-rose-400">{error}</span>}
        </div>
      </form>

      <div className="card">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">History</h2>
        {transfers.length === 0 ? (
          <p className="text-sm text-ink-300">No transfers yet.</p>
        ) : (
          <div className="space-y-2">
            {transfers.map((t) => (
              <div
                key={t.id}
                className="rounded-lg border border-white/10 px-3 py-2 text-sm"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-ink-300">
                    #{t.id} · {t.from_account_id} → {t.to_account_id}
                  </span>
                  <span className="font-medium">
                    £{Number(t.amount).toLocaleString('en-GB', {
                      minimumFractionDigits: 2,
                    })}
                  </span>
                </div>
                {t.note && (
                  <div className="mt-1 text-xs text-slate-300">
                    {/*
                      LAB 13: the note is rendered as raw HTML on purpose.
                      The server-side renderer (NoteRenderer) is the fix
                      location; when it escapes the note, this shows the
                      escaped text instead of live markup.
                    */}
                    <div
                      className="txn-note"
                      dangerouslySetInnerHTML={{ __html: t.note }}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
