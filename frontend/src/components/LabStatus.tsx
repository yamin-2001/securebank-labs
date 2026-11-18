import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface LabState {
  users: number
  accounts: number
  transfers: number
  balance_total: number
}

/**
 * The lab state strip.
 *
 * Exploiting a lab moves money, promotes accounts and stores notes, so the
 * state drifts as you work. This shows the seeded totals so a drift is
 * visible, and the navbar's Reset button restores them.
 */
export default function LabStatus() {
  const [state, setState] = useState<LabState | null>(null)

  useEffect(() => {
    api
      .get<LabState>('/api/lab/state')
      .then(setState)
      .catch(() => setState(null))
  }, [])

  if (!state) return null

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-300">
      <span>
        <span className="text-slate-300">{state.users}</span> users
      </span>
      <span>
        <span className="text-slate-300">{state.accounts}</span> accounts
      </span>
      <span>
        <span className="text-slate-300">{state.transfers}</span> transfers
      </span>
      <span>
        seeded balance £
        <span className="text-slate-300">
          {Number(state.balance_total).toLocaleString('en-GB', {
            minimumFractionDigits: 2,
          })}
        </span>
      </span>
    </div>
  )
}
