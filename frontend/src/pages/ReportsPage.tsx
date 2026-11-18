import { useState } from 'react'
import { api, ApiError } from '../api/client'

/**
 * The reports page.
 *
 * LAB 11 (SpEL) and LAB 12 (SSTI + command injection) live here: the
 * template box and the date filter are the two inputs the server evaluates.
 */
export default function ReportsPage() {
  const [template, setTemplate] = useState("Statement for #{accountId}")
  const [accountId, setAccountId] = useState('1')
  const [report, setReport] = useState<string | null>(null)

  const [fromDate, setFromDate] = useState('2026-01-01')
  const [toDate, setToDate] = useState('2026-01-31')
  const [filterOutput, setFilterOutput] = useState<string | null>(null)

  const [error, setError] = useState<string | null>(null)

  async function generate(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setReport(null)
    try {
      const res = await api.post<{ report: string }>('/api/report/generate', {
        template,
        account_id: accountId,
      })
      setReport(res.report)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Report failed.')
    }
  }

  async function dateFilter(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setFilterOutput(null)
    try {
      const res = await api.post<Record<string, unknown>>(
        '/api/report/date-filter',
        { from_date: fromDate, to_date: toDate },
      )
      setFilterOutput(JSON.stringify(res, null, 2))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Date filter failed.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Reports</h1>
        <p className="mt-1 text-sm text-ink-300">
          Generate a statement from a template, and filter it by date range.
        </p>
      </div>

      <form onSubmit={generate} className="card space-y-4">
        <h2 className="text-sm font-semibold text-slate-100">Statement template</h2>

        <div className="grid gap-3 sm:grid-cols-4">
          <div className="sm:col-span-3">
            <label className="label" htmlFor="template">
              Template
            </label>
            <input
              id="template"
              className="input font-mono text-xs"
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="accountId">
              Account id
            </label>
            <input
              id="accountId"
              className="input"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
            />
          </div>
        </div>

        <button type="submit" className="btn-primary">
          Generate report
        </button>

        {report !== null && (
          <pre className="overflow-x-auto rounded-lg border border-white/10 bg-black/30 p-3 font-mono text-xs text-slate-200">
            {report}
          </pre>
        )}
      </form>

      <form onSubmit={dateFilter} className="card space-y-4">
        <h2 className="text-sm font-semibold text-slate-100">Date filter</h2>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="fromDate">
              From date
            </label>
            <input
              id="fromDate"
              className="input font-mono text-xs"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="toDate">
              To date
            </label>
            <input
              id="toDate"
              className="input font-mono text-xs"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
            />
          </div>
        </div>

        <button type="submit" className="btn-primary">
          Apply filter
        </button>

        {filterOutput !== null && (
          <pre className="overflow-x-auto rounded-lg border border-white/10 bg-black/30 p-3 font-mono text-xs text-slate-200">
            {filterOutput}
          </pre>
        )}
      </form>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}
    </div>
  )
}
