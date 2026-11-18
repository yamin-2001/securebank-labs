import { useMemo, useState } from 'react'
import labs from '../labs.json'

interface Lab {
  id: number
  slug: string
  owasp: string
  title: string
  severity: string
  endpoint: string
  exploit: string
  affected: string
  hint: string
}

interface Props {
  open: boolean
  onClose: () => void
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
  high: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
  medium: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
  low: 'bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30',
}

export default function LabPanel({ open, onClose }: Props) {
  const [selected, setSelected] = useState<Lab | null>(null)
  const [filter, setFilter] = useState('')

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    if (!needle) return labs.labs
    return labs.labs.filter(
      (lab) =>
        lab.title.toLowerCase().includes(needle) ||
        lab.owasp.toLowerCase().includes(needle) ||
        lab.endpoint.toLowerCase().includes(needle),
    )
  }, [filter])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-40 flex">
      <div
        className="flex-1 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden
      />

      <aside className="flex w-full max-w-md flex-col border-l border-white/10 bg-ink-900 shadow-2xl">
        <div className="flex items-center gap-3 border-b border-white/10 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-100">Lab panel</h2>
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter labs…"
            className="input ml-auto max-w-[9rem] py-1 text-xs"
          />
          <button
            type="button"
            onClick={onClose}
            className="btn-ghost px-2 py-1 text-xs"
            aria-label="Close the lab panel"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-3">
          {visible.map((lab) => (
            <button
              key={lab.id}
              type="button"
              onClick={() => setSelected(lab)}
              className="mb-2 w-full rounded-lg border border-white/10 bg-white/[0.03] p-3 text-left transition-colors hover:bg-white/[0.07]"
            >
              <div className="flex items-center gap-2">
                <span className="pill bg-bank-500/20 text-bank-100">
                  {lab.id}
                </span>
                <span className="pill bg-white/5 text-ink-300">{lab.owasp}</span>
                <span
                  className={`pill ${SEVERITY_STYLES[lab.severity] ?? SEVERITY_STYLES.low}`}
                >
                  {lab.severity}
                </span>
              </div>
              <div className="mt-1.5 text-sm font-medium text-slate-100">
                {lab.title}
              </div>
              <div className="mt-0.5 font-mono text-[11px] text-ink-300">
                {lab.endpoint}
              </div>
            </button>
          ))}

          {visible.length === 0 && (
            <p className="p-4 text-center text-sm text-ink-300">
              No lab matches “{filter}”.
            </p>
          )}
        </div>
      </aside>

      {selected && (
        <div className="fixed inset-0 z-50 grid place-items-center p-4">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setSelected(null)}
          />
          <div className="card relative z-10 max-h-[85vh] w-full max-w-2xl overflow-y-auto">
            <div className="flex items-center gap-2">
              <span className="pill bg-bank-500/20 text-bank-100">
                LAB {selected.id}
              </span>
              <span className="pill bg-white/5 text-ink-300">
                {selected.owasp}
              </span>
              <span
                className={`pill ${SEVERITY_STYLES[selected.severity] ?? SEVERITY_STYLES.low}`}
              >
                {selected.severity}
              </span>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="btn-ghost ml-auto px-2 py-1 text-xs"
              >
                ✕
              </button>
            </div>

            <h3 className="mt-3 text-lg font-semibold text-slate-100">
              {selected.title}
            </h3>

            <Section title="Endpoint">
              <code className="font-mono text-xs text-bank-100">
                {selected.endpoint}
              </code>
            </Section>

            <Section title="Exploit steps">{selected.exploit}</Section>

            <Section title="Affected code">
              <code className="font-mono text-xs text-amber-200">
                {selected.affected}
              </code>
            </Section>

            <Section title="Hint">{selected.hint}</Section>
          </div>
        </div>
      )}
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-300">
        {title}
      </div>
      <div className="mt-1.5 text-sm leading-relaxed text-slate-300">
        {children}
      </div>
    </div>
  )
}
