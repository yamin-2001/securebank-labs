import { NavLink } from 'react-router-dom'
import { api, type Session } from '../api/client'
import LabStatus from './LabStatus'

interface Props {
  session: Session
  onLogout: () => void
  onTogglePanel: () => void
}

const LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/accounts', label: 'Accounts' },
  { to: '/transfers', label: 'Transfers' },
  { to: '/reports', label: 'Reports' },
  { to: '/profile', label: 'Profile' },
  { to: '/ops-console', label: 'Ops console' },
]

export default function NavBar({ session, onLogout, onTogglePanel }: Props) {
  async function resetLabState() {
    await api.post('/api/lab/reset')
    // The seeded state is back: balances, roles and password hashes. A
    // reload makes every page pick it up.
    window.location.reload()
  }

  return (
    <header className="sticky top-0 z-30 border-b border-white/10 bg-ink-900/85 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-bank-500 text-sm font-bold text-white">
            S
          </div>
          <span className="text-sm font-semibold tracking-wide text-slate-100">
            SecureBank
          </span>
        </div>

        <nav className="ml-4 hidden items-center gap-1 md:flex">
          {LINKS.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `rounded-lg px-3 py-1.5 text-sm transition-colors ${
                  isActive
                    ? 'bg-white/10 text-slate-100'
                    : 'text-ink-300 hover:bg-white/5 hover:text-slate-200'
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
          {session.role === 'admin' && (
            <NavLink
              to="/admin"
              className={({ isActive }) =>
                `rounded-lg px-3 py-1.5 text-sm transition-colors ${
                  isActive
                    ? 'bg-white/10 text-slate-100'
                    : 'text-ink-300 hover:bg-white/5 hover:text-slate-200'
                }`
              }
            >
              Admin
            </NavLink>
          )}
        </nav>

        <div className="ml-auto flex items-center gap-3">
          <button
            type="button"
            onClick={onTogglePanel}
            className="btn-ghost text-xs"
            title="Open the lab panel"
          >
            Labs
          </button>
          <button
            type="button"
            onClick={resetLabState}
            className="btn-ghost text-xs"
            title="Restore the seeded balances, roles and password hashes"
          >
            Reset
          </button>
          <div className="hidden text-right sm:block">
            <div className="text-xs font-medium text-slate-200">
              {session.username}
            </div>
            <div className="text-[11px] text-ink-300">{session.role}</div>
          </div>
          <div className="hidden lg:block">
            <LabStatus />
          </div>
          <button type="button" onClick={onLogout} className="btn-ghost text-xs">
            Sign out
          </button>
        </div>
      </div>

      <nav className="flex items-center gap-1 overflow-x-auto border-t border-white/5 px-4 py-2 md:hidden">
        {LINKS.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `whitespace-nowrap rounded-lg px-3 py-1 text-xs ${
                isActive ? 'bg-white/10 text-slate-100' : 'text-ink-300'
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
        {session.role === 'admin' && (
          <NavLink
            to="/admin"
            className="whitespace-nowrap rounded-lg px-3 py-1 text-xs text-ink-300"
          >
            Admin
          </NavLink>
        )}
      </nav>
    </header>
  )
}
