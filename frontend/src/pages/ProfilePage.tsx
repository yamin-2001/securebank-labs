import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'

interface Profile {
  id: number
  username: string
  email: string
  full_name: string
  role: string
}

/**
 * The profile page.
 *
 * LAB 15 (mass assignment): the update form sends the raw JSON body, so a
 * `role` field in the payload is what the server binds. The "extra fields"
 * box is here so you can send `{"role":"admin"}` and watch it land.
 */
export default function ProfilePage() {
  const [profile, setProfile] = useState<Profile | null>(null)
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [extra, setExtra] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<Profile>('/api/profile')
      .then((p) => {
        setProfile(p)
        setEmail(p.email ?? '')
        setFullName(p.full_name ?? '')
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setMessage(null)
    setError(null)

    // The extra box is merged into the same request body — that is the
    // whole point of the lab.
    let extraFields: Record<string, unknown> = {}
    if (extra.trim()) {
      try {
        extraFields = JSON.parse(extra)
      } catch {
        setError('The extra fields must be valid JSON.')
        return
      }
    }

    try {
      const updated = await api.patch<Profile>('/api/profile', {
        email,
        full_name: fullName,
        ...extraFields,
      })
      setProfile(updated)
      setMessage('Profile updated.')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Update failed.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Profile</h1>
        <p className="mt-1 text-sm text-ink-300">
          Your account details and the request body the server accepts.
        </p>
      </div>

      {profile && (
        <div className="card grid gap-3 sm:grid-cols-2">
          <Field label="Id" value={String(profile.id)} />
          <Field label="Username" value={profile.username} />
          <Field label="Email" value={profile.email} />
          <Field label="Full name" value={profile.full_name} />
          <Field label="Role" value={profile.role} />
        </div>
      )}

      <form onSubmit={save} className="card space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="fullName">
              Full name
            </label>
            <input
              id="fullName"
              className="input"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
            />
          </div>
        </div>

        <div>
          <label className="label" htmlFor="extra">
            Extra fields (merged into the same request body)
          </label>
          <input
            id="extra"
            className="input font-mono text-xs"
            value={extra}
            onChange={(e) => setExtra(e.target.value)}
            placeholder='{"role": "admin"}'
          />
        </div>

        <div className="flex items-center gap-3">
          <button type="submit" className="btn-primary">
            Save profile
          </button>
          {message && <span className="text-sm text-emerald-400">{message}</span>}
          {error && <span className="text-sm text-rose-400">{error}</span>}
        </div>
      </form>
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
