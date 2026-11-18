import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { getSession, logout } from './api/client'
import NavBar from './components/NavBar'
import LabPanel from './components/LabPanel'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AccountsPage from './pages/AccountsPage'
import TransfersPage from './pages/TransfersPage'
import ProfilePage from './pages/ProfilePage'
import AdminPage, { OperationsConsole } from './pages/AdminPage'
import ReportsPage from './pages/ReportsPage'

export default function App() {
  const [session, setSession] = useState(getSession())
  const [panelOpen, setPanelOpen] = useState(false)
  const location = useLocation()

  // Close the lab panel whenever the route changes — it is a drawer, not a
  // page.
  useEffect(() => {
    setPanelOpen(false)
  }, [location.pathname])

  if (!session) {
    return (
      <Routes>
        <Route
          path="*"
          element={<LoginPage onLoggedIn={(s) => setSession(s)} />}
        />
      </Routes>
    )
  }

  return (
    <div className="min-h-screen">
      <NavBar
        session={session}
        onLogout={() => {
          logout()
          setSession(null)
        }}
        onTogglePanel={() => setPanelOpen((v) => !v)}
      />

      <div className="mx-auto max-w-6xl px-4 py-6">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/accounts" element={<AccountsPage />} />
          <Route path="/transfers" element={<TransfersPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/ops-console" element={<OperationsConsole />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </div>

      <LabPanel open={panelOpen} onClose={() => setPanelOpen(false)} />
    </div>
  )
}
