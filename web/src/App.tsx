import { lazy, Suspense, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useLocation, parseLocation, canonicalPath, navigate } from './lib/router'
import ConsoleProvider from './components/Layout/ConsoleProvider'
import Sidebar from './components/Layout/Sidebar'
import TopBar, { ReadOnlyBanner } from './components/Layout/TopBar'
import { AuthProvider, useAuth } from './lib/authContext'
import LoginPage from './components/Auth/LoginPage'
import ErrorBoundary from './components/ErrorBoundary'
import DashboardPage from './pages/DashboardPage'
import TimelinePage from './pages/TimelinePage'
import ServersPage from './pages/ServersPage'
import DriftPage from './pages/DriftPage'
import IntegrationsPage from './pages/IntegrationsPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'

// Monaco is large; only pull it in when the inspector drawer opens.
const InspectorDrawer = lazy(() => import('./components/Inspector/InspectorDrawer'))

export default function App() {
  const loc = useLocation()
  const route = parseLocation(loc)

  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [selectedHostId, setSelectedHostId] = useState('')

  // Settle legacy paths onto their canonical route. `/grafana` was the route
  // before the integrations hub existed; rewriting it keeps the address bar
  // honest while old bookmarks and Grafana deep links keep working.
  useEffect(() => {
    const canonical = canonicalPath(loc)
    if (canonical && canonical !== loc) {
      window.history.replaceState(null, '', canonical)
      navigate(canonical)
    }
  }, [loc])

  // Debounce the universal search so each keystroke doesn't hit the API.
  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput), 300)
    return () => clearTimeout(t)
  }, [searchInput])

  const page = useMemo(() => {
    switch (route.view) {
      case 'timeline':
        return <TimelinePage />
      case 'servers':
        return <ServersPage />
      case 'drift':
        return <DriftPage />
      case 'integrations':
        return <IntegrationsPage />
      case 'reports':
        return <ReportsPage />
      case 'settings':
        return <SettingsPage />
      case 'dashboard':
      default:
        return <DashboardPage />
    }
  }, [route.view])

  return (
    <AuthProvider>
      <Gate>
        <ConsoleProvider
          search={search}
          view={route.view}
          hostId={selectedHostId}
          setHostId={setSelectedHostId}
        >
          <div className="flex h-full overflow-hidden bg-slate-50">
            <Sidebar />
            <div className="flex min-w-0 flex-1 flex-col">
              <TopBar search={searchInput} onSearch={setSearchInput} />
              <ReadOnlyBanner />
              <main className="min-h-0 flex-1 overflow-hidden">
                <ErrorBoundary key={route.view} label="this page">
                  {page}
                </ErrorBoundary>
              </main>
            </div>
          </div>

          {route.eventId ? (
            <Suspense fallback={<div className="fixed inset-0 z-50 bg-slate-900/30" aria-hidden />}>
              <ErrorBoundary label="the inspector drawer">
                <InspectorDrawer eventId={route.eventId} initialTab={route.tab} />
              </ErrorBoundary>
            </Suspense>
          ) : null}
        </ConsoleProvider>
      </Gate>
    </AuthProvider>
  )
}

/**
 * Blocks the console behind the sign-in screen when the deployment requires
 * authentication.
 *
 * Demo/dev deployments sign in automatically, so the gate is invisible there.
 * A production server has no auto-login, and rendering the console anyway would
 * show six pages of empty panels fed by 401s; the login screen is the honest
 * first paint. While the posture is still loading the console is not rendered at
 * all, which avoids a flash of either state.
 */
function Gate({ children }: { children: ReactNode }) {
  const auth = useAuth()
  if (auth.isLoading) {
    return (
      <div className="flex h-full items-center justify-center bg-slate-50 text-sm text-slate-400">
        Loading console…
      </div>
    )
  }
  if (!auth.user) {
    return (
      <div className="h-full overflow-auto">
        <LoginPage sso={auth.me?.sso} />
      </div>
    )
  }
  return <>{children}</>
}
