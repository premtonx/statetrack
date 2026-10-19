import { useEffect, useRef, useState } from 'react'
import {
  Bell,
  Building2,
  Check,
  ChevronDown,
  LogOut,
  Search,
  ShieldCheck,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { useConsole } from '../../lib/consoleContext'
import { useAuth } from '../../lib/authContext'
import { useLogout } from '../../api/hooks'
import { NAV_ITEMS } from '../../lib/nav'
import { ROLE_OPTIONS, type Role } from '../../types'

/** Closes a popover when the pointer lands outside it. */
function useDismiss(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, onClose])
  return ref
}

function LiveIndicator() {
  const { liveStatus } = useConsole()
  const live = liveStatus === 'open'
  const state = live ? 'Live' : liveStatus === 'connecting' ? 'Connecting' : 'Offline'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium',
        live
          ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
          : liveStatus === 'connecting'
            ? 'border-slate-200 bg-slate-50 text-slate-500'
            : 'border-red-200 bg-red-50 text-red-700',
      )}
      title={
        live
          ? 'WebSocket connected — changes stream in as they happen.'
          : liveStatus === 'connecting'
            ? 'Connecting to the live stream…'
            : 'Live stream offline — showing the last loaded window.'
      }
    >
      <span className="relative flex h-1.5 w-1.5">
        {live ? (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-70" />
        ) : null}
        <span
          className={cn(
            'relative inline-flex h-1.5 w-1.5 rounded-full',
            live ? 'bg-emerald-600' : liveStatus === 'connecting' ? 'bg-slate-400' : 'bg-red-600',
          )}
        />
      </span>
      {state}
    </span>
  )
}

/** Notification bell with an unread badge and a small dropdown. */
function NotificationsMenu() {
  const [open, setOpen] = useState(false)
  const { openEvent } = useConsole()
  const ref = useDismiss(open, () => setOpen(false))

  const items = [
    { id: 'n1', tone: 'text-red-600', title: 'Level 1 · nginx.conf modified', meta: 'prod-web-01 · 6m ago' },
    { id: 'n2', tone: 'text-amber-600', title: 'Drift detected on 3 targets', meta: 'prod-web-02 vs prod-web-01 · 1h ago' },
    { id: 'n3', tone: 'text-slate-500', title: 'Agent offline', meta: 'staging-web-01 · 19h ago' },
  ]

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Notifications"
        className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-slate-700"
      >
        <Bell className="h-4 w-4" />
        <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-semibold text-white">
          3
        </span>
      </button>
      {open ? (
        <div className="panel-enter absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
            <span className="text-xs font-semibold text-slate-700">Notifications</span>
            <span className="rounded-full bg-red-50 px-1.5 text-[10px] font-semibold text-red-700">
              3 unread
            </span>
          </div>
          <ul>
            {items.map((n) => (
              <li key={n.id}>
                <button
                  onClick={() => {
                    setOpen(false)
                    openEvent('', undefined)
                  }}
                  className="flex w-full flex-col items-start gap-0.5 border-b border-slate-100 px-3 py-2.5 text-left last:border-0 hover:bg-slate-50"
                >
                  <span className={cn('text-xs font-medium', n.tone)}>{n.title}</span>
                  <span className="text-[11px] text-slate-400">{n.meta}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  )
}

/**
 * Profile pill and its menu: the live identity, the 2FA / SSO posture, and the
 * RBAC demo switcher.
 *
 * The switcher is the console's live proof that authorization is enforced
 * server-side: picking Auditor immediately narrows the session, the next
 * mutating request 403s, and this menu plus the banner appear read-only. It is
 * only offered when the server reports demo mode, so a production deployment
 * never shows it.
 */
function ProfileMenu() {
  const [open, setOpen] = useState(false)
  const { goTo } = useConsole()
  const auth = useAuth()
  const logout = useLogout()
  const ref = useDismiss(open, () => setOpen(false))

  const user = auth.user
  const role = user?.role ?? null
  const initials = user?.initials || '··'

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-full border border-slate-200 bg-white py-1 pl-1 pr-2.5 transition-colors hover:bg-slate-50"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-blue-600 text-xs font-semibold text-white">
          {initials}
        </span>
        <span className="hidden text-left leading-tight sm:block">
          <span className="block text-xs font-semibold text-slate-800">
            {user?.name || 'Not signed in'}
          </span>
          <span className="block text-[10px] text-slate-400">
            {auth.roleLabel(role) || (auth.isLoading ? 'Loading…' : '—')}
          </span>
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
      </button>

      {open ? (
        <div className="panel-enter absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg">
          {/* Identity */}
          <div className="flex items-start gap-3 px-4 py-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-600 text-sm font-semibold text-white">
              {initials}
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold text-slate-900">
                {user?.name || 'Not signed in'}
              </p>
              <p className="truncate text-xs text-slate-500">{user?.email || 'anonymous'}</p>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <span className="inline-flex items-center rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[10px] font-medium text-blue-700">
                  {auth.roleLabel(role) || 'Unknown role'}
                </span>
                {user?.totp_enabled ? (
                  <span className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-emerald-700">
                    <ShieldCheck className="h-3 w-3" /> 2FA Enabled
                  </span>
                ) : (
                  <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[10px] font-medium text-amber-700">
                    2FA Off
                  </span>
                )}
                {auth.me?.sso?.enabled ? (
                  <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-600">
                    SSO
                  </span>
                ) : null}
              </div>
            </div>
          </div>

          <div className="h-px bg-slate-100" />

          {/* RBAC demo switcher */}
          {auth.demoMode && user ? (
            <div className="px-2 py-2">
              <p className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                View console as
              </p>
              {ROLE_OPTIONS.map((opt) => {
                const on = opt.id === role
                // The granted role is the ceiling: an operator acting as
                // Auditor cannot switch back to Administrator.
                const reachable =
                  !auth.realRole || auth.realRole === 'admin' || opt.id === auth.realRole || opt.id === 'auditor'
                return (
                  <button
                    key={opt.id}
                    role="menuitemradio"
                    aria-checked={on}
                    disabled={!reachable || auth.isSwitchingRole}
                    onClick={() => {
                      if (opt.id !== role) auth.setRole(opt.id as Role)
                      setOpen(false)
                    }}
                    className={cn(
                      'flex w-full items-start gap-2.5 rounded-lg px-2 py-2 text-left transition-colors',
                      on ? 'bg-blue-50' : 'hover:bg-slate-50',
                      !reachable && 'cursor-not-allowed opacity-40 hover:bg-transparent',
                    )}
                  >
                    <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center">
                      {on ? <Check className="h-3.5 w-3.5 text-blue-600" /> : null}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span
                        className={cn(
                          'block text-xs font-medium',
                          on ? 'text-blue-700' : 'text-slate-700',
                        )}
                      >
                        {opt.label}
                      </span>
                      <span className="mt-0.5 block text-[11px] leading-snug text-slate-400">
                        {opt.description}
                      </span>
                    </span>
                  </button>
                )
              })}
            </div>
          ) : null}

          <div className="h-px bg-slate-100" />

          <div className="px-2 py-1.5">
            <button
              onClick={() => {
                setOpen(false)
                goTo('settings')
              }}
              className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-xs text-slate-600 hover:bg-slate-50"
            >
              <Building2 className="h-3.5 w-3.5 text-slate-400" /> Security &amp; SSO settings
            </button>
            <button
              onClick={() => {
                setOpen(false)
                logout.mutate()
              }}
              className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-xs text-slate-600 hover:bg-slate-50"
            >
              <LogOut className="h-3.5 w-3.5 text-slate-400" /> Sign out
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}

/** Compact integrations status, shown in the header cluster. */
function GrafanaBadge() {
  const { goTo } = useConsole()
  return (
    <button
      onClick={() => goTo('integrations')}
      title="Integrations — Grafana annotations, monitoring pollers and ChatOps delivery."
      className="hidden items-center gap-1.5 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-800 md:inline-flex"
    >
      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-600" />
      Integrations
    </button>
  )
}

/**
 * Read-only banner shown while acting as the compliance auditor.
 *
 * Deliberately quiet (a single slim strip) but impossible to miss: a console
 * that silently refuses writes is worse than one that explains why.
 */
export function ReadOnlyBanner() {
  const auth = useAuth()
  if (!auth.user || !auth.readOnly) return null
  return (
    <div className="flex shrink-0 items-center justify-center gap-2 border-b border-amber-200 bg-amber-50 px-4 py-1.5 text-xs font-medium text-amber-800">
      <span aria-hidden>🔒</span>
      <span>
        Viewing as Read-Only Compliance Auditor — mutating actions are disabled and the server
        rejects writes from this session.
      </span>
    </div>
  )
}

interface TopBarProps {
  search: string
  onSearch: (value: string) => void
}

/**
 * Top application bar: universal search with a ⌘K shortcut badge, the live
 * WebSocket pulse, notifications and the profile menu.
 */
export default function TopBar({ search, onSearch }: TopBarProps) {
  const { view } = useConsole()
  const inputRef = useRef<HTMLInputElement>(null)

  // ⌘K / Ctrl-K focuses the universal search from anywhere in the console.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        inputRef.current?.focus()
        inputRef.current?.select()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const current = NAV_ITEMS.find((n) => n.id === view)

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-slate-200 bg-white px-4">
      <div className="hidden min-w-0 shrink-0 items-center gap-1.5 lg:flex">
        <span className="truncate text-sm font-medium text-slate-400">StateTrack</span>
        <span className="text-sm text-slate-300">/</span>
        <span className="truncate text-sm font-semibold text-slate-800">
          {current?.label ?? 'Dashboard'}
        </span>
      </div>

      <div className="relative min-w-0 flex-1 lg:max-w-xl lg:pl-2">
        <Search className="pointer-events-none absolute left-[0.875rem] top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 lg:left-[1.375rem]" />
        <input
          ref={inputRef}
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search changes, servers, packages, users..."
          aria-label="Universal search"
          className="h-9 w-full rounded-lg border border-slate-200 bg-slate-50 pl-9 pr-12 text-sm text-slate-900 outline-none transition-colors placeholder:text-slate-400 focus:border-blue-400 focus:bg-white focus:ring-2 focus:ring-blue-500/15"
        />
        <span className="pointer-events-none absolute right-2.5 top-1/2 hidden -translate-y-1/2 rounded border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-400 sm:block">
          ⌘K
        </span>
      </div>

      <div className="ml-auto flex shrink-0 items-center gap-2">
        <GrafanaBadge />
        <LiveIndicator />
        <NotificationsMenu />
        <ProfileMenu />
      </div>
    </header>
  )
}
