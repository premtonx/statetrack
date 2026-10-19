import { ArrowRight, Waypoints } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useConsole } from '../../lib/consoleContext'
import { useHostList } from '../../api/hooks'
import { NAV_ITEMS } from '../../lib/nav'
import { PreviewBadge } from '../ui/StatusPill'

/** The console version shown in the sidebar. Kept in step with the release tag. */
const CONSOLE_VERSION = 'v0.1.0'

/**
 * Persistent 240px drawer: brand header, the seven-page navigation with
 * Google-style active pills, and a compact fleet-health footer whose
 * "Fleet Health →" row links to the Servers page (the full breakdown lives
 * there rather than as a dashboard card).
 *
 * A deployment with no enrolled agents reports "0/0 agents online" and asks
 * the operator to enrol one; it does not report an outage for a fleet that does
 * not exist yet.
 */
export default function Sidebar() {
  const { view, goTo } = useConsole()
  const { total, online, isLive } = useHostList()
  const noAgents = total === 0
  const allHealthy = total === 0 || online === total

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-200 bg-white">
      {/* Brand */}
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-slate-200 px-4">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-600 text-white shadow-xs">
          <Waypoints className="h-4 w-4" strokeWidth={2.2} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold tracking-tight text-slate-900">StateTrack</p>
          <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">
            {CONSOLE_VERSION}
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="min-h-0 flex-1 overflow-y-auto px-2 py-3">
        <p className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          Monitoring
        </p>
        <ul className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            const active = view === item.id
            return (
              <li key={item.id}>
                <button
                  onClick={() => goTo(item.id)}
                  aria-current={active ? 'page' : undefined}
                  className={cn(
                    'group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm font-medium transition-colors',
                    active
                      ? 'bg-blue-50 text-blue-700'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
                  )}
                >
                  <Icon
                    className={cn(
                      'h-4 w-4 shrink-0',
                      active ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-500',
                    )}
                  />
                  <span className="truncate">{item.label}</span>
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Fleet health footer */}
      <div className="shrink-0 border-t border-slate-200 px-3 py-3">
        <div className="flex items-center gap-1.5 px-1">
          <span
            className={cn(
              'h-1.5 w-1.5 shrink-0 rounded-full',
              noAgents ? 'bg-slate-300' : allHealthy ? 'bg-emerald-600' : 'bg-red-600',
            )}
          />
          <span className="truncate text-[11px] font-medium text-slate-700">
            {noAgents
              ? 'No agents enrolled'
              : allHealthy
                ? 'All Systems Operational'
                : `${total - online} agent(s) offline`}
          </span>
          {!isLive ? <PreviewBadge label="Sample" /> : null}
        </div>
        <p className="mt-0.5 px-1 text-[10px] tabular-nums text-slate-500">
          {online}/{total} agents online
        </p>
        <button
          onClick={() => goTo('servers')}
          className="mt-1.5 flex w-full items-center gap-1 rounded-md px-1 py-1 text-left text-[11px] font-medium text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-700"
        >
          Fleet Health
          <ArrowRight className="h-3 w-3" />
        </button>
      </div>
    </aside>
  )
}
