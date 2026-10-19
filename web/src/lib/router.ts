import { useSyncExternalStore } from 'react'

/**
 * Minimal history-based router for the console. Routes:
 *   /                 → dashboard (alias of /dashboard)
 *   /dashboard        → KPI overview
 *   /timeline         → change timeline
 *   /servers          → server fleet inventory
 *   /drift            → cross-host drift matrix
 *   /integrations     → enterprise integrations hub
 *   /grafana          → alias of /integrations (pre-hub bookmarks)
 *   /reports          → report builder / exports
 *   /settings         → platform settings
 *   /events/:id       → the route above plus the inspector drawer on :id
 *   /?event=:id       → alias of /events/:id (Grafana deep links)
 *
 * A `?view=` query parameter is also honoured for drawer deep links that must
 * return to a specific page (e.g. `/?view=reports&event=<id>`).
 */
export type View =
  | 'dashboard'
  | 'timeline'
  | 'servers'
  | 'drift'
  | 'integrations'
  | 'reports'
  | 'settings'

export const DEFAULT_VIEW: View = 'dashboard'

type Listener = () => void
const listeners = new Set<Listener>()

function snapshot(): string {
  return window.location.pathname + window.location.search
}

function subscribe(listener: Listener): () => void {
  listeners.add(listener)
  window.addEventListener('popstate', listener)
  return () => {
    listeners.delete(listener)
    window.removeEventListener('popstate', listener)
  }
}

export function navigate(to: string) {
  if (snapshot() === to) return
  window.history.pushState(null, '', to)
  for (const l of listeners) l()
}

/** Reactively returns the current `pathname + search` string. */
export function useLocation(): string {
  return useSyncExternalStore(subscribe, snapshot, () => '')
}

/**
 * Inspector drawer tabs. A `?tab=` query parameter lets a row-level action
 * deep-link straight to the pane it is about, e.g. the table's `</> Diff`
 * button opening the Monaco diff rather than the default overview.
 */
export type EventTab = 'overview' | 'diff' | 'analyze' | 'actor' | 'related'

const EVENT_TABS: EventTab[] = ['overview', 'diff', 'analyze', 'actor', 'related']

function isEventTab(value: string | null): value is EventTab {
  return value !== null && (EVENT_TABS as string[]).includes(value)
}

export interface Route {
  view: View
  eventId: string | null
  /** Requested inspector tab, or null to use the drawer default. */
  tab: EventTab | null
}

const PATH_VIEWS: Record<string, View> = {
  dashboard: 'dashboard',
  timeline: 'timeline',
  servers: 'servers',
  drift: 'drift',
  integrations: 'integrations',
  reports: 'reports',
  settings: 'settings',
}

/**
 * Legacy path aliases kept for backwards compatibility.
 *
 * `/grafana` was the route of the single-purpose Grafana page before it grew
 * into the integrations hub. Bookmarks, Grafana annotation deep links and
 * alert bodies produced by older builds still point at it, so it resolves to
 * the hub rather than 404-ing into the dashboard.
 */
const PATH_ALIASES: Record<string, View> = {
  grafana: 'integrations',
}

function resolvePathView(segment: string | undefined): View | undefined {
  if (!segment) return undefined
  return PATH_VIEWS[segment] ?? PATH_ALIASES[segment]
}

function isView(value: string | null): value is View {
  return value !== null && (value in PATH_VIEWS || value in PATH_ALIASES)
}

/**
 * Returns the canonical path for a legacy alias, or null when the location is
 * already canonical.
 *
 * The shell calls this on every route change so the address bar settles on
 * `/integrations` even when the operator arrived via an old `/grafana`
 * bookmark. It is a `replaceState`, not a push, so Back does not bounce the
 * operator between the alias and its target.
 */
export function canonicalPath(loc: string): string | null {
  const [path = '', query = ''] = loc.split('?')
  const seg = path.split('/').filter(Boolean)
  const target = seg[0] ? PATH_ALIASES[seg[0]] : undefined
  if (!target) return null
  const rest = seg.slice(1).join('/')
  return `/${target}${rest ? `/${rest}` : ''}${query ? `?${query}` : ''}`
}

export function parseLocation(loc: string): Route {
  const [path = '', query = ''] = loc.split('?')
  const params = new URLSearchParams(query)
  const eventId = params.get('event')
  const tab = isEventTab(params.get('tab')) ? (params.get('tab') as EventTab) : null

  const seg = path.split('/').filter(Boolean)
  // /events/:id keeps the current page and opens the drawer.
  if (seg[0] === 'events' && seg[1]) {
    return {
      view: isView(params.get('view')) ? (params.get('view') as View) : DEFAULT_VIEW,
      eventId: seg[1],
      tab,
    }
  }
  if (seg.length === 0) {
    return {
      view: eventId && isView(params.get('view')) ? (params.get('view') as View) : DEFAULT_VIEW,
      eventId,
      tab,
    }
  }
  const view = resolvePathView(seg[0])
  if (view) return { view, eventId, tab }
  return { view: DEFAULT_VIEW, eventId, tab }
}

/** URL for a top-level page. */
export function viewUrl(view: View): string {
  return view === 'dashboard' ? '/' : `/${view}`
}

/**
 * Onboarding links land on a specific Settings tab rather than the page top:
 * "Open agent setup" from an empty state has exactly one useful destination,
 * and making the operator find the tab themselves is the friction this release
 * is removing.
 */
export function settingsUrl(tab: 'general' | 'security' | 'agents' | 'audit'): string {
  return `/settings?tab=${tab}`
}

/**
 * Deep link for an event. Embeds the originating view so closing the drawer
 * returns the operator to the page they were inspecting from, and an optional
 * inspector tab so row-level actions (e.g. `</> Diff`) land on the right pane.
 */
export function eventUrl(id: string, view?: View, tab?: EventTab): string {
  const params = new URLSearchParams()
  if (view && view !== DEFAULT_VIEW) params.set('view', view)
  if (tab) params.set('tab', tab)
  const q = params.toString()
  return `/events/${id}${q ? `?${q}` : ''}`
}
