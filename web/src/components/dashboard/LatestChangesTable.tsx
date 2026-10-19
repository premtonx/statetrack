import { useMemo, useState } from 'react'
import { ArrowRight, Code2, Filter, Search, X } from 'lucide-react'
import { cn, formatClock } from '../../lib/utils'
import { actionName, IMPACT_OPTIONS } from '../../lib/labels'
import { LevelDot } from '../ui/StatusPill'
import { HostPill } from '../Timeline/HostPill'
import RuleBadge from '../Recommendations/RuleBadge'
import type { Event } from '../../types'

export interface LatestChangesTableProps {
  events: Event[]
  /** Total events in the window, for the "Showing x of y" footer. */
  totalInWindow: number
  isLoading?: boolean
  /** False when the rows come from the seeded preview store. */
  isLive?: boolean
  onView: (id: string) => void
  /** Opens the inspector directly on the Monaco diff tab. */
  onViewDiff: (id: string) => void
  onOpenTimeline: () => void
  className?: string
}

/** Rows rendered at once. The footer reports the window total, not this cap. */
const PAGE_SIZE = 25

const REFRESH_SECONDS = 30

/**
 * Zone 2 — the hero mutation feed.
 *
 * One white surface holding the title, an integrated filter toolbar, the
 * column headers, the rows and a summary footer. Filtering is client-side over
 * the events already fetched for the window (the dashboard loads a single
 * capped batch), which keeps facet changes instant and avoids a refetch per
 * keystroke.
 */
export default function LatestChangesTable({
  events,
  totalInWindow,
  isLoading,
  isLive = true,
  onView,
  onViewDiff,
  onOpenTimeline,
  className,
}: LatestChangesTableProps) {
  const [search, setSearch] = useState('')
  const [impact, setImpact] = useState(0)
  const [server, setServer] = useState('')
  const [actor, setActor] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  // Facets are derived from the loaded rows, so a dropdown never offers a value
  // that would return nothing.
  const { servers, actors } = useMemo(() => {
    const s = new Set<string>()
    const a = new Set<string>()
    for (const e of events ?? []) {
      if (e?.hostname) s.add(e.hostname)
      if (e?.actor_username) a.add(e.actor_username)
    }
    return {
      servers: [...s].sort((x, y) => x.localeCompare(y)),
      actors: [...a].sort((x, y) => x.localeCompare(y)),
    }
  }, [events])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return (events ?? []).filter((e) => {
      if (!e?.id) return false
      if (impact && Number(e.impact_level) !== impact) return false
      if (server && e.hostname !== server) return false
      if (actor && e.actor_username !== actor) return false
      if (q) {
        const hay = `${e.path_or_key ?? ''} ${e.summary ?? ''} ${e.hostname ?? ''} ${
          e.actor_username ?? ''
        } ${e.target_type ?? ''}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [events, search, impact, server, actor])

  const visible = filtered.slice(0, limit)
  const hasFilters = Boolean(search || impact || server || actor)

  const clearFilters = () => {
    setSearch('')
    setImpact(0)
    setServer('')
    setActor('')
    setLimit(PAGE_SIZE)
  }

  return (
    <section
      className={cn(
        'flex min-h-0 flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs',
        className,
      )}
    >
      {/* Title row */}
      <div className="flex items-start gap-3 px-4 py-3.5">
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold text-slate-900">Latest changes</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Investigate what changed, where, and by whom.
          </p>
        </div>
        <button
          onClick={onOpenTimeline}
          className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-[13px] font-medium text-blue-700 transition-colors hover:bg-blue-50"
        >
          View timeline
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Integrated filter toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-y border-slate-200 bg-slate-50/60 px-4 py-2">
        <div className="relative min-w-0 flex-1 basis-56">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by path, server, actor or impact..."
            aria-label="Filter changes"
            className="h-8 w-full rounded-lg border border-slate-200 bg-white pl-8 pr-3 text-[13px] text-slate-900 outline-none transition-colors placeholder:text-slate-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15"
          />
        </div>

        <FilterSelect
          ariaLabel="Filter by impact level"
          value={impact}
          onChange={(v) => setImpact(Number(v))}
          options={[
            { value: '0', label: 'All impact levels' },
            ...IMPACT_OPTIONS.map((o) => ({ value: String(o.value), label: o.label })),
          ]}
        />
        <FilterSelect
          ariaLabel="Filter by server"
          value={server}
          onChange={setServer}
          options={[
            { value: '', label: 'All servers' },
            ...servers.map((s) => ({ value: s, label: s })),
          ]}
        />
        <FilterSelect
          ariaLabel="Filter by actor"
          value={actor}
          onChange={setActor}
          options={[
            { value: '', label: 'All actors' },
            ...actors.map((a) => ({ value: a, label: a })),
          ]}
        />

        {hasFilters ? (
          <button
            onClick={clearFilters}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50"
          >
            <X className="h-3 w-3" />
            Clear
          </button>
        ) : (
          <span className="inline-flex shrink-0 items-center gap-1 px-1 text-[11px] text-slate-400">
            <Filter className="h-3 w-3" />
            No filters
          </span>
        )}
      </div>

      {/* Table */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 z-10 bg-white">
            <tr className="border-b border-slate-200 text-[10px] uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2 text-left font-semibold">Time</th>
              <th className="px-3 py-2 text-left font-semibold">Impact</th>
              <th className="px-3 py-2 text-left font-semibold">Event / Target</th>
              <th className="px-3 py-2 text-left font-semibold">Server</th>
              <th className="px-3 py-2 text-left font-semibold">Actor</th>
              <th className="px-3 py-2 text-left font-semibold">Action</th>
              <th className="px-3 py-2 text-right font-semibold">Diff</th>
              <th className="px-4 py-2 text-right font-semibold">View</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({ length: 4 }).map((_, i) => (
                  <tr key={`skeleton-${i}`} className="border-b border-slate-100">
                    {Array.from({ length: 8 }).map((__, j) => (
                      <td key={j} className="px-3 py-3">
                        <span className="block h-3 w-full animate-pulse rounded bg-slate-100" />
                      </td>
                    ))}
                  </tr>
                ))
              : null}

            {!isLoading && visible.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-14 text-center">
                  <p className="text-sm font-medium text-slate-500">
                    {hasFilters ? 'No changes match these filters' : 'No changes in this window'}
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    {hasFilters
                      ? 'Try widening the time range or clearing a filter.'
                      : 'Changes reported by monitored agents will appear here automatically.'}
                  </p>
                  {hasFilters ? (
                    <button
                      onClick={clearFilters}
                      className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50"
                    >
                      Clear filters
                    </button>
                  ) : null}
                </td>
              </tr>
            ) : null}

            {visible.map((e) => (
              <tr
                key={e.id}
                onClick={() => onView(e.id)}
                className="cursor-pointer border-b border-slate-100 transition-colors last:border-0 hover:bg-slate-50/80"
              >
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-[13px] tabular-nums text-slate-500">
                  {formatClock(e.occurred_at)}
                </td>

                <td className="whitespace-nowrap px-3 py-2.5">
                  <span className="inline-flex items-center gap-1.5 text-[13px] text-slate-700">
                    <LevelDot level={e.impact_level} />
                    {impactShortLabel(e.impact_level)}
                  </span>
                </td>

                <td className="max-w-[24rem] px-3 py-2.5">
                  <span className="block truncate text-[13px] font-medium text-slate-900">
                    {e.path_or_key || e.target_type}
                  </span>
                  <span className="mt-0.5 block truncate text-xs text-slate-500">{e.summary}</span>
                  {e.metadata?.rule_name ? (
                    <span className="mt-1 inline-flex">
                      <RuleBadge event={e} />
                    </span>
                  ) : null}
                </td>

                <td className="whitespace-nowrap px-3 py-2.5">
                  <HostPill hostname={e.hostname || e.host_id} />
                </td>

                <td className="px-3 py-2.5">
                  <span className="block truncate text-[13px] text-slate-800">
                    {e.actor_username || '—'}
                  </span>
                  {e.process_name ? (
                    <span className="mt-0.5 block truncate text-xs text-slate-500">
                      via {e.process_name}
                    </span>
                  ) : null}
                </td>

                <td className="whitespace-nowrap px-3 py-2.5 text-[13px] text-slate-600">
                  {actionName(e.action)}
                </td>

                <td className="whitespace-nowrap px-3 py-2.5 text-right">
                  {e.has_diff ? (
                    <button
                      onClick={(ev) => {
                        ev.stopPropagation()
                        onViewDiff(e.id)
                      }}
                      title="Open the side-by-side diff"
                      className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 font-mono text-[11px] font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
                    >
                      <Code2 className="h-3 w-3" />
                      Diff
                    </button>
                  ) : (
                    <span className="text-xs text-slate-300">—</span>
                  )}
                </td>

                <td className="whitespace-nowrap px-4 py-2.5 text-right">
                  <span className="inline-flex items-center gap-1 text-[13px] font-medium text-slate-500">
                    View
                    <ArrowRight className="h-3.5 w-3.5" />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-slate-200 bg-slate-50/60 px-4 py-2.5 text-xs text-slate-500">
        <span className="tabular-nums">
          Showing {visible.length} of {filtered.length}
          {filtered.length !== totalInWindow ? ` (${totalInWindow} in window)` : ''} events
        </span>
        <span className="hidden sm:inline">·</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-600" />
          Auto-updates every {REFRESH_SECONDS}s
        </span>
        {!isLive ? (
          <span className="ml-auto rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
            Preview data
          </span>
        ) : null}
        {isLive && filtered.length > visible.length ? (
          <button
            onClick={() => setLimit((n) => n + PAGE_SIZE)}
            className="ml-auto rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50"
          >
            Show {Math.min(PAGE_SIZE, filtered.length - visible.length)} more
          </button>
        ) : null}
      </div>
    </section>
  )
}

/** Compact level label for the table: "L1 Critical", "L3 Drift", … */
function impactShortLabel(level: number): string {
  switch (Number(level)) {
    case 1:
      return 'L1 Critical'
    case 2:
      return 'L2 Grouped'
    case 3:
      return 'L3 Drift'
    case 4:
      return 'L4 Forensic'
    default:
      return 'Unclassified'
  }
}

/** Neutral outline dropdown used by the filter toolbar. */
function FilterSelect({
  value,
  onChange,
  options,
  ariaLabel,
}: {
  value: string | number
  onChange: (value: string) => void
  options: { value: string; label: string }[]
  ariaLabel: string
}) {
  return (
    <div className="relative shrink-0">
      <select
        aria-label={ariaLabel}
        value={String(value)}
        onChange={(e) => onChange(e.target.value)}
        className="h-8 cursor-pointer appearance-none rounded-lg border border-slate-200 bg-white pl-2.5 pr-7 text-xs text-slate-700 outline-none transition-colors hover:bg-slate-50 focus:border-blue-400 focus:ring-2 focus:ring-blue-500/15"
      >
        {(options ?? []).map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <svg
        className="pointer-events-none absolute right-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400"
        viewBox="0 0 12 12"
        fill="none"
        aria-hidden
      >
        <path d="M3 4.5 6 7.5 9 4.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    </div>
  )
}
