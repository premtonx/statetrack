import { useMemo, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Loader2 } from 'lucide-react'
import { useEvents, type TimelineFilters } from '../../api/hooks'
import type { Event } from '../../types'
import { cn } from '../../lib/utils'
import EventRow from './EventRow'

type Row =
  | {
      type: 'header'
      key: string
      label: string
      dateLabel: string
      count: number
      /** Position within the day group, for card edge styling. */
      pos: 'single'
    }
  | {
      type: 'event'
      key: string
      event: Event
      pos: 'first' | 'middle' | 'last' | 'single'
    }

function dayParts(iso: string): { label: string; dateLabel: string; key: string } {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return { label: '', dateLabel: '', key: '' }
  const key = d.toDateString()
  const dateLabel = d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
  const now = new Date()
  if (key === now.toDateString()) return { label: 'Today', dateLabel, key }
  const y = new Date(now)
  y.setDate(now.getDate() - 1)
  if (key === y.toDateString()) return { label: 'Yesterday', dateLabel, key }
  return {
    label: d.toLocaleDateString(undefined, { weekday: 'long' }),
    dateLabel: d.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' }),
    key,
  }
}

/**
 * Builds the flat virtualized row list: a header per calendar day followed by
 * that day's events, each tagged with its position inside the day group so the
 * rows can be stitched into one continuous card.
 */
function buildRows(events: Event[], showHeaders: boolean): Row[] {
  const rows: Row[] = []
  const groups: { key: string; events: Event[] }[] = []

  for (const e of events) {
    if (!e || !e.id || typeof e.occurred_at !== 'string') continue
    const { key } = dayParts(e.occurred_at)
    const last = groups[groups.length - 1]
    if (last && last.key === key) last.events.push(e)
    else groups.push({ key, events: [e] })
  }

  for (const group of groups) {
    if (showHeaders) {
      const { label, dateLabel } = dayParts(group.events[0].occurred_at)
      rows.push({
        type: 'header',
        key: `h:${group.key}`,
        label,
        dateLabel,
        count: group.events.length,
        pos: 'single',
      })
    }
    group.events.forEach((event, i) => {
      rows.push({
        type: 'event',
        key: event.id,
        event,
        pos: group.events.length === 1 ? 'single' : i === 0 ? 'first' : i === group.events.length - 1 ? 'last' : 'middle',
      })
    })
  }
  return rows
}

interface TimelineProps {
  filters: TimelineFilters
  onOpenEvent: (id: string) => void
  /** Renders date section headers (off inside a single-day card). */
  showDayHeaders?: boolean
  /**
   * Ask the API to attach each event's change-control verdict so rows can
   * badge unauthorised production edits. Off for embedded feeds (a dashboard
   * card, a single host's recent changes) where the badge would be noise and
   * the extra two reads per page are not worth paying.
   */
  annotateCompliance?: boolean
  /** Opens agent enrolment from the empty state. */
  onOpenAgents?: () => void
}

/**
 * Virtualized change list. Kept virtualized so a 100k-event history scrolls
 * smoothly; layout matches the card-based timeline design with one continuous
 * surface per calendar day.
 *
 * An empty result is rendered as an empty result. The console never substitutes
 * a seeded timeline, so a fresh install sees the enrolment prompt rather than a
 * plausible-looking history of changes that never happened.
 */
export default function Timeline({
  filters,
  onOpenEvent,
  showDayHeaders = true,
  annotateCompliance = false,
  onOpenAgents,
}: TimelineProps) {
  // The annotation flag is folded into the filters object rather than passed
  // separately, because it is part of the query key: a timeline with verdicts
  // and one without are different server responses and must not share a cache
  // entry.
  const query: TimelineFilters = useMemo(
    () => (annotateCompliance ? { ...filters, annotate: 'compliance' as const } : filters),
    [filters, annotateCompliance],
  )
  const { data, isLoading, isError, hasNextPage, isFetchingNextPage, fetchNextPage } =
    useEvents(query)

  // Flatten all pages and drop child events (they live inside parent cards).
  // Defensive: a malformed/partial page must never surface null items into
  // the list (a single bad entry would otherwise crash the whole tree).
  const events = useMemo(() => {
    const all = data?.pages.flatMap((p) => p?.events ?? []) ?? []
    return all.filter(
      (e): e is Event => Boolean(e && typeof e === 'object' && e.id && !e.parent_event_id),
    )
  }, [data])

  const rows = useMemo(() => buildRows(events, showDayHeaders), [events, showDayHeaders])

  const scrollRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => {
      const r = rows[i]
      if (!r) return 58
      return r.type === 'header' ? 40 : 58
    },
    overscan: 12,
  })

  const onScroll = () => {
    const el = scrollRef.current
    if (!el || !hasNextPage || isFetchingNextPage) return
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 800) {
      fetchNextPage()
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center text-slate-400">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading timeline…
      </div>
    )
  }

  if (rows.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center text-slate-400">
        <p className="text-sm font-medium text-slate-600">
          {isError
            ? 'Could not reach the StateTrack API'
            : 'No servers enrolled yet — no changes to show'}
        </p>
        <p className="max-w-md text-xs leading-5">
          {isError
            ? 'The console could not load the change history. Check that the server is running and reachable.'
            : 'Copy the Linux or Windows install command under Settings → Agents to connect your first host. Changes detected on monitored hosts will stream in here live.'}
        </p>
        {!isError && onOpenAgents ? (
          <button
            onClick={onOpenAgents}
            className="mt-1 rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700"
          >
            Open agent setup
          </button>
        ) : null}
      </div>
    )
  }

  const items = virtualizer.getVirtualItems()

  return (
    <div ref={scrollRef} onScroll={onScroll} className="h-full overflow-y-auto">
      <div className="relative w-full px-3 py-3 sm:px-4" style={{ height: virtualizer.getTotalSize() }}>
        {items.map((vi) => {
          const row = rows[vi.index]
          if (!row) return null
          return (
            <div
              key={row.key}
              data-index={vi.index}
              ref={virtualizer.measureElement}
              className="absolute left-3 right-3 top-0 sm:left-4 sm:right-4"
              style={{ transform: `translateY(${vi.start}px)` }}
            >
              {row.type === 'header' ? (
                <div className="flex items-center gap-3 px-1 pb-1.5 pt-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                    {row.label}
                  </h3>
                  <span className="text-xs text-slate-400">{row.dateLabel}</span>
                  <span className="h-px flex-1 bg-slate-200" />
                  <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[11px] tabular-nums text-slate-500">
                    {row.count} changes
                  </span>
                </div>
              ) : (
                <div
                  className={cn(
                    'border-x border-slate-200/80 bg-white',
                    row.pos === 'first' && 'rounded-t-xl border-t shadow-xs',
                    row.pos === 'single' && 'rounded-xl border-y shadow-xs',
                    row.pos === 'last' && 'rounded-b-xl border-b shadow-xs',
                  )}
                >
                  <EventRow
                    event={row.event}
                    onOpen={onOpenEvent}
                    divider={row.pos !== 'last' && row.pos !== 'single'}
                  />
                </div>
              )}
            </div>
          )
        })}
      </div>
      {isFetchingNextPage ? (
        <div className="flex items-center justify-center gap-2 py-4 text-xs text-slate-400">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading more…
        </div>
      ) : null}
    </div>
  )
}
