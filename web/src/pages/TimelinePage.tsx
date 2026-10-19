import { useMemo, useState } from 'react'
import { Filter, RefreshCw, SlidersHorizontal } from 'lucide-react'
import PageHeader from '../components/ui/PageHeader'
import { Button, Select, Toggle } from '../components/ui/controls'
import Timeline from '../components/Timeline/Timeline'
import { useHostList, type TimelineFilters } from '../api/hooks'
import { CATEGORY_FILTER_OPTIONS, IMPACT_OPTIONS, TIMELINE_RANGES } from '../lib/labels'
import { useConsole } from '../lib/consoleContext'
import { windowFrom } from '../lib/timeWindow'
import { cn } from '../lib/utils'
import type { ImpactLevel } from '../types'

export default function TimelinePage() {
  const { search, openEvent, hostId, setHostId, liveStatus, goTo } = useConsole()
  const { hosts } = useHostList()

  const [range, setRange] = useState('24h')
  const [impact, setImpact] = useState<ImpactLevel | 0>(0)
  const [category, setCategory] = useState(0)
  const [host, setHost] = useState(hostId)
  // "Live" narrows the window to the last 15 minutes so the list tracks the
  // WebSocket stream instead of the full historical range.
  const [liveOnly, setLiveOnly] = useState(false)
  const effectiveRange = liveOnly ? '15m' : range

  const filters = useMemo<TimelineFilters>(() => {
    return {
      host_id: host || undefined,
      impact_level: impact,
      category,
      search: search || undefined,
      // Anchored helper (not inline Date.now()) so the query key is stable.
      from: windowFrom(effectiveRange),
    }
  }, [host, impact, category, search, effectiveRange])

  const activeFilterCount =
    (impact ? 1 : 0) + (category ? 1 : 0) + (host ? 1 : 0) + (search ? 1 : 0)

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Timeline"
        subtitle="Every recorded change, newest first — click any row to inspect the diff and actor lineage."
        actions={
          <>
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium',
                liveStatus === 'open'
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                  : 'border-slate-200 bg-slate-50 text-slate-500',
              )}
            >
              <span
                className={cn(
                  'h-1.5 w-1.5 rounded-full',
                  liveStatus === 'open' ? 'animate-pulse bg-emerald-600' : 'bg-slate-400',
                )}
              />
              {liveStatus === 'open' ? 'Streaming live' : 'Stream idle'}
            </span>
            <Button
              icon={<RefreshCw className="h-4 w-4" />}
              onClick={() => {
                setImpact(0)
                setCategory(0)
                setHost('')
                setHostId('')
              }}
              disabled={activeFilterCount === 0}
            >
              Reset filters
            </Button>
          </>
        }
      />

      <div className="min-h-0 flex-1 overflow-hidden">
        <div className="flex h-full flex-col">
          {/* Filter toolbar */}
          <div className="flex flex-wrap items-end gap-3 border-b border-slate-200 bg-white px-4 py-3 sm:px-6">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
              <Filter className="h-3.5 w-3.5" />
              Filters
              {activeFilterCount > 0 ? (
                <span className="rounded-full bg-blue-50 px-1.5 text-[10px] font-semibold text-blue-700">
                  {activeFilterCount}
                </span>
              ) : null}
            </div>

            <Select
              aria-label="Time range"
              value={effectiveRange}
              disabled={liveOnly}
              onChange={(e) => setRange(e.target.value)}
              wrapperClassName="w-40"
            >
              {TIMELINE_RANGES.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </Select>

            <Select
              aria-label="Impact level"
              value={impact}
              onChange={(e) => setImpact(Number(e.target.value) as ImpactLevel | 0)}
              wrapperClassName="w-44"
            >
              <option value={0}>All Levels</option>
              {IMPACT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>

            <Select
              aria-label="Server"
              value={host}
              onChange={(e) => {
                setHost(e.target.value)
                setHostId(e.target.value)
              }}
              wrapperClassName="w-44"
            >
              <option value="">All Servers</option>
              {(hosts ?? []).map((h) => (
                <option key={h.id} value={h.id}>
                  {h.hostname}
                </option>
              ))}
            </Select>

            <Select
              aria-label="Event type"
              value={category}
              onChange={(e) => setCategory(Number(e.target.value))}
              wrapperClassName="w-44"
            >
              {CATEGORY_FILTER_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>

            <div className="ml-auto flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1">
              <span className="flex items-center gap-1.5 text-xs font-medium text-slate-600">
                <SlidersHorizontal className="h-3.5 w-3.5 text-slate-400" />
                Live
              </span>
              <Toggle checked={liveOnly} onChange={setLiveOnly} />
            </div>
          </div>

          {/* Timeline list */}
          <div className="min-h-0 flex-1 overflow-hidden bg-slate-50">
            <Timeline
              filters={filters}
              annotateCompliance
              onOpenEvent={(id) => openEvent(id, 'timeline')}
              onOpenAgents={() => goTo('settings', { settingsTab: 'agents' })}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
