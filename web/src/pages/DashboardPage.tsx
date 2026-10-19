import { useMemo, useState } from 'react'
import { FileBarChart } from 'lucide-react'
import FleetPulse from '../components/dashboard/FleetPulse'
import ChangeActivityChart from '../components/dashboard/ChangeActivityChart'
import LatestChangesTable from '../components/dashboard/LatestChangesTable'
import RecommendationBanner from '../components/Recommendations/RecommendationBanner'
import RecommendationsDrawer from '../components/Recommendations/RecommendationsDrawer'
import { AgentSetupEmptyState } from '../components/ui/EmptyState'
import { Select } from '../components/ui/controls'
import { useFleetStats, useKpiDeltas } from '../api/aggregates'
import { useEventFeed, useHostList, useRecommendations, type TimelineFilters } from '../api/hooks'
import { AGGREGATE_RANGES } from '../lib/labels'
import { useConsole } from '../lib/consoleContext'
import { windowFrom } from '../lib/timeWindow'
import type { Event } from '../types'

/** Rows the feed loads. The table filters and paginates client-side. */
const FEED_LIMIT = 25

export default function DashboardPage() {
  const [range, setRange] = useState('24h')
  const [showRecommendations, setShowRecommendations] = useState(false)
  const [bannerDismissed, setBannerDismissed] = useState(false)
  const { openEvent, goTo, hostId } = useConsole()

  const stats = useFleetStats(range, hostId)
  const deltas = useKpiDeltas()
  const recommendations = useRecommendations('pending')
  const fleet = useHostList()

  // A clean install has no hosts at all. Until the first agent enrols there is
  // nothing to chart, so the overview leads with the enrolment path instead of
  // a grid of zeroes.
  const isEmptyFleet = !fleet.isLoading && fleet.total === 0

  // The window lower bound must be memoised: computing it inline yields a new
  // query key on every render, which cancels the request before it settles.
  const feedFilters = useMemo<TimelineFilters>(
    () => ({ from: windowFrom(range), host_id: hostId || undefined, root_only: true }),
    [range, hostId],
  )
  const { events, isLoading, isFallback } = useEventFeed(feedFilters, FEED_LIMIT)

  // The feed only returns root events, but keep the guard so a malformed page
  // can never surface a child row or a null entry into the table.
  const rows = useMemo(
    () => (events ?? []).filter((e): e is Event => Boolean(e && e.id && !e.parent_event_id)),
    [events],
  )

  return (
    <div className="flex h-full flex-col">
      {/* Title row */}
      <div className="flex shrink-0 flex-col gap-3 border-b border-slate-200 bg-white px-4 py-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-slate-900">
            Infrastructure overview
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Git history for your live servers. Track what changed, who changed it, and why.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 lg:shrink-0">
          <Select
            aria-label="Time range"
            value={range}
            onChange={(e) => setRange(e.target.value)}
            wrapperClassName="w-40"
          >
            {AGGREGATE_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </Select>
          <button
            onClick={() => goTo('reports')}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-1.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50"
          >
            <FileBarChart className="h-4 w-4 text-slate-500" />
            Generate report
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
        {/*
          `min-h-full` + a flex column lets Zone 2 grow into whatever vertical
          space is left, so the changes feed is always the dominant surface
          rather than a short table floating above empty page.
        */}
        <div className="flex min-h-full flex-col gap-4">
          {isEmptyFleet ? (
            <AgentSetupEmptyState
              className="shrink-0"
              onOpenAgents={() => goTo('settings', { settingsTab: 'agents' })}
              onOpenDocs={() => goTo('servers')}
            />
          ) : null}

          {!bannerDismissed ? (
            <RecommendationBanner
              pending={recommendations.pending}
              hostnames={recommendations.hostnames}
              onReview={() => setShowRecommendations(true)}
              onDismiss={() => setBannerDismissed(true)}
              className="shrink-0"
            />
          ) : null}

          {/* Zone 1 — Fleet Pulse & Activity (one split surface) */}
          <section className="shrink-0 rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] xl:gap-8">
              <FleetPulse total={stats.total} byLevel={stats.byLevel} deltas={deltas} />
              <ChangeActivityChart
                data={stats.series}
                className="xl:border-l xl:border-slate-200 xl:pl-8"
              />
            </div>
          </section>

          {/* Zone 2 — Latest Changes (hero) */}
          <LatestChangesTable
            events={rows}
            totalInWindow={Math.max(stats.total, rows.length)}
            isLoading={isLoading}
            isLive={!isFallback}
            onView={(id) => openEvent(id, 'dashboard')}
            onViewDiff={(id) => openEvent(id, 'dashboard', 'diff')}
            onOpenTimeline={() => goTo('timeline')}
            className="min-h-[26rem] flex-1"
          />
        </div>
      </div>

      {showRecommendations ? (
        <RecommendationsDrawer
          feed={recommendations}
          onClose={() => setShowRecommendations(false)}
        />
      ) : null}
    </div>
  )
}
