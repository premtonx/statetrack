import { useMemo } from 'react'
import { sampleDataEnabled, useEventFeed } from './hooks'
import { windowFrom } from '../lib/timeWindow'
import type { ImpactLevel } from '../types'
import { CHANGES_OVER_TIME, KPI_DELTAS, type StackedPoint } from './mockData'

export interface FleetStats {
  total: number
  byLevel: Record<ImpactLevel, number>
  /** Stacked hourly series for the "Changes Over Time" chart. */
  series: StackedPoint[]
  /** True when the numbers are seeded samples because the API returned nothing. */
  isFallback: boolean
  isLoading: boolean
}

/**
 * Aggregates the change feed into the dashboard/report KPIs.
 *
 * An empty window yields zeros and an empty hourly series, which is the honest
 * answer for a freshly-installed server: the cards read 0 rather than showing a
 * fabricated fleet. Seeded distribution only appears in an explicit sample-data
 * build (`VITE_STATETRACK_SAMPLE_DATA=1`).
 */
export function useFleetStats(range: string, hostId?: string): FleetStats {
  // Memoised so the query key is stable across renders. Computing
  // `Date.now()` inline here restarts the request on every render, which
  // leaves `events` permanently empty.
  const filters = useMemo(
    () => ({ host_id: hostId || undefined, from: windowFrom(range), root_only: true }),
    [range, hostId],
  )
  const { events, isLoading, isFallback } = useEventFeed(filters, 500)

  return useMemo(() => {
    const pool = events
    const byLevel: Record<ImpactLevel, number> = { 1: 0, 2: 0, 3: 0, 4: 0 }
    for (const e of pool) {
      const lvl = Number(e?.impact_level) as ImpactLevel
      if (byLevel[lvl] !== undefined) byLevel[lvl] += 1
    }
    return {
      total: pool.length,
      byLevel,
      series: isFallback ? CHANGES_OVER_TIME : bucketByHour(pool),
      isFallback,
      isLoading,
    }
  }, [events, isFallback, isLoading])
}

/**
 * Buckets events into the last 24 hourly slots. Slots are keyed by their
 * absolute epoch hour rather than the clock label, so events recorded on
 * different days never collide inside the same bucket.
 */
function bucketByHour(events: { occurred_at: string; impact_level: number }[]): StackedPoint[] {
  const now = Date.now()
  const buckets = new Map<number, StackedPoint>()
  const order: number[] = []

  for (let i = 23; i >= 0; i--) {
    const slot = now - i * 3600_000
    const epochHour = Math.floor(slot / 3600_000)
    if (!buckets.has(epochHour)) {
      const d = new Date(epochHour * 3600_000)
      buckets.set(epochHour, { label: `${String(d.getHours()).padStart(2, '0')}:00`, values: {} })
      order.push(epochHour)
    }
  }

  for (const e of events ?? []) {
    const d = new Date(e?.occurred_at)
    if (Number.isNaN(d.getTime())) continue
    const slot = buckets.get(Math.floor(d.getTime() / 3600_000))
    if (!slot) continue
    const lvl = Number(e.impact_level)
    if (lvl < 1 || lvl > 4) continue
    const level = lvl as 1 | 2 | 3 | 4
    slot.values[level] = (slot.values[level] ?? 0) + 1
  }

  return order.map((k) => buckets.get(k) as StackedPoint)
}

/**
 * Comparison deltas are only meaningful once there is a previous window to
 * compare against. A zeroed install therefore renders no delta pill at all
 * rather than an invented "+12%".
 */
export function useKpiDeltas(): typeof KPI_DELTAS | undefined {
  return sampleDataEnabled() ? KPI_DELTAS : undefined
}

export { KPI_DELTAS }
