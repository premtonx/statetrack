import { Activity } from 'lucide-react'
import { cn, formatNumber } from '../../lib/utils'
import { LEVELS, LEVEL_ORDER } from '../../lib/labels'
import { DeltaPill, type DeltaBadge } from '../ui/MetricCard'
import type { ImpactLevel } from '../../types'

export interface FleetPulseProps {
  total: number
  byLevel: Record<ImpactLevel, number>
  /**
   * Comparison badges against the previous window. Absent on a fresh install
   * with no history, in which case no delta pill is rendered at all.
   */
  deltas?: {
    total: DeltaBadge
    critical: DeltaBadge
    grouped: DeltaBadge
    drift: DeltaBadge
  }
  className?: string
}

/**
 * Zone 1, left half: four headline counters, a slim segmented ratio bar for the
 * impact-level distribution, and its inline dot legend.
 *
 * The counters are deliberately borderless — they sit directly on the shared
 * white surface so the strip reads as one instrument panel rather than four
 * separate cards. Colour is reserved for the level indicators; every other
 * element is neutral slate.
 */
export default function FleetPulse({ total, byLevel, deltas, className }: FleetPulseProps) {
  const counters = [
    { id: 'total', label: 'Total changes', value: total, delta: deltas?.total, dot: 'bg-slate-900' },
    { id: 'l1', label: 'L1 Critical', value: byLevel[1], delta: deltas?.critical, dot: 'bg-red-600' },
    { id: 'l2', label: 'L2 Grouped', value: byLevel[2], delta: deltas?.grouped, dot: 'bg-purple-600' },
    { id: 'l3', label: 'L3 Drift', value: byLevel[3], delta: deltas?.drift, dot: 'bg-amber-500' },
  ] as const

  const pct = (n: number) => (total > 0 ? (n / total) * 100 : 0)

  return (
    <div className={cn('flex min-w-0 flex-col', className)}>
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4 shrink-0 text-slate-400" />
        <h2 className="text-sm font-semibold text-slate-900">Fleet Pulse</h2>
        <span className="truncate text-xs text-slate-500">
          Change activity across your infrastructure
        </span>
      </div>

      {/* Counters */}
      <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-4 lg:grid-cols-4">
        {counters.map((c) => (
          <div key={c.id} className="min-w-0">
            <p className="flex items-center gap-1.5 text-xs font-medium text-slate-500">
              <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', c.dot)} aria-hidden />
              <span className="truncate">{c.label}</span>
            </p>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-[23px] font-semibold leading-none tabular-nums tracking-tight text-slate-900">
                {formatNumber(c.value)}
              </span>
              {c.delta ? <DeltaPill delta={c.delta} /> : null}
            </div>
          </div>
        ))}
      </div>

      {/* Segmented ratio bar */}
      <div className="mt-5">
        <div
          className="flex h-2 w-full overflow-hidden rounded-full bg-slate-100"
          role="img"
          aria-label={LEVEL_ORDER.map((l) => `${LEVELS[l].name} ${Math.round(pct(byLevel[l]))}%`).join(', ')}
        >
          {LEVEL_ORDER.map((l) => {
            const width = pct(byLevel[l])
            if (width <= 0) return null
            return (
              <span
                key={l}
                className="h-full"
                style={{ width: `${width}%`, background: LEVELS[l].hex }}
                title={`${LEVELS[l].label} · ${formatNumber(byLevel[l])}`}
              />
            )
          })}
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1">
          {LEVEL_ORDER.map((l) => (
            <span key={l} className="inline-flex items-center gap-1.5 text-[11px] text-slate-500">
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{ background: LEVELS[l].hex }}
                aria-hidden
              />
              <span className="tabular-nums">{Math.round(pct(byLevel[l]))}%</span>
              {LEVELS[l].name}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
