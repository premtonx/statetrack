import type { ReactNode } from 'react'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import { cn } from '../../lib/utils'

export type Accent = 'blue' | 'red' | 'purple' | 'amber' | 'green' | 'slate'

const ACCENT: Record<Accent, { icon: string; value: string; ring: string }> = {
  blue: { icon: 'bg-blue-50 text-blue-600', value: 'text-slate-900', ring: 'ring-blue-100' },
  red: { icon: 'bg-red-50 text-red-600', value: 'text-slate-900', ring: 'ring-red-100' },
  purple: { icon: 'bg-purple-50 text-purple-600', value: 'text-slate-900', ring: 'ring-purple-100' },
  amber: { icon: 'bg-amber-50 text-amber-600', value: 'text-slate-900', ring: 'ring-amber-100' },
  green: { icon: 'bg-emerald-50 text-emerald-600', value: 'text-slate-900', ring: 'ring-emerald-100' },
  slate: { icon: 'bg-slate-100 text-slate-500', value: 'text-slate-900', ring: 'ring-slate-100' },
}

export interface DeltaBadge {
  value: string
  /** True when the movement is good news (drives the arrow + color). */
  positive?: boolean
  /** Override the arrow direction when the sign and the desirability differ. */
  direction?: 'up' | 'down'
}

interface MetricCardProps {
  label: string
  value: ReactNode
  /** Small muted note under the metric, e.g. "vs. previous 24h". */
  hint?: ReactNode
  delta?: DeltaBadge
  icon?: ReactNode
  accent?: Accent
  className?: string
}

/**
 * High-density KPI tile: icon, label, large metric and an optional delta pill.
 */
export default function MetricCard({
  label,
  value,
  hint,
  delta,
  icon,
  accent = 'slate',
  className,
}: MetricCardProps) {
  const tone = ACCENT[accent]
  return (
    <div
      className={cn(
        'rounded-xl border border-slate-200/80 bg-white p-4 shadow-xs transition-shadow hover:shadow-sm',
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
        {icon ? (
          <span
            className={cn(
              'flex h-8 w-8 items-center justify-center rounded-lg ring-1',
              tone.icon,
              tone.ring,
            )}
          >
            {icon}
          </span>
        ) : null}
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className={cn('text-xl font-semibold tabular-nums', tone.value)}>{value}</span>
        {delta ? <DeltaPill delta={delta} /> : null}
      </div>
      {hint ? <p className="mt-1 text-xs text-slate-400">{hint}</p> : null}
    </div>
  )
}

export function DeltaPill({ delta }: { delta: DeltaBadge }) {
  const up = (delta.direction ?? (delta.value.trim().startsWith('-') ? 'down' : 'up')) === 'up'
  const good = delta.positive ?? up
  const Icon = up ? ArrowUpRight : ArrowDownRight
  return (
    <span
      className={cn(
        'inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[11px] font-semibold tabular-nums',
        good
          ? 'bg-emerald-50 text-emerald-700'
          : 'bg-red-50 text-red-700',
      )}
    >
      <Icon className="h-3 w-3" />
      {delta.value}
    </span>
  )
}
