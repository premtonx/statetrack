import { useMemo, useState } from 'react'
import { cn } from '../../lib/utils'
import { LEVELS, LEVEL_ORDER } from '../../lib/labels'
import type { ImpactLevel } from '../../types'

interface ChangeDistributionChartProps {
  /** Count per impact level id. */
  counts: Partial<Record<ImpactLevel, number>>
  size?: number
  className?: string
}

/**
 * Pure-SVG doughnut with the total in the centre and an interactive legend
 * that highlights the matching ring segment on hover. No chart library.
 */
export default function ChangeDistributionChart({
  counts,
  size = 168,
  className,
}: ChangeDistributionChartProps) {
  const [active, setActive] = useState<ImpactLevel | null>(null)

  const { segments, total } = useMemo(() => {
    const safe = LEVEL_ORDER.map((l) => ({ level: l, value: Number(counts?.[l]) || 0 }))
    const sum = safe.reduce((a, s) => a + s.value, 0)
    const circumference = Math.PI * 2 * 62 // r = 62
    let offset = 0
    const segs = safe.map((s) => {
      const frac = sum > 0 ? s.value / sum : 0
      const length = frac * circumference
      const seg = { ...s, length, offset, circumference, frac }
      offset += length
      return seg
    })
    return { segments: segs, total: sum }
  }, [counts])

  return (
    <div className={cn('flex flex-col items-center gap-5 sm:flex-row sm:items-center', className)}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg viewBox="0 0 168 168" className="h-full w-full -rotate-90">
          <circle cx="84" cy="84" r="62" fill="none" stroke="#f1f5f9" strokeWidth="20" />
          {segments.map((s) => {
            if (s.length <= 0) return null
            const dim = active !== null && active !== s.level
            return (
              <circle
                key={s.level}
                cx="84"
                cy="84"
                r="62"
                fill="none"
                stroke={LEVELS[s.level].hex}
                strokeWidth={active === s.level ? 24 : 20}
                strokeDasharray={`${s.length} ${s.circumference - s.length}`}
                strokeDashoffset={-s.offset}
                opacity={dim ? 0.28 : 1}
                className="transition-all duration-200"
                onMouseEnter={() => setActive(s.level)}
                onMouseLeave={() => setActive(null)}
              />
            )
          })}
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-slate-900">
            {active !== null ? (Number(counts?.[active]) || 0) : total}
          </span>
          <span className="text-[11px] uppercase tracking-wide text-slate-400">
            {active !== null ? LEVELS[active].name : 'Total changes'}
          </span>
        </div>
      </div>

      <ul className="w-full min-w-0 space-y-1">
        {segments.map((s) => {
          const dim = active !== null && active !== s.level
          return (
            <li key={s.level}>
              <button
                onMouseEnter={() => setActive(s.level)}
                onMouseLeave={() => setActive(null)}
                onFocus={() => setActive(s.level)}
                onBlur={() => setActive(null)}
                className={cn(
                  'flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors',
                  dim ? 'opacity-55' : 'hover:bg-slate-50',
                )}
              >
                <span
                  className="h-2.5 w-2.5 shrink-0 rounded-full"
                  style={{ background: LEVELS[s.level].hex }}
                />
                <span className="min-w-0 flex-1 truncate text-sm text-slate-600">
                  {LEVELS[s.level].label}
                </span>
                <span className="shrink-0 text-sm font-semibold tabular-nums text-slate-900">
                  {s.value}
                </span>
                <span className="w-10 shrink-0 text-right text-xs tabular-nums text-slate-400">
                  {total > 0 ? Math.round(s.frac * 100) : 0}%
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
