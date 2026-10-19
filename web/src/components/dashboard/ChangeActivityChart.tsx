import { useMemo, useState } from 'react'
import { cn } from '../../lib/utils'
import { LEVELS, LEVEL_ORDER } from '../../lib/labels'
import type { StackedPoint } from '../../api/mockData'

interface ChangeActivityChartProps {
  data: StackedPoint[]
  height?: number
  className?: string
}

const PAD_TOP = 6
const PAD_BOTTOM = 16

/**
 * Compact, high-density stacked column chart for the Fleet Pulse strip.
 *
 * Pure SVG (no charting dependency), sized by viewBox so it reflows without
 * layout shift. Grid and axis chrome stay neutral slate; only the level
 * segments carry colour. Rendered with `preserveAspectRatio="none"` so it
 * fills whatever width the split surface gives it.
 */
export default function ChangeActivityChart({
  data,
  height = 132,
  className,
}: ChangeActivityChartProps) {
  const [hover, setHover] = useState<number | null>(null)
  const points = (data ?? []).filter(Boolean)

  const { yMax, peak } = useMemo(() => {
    const sums = points.map((p) =>
      LEVEL_ORDER.reduce((a, l) => a + (Number(p?.values?.[l]) || 0), 0),
    )
    // `peak` is the real maximum, which is 0 on a clean install. `yMax` only
    // guards the division that lays out the gridlines, so an empty fleet draws
    // a flat baseline instead of claiming "peak 1 / hour" — a fabricated number
    // in the one place an operator looks to confirm nothing has changed.
    return { yMax: Math.max(1, ...sums), peak: Math.max(0, ...sums) }
  }, [points])

  // Two horizontal gridlines (mid + top) keep the compact chart uncluttered.
  const ticks = useMemo(() => [yMax, Math.round(yMax / 2)], [yMax])

  const width = 480
  const innerH = height - PAD_TOP - PAD_BOTTOM
  const slot = width / Math.max(1, points.length)
  const barW = Math.max(2.5, Math.min(12, slot * 0.6))
  const y = (v: number) => PAD_TOP + innerH - (v / yMax) * innerH

  if (points.length === 0) {
    return (
      <div
        className={cn('flex items-center justify-center text-xs text-slate-400', className)}
        style={{ height }}
      >
        No change volume in this window.
      </div>
    )
  }

  const active = hover !== null ? points[hover] : null
  const activeTotal = active
    ? LEVEL_ORDER.reduce((a, l) => a + (Number(active?.values?.[l]) || 0), 0)
    : 0

  return (
    <div className={cn('flex min-w-0 flex-col', className)}>
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold text-slate-900">Change activity (last 24 hours)</h2>
        <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">
          Hourly
        </span>
        <span className="ml-auto text-[11px] tabular-nums text-slate-400">
          {active ? (
            <>
              <span className="font-medium text-slate-700">{active.label}</span> · {activeTotal}{' '}
              changes
            </>
          ) : peak > 0 ? (
            `peak ${peak} / hour`
          ) : (
            'no changes'
          )}
        </span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="mt-3 h-auto w-full"
        style={{ height }}
        role="img"
        aria-label="Change activity over the last 24 hours by impact level"
        preserveAspectRatio="none"
        onMouseLeave={() => setHover(null)}
      >
        {ticks.map((t) => (
          <line
            key={t}
            x1={0}
            x2={width}
            y1={y(t)}
            y2={y(t)}
            stroke="#e2e8f0"
            strokeWidth={1}
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {points.map((p, i) => {
          const x = i * slot + (slot - barW) / 2
          let cursor = PAD_TOP + innerH
          const isHover = hover === i
          return (
            <g key={p.label} onMouseEnter={() => setHover(i)}>
              {/* Full-height hover target so thin bars stay easy to hit. */}
              <rect
                x={i * slot}
                y={PAD_TOP}
                width={slot}
                height={innerH}
                fill={isHover ? 'rgba(15,23,42,0.04)' : 'transparent'}
              />
              {LEVEL_ORDER.map((level) => {
                const v = Number(p?.values?.[level]) || 0
                if (v <= 0) return null
                const h = (v / yMax) * innerH
                cursor -= h
                return (
                  <rect
                    key={level}
                    x={x}
                    y={cursor}
                    width={barW}
                    height={Math.max(1, h)}
                    fill={LEVELS[level].hex}
                    opacity={hover === null || isHover ? 1 : 0.35}
                  />
                )
              })}
            </g>
          )
        })}

        {/* Sparse x labels keep the compact chart legible. */}
        {points.map((p, i) =>
          i % 4 === 0 ? (
            <text
              key={`x-${p.label}`}
              x={i * slot + slot / 2}
              y={height - 4}
              textAnchor="middle"
              fontSize={9}
              fill="#94a3b8"
            >
              {p.label}
            </text>
          ) : null,
        )}
      </svg>
    </div>
  )
}
