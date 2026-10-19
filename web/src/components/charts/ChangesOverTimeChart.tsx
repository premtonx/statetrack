import { useMemo, useState } from 'react'
import { cn } from '../../lib/utils'
import { LEVELS, LEVEL_ORDER } from '../../lib/labels'

export interface StackedPoint {
  label: string
  /** Value per impact level id (1…4). Missing keys count as zero. */
  values: Partial<Record<1 | 2 | 3 | 4, number>>
}

interface ChangesOverTimeChartProps {
  data: StackedPoint[]
  height?: number
  className?: string
}

const PAD_LEFT = 34
const PAD_BOTTOM = 22
const PAD_TOP = 10
const PAD_RIGHT = 6

/**
 * Dependency-free stacked column chart (pure SVG) showing change volume per
 * hour broken down by impact level. Responsive via a viewBox and percentage
 * sizing so it never causes layout shift.
 */
export default function ChangesOverTimeChart({
  data,
  height = 208,
  className,
}: ChangesOverTimeChartProps) {
  const [hover, setHover] = useState<number | null>(null)
  const points = data ?? []

  const { max, peak } = useMemo(() => {
    const sums = points.map((p) =>
      LEVEL_ORDER.reduce((a, l) => a + (Number(p?.values?.[l]) || 0), 0),
    )
    return {
      // `max` only feeds the tick calculation; `peak` is the number shown, so a
      // window with no changes does not report "peak 1 / hour".
      max: Math.max(1, ...sums),
      peak: Math.max(0, ...sums),
    }
  }, [points])

  const width = 720
  const innerW = width - PAD_LEFT - PAD_RIGHT
  const innerH = height - PAD_TOP - PAD_BOTTOM
  const slot = innerW / Math.max(1, points.length)
  const barW = Math.max(3, Math.min(20, slot * 0.62))

  // Four horizontal gridlines with rounded "nice" values.
  const ticks = useMemo(() => {
    const step = Math.max(1, Math.ceil(max / 4))
    return Array.from({ length: 5 }, (_, i) => i * step)
  }, [max])
  const yMax = ticks[ticks.length - 1] || 1

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

  return (
    <div className={cn('w-full', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full"
        style={{ height }}
        role="img"
        aria-label="Changes over time by impact level"
        preserveAspectRatio="none"
      >
        {/* Gridlines + y-axis labels */}
        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={PAD_LEFT}
              x2={width - PAD_RIGHT}
              y1={y(t)}
              y2={y(t)}
              stroke="#e2e8f0"
              strokeWidth={1}
            />
            <text x={PAD_LEFT - 6} y={y(t) + 3} textAnchor="end" fontSize={9} fill="#94a3b8">
              {t}
            </text>
          </g>
        ))}

        {/* Stacked columns */}
        {points.map((p, i) => {
          const x = PAD_LEFT + i * slot + (slot - barW) / 2
          let cursor = PAD_TOP + innerH
          const isHover = hover === i
          return (
            <g
              key={p.label}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            >
              {/* Full-height hover target so thin bars stay easy to hit. */}
              <rect
                x={PAD_LEFT + i * slot}
                y={PAD_TOP}
                width={slot}
                height={innerH}
                fill={isHover ? 'rgba(26,115,232,0.05)' : 'transparent'}
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
                    rx={1.5}
                    fill={LEVELS[level].hex}
                    opacity={hover === null || isHover ? 1 : 0.45}
                  />
                )
              })}
            </g>
          )
        })}

        {/* X labels — every 3rd hour keeps them legible at all widths. */}
        {points.map((p, i) =>
          i % 3 === 0 ? (
            <text
              key={`x-${p.label}`}
              x={PAD_LEFT + i * slot + slot / 2}
              y={height - 6}
              textAnchor="middle"
              fontSize={9}
              fill="#94a3b8"
            >
              {p.label}
            </text>
          ) : null,
        )}
      </svg>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1">
        {LEVEL_ORDER.map((l) => (
          <span key={l} className="flex items-center gap-1.5 text-[11px] text-slate-500">
            <span className="h-2 w-2 rounded-sm" style={{ background: LEVELS[l].hex }} />
            {LEVELS[l].label}
          </span>
        ))}
        <span className="ml-auto text-[11px] text-slate-400">
          {active ? (
            <>
              <span className="font-medium text-slate-700">{active.label}</span> ·{' '}
              {LEVEL_ORDER.reduce((a, l) => a + (Number(active?.values?.[l]) || 0), 0)} changes
            </>
          ) : peak > 0 ? (
            `peak ${peak} / hour`
          ) : (
            'no changes'
          )}
        </span>
      </div>
    </div>
  )
}
