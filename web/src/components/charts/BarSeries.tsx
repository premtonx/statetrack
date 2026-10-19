import { cn } from '../../lib/utils'

interface BarSeriesProps {
  /** Label → value pairs rendered as horizontal proportional bars. */
  data: { label: string; value: number; color?: string }[]
  /** Formats the trailing value, e.g. `(v) => v.toLocaleString()`. */
  format?: (v: number) => string
  className?: string
}

/**
 * Tailwind flex-bar list — used for "Changes by Level" and similar breakdowns
 * where a full chart would be overkill.
 */
export default function BarSeries({ data, format, className }: BarSeriesProps) {
  const rows = data ?? []
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <ul className={cn('space-y-2.5', className)}>
      {rows.map((r) => (
        <li key={r.label}>
          <div className="mb-1 flex items-baseline justify-between gap-3">
            <span className="truncate text-xs font-medium text-slate-600">{r.label}</span>
            <span className="shrink-0 text-xs font-semibold tabular-nums text-slate-900">
              {format ? format(r.value) : r.value.toLocaleString()}
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100">
            <div
              className="h-full rounded-full transition-[width] duration-500"
              style={{
                width: `${Math.max(2, (r.value / max) * 100)}%`,
                background: r.color ?? '#1a73e8',
              }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}

interface SparklineProps {
  values: number[]
  color?: string
  width?: number
  height?: number
  className?: string
}

/** Tiny inline trend line for table ranking cells. */
export function Sparkline({
  values,
  color = '#1a73e8',
  width = 72,
  height = 22,
  className,
}: SparklineProps) {
  const vals = (values ?? []).filter((v) => Number.isFinite(v))
  if (vals.length < 2) return null
  const max = Math.max(...vals)
  const min = Math.min(...vals)
  const range = max - min || 1
  const step = width / (vals.length - 1)
  const path = vals
    .map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(height - ((v - min) / range) * (height - 4) - 2).toFixed(1)}`)
    .join(' ')

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      className={cn('shrink-0', className)}
      aria-hidden
    >
      <path d={path} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" />
    </svg>
  )
}
