import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'
import { categoryStyle, levelStyle } from '../../lib/labels'

export type PillTone = 'blue' | 'red' | 'purple' | 'amber' | 'green' | 'slate' | 'cyan'

const TONES: Record<PillTone, string> = {
  blue: 'bg-blue-50 text-blue-700 border-blue-200',
  red: 'bg-red-50 text-red-700 border-red-200',
  purple: 'bg-purple-50 text-purple-700 border-purple-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  green: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  slate: 'bg-slate-100 text-slate-600 border-slate-200',
  cyan: 'bg-cyan-50 text-cyan-700 border-cyan-200',
}

interface StatusPillProps {
  children: ReactNode
  tone?: PillTone
  /** Renders a leading status dot. */
  dot?: boolean
  className?: string
  mono?: boolean
}

/** Rounded badge used for levels, statuses, categories and counts. */
export default function StatusPill({
  children,
  tone = 'slate',
  dot,
  className,
  mono,
}: StatusPillProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        TONES[tone],
        mono && 'font-mono',
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" /> : null}
      {children}
    </span>
  )
}

/** Impact-level pill (Level 1 … Level 4) with the canonical color semantics. */
export function LevelPill({ level, short }: { level: number; short?: boolean }) {
  const style = levelStyle(level)
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        style.badge,
      )}
      title={style.label}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', style.dot)} />
      {short ? style.short : style.pill}
    </span>
  )
}

/** Bare colored dot for dense table cells. */
export function LevelDot({ level, className }: { level: number; className?: string }) {
  const style = levelStyle(level)
  return (
    <span
      className={cn('inline-block h-2 w-2 shrink-0 rounded-full', style.dot, className)}
      title={style.label}
    />
  )
}

/** Event-category tag, e.g. "Config change" / "Package update". */
export function CategoryTag({ category, short }: { category: number; short?: boolean }) {
  const style = categoryStyle(category)
  return (
    <span
      className={cn(
        'inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        style.badge,
      )}
    >
      {short ? style.label : style.tag}
    </span>
  )
}

/** Online / offline server status pill. */
export function StatusDot({
  online,
  label,
  className,
}: {
  online: boolean
  label?: string
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        online
          ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
          : 'border-red-200 bg-red-50 text-red-700',
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', online ? 'bg-emerald-600' : 'bg-red-600')} />
      {label ?? (online ? 'Online' : 'Offline')}
    </span>
  )
}

/**
 * Marks values that come from the seeded preview store rather than a live
 * backend, so the console never presents sample data as real fleet state.
 */
export function PreviewBadge({ label = 'Preview data' }: { label?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 whitespace-nowrap rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500"
      title="Seeded sample data — no agent has reported yet."
    >
      <span className="h-1 w-1 rounded-full bg-slate-400" />
      {label}
    </span>
  )
}
