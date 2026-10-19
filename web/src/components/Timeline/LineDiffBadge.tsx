import { FileDiff } from 'lucide-react'
import { cn } from '../../lib/utils'
import { parseLineDiff, lineDiffLabel } from '../../lib/labels'
import type { Event } from '../../types'

/**
 * Compact `+12 -3` line-diff summary. Counts come from the event columns when
 * present, otherwise they are parsed out of the agent's summary text.
 */
export default function LineDiffBadge({ event, className }: { event: Event; className?: string }) {
  const explicit = lineDiffLabel(event.lines_added, event.lines_removed)
  const parsed = parseLineDiff(event.summary)
  const stat = explicit ?? parsed

  if (stat) {
    return (
      <span
        className={cn(
          'inline-flex shrink-0 items-center gap-1.5 rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[11px] font-medium tabular-nums',
          className,
        )}
        title="Added / removed lines"
      >
        <span className="text-emerald-600">+{stat.added}</span>
        <span className="text-red-600">-{stat.removed}</span>
      </span>
    )
  }

  if (event.has_diff) {
    return (
      <span
        className={cn(
          'inline-flex shrink-0 items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700',
          className,
        )}
      >
        <FileDiff className="h-3 w-3" /> Diff
      </span>
    )
  }

  return null
}
