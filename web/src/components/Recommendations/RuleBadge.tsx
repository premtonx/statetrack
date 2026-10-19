import { Zap } from 'lucide-react'
import { cn } from '../../lib/utils'
import { levelStyle } from '../../lib/labels'
import type { Event } from '../../types'

/** Strips the server's `"<name> [L2]"` suffix so the badge can render the
 * level from the event's own impact level instead of duplicating it. */
function ruleName(raw?: string): string {
  if (!raw) return ''
  return raw.replace(/\s*\[L[1-4]\]\s*$/i, '').trim()
}

/**
 * Accent badge shown on a timeline row / inspector header when the event's
 * verdict came from a granular policy rule rather than the built-in
 * heuristics: `⚡ Rule: CheckoutApp (L1)`.
 *
 * The rule is reported by the agent in `metadata.rule_name` (see
 * agent/internal/engine — applyRuleMetadata).
 */
export default function RuleBadge({
  event,
  className,
  onClick,
}: {
  event: Event
  className?: string
  onClick?: (e: React.MouseEvent) => void
}) {
  const raw = event?.metadata?.rule_name
  const name = ruleName(raw)
  if (!name) return null

  const style = levelStyle(event.impact_level)
  const tags = (event.metadata?.rule_tags ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean)

  return (
    <span
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      className={cn(
        'inline-flex max-w-full items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium',
        style.badge,
        onClick && 'cursor-pointer hover:brightness-[0.97]',
        className,
      )}
      title={`Matched policy rule "${name}"${tags.length ? ` · tags: ${tags.join(', ')}` : ''}`}
    >
      <Zap className="h-3 w-3 shrink-0" strokeWidth={2.4} />
      <span className="truncate">
        Rule: <span className="font-semibold">{name}</span> ({style.short})
      </span>
    </span>
  )
}

/** Bare `⚡ <name> (L1)` form for dense table cells and drawer sidebars. */
export function RuleBadgeText({ event, className }: { event: Event; className?: string }) {
  const name = ruleName(event?.metadata?.rule_name)
  if (!name) return null
  const style = levelStyle(event.impact_level)
  return (
    <span className={cn('inline-flex items-center gap-1 font-medium', className)}>
      <Zap className={cn('h-3 w-3 shrink-0', style.dot.replace('bg-', 'text-'))} strokeWidth={2.4} />
      <span className="truncate text-slate-700">{name}</span>
      <span className="text-slate-400">({style.short})</span>
    </span>
  )
}
