import { useState } from 'react'
import { ChevronDown, ChevronRight, Loader2 } from 'lucide-react'
import { cn, formatClock, formatNumber } from '../../lib/utils'
import { useEventDetail } from '../../api/hooks'
import { levelStyle } from '../../lib/labels'
import type { Event } from '../../types'
import { HostPill } from './HostPill'
import RuleBadge from '../Recommendations/RuleBadge'

interface ParentCardProps {
  event: Event
  onOpen: (id: string, context?: string) => void
  divider?: boolean
}

/**
 * L2 grouped transaction: collapsed by default, expands to reveal the child
 * mutations inline. Mirrors the timeline grid so the node column stays aligned
 * with the sibling rows.
 */
export default function ParentCard({ event, onOpen, divider }: ParentCardProps) {
  const [expanded, setExpanded] = useState(false)
  const style = levelStyle(2)
  const detail = useEventDetail(expanded ? event.id : null)
  const hostname = event.hostname || event.host_id
  const children = detail.data?.children ?? []

  return (
    <div className={cn('relative', style.tint, divider && 'border-b border-slate-100')}>
      <div className="flex w-full items-stretch gap-3 pl-5 pr-3 sm:gap-4 sm:pl-8">
        {/* Time */}
        <div className="flex w-14 shrink-0 items-start justify-end pt-3.5">
          <span className="font-mono text-[11px] tabular-nums text-slate-400">
            {formatClock(event.occurred_at)}
          </span>
        </div>

        {/* Node */}
        <div className="relative flex w-3 shrink-0 justify-center pt-4">
          <span aria-hidden className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-slate-200" />
          <span className={cn('relative z-10 h-2.5 w-2.5 rounded-full ring-4 ring-white', style.dot)} />
        </div>

        {/* Body */}
        <div className="min-w-0 flex-1 py-3">
          <button
            onClick={() => setExpanded((e) => !e)}
            aria-expanded={expanded}
            className="group flex w-full items-start gap-2 text-left"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
                    style.badge,
                  )}
                >
                  <span className={cn('h-1.5 w-1.5 rounded-full', style.dot)} />
                  {style.pill}
                </span>
                <span className="truncate text-sm font-medium text-slate-900">{event.summary}</span>
                <RuleBadge event={event} onClick={(e) => e.stopPropagation()} />
              </div>
              <p className="mt-1 truncate text-xs text-slate-500">
                {formatNumber(event.child_count)} related changes · actor{' '}
                {event.actor_username || 'unknown'}
                {event.process_name ? ` via ${event.process_name}` : ''}
              </p>
            </div>
            <span className="mt-0.5 flex shrink-0 items-center gap-1.5 text-xs font-medium text-purple-700">
              {expanded ? 'Hide' : `Show ${formatNumber(event.child_count)}`}
              {expanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
              )}
            </span>
          </button>
        </div>

        {/* Aside */}
        <div className="hidden shrink-0 items-center gap-2 py-3 sm:flex">
          <button
            onClick={() => onOpen(event.id, 'parent')}
            className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
          >
            Inspect
          </button>
          <HostPill hostname={hostname} />
        </div>
      </div>

      {expanded ? (
        <div className="border-t border-purple-100 bg-white/70 px-5 py-2 sm:pl-8">
          {detail.isLoading ? (
            <div className="flex items-center gap-2 py-2 pl-20 text-xs text-slate-400">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading grouped changes…
            </div>
          ) : null}

          {!detail.isLoading && children.length === 0 ? (
            <p className="py-2 pl-20 text-xs text-slate-400">
              No child mutations recorded (grouped on the agent side).
            </p>
          ) : null}

          <ul className="divide-y divide-slate-100">
            {children.map((child) => (
              <li key={child.id}>
                <button
                  onClick={() => onOpen(child.id, 'child')}
                  className="flex w-full items-center gap-3 py-1.5 pl-20 pr-2 text-left text-xs transition-colors hover:text-blue-700"
                >
                  <span className="shrink-0 font-mono tabular-nums text-slate-400">
                    {formatClock(child.occurred_at)}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-slate-700">
                    {child.path_or_key}
                  </span>
                  <span className="hidden shrink-0 text-slate-400 sm:block">{child.summary}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  )
}
