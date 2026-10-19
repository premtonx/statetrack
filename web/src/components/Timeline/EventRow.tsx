import { cn, formatClock } from '../../lib/utils'
import { levelStyle } from '../../lib/labels'
import type { Event } from '../../types'
import TimelineItem from './TimelineItem'
import ParentCard from './ParentCard'
import { HostPill } from './HostPill'
import LineDiffBadge from './LineDiffBadge'
import RuleBadge from '../Recommendations/RuleBadge'
import { ChangeControlBadge } from '../Compliance/ChangeControlBadge'

interface EventRowProps {
  event: Event
  onOpen: (id: string, context?: string) => void
  /** Draws a separator below the row (false on the last row of a day group). */
  divider?: boolean
}

/**
 * A single (non-grouped) change. Critical changes carry a soft red wash so
 * they are visible while scrolling, matching the console screenshots.
 */
export default function EventRow({ event, onOpen, divider }: EventRowProps) {
  if (event.impact_level === 2 && event.child_count > 0) {
    return <ParentCard event={event} onOpen={onOpen} divider={divider} />
  }

  const style = levelStyle(event.impact_level)
  const hostname = event.hostname || event.host_id
  const subtitle = buildSubtitle(event)

  return (
    <TimelineItem
      time={formatClock(event.occurred_at)}
      dotClass={style.dot}
      tintClass={event.impact_level === 1 ? style.tint : undefined}
      category={event.category}
      divider={divider}
      onClick={() => onOpen(event.id)}
      aside={
        <>
          <LineDiffBadge event={event} />
          <HostPill hostname={hostname} />
        </>
      }
    >
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
              style.badge,
            )}
          >
            {style.pill}
          </span>
          <span className="truncate text-sm font-medium text-slate-900">{mainTarget(event)}</span>
          <RuleBadge event={event} onClick={(e) => e.stopPropagation()} />
          {/* Only rendered for a matched ticket or an actual violation: a row
              that showed "Change Approved" on every change would bury the two
              that matter. */}
          <ChangeControlBadge
            compliance={event.compliance}
            reason={event.compliance_reason}
            ticketRef={event.ticket_ref}
            ticketStatus={event.ticket_status}
          />
          <span className="lg:hidden">
            <HostPill hostname={hostname} />
          </span>
        </div>
        <p className="truncate text-xs text-slate-500">{subtitle}</p>
      </div>
    </TimelineItem>
  )
}

/** Registry keys are long; files read best with the basename emphasized. */
function mainTarget(event: Event): string {
  if (event.target_type === 'registry') return event.path_or_key
  if (event.target_type === 'service' || event.target_type === 'process' || event.target_type === 'transaction') {
    return event.path_or_key
  }
  return event.path_or_key || event.target_type
}

function buildSubtitle(event: Event): string {
  const actor = event.actor_username ? `by ${event.actor_username}` : 'by unknown actor'
  const via = event.process_name ? ` via ${event.process_name}` : ''
  const ip = event.remote_ip ? ` from ${event.remote_ip}` : ''
  if (event.impact_level === 2 && event.child_count > 0) {
    return `Updated ${event.child_count} items ${actor}${via}`
  }
  if (event.summary) return `${event.summary} ${actor}${via}${ip}`
  return `Configuration changed ${actor}${via}${ip}`
}
