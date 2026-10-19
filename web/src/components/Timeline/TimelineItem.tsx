import { ChevronRight } from 'lucide-react'
import { cn } from '../../lib/utils'
import { CategoryTag } from '../ui/StatusPill'

export interface TimelineItemProps {
  /** Time column (HH:MM or HH:MM:SS). */
  time: string
  /** Level dot color class, e.g. `bg-red-600`. */
  dotClass: string
  /** Soft tint behind the whole row (critical rows get a red wash). */
  tintClass?: string
  /** Left block content: level pill + title + path. */
  children: React.ReactNode
  /** Right column: host pill / metadata. */
  aside?: React.ReactNode
  /** Category tag pill on the far right. */
  category?: number
  onClick?: () => void
  /** Rendered under the row (e.g. expanded children). */
  footer?: React.ReactNode
  /** Suppresses hover affordances and the connector for nested child rows. */
  interactive?: boolean
  /** Draws the row separator (omit on the last row of a day group). */
  divider?: boolean
  className?: string
}

/**
 * One node on the vertical timeline. The node column draws a full-height
 * connector segment behind the level dot, so consecutive rows stack into a
 * single continuous history line.
 */
export default function TimelineItem({
  time,
  dotClass,
  tintClass,
  children,
  aside,
  category,
  onClick,
  footer,
  interactive = true,
  divider = false,
  className,
}: TimelineItemProps) {
  const clickable = interactive && !!onClick
  const Tag = clickable ? 'button' : 'div'
  return (
    <div className={cn('relative', className)}>
      <Tag
        {...(clickable ? { onClick, type: 'button' as const } : {})}
        className={cn(
          'group flex w-full items-stretch gap-3 pl-5 pr-3 text-left transition-colors sm:gap-4 sm:pl-8',
          tintClass,
          divider && 'border-b border-slate-100',
          clickable && 'hover:bg-slate-50',
        )}
      >
        {/* Time */}
        <div className="flex w-14 shrink-0 items-start justify-end pt-3.5">
          <span className="font-mono text-[11px] tabular-nums text-slate-400">{time}</span>
        </div>

        {/* Node + connector */}
        <div className="relative flex w-3 shrink-0 justify-center pt-4">
          {interactive ? (
            <span
              aria-hidden
              className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-slate-200"
            />
          ) : null}
          <span
            className={cn(
              'relative z-10 h-2.5 w-2.5 rounded-full ring-4 ring-white transition-transform',
              dotClass,
              clickable && 'group-hover:scale-110',
            )}
          />
        </div>

        {/* Body */}
        <div className="min-w-0 flex-1 py-3">{children}</div>

        {/* Aside */}
        {aside ? (
          <div className="hidden shrink-0 items-center gap-2 py-3 sm:flex">{aside}</div>
        ) : null}

        {/* Category tag */}
        {category !== undefined ? (
          <div className="hidden shrink-0 items-center gap-2 py-3 lg:flex">
            <CategoryTag category={category} />
          </div>
        ) : null}

        {clickable ? (
          <ChevronRight className="mt-3.5 hidden h-4 w-4 shrink-0 text-slate-300 transition-transform group-hover:translate-x-0.5 group-hover:text-slate-500 sm:block" />
        ) : null}
      </Tag>
      {footer}
    </div>
  )
}
