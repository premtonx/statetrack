import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

interface CardProps {
  children: ReactNode
  className?: string
  /** Renders the card without internal padding (e.g. for tables). */
  flush?: boolean
}

/**
 * Crisp white surface used by every page: subtle border, rounded corners and
 * a micro-shadow, matching the Google Cloud Console card language.
 */
export default function Card({ children, className, flush }: CardProps) {
  return (
    <section
      className={cn(
        'rounded-xl border border-slate-200/80 bg-white shadow-xs',
        flush ? 'overflow-hidden' : 'p-4',
        className,
      )}
    >
      {children}
    </section>
  )
}

interface CardHeaderProps {
  title: ReactNode
  subtitle?: ReactNode
  /** Right-hand controls (filters, actions, legends). */
  actions?: ReactNode
  icon?: ReactNode
  className?: string
}

export function CardHeader({ title, subtitle, actions, icon, className }: CardHeaderProps) {
  return (
    <div className={cn('flex items-start gap-3', className)}>
      {icon ? (
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500">
          {icon}
        </span>
      ) : null}
      <div className="min-w-0 flex-1">
        <h2 className="truncate text-sm font-semibold text-slate-900">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/** Consistent section heading used above card grids. */
export function SectionTitle({
  children,
  hint,
  actions,
}: {
  children: ReactNode
  hint?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="mb-3 flex items-end justify-between gap-3">
      <div>
        <h2 className="text-sm font-semibold text-slate-900">{children}</h2>
        {hint ? <p className="mt-0.5 text-xs text-slate-500">{hint}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  )
}
