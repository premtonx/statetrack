import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

interface PageHeaderProps {
  title: ReactNode
  subtitle?: ReactNode
  /** Right-hand toolbar (filters, primary actions). */
  actions?: ReactNode
  /** Rendered above the title — used for the dashboard greeting banner. */
  eyebrow?: ReactNode
  className?: string
}

/** Consistent page title block with a right-aligned action cluster. */
export default function PageHeader({
  title,
  subtitle,
  actions,
  eyebrow,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-3 border-b border-slate-200 bg-white/60 px-4 py-4 backdrop-blur sm:px-6 lg:flex-row lg:items-center lg:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow ? <div className="mb-1">{eyebrow}</div> : null}
        <h1 className="truncate text-lg font-semibold tracking-tight text-slate-900">{title}</h1>
        {subtitle ? <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p> : null}
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2 lg:shrink-0">{actions}</div>
      ) : null}
    </div>
  )
}
