import type { ReactNode } from 'react'
import { ArrowRight, Server } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface EmptyStateProps {
  title: string
  description: ReactNode
  /** Primary call to action (usually "open agent setup"). */
  actionLabel?: string
  onAction?: () => void
  secondaryLabel?: string
  onSecondary?: () => void
  icon?: ReactNode
  className?: string
}

/**
 * Shared empty state for a freshly-installed deployment.
 *
 * A new server has no hosts and no events, and the console must say so plainly
 * rather than dressing the page in sample data. The default copy points at the
 * two things an operator needs next: the agent install command under Settings →
 * Agents, and the documentation that explains the parameters.
 */
export default function EmptyState({
  title,
  description,
  actionLabel,
  onAction,
  secondaryLabel,
  onSecondary,
  icon,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center',
        className,
      )}
    >
      <span className="flex h-11 w-11 items-center justify-center rounded-full bg-slate-100 text-slate-500">
        {icon ?? <Server className="h-5 w-5" />}
      </span>
      <div className="max-w-xl">
        <p className="text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-1 text-sm leading-6 text-slate-500">{description}</p>
      </div>
      {actionLabel && onAction ? (
        <div className="mt-1 flex flex-wrap items-center justify-center gap-2">
          <button
            onClick={onAction}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700"
          >
            {actionLabel}
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
          {secondaryLabel && onSecondary ? (
            <button
              onClick={onSecondary}
              className="rounded-lg border border-slate-200 bg-white px-3.5 py-1.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50"
            >
              {secondaryLabel}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

/**
 * The canonical first-boot copy. Kept in one place so every page tells the
 * operator the same next step instead of inventing its own wording.
 */
export const NO_AGENTS_TITLE = 'No servers enrolled yet'
export const NO_AGENTS_BODY =
  'Copy the Linux or Windows install command under Settings → Agents to connect your first host. The command writes the agent configuration, verifies the release checksum and registers the service.'

export function AgentSetupEmptyState({
  onOpenAgents,
  onOpenDocs,
  className,
}: {
  onOpenAgents: () => void
  onOpenDocs?: () => void
  className?: string
}) {
  return (
    <EmptyState
      title={NO_AGENTS_TITLE}
      description={NO_AGENTS_BODY}
      actionLabel="Open agent setup"
      onAction={onOpenAgents}
      secondaryLabel={onOpenDocs ? 'Read the docs' : undefined}
      onSecondary={onOpenDocs}
      className={className}
    />
  )
}
