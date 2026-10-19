import { ArrowRight, X } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface RecommendationBannerProps {
  /** Pending recommendation count. The banner renders nothing when 0. */
  pending: number
  /** Distinct hostnames with pending recommendations (sorted). */
  hostnames: string[]
  onReview: () => void
  /** Optional local dismissal for the current session. */
  onDismiss?: () => void
  className?: string
}

/** "2 servers", "prod-web-01", "prod-web-01 and win-app-02". */
function scopePhrase(hostnames: string[]): string {
  const list = (hostnames ?? []).filter(Boolean)
  if (list.length === 0) return 'your fleet'
  if (list.length === 1) return list[0]
  if (list.length === 2) return `${list[0]} and ${list[1]}`
  return `${list.length} servers`
}

/**
 * Slim discovery call-to-action shown directly under the page title when the
 * agents have reported workloads that lack a granular policy rule:
 *
 *   💡 4 workload recommendations: Review high-frequency changes, outdated
 *      packages and drift detected across 2 servers.  [Review recommendations →] ✕
 *
 * Deliberately restrained: no gradient, no hero button. The review action is a
 * quiet inline link so the banner never competes with the changes table.
 */
export default function RecommendationBanner({
  pending,
  hostnames,
  onReview,
  onDismiss,
  className,
}: RecommendationBannerProps) {
  if (!pending || pending <= 0) return null

  return (
    <div
      role="status"
      className={cn(
        'flex items-start gap-2.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2.5 shadow-xs',
        className,
      )}
    >
      <span aria-hidden className="shrink-0 text-sm leading-5">
        💡
      </span>

      <p className="min-w-0 flex-1 text-[13px] leading-5 text-slate-600">
        <span className="font-semibold text-slate-900">
          {pending} workload recommendation{pending === 1 ? '' : 's'}:
        </span>{' '}
        Review high-frequency changes, outdated packages and drift detected across{' '}
        <span className="font-medium text-slate-700">{scopePhrase(hostnames)}</span>.
      </p>

      <div className="flex shrink-0 items-center gap-1">
        <button
          onClick={onReview}
          className="inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-1 text-[13px] font-medium text-blue-700 transition-colors hover:bg-blue-50"
        >
          Review recommendations
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
        {onDismiss ? (
          <button
            onClick={onDismiss}
            aria-label="Dismiss recommendation banner"
            className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        ) : null}
      </div>
    </div>
  )
}
