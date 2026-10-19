import { useEffect, useMemo, useState } from 'react'
import {
  Check,
  CheckCheck,
  Loader2,
  Sparkles,
  X,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { levelStyle, workloadStyle } from '../../lib/labels'
import { Button } from '../ui/controls'
import StatusPill from '../ui/StatusPill'
import { HostPill } from '../Timeline/HostPill'
import { useReadOnly } from '../../lib/authContext'
import type { Recommendation, RecommendationStatusFilter } from '../../types'
import type { RecommendationFeed } from '../../api/hooks'

export interface RecommendationsDrawerProps {
  feed: RecommendationFeed
  onClose: () => void
  /** Restricts the view to one host (set from the Servers table row action). */
  hostFilter?: string
  onClearHostFilter?: () => void
  /** Which recommendation lifecycle to show. */
  status?: RecommendationStatusFilter
  onStatus?: (status: RecommendationStatusFilter) => void
}

const STATUS_TABS: { id: RecommendationStatusFilter; label: string }[] = [
  { id: 'pending', label: 'Pending' },
  { id: 'applied', label: 'Applied' },
  { id: 'dismissed', label: 'Dismissed' },
  { id: 'all', label: 'All' },
]

/**
 * Slide-over review queue for auto-discovered workloads. Each card shows the
 * workload type, target path, the suggested impact level and why the agent
 * thinks it deserves that level, plus the per-item accept/dismiss controls.
 */
export default function RecommendationsDrawer({
  feed,
  onClose,
  hostFilter,
  onClearHostFilter,
  status = 'pending',
  onStatus,
}: RecommendationsDrawerProps) {
  const {
    recommendations,
    selectedIds,
    toggle,
    toggleAll,
    applyOne,
    dismissOne,
    applySelected,
    applyAll,
    isMutating,
    isFallback,
  } = feed

  const [busyId, setBusyId] = useState('')
  const readOnly = useReadOnly()
  const list = useMemo(
    () => (recommendations ?? []).filter((r) => r && r.id),
    [recommendations],
  )
  const allSelected = list.length > 0 && selectedIds.length === list.length

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const confirmed = status === 'pending'

  const runOne = (id: string, fn: (id: string) => void) => {
    setBusyId(id)
    fn(id)
    window.setTimeout(() => setBusyId(''), 400)
  }

  return (
    <div
      className="fixed inset-0 z-50"
      role="dialog"
      aria-modal="true"
      aria-label="Recommendations"
    >
      <div
        className="drawer-backdrop absolute inset-0 bg-slate-900/30"
        onClick={onClose}
        aria-hidden
      />

      <div className="drawer-enter absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col border-l border-slate-200 bg-white shadow-2xl">
        {/* Header */}
        <div className="shrink-0 border-b border-slate-200 px-5 py-4">
          <div className="flex items-start gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-600 text-white shadow-xs">
              <Sparkles className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1">
              <h2 className="truncate text-sm font-semibold text-slate-900">
                Recommended policy rules
              </h2>
              <p className="mt-0.5 text-xs text-slate-500">
                The discovery engine found these workloads without a granular rule. Approving one
                generates a Level&nbsp;+ diff policy and pushes it to the agent.
              </p>
            </div>
            <button
              onClick={onClose}
              aria-label="Close recommendations"
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Filters */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-0.5">
              {STATUS_TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => onStatus?.(t.id)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                    t.id === status
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-500 hover:text-slate-700',
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
            {hostFilter ? (
              <span className="inline-flex items-center gap-1.5">
                <HostPill hostname={hostFilter} />
                <button
                  onClick={onClearHostFilter}
                  aria-label="Clear host filter"
                  className="flex h-5 w-5 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ) : null}
            {isFallback ? (
              <StatusPill tone="slate">Preview data</StatusPill>
            ) : null}
          </div>
        </div>

        {/* Body */}
        <div className="min-h-0 flex-1 overflow-y-auto bg-slate-50/60 px-5 py-4">
          {list.length === 0 ? (
            <div className="mx-auto mt-10 max-w-sm rounded-xl border border-dashed border-slate-200 bg-white px-4 py-10 text-center">
              <CheckCheck className="mx-auto h-6 w-6 text-emerald-500" />
              <p className="mt-2 text-sm font-medium text-slate-600">
                {status === 'pending' ? 'All caught up' : 'Nothing here'}
              </p>
              <p className="mt-1 text-xs text-slate-400">
                {status === 'pending'
                  ? 'Every discovered workload already has a policy rule.'
                  : 'No recommendations in this state.'}
              </p>
            </div>
          ) : (
            <ul className="space-y-3">
              {list.map((r) => (
                <RecommendationCard
                  key={r.id}
                  recommendation={r}
                  selected={selectedIds.includes(r.id)}
                  busy={isMutating && busyId === r.id}
                  showHost
                  onToggle={() => toggle(r.id)}
                  onApply={readOnly ? undefined : () => runOne(r.id, applyOne)}
                  onDismiss={readOnly ? undefined : () => runOne(r.id, dismissOne)}
                />
              ))}
            </ul>
          )}
        </div>

        {/* Footer */}
        <div className="flex shrink-0 flex-wrap items-center gap-3 border-t border-slate-200 bg-white px-5 py-3">
          {confirmed && list.length > 0 && !readOnly ? (
            <label className="flex cursor-pointer items-center gap-2 text-xs font-medium text-slate-600">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={(e) => toggleAll(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500/30"
              />
              Select all ({list.length})
            </label>
          ) : null}

          {readOnly ? (
            <span className="flex items-center gap-1.5 text-xs font-medium text-amber-700">
              🔒 Read-only session — approving and dismissing is disabled.
            </span>
          ) : null}

          <span className="ml-auto flex items-center gap-2">
            {selectedIds.length > 0 && !readOnly ? (
              <Button
                onClick={applySelected}
                disabled={isMutating}
                icon={
                  isMutating ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Check className="h-4 w-4" />
                  )
                }
              >
                Apply {selectedIds.length} selected
              </Button>
            ) : null}
            {confirmed && list.length > 0 && !readOnly ? (
              <Button
                variant="primary"
                onClick={applyAll}
                disabled={isMutating}
                icon={
                  isMutating ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <CheckCheck className="h-4 w-4" />
                  )
                }
              >
                Apply {list.length} Recommended Rule{list.length === 1 ? '' : 's'}
              </Button>
            ) : null}
          </span>
        </div>
      </div>
    </div>
  )
}

/**
 * One discovered workload. The card mirrors the Google-style list item:
 * workload glyph, target name + config path, the suggested level badge and
 * the reasoning sentence.
 */
export function RecommendationCard({
  recommendation,
  selected,
  busy,
  showHost,
  onToggle,
  onApply,
  onDismiss,
}: {
  recommendation: Recommendation
  selected?: boolean
  busy?: boolean
  showHost?: boolean
  onToggle?: () => void
  onApply?: () => void
  onDismiss?: () => void
}) {
  const r = recommendation
  const wl = workloadStyle(r?.workload_type)
  const lvl = levelStyle(Number(r?.suggested_level) || 3)

  return (
    <li
      className={cn(
        'rounded-xl border bg-white p-3.5 shadow-xs transition-colors',
        selected ? 'border-blue-300 ring-2 ring-blue-500/15' : 'border-slate-200/80',
      )}
    >
      <div className="flex items-start gap-3">
        {onToggle && r.status === 'pending' ? (
          <input
            type="checkbox"
            checked={Boolean(selected)}
            onChange={onToggle}
            aria-label={`Select ${r.name}`}
            className="mt-1 h-3.5 w-3.5 shrink-0 rounded border-slate-300 text-blue-600 focus:ring-blue-500/30"
          />
        ) : null}

        <span
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-base',
            wl.tile,
          )}
          aria-hidden
        >
          {wl.glyph}
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-semibold text-slate-900">{r.name}</span>
            <span
              className={cn(
                'inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium',
                wl.badge,
              )}
            >
              {wl.label}
            </span>
            <LevelSuggestionBadge level={Number(r.suggested_level) || 3} />
            {r.suggested_diff ? (
              <span className="inline-flex items-center whitespace-nowrap rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700">
                Text diff
              </span>
            ) : (
              <span className="inline-flex items-center whitespace-nowrap rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-500">
                Hash only
              </span>
            )}
          </div>

          <p className="mt-1.5 break-all font-mono text-xs text-slate-700">{r.config_path}</p>
          <p className="mt-1.5 text-xs text-slate-500">{r.reason}</p>

          {r.status !== 'pending' ? (
            <p className="mt-2 text-[11px] font-medium text-slate-400">
              {r.status === 'applied' ? 'Rule applied' : 'Dismissed'}
            </p>
          ) : null}
        </div>

        <div className="flex shrink-0 flex-col items-end gap-2">
          {showHost ? <HostPill hostname={r.hostname || r.host_id} /> : null}
          {onApply || onDismiss ? (
            <div className="flex items-center gap-1.5">
              {onDismiss ? (
                <button
                  onClick={onDismiss}
                  disabled={busy}
                  className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] font-medium text-slate-500 transition-colors hover:bg-slate-50 hover:text-slate-700 disabled:opacity-50"
                >
                  Dismiss
                </button>
              ) : null}
              {onApply ? (
                <button
                  onClick={onApply}
                  disabled={busy}
                  className="inline-flex items-center gap-1 rounded-lg bg-blue-600 px-2.5 py-1 text-[11px] font-medium text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
                  title={`Apply as ${lvl.label}`}
                >
                  {busy ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Check className="h-3 w-3" />
                  )}
                  Accept
                </button>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </li>
  )
}

/** `Level 1 Critical` (red) / `Level 3 Drift` (amber) suggestion badge. */
function LevelSuggestionBadge({ level }: { level: number }) {
  const style = levelStyle(level)
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium',
        style.badge,
      )}
      title={`Suggested impact level: ${style.label}`}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', style.dot)} />
      {style.label}
    </span>
  )
}
