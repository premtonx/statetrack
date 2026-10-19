import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ArrowLeftRight,
  Check,
  Copy,
  ExternalLink,
  FileDiff,
  FileText,
  Fingerprint,
  GitBranch,
  Hash,
  PanelRight,
  Ruler,
  ShieldAlert,
  X,
  Zap,
} from 'lucide-react'
import { useEventCompliance, useEventDetail } from '../../api/hooks'
import type { Event } from '../../types'
import { useConsole } from '../../lib/consoleContext'
import {
  cn,
  formatBytes,
  formatFull,
  formatNumber,
  shortHash,
  timeAgo,
} from '../../lib/utils'
import { actionName, categoryStyle, parseLineDiff, levelStyle } from '../../lib/labels'
import LineageBar from './LineageBar'
import DiffViewer from './DiffViewer'
import PostMortemModal from './PostMortemModal'
import AnalyzePanel from './AnalyzePanel'
import { HostPill } from '../Timeline/HostPill'
import RuleBadge from '../Recommendations/RuleBadge'
import { ChangeControlBadge } from '../Compliance/ChangeControlBadge'
import { Tabs, type TabItem } from '../ui/controls'
import StatusPill, { CategoryTag, LevelPill } from '../ui/StatusPill'
import type { EventTab } from '../../lib/router'

type InspectorTab = EventTab

interface InspectorDrawerProps {
  eventId: string
  /** Tab to open on mount (from `?tab=` deep links, e.g. the `</> Diff` action). */
  initialTab?: EventTab | null
  onClose?: () => void
}

function MetaRow({
  label,
  value,
  icon,
  mono = true,
}: {
  label: string
  value?: string | number | null
  icon?: React.ReactNode
  mono?: boolean
}) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="flex items-start gap-2.5 py-2">
      {icon ? <span className="mt-0.5 shrink-0 text-slate-400">{icon}</span> : null}
      <span className="min-w-0 flex-1 text-xs text-slate-500">{label}</span>
      <span
        className={cn(
          'max-w-[60%] break-all text-right text-xs text-slate-800',
          mono && 'font-mono',
        )}
      >
        {value}
      </span>
    </div>
  )
}

/** Splits a unified diff to derive the changed-line counts. */
function diffStats(diff?: string): { added: number; removed: number } {
  if (!diff) return { added: 0, removed: 0 }
  let added = 0
  let removed = 0
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++') || line.startsWith('---')) continue
    if (line.startsWith('+')) added++
    else if (line.startsWith('-')) removed++
  }
  return { added, removed }
}

function RelatedList({ events, onOpen }: { events: Event[]; onOpen: (id: string) => void }) {
  const list = events ?? []
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Related changes
        </h3>
        <StatusPill tone="slate">{list.length}</StatusPill>
      </div>
      {list.length === 0 ? (
        <p className="rounded-lg border border-dashed border-slate-200 px-3 py-6 text-center text-xs text-slate-400">
          No related events recorded for this change.
        </p>
      ) : (
        <ul className="divide-y divide-slate-100 overflow-hidden rounded-lg border border-slate-200">
          {list.map((c) => (
            <li key={c.id}>
              <button
                onClick={() => onOpen(c.id)}
                className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-slate-50"
              >
                <LevelPill level={c.impact_level} short />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-xs text-slate-800">
                    {c.path_or_key}
                  </span>
                  <span className="block truncate text-[11px] text-slate-400">{c.summary}</span>
                </span>
                <span className="shrink-0 font-mono text-[11px] text-slate-400">
                  {timeAgo(c.occurred_at)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * Slide-over inspector: header context, tabbed body, a side-by-side Monaco
 * diff and a right-hand metadata sidebar with hashes, sizes and line counts.
 */
export default function InspectorDrawer({ eventId, initialTab, onClose }: InspectorDrawerProps) {
  const { closeEvent, openEvent } = useConsole()
  const { data, isLoading, isError } = useEventDetail(eventId)
  const compliance = useEventCompliance(eventId)
  const [tab, setTab] = useState<InspectorTab>(initialTab ?? 'diff')
  const [copied, setCopied] = useState(false)
  const [exporting, setExporting] = useState(false)

  // A new deep link (e.g. clicking `</> Diff` on another row) must retarget the
  // open drawer rather than leave it on the previous event's tab.
  useEffect(() => {
    if (initialTab) setTab(initialTab)
  }, [initialTab, eventId])

  const event = data
  const verdict = compliance.data?.verdict
  const level = event ? levelStyle(event.impact_level) : levelStyle(3)
  const lines = useMemo(
    () => (event ? (parseLineDiff(event.summary) ?? diffStats(event.diff)) : { added: 0, removed: 0 }),
    [event],
  )
  const category = event ? categoryStyle(event.category) : undefined

  const close = useCallback(() => {
    if (onClose) onClose()
    else closeEvent()
  }, [onClose, closeEvent])

  // Escape closes the drawer, matching the footer hint.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [close])

  const tabs: TabItem<InspectorTab>[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'diff', label: 'Diff' },
    { id: 'analyze', label: '✦ Analyze & Rollback' },
    { id: 'actor', label: 'Actor Tree' },
    { id: 'related', label: 'Related Events', count: event?.children?.length ?? 0 },
  ]

  const copyDiff = () => {
    if (!event?.diff) return
    void navigator.clipboard?.writeText(event.diff)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Event inspector">
      <div className="drawer-backdrop absolute inset-0 bg-slate-900/30" onClick={close} aria-hidden />

      <div className="drawer-enter absolute inset-y-0 right-0 flex w-full max-w-6xl flex-col border-l border-slate-200 bg-white shadow-2xl">
        {isLoading ? (
          <div className="flex flex-1 items-center justify-center text-sm text-slate-400">
            Loading event…
          </div>
        ) : null}

        {isError ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2">
            <p className="text-sm font-medium text-red-600">Failed to load event</p>
            <p className="font-mono text-xs text-slate-400">{eventId}</p>
            <button
              onClick={close}
              className="mt-2 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50"
            >
              Close
            </button>
          </div>
        ) : null}

        {event ? (
          <>
            {/* Header */}
            <div className="flex items-start gap-3 border-b border-slate-200 px-5 py-4">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <LevelPill level={event.impact_level} />
                  {category ? <CategoryTag category={event.category} /> : null}
                  <RuleBadge event={event} />
                  <ChangeControlBadge
                    compliance={verdict?.compliance}
                    reason={verdict?.compliance_reason}
                    ticketRef={verdict?.ticket_ref}
                    ticketStatus={verdict?.ticket_status}
                  />
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
                    <ShieldAlert className="h-3 w-3" />
                    Verified agent report
                  </span>
                </div>
                <h2 className="mt-2 flex min-w-0 items-baseline gap-2">
                  <span className="shrink-0 text-[11px] font-bold uppercase tracking-wide text-slate-500">
                    {actionName(event.action)}
                  </span>
                  <span className="truncate font-mono text-sm font-semibold text-slate-900">
                    {event.path_or_key}
                  </span>
                </h2>
                <p className="mt-1 truncate text-xs text-slate-500">{event.summary}</p>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                  <span className="font-mono">{formatFull(event.occurred_at)}</span>
                  <HostPill hostname={event.hostname || event.host_id} />
                  <span>
                    actor{' '}
                    <span className="font-medium text-slate-700">
                      {event.actor_username || 'unknown'}
                    </span>
                  </span>
                  {event.process_name ? (
                    <span>
                      via <span className="font-mono text-slate-700">{event.process_name}</span>
                    </span>
                  ) : null}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  onClick={() => setExporting(true)}
                  title="Compile a downloadable incident post-mortem (Markdown or JSON)"
                  className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
                >
                  <FileText className="h-3.5 w-3.5" />
                  Export Post-Mortem
                </button>
                <button
                  onClick={close}
                  aria-label="Close inspector"
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Tabs */}
            <div className="px-5">
              <Tabs tabs={tabs} active={tab} onChange={setTab} />
            </div>

            {/* Body */}
            <div className="min-h-0 flex-1 overflow-y-auto">
              <div
                className={cn(
                  'grid grid-cols-1 gap-5 p-5',
                  // The analyzer's output is prose plus monospace commands, so it
                  // reads better full-width than squeezed beside the metadata rail.
                  tab !== 'analyze' && 'xl:grid-cols-[minmax(0,1fr)_16rem]',
                )}
              >
                <div className="min-w-0 space-y-5">
                  {tab === 'overview' ? (
                    <>
                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                        {[
                          { label: 'Impact', value: level.label, tone: level.hex },
                          { label: 'Target type', value: event.target_type || '—', tone: '#475569' },
                          { label: 'Lines changed', value: `+${lines.added} −${lines.removed}`, tone: '#1e8e3e' },
                          {
                            label: 'Source',
                            value: event.diff_source === 's3' ? 'S3 blob' : event.has_diff ? 'inline' : 'metadata',
                            tone: '#1a73e8',
                          },
                        ].map((s) => (
                          <div
                            key={s.label}
                            className="rounded-lg border border-slate-200 bg-slate-50/50 px-3 py-2"
                          >
                            <p className="text-[10px] uppercase tracking-wide text-slate-400">
                              {s.label}
                            </p>
                            <p
                              className="mt-0.5 truncate text-xs font-semibold"
                              style={{ color: s.tone }}
                            >
                              {s.value}
                            </p>
                          </div>
                        ))}
                      </div>

                      <LineageBar event={event} />

                      {event.metadata?.rule_name ? (
                        <div className="rounded-lg border border-blue-200 bg-blue-50/50">
                          <div className="flex items-center gap-2 border-b border-blue-100 px-3 py-2">
                            <Zap className="h-3.5 w-3.5 text-blue-600" />
                            <h3 className="text-xs font-semibold uppercase tracking-wide text-blue-700">
                              Matched policy rule
                            </h3>
                          </div>
                          <div className="divide-y divide-blue-100 px-3">
                            <MetaRow
                              label="Rule name"
                              value={event.metadata.rule_name}
                              mono={false}
                            />
                            <MetaRow label="Applied level" value={level.label} mono={false} />
                            <MetaRow
                              label="Diff policy"
                              value={event.has_diff ? 'text diff' : 'hash only'}
                              mono={false}
                            />
                            {event.metadata.rule_tags ? (
                              <MetaRow
                                label="Tags"
                                value={event.metadata.rule_tags.split(',').join(', ')}
                                mono={false}
                              />
                            ) : null}
                            <MetaRow
                              label="Verdict"
                              value={event.metadata.classification}
                              mono={false}
                            />
                          </div>
                        </div>
                      ) : null}

                      <div className="rounded-lg border border-slate-200">
                        <div className="border-b border-slate-200 bg-slate-50/70 px-3 py-2">
                          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                            Target state
                          </h3>
                        </div>
                        <div className="divide-y divide-slate-100 px-3">
                          <MetaRow
                            label="Path / key"
                            value={event.path_or_key}
                            icon={<GitBranch className="h-3.5 w-3.5" />}
                          />
                          <MetaRow
                            label="Hash before"
                            value={shortHash(event.hash_before)}
                            icon={<Hash className="h-3.5 w-3.5" />}
                          />
                          <MetaRow
                            label="Hash after"
                            value={shortHash(event.hash_after)}
                            icon={<Hash className="h-3.5 w-3.5" />}
                          />
                          <MetaRow label="Version before" value={event.version_before} />
                          <MetaRow label="Version after" value={event.version_after} />
                          <MetaRow label="Remote IP" value={event.remote_ip} icon={<ExternalLink className="h-3.5 w-3.5" />} />
                        </div>
                      </div>
                    </>
                  ) : null}

                  {tab === 'diff' ? (
                    event.has_diff && event.diff ? (
                      <DiffViewer
                        diff={event.diff}
                        pathOrKey={event.path_or_key}
                        targetType={event.target_type}
                        modelKey={event.id}
                        height={620}
                      />
                    ) : (
                      <div className="rounded-lg border border-dashed border-slate-200 px-4 py-12 text-center">
                        <FileDiff className="mx-auto h-5 w-5 text-slate-300" />
                        <p className="mt-2 text-sm font-medium text-slate-500">
                          No text diff recorded
                        </p>
                        <p className="mt-1 text-xs text-slate-400">
                          {event.impact_level === 3
                            ? 'Level 3 drift stores metadata and hashes only.'
                            : 'This event changed metadata, not file contents.'}
                        </p>
                      </div>
                    )
                  ) : null}

                  {tab === 'analyze' ? <AnalyzePanel eventId={event.id} /> : null}

                  {tab === 'actor' ? <LineageBar event={event} /> : null}

                  {tab === 'related' ? (
                    <RelatedList
                      events={event.children ?? []}
                      onOpen={(id) => openEvent(id)}
                    />
                  ) : null}
                </div>

                {/* Metadata sidebar. Hidden on the analyzer tab, which uses the
                    full width for prose and commands. */}
                {tab === 'analyze' ? null : (
                <aside className="order-first space-y-4 xl:order-last">
                  <div className="rounded-lg border border-slate-200">
                    <div className="flex items-center gap-2 border-b border-slate-200 bg-slate-50/70 px-3 py-2">
                      <PanelRight className="h-3.5 w-3.5 text-slate-400" />
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                        Metadata
                      </h3>
                    </div>
                    <div className="divide-y divide-slate-100 px-3">
                      <MetaRow label="Type" value={event.target_type || '—'} mono={false} />
                      <MetaRow label="Category" value={category?.label} mono={false} />
                      <MetaRow
                        label="Lines added"
                        value={`+${lines.added}`}
                        icon={<Ruler className="h-3.5 w-3.5" />}
                      />
                      <MetaRow
                        label="Lines removed"
                        value={`−${lines.removed}`}
                        icon={<Ruler className="h-3.5 w-3.5" />}
                      />
                      <MetaRow label="Size before" value={formatBytes(event.file_size_before)} mono={false} />
                      <MetaRow label="Size after" value={formatBytes(event.file_size_after)} mono={false} />
                      <MetaRow label="PID" value={event.pid ? formatNumber(event.pid) : undefined} />
                      <MetaRow label="Parent PID" value={event.ppid ? formatNumber(event.ppid) : undefined} />
                      <MetaRow
                        label="Actor SID"
                        value={event.actor_sid}
                        icon={<Fingerprint className="h-3.5 w-3.5" />}
                      />
                      <MetaRow label="Login UID" value={event.login_uid} />
                      <MetaRow label="Child events" value={formatNumber(event.child_count)} mono={false} />
                    </div>
                  </div>

                  {event.cmdline ? (
                    <div className="rounded-lg border border-slate-200 bg-slate-900 px-3 py-2.5">
                      <p className="mb-1 text-[10px] uppercase tracking-wide text-slate-400">
                        Command line
                      </p>
                      <p className="break-all font-mono text-[11px] leading-relaxed text-slate-100">
                        $ {event.cmdline}
                      </p>
                    </div>
                  ) : null}

                  {event.metadata && Object.keys(event.metadata).length > 0 ? (
                    <div className="rounded-lg border border-slate-200">
                      <div className="border-b border-slate-200 bg-slate-50/70 px-3 py-2">
                        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                          Agent metadata
                        </h3>
                      </div>
                      <div className="divide-y divide-slate-100 px-3">
                        {Object.entries(event.metadata ?? {}).map(([k, v]) => (
                          <MetaRow key={k} label={k} value={v} mono={false} />
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <button
                    onClick={copyDiff}
                    disabled={!event.diff}
                    className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 disabled:opacity-40"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? 'Copied' : 'Copy Diff'}
                  </button>
                </aside>
                )}
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center gap-3 border-t border-slate-200 bg-slate-50/60 px-5 py-2.5 text-[11px] text-slate-500">
              <Activity className="h-3.5 w-3.5 text-emerald-600" />
              Event id <span className="font-mono text-slate-700">{event.id}</span>
              <span className="ml-auto flex items-center gap-3">
                <span className="flex items-center gap-1">
                  <ArrowLeftRight className="h-3 w-3" /> side-by-side diff
                </span>
                <span>Esc closes</span>
              </span>
            </div>
          </>
        ) : null}
      </div>

      {exporting && event ? (
        <PostMortemModal
          eventId={event.id}
          eventSummary={event.summary}
          onClose={() => setExporting(false)}
        />
      ) : null}
    </div>
  )
}
