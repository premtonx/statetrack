import { useMemo, useState } from 'react'
import {
  AlertTriangle,
  BarChart3,
  Download,
  FileSpreadsheet,
  FileText,
  ShieldCheck,
  ShieldX,
  Ticket,
} from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill, { LevelPill } from '../ui/StatusPill'
import { Button, Select } from '../ui/controls'
import BarSeries from '../charts/BarSeries'
import PostMortemModal from '../Inspector/PostMortemModal'
import { ChangeTicketBadge, ComplianceBadge } from '../Compliance/ChangeControlBadge'
import { COMPLIANCE_FILTER_OPTIONS, complianceStyle } from '../../lib/labels'
import { cn, formatDateTime } from '../../lib/utils'
import type { Compliance, ComplianceEvent } from '../../types'

/**
 * The change-control report: every change with its ITSM verdict, filterable to
 * the exceptions an auditor is looking for.
 *
 * A separate tab from the timeline on purpose. The timeline answers "what
 * happened"; this answers "what was *not* approved", which is a different query
 * with a different default — the unauthorised filter is pre-applied, because a
 * reviewer opening this tab is looking for exceptions, not for the fleet's
 * total change volume.
 *
 * Deliberately presentational: the page owns the filter state and the query, so
 * the tab's exception count and the table below it read the same response. A
 * component that fetched its own data could badge "3 exceptions" while showing
 * a table filtered to approved changes.
 *
 * Verdicts are computed server-side per request, never stored. A ticket raised
 * retroactively for last night's incident changes the verdict on the historical
 * event, and that is correct: the report reflects the change calendar as it
 * stands today, and a persisted decision would go stale the moment a ticket is
 * edited.
 */
export default function ComplianceReport({
  events,
  counts,
  enforced,
  isFallback,
  isLoading,
  verdict,
  onVerdictChange,
  hostFilter,
  onHostFilterChange,
  onOpenEvent,
}: {
  events: ComplianceEvent[]
  counts: Record<Compliance, number>
  /** False when enforcement is off: the verdicts are advisory, not actionable. */
  enforced: boolean
  isFallback: boolean
  isLoading: boolean
  verdict: Compliance | ''
  onVerdictChange: (v: Compliance | '') => void
  hostFilter: string
  onHostFilterChange: (h: string) => void
  onOpenEvent: (id: string) => void
}) {
  const [preview, setPreview] = useState<ComplianceEvent | null>(null)
  const [generatedAt, setGeneratedAt] = useState<string | null>(null)

  const rows = events ?? []

  // The host dropdown is built from the current result set rather than the
  // host inventory: an option that yields an empty table is worse than no
  // option, and these rows are already scoped to the reporting window.
  const hosts = useMemo(() => {
    const out = new Set<string>()
    for (const e of rows) out.add(e.hostname || e.host_id)
    return [...out].sort()
  }, [rows])

  const columns: DataTableColumn<ComplianceEvent>[] = useMemo(
    () => [
      {
        key: 'time',
        header: 'Time',
        cell: (e) => (
          <span className="whitespace-nowrap font-mono text-xs tabular-nums text-slate-500">
            {formatDateTime(e.occurred_at)}
          </span>
        ),
      },
      {
        key: 'level',
        header: 'Level',
        cell: (e) => <LevelPill level={e.impact_level} short />,
      },
      {
        key: 'host',
        header: 'Server',
        cell: (e) => (
          <span className="font-mono text-xs text-slate-600">{e.hostname || e.host_id}</span>
        ),
      },
      {
        key: 'target',
        header: 'Target',
        className: 'max-w-[20rem]',
        cell: (e) => (
          <span className="block truncate font-mono text-xs text-slate-700" title={e.path_or_key}>
            {e.path_or_key || e.summary}
          </span>
        ),
      },
      {
        key: 'actor',
        header: 'Actor',
        cell: (e) => (
          <span className="font-mono text-xs text-slate-600">{e.actor_username || '—'}</span>
        ),
      },
      {
        key: 'verdict',
        header: 'Change Control',
        cell: (e) => (
          <div className="flex flex-col items-start gap-1">
            <ComplianceBadge compliance={e.compliance} reason={e.compliance_reason} />
            {e.ticket_ref ? (
              <ChangeTicketBadge ref={e.ticket_ref} status={e.ticket_status} />
            ) : null}
          </div>
        ),
      },
      {
        key: 'actions',
        header: '',
        align: 'right',
        cell: (e) => (
          <div className="flex items-center justify-end gap-1">
            <button
              onClick={(ev) => {
                // Stops the row's own click from also opening the inspector:
                // the two affordances lead to different places, and the
                // post-mortem is the more expensive one to lose.
                ev.stopPropagation()
                onOpenEvent(e.id)
              }}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
            >
              Inspect
            </button>
            <button
              onClick={(ev) => {
                ev.stopPropagation()
                setPreview(e)
              }}
              title="Compile the incident post-mortem bundle for this change"
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
            >
              <FileText className="h-3 w-3" />
              Post-mortem
            </button>
          </div>
        ),
      },
    ],
    [onOpenEvent],
  )

  const download = (name: string, content: string, type: string) => {
    const blob = new Blob([content], { type })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
    URL.revokeObjectURL(a.href)
    setGeneratedAt(new Date().toISOString())
  }

  /**
   * CSV of the findings — the artefact an auditor actually asks for.
   *
   * Every field is quoted and internal quotes are doubled, because the
   * `reason` column is prose that routinely contains commas and the ticket
   * summaries contain quotes. An unescaped value there silently shifts every
   * subsequent column in the consumer's spreadsheet.
   */
  const csv = () => {
    const header = 'time,host,actor,level,target,verdict,ticket,reason'
    const quote = (v: string) => `"${(v ?? '').replace(/"/g, '""')}"`
    const body = rows
      .map((e) =>
        [
          e.occurred_at,
          e.hostname || e.host_id,
          e.actor_username ?? '',
          `L${e.impact_level}`,
          e.path_or_key,
          complianceStyle(e.compliance).label,
          e.ticket_ref ?? '',
          e.compliance_reason ?? '',
        ]
          .map(quote)
          .join(','),
      )
      .join('\n')
    return `${header}\n${body}`
  }

  const exceptions = counts.unapproved + counts.expired

  return (
    <div className="space-y-5">
      {/* Verdict summary — the four outcomes in the order a reviewer triages
          them: violations first, then the two benign verdicts. */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <VerdictCard
          label="Unauthorised Changes"
          value={counts.unapproved}
          tone="red"
          icon={<ShieldX className="h-4 w-4" />}
          hint="No approved ticket covers these"
        />
        <VerdictCard
          label="Expired Windows"
          value={counts.expired}
          tone="amber"
          icon={<AlertTriangle className="h-4 w-4" />}
          hint="Ticket exists but its window had closed"
        />
        <VerdictCard
          label="Authorised Changes"
          value={counts.approved}
          tone="green"
          icon={<ShieldCheck className="h-4 w-4" />}
          hint="Matched to an approved change request"
        />
        <VerdictCard
          label="No Ticket Required"
          value={counts.not_required}
          tone="slate"
          icon={<Ticket className="h-4 w-4" />}
          hint="Below the enforcement threshold"
        />
      </div>

      {!enforced && !isFallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
          <span>
            Change-ticket enforcement is off, so these verdicts are advisory. Enable it under{' '}
            <span className="font-medium">Integrations → Change Management</span> to make them
            actionable.
          </span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <Card flush>
          <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
            <CardHeader
              className="min-w-0 flex-1"
              title="Change-Control Report"
              subtitle="Every change with its ITSM verdict — the default filter shows only exceptions"
              icon={<ShieldCheck className="h-4 w-4" />}
            />
            <div className="flex flex-wrap items-center gap-2">
              {isFallback ? (
                <StatusPill tone="amber" dot>
                  Preview data
                </StatusPill>
              ) : null}
              <StatusPill tone={exceptions > 0 ? 'red' : 'green'} dot>
                {exceptions} exception{exceptions === 1 ? '' : 's'}
              </StatusPill>
              <div className="w-48">
                <Select
                  aria-label="Verdict filter"
                  value={verdict}
                  onChange={(e) => onVerdictChange(e.target.value as Compliance | '')}
                >
                  {COMPLIANCE_FILTER_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="w-44">
                <Select
                  aria-label="Host filter"
                  value={hostFilter}
                  onChange={(e) => onHostFilterChange(e.target.value)}
                >
                  <option value="">All servers</option>
                  {hosts.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </Select>
              </div>
              <Button
                size="sm"
                icon={<FileSpreadsheet className="h-3.5 w-3.5" />}
                disabled={rows.length === 0}
                onClick={() =>
                  download(`statetrack-change-control-${verdict || 'all'}.csv`, csv(), 'text/csv')
                }
              >
                Export CSV
              </Button>
            </div>
          </div>

          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(e) => e.id}
            loading={isLoading}
            pageSize={12}
            empty={
              verdict === 'unapproved'
                ? 'No unauthorised production changes in this window.'
                : 'No changes match the selected filter.'
            }
          />

          {generatedAt ? (
            <p className="flex items-center gap-1.5 border-t border-slate-100 px-4 py-2 text-xs text-emerald-700">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-600" />
              Export generated {formatDateTime(generatedAt)}
            </p>
          ) : null}
        </Card>

        <div className="space-y-5">
          <Card>
            <CardHeader
              title="Verdict Breakdown"
              subtitle="Share of changes by change-control outcome"
              icon={<BarChart3 className="h-4 w-4" />}
            />
            <BarSeries
              className="mt-4"
              data={(['unapproved', 'expired', 'approved', 'not_required'] as Compliance[]).map(
                (c) => ({
                  label: complianceStyle(c).label,
                  value: counts[c],
                  color: COMPLIANCE_CHART_HEX[c],
                }),
              )}
            />
            <p className="mt-4 border-t border-slate-100 pt-3 text-[11px] leading-relaxed text-slate-400">
              Scope is matched on each ticket&apos;s hosts, environments and path globs, within its
              authorised window plus the configured grace period.
            </p>
          </Card>

          <Card>
            <CardHeader
              title="What This Report Proves"
              subtitle="The audit trail this view is designed to produce"
              icon={<Download className="h-4 w-4" />}
            />
            <ul className="mt-3 space-y-2 text-[11px] leading-relaxed text-slate-600">
              {[
                'Which production changes had no approved change request behind them.',
                'Which changes cited a ticket that was rejected, cancelled or still awaiting approval.',
                'Which changes ran outside the authorised window of an otherwise valid ticket.',
                'Which ticket authorised each covered change, with a link to the ITSM record.',
                'A CSV of the above for offline review, plus a Markdown post-mortem per incident.',
              ].map((line) => (
                <li key={line} className="flex gap-2">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-400" />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>

      {preview ? (
        <PostMortemModal
          eventId={preview.id}
          eventSummary={`${preview.path_or_key || preview.summary} · ${
            preview.hostname || preview.host_id
          }`}
          onClose={() => setPreview(null)}
        />
      ) : null}
    </div>
  )
}

/** Chart colours keyed by verdict, matching the badge semantics in labels.ts. */
const COMPLIANCE_CHART_HEX: Record<Compliance, string> = {
  unapproved: '#d93025',
  expired: '#f9ab00',
  approved: '#1e8e3e',
  not_required: '#94a3b8',
}

const TONES = {
  red: 'text-red-600',
  amber: 'text-amber-600',
  green: 'text-emerald-600',
  slate: 'text-slate-500',
} as const

function VerdictCard({
  label,
  value,
  tone,
  icon,
  hint,
}: {
  label: string
  value: number
  tone: keyof typeof TONES
  icon: React.ReactNode
  hint: string
}) {
  return (
    <Card>
      <div className="flex items-start gap-3">
        <span
          className={cn(
            'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-50',
            TONES[tone],
          )}
        >
          {icon}
        </span>
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-wide text-slate-400">{label}</p>
          <p className="mt-0.5 text-2xl font-semibold tabular-nums text-slate-900">{value}</p>
          <p className="mt-0.5 truncate text-[11px] text-slate-500" title={hint}>
            {hint}
          </p>
        </div>
      </div>
    </Card>
  )
}
