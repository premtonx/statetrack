import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  FileText,
  RefreshCw,
  ShieldAlert,
  Ticket,
} from 'lucide-react'
import Card from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import { Button, SegmentedControl } from '../ui/controls'
import { ComplianceBadge } from '../Compliance/ChangeControlBadge'
import { postMortemDownloadUrl } from '../../api/client'
import { usePostMortem } from '../../api/hooks'
import { copyText } from '../../lib/clipboard'
import { cn, formatDateTime } from '../../lib/utils'

type ExportFormat = 'md' | 'json'
type IncidentWindow = '15m' | '30m' | '1h' | '4h'

const WINDOWS: { id: IncidentWindow; label: string }[] = [
  { id: '15m', label: '±15m' },
  { id: '30m', label: '±30m' },
  { id: '1h', label: '±1h' },
  { id: '4h', label: '±4h' },
]

/**
 * The 1-click "War Room Export" preview.
 *
 * Assembling the bundle server-side is the whole feature: the operator's
 * alternative is an hour of copy-paste across six tabs, done after the
 * incident, which means done badly or not at all. This dialog is therefore a
 * preview of a *document*, not a report builder — the Markdown shown here is
 * byte-identical to what the download produces, because both come from the
 * same response.
 *
 * The dialog renders above the inspector drawer (z-[70] vs the drawer's z-50)
 * rather than replacing it, so an operator keeps the event context behind it.
 */
export default function PostMortemModal({
  eventId,
  eventSummary,
  onClose,
}: {
  eventId: string
  /** Dialog subtitle, so the operator can confirm the target at a glance. */
  eventSummary?: string
  onClose: () => void
}) {
  const [range, setRange] = useState<IncidentWindow>('30m')
  const [format, setFormat] = useState<ExportFormat>('md')
  const [copied, setCopied] = useState(false)

  // Only fetched while the dialog is open (`enabled`): assembling a bundle
  // touches the ticket set, the audit trail and the monitoring config, which is
  // far more work than an operator's triage clicks should cost.
  const query = usePostMortem(eventId, range, true)
  const bundle = query.data

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // Capture phase + stopPropagation: without it the inspector drawer's
        // own Escape handler also fires and closes the drawer underneath,
        // losing the operator's place in the incident.
        e.stopPropagation()
        onClose()
      }
    }
    globalThis.addEventListener('keydown', onKey, true)
    return () => globalThis.removeEventListener('keydown', onKey, true)
  }, [onClose])

  useEffect(() => {
    if (!copied) return
    const t = globalThis.setTimeout(() => setCopied(false), 1600)
    return () => globalThis.clearTimeout(t)
  }, [copied])

  const markdown = bundle?.markdown ?? ''
  const json = useMemo(() => (bundle ? JSON.stringify(bundle, null, 2) : ''), [bundle])
  const body = format === 'md' ? markdown : json

  const handleCopy = async () => {
    // Only meaningful for Markdown, but the label and the button are shared:
    // copying the JSON form is still useful, so it copies whichever tab is up.
    if (!body) return
    setCopied(await copyText(body))
  }

  const downloadName = `statetrack-postmortem-${slug(
    bundle?.event?.host || 'unknown-host',
  )}-${eventId.slice(0, 8)}.${format}`

  const timelineCount = bundle?.timeline?.length ?? 0
  const auditCount = bundle?.control_plane?.length ?? 0

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto p-4 sm:items-center">
      <div
        className="drawer-backdrop absolute inset-0 bg-slate-900/40"
        onClick={onClose}
        aria-hidden
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-label="Incident post-mortem bundle"
        className="panel-enter relative my-auto flex max-h-[90vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl"
      >
        {/* Header */}
        <div className="flex items-start gap-3 border-b border-slate-200 px-5 py-4">
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-600">
            <FileText className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-sm font-semibold text-slate-900">
              Incident Post-Mortem Bundle
            </h2>
            <p className="mt-0.5 truncate text-xs text-slate-500">
              {eventSummary ||
                'Compiled report with scrubbed diff, lineage, timeline and rollback plan'}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {bundle?.compliance ? (
              <ComplianceBadge compliance={bundle.compliance} reason={bundle.compliance_reason} />
            ) : null}
            <StatusPill tone="slate" mono>
              {bundle ? `bundle v${bundle.version}` : '—'}
            </StatusPill>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-100 bg-slate-50/60 px-5 py-2.5">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
            Incident window
          </span>
          <SegmentedControl options={WINDOWS} value={range} onChange={setRange} />

          <div className="ml-auto flex flex-wrap items-center gap-2">
            <SegmentedControl
              options={[
                { id: 'md' as ExportFormat, label: 'Markdown' },
                { id: 'json' as ExportFormat, label: 'JSON' },
              ]}
              value={format}
              onChange={setFormat}
            />
            <Button
              size="sm"
              icon={copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              disabled={!body}
              onClick={() => void handleCopy()}
            >
              {copied ? 'Copied' : 'Copy Markdown'}
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon={<Download className="h-3.5 w-3.5" />}
              disabled={!bundle}
              onClick={() => downloadBundle(eventId, format, range, downloadName)}
            >
              Download .{format}
            </Button>
          </div>
        </div>

        {/* Summary strip */}
        {bundle ? (
          <div className="grid grid-cols-2 gap-2 border-b border-slate-100 px-5 py-2.5 sm:grid-cols-4">
            <Fact label="Severity" value={bundle.event?.level_label || '—'} />
            <Fact
              label="Rule"
              value={bundle.event?.rule_name || bundle.event?.classification || 'unmatched'}
            />
            <Fact
              label="Window"
              value={`${bundle.window?.label || ''} · ${timelineCount} change${
                timelineCount === 1 ? '' : 's'
              }`}
            />
            <Fact label="Audit actions" value={`${auditCount} recorded`} />
          </div>
        ) : null}

        {/* Body */}
        <div className="min-h-0 flex-1 overflow-y-auto bg-slate-50/40 px-5 py-4">
          {query.isLoading ? (
            <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-10 text-sm text-slate-500">
              <RefreshCw className="h-4 w-4 animate-spin" />
              Assembling the incident bundle…
            </div>
          ) : null}

          {query.isError ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-3 text-xs text-red-800">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div className="min-w-0">
                <div className="font-medium">Could not assemble the post-mortem</div>
                <div className="break-words">
                  {query.error instanceof Error ? query.error.message : 'Request failed'}
                </div>
              </div>
            </div>
          ) : null}

          {bundle ? (
            <div className="space-y-3">
              {bundle.diff_redacted ? (
                <Notice tone="amber" icon={<ShieldAlert className="h-3.5 w-3.5" />}>
                  Secret-looking values in the diff were replaced with deterministic
                  <span className="mx-1 font-mono">[REDACTED:sha256:…]</span>
                  stubs at the agent, before the change ever left the host.
                </Notice>
              ) : null}

              {bundle.change_ticket ? (
                <Notice tone="blue" icon={<Ticket className="h-3.5 w-3.5" />}>
                  Correlated to{' '}
                  <span className="font-mono font-semibold">{bundle.change_ticket.ref}</span>
                  {bundle.change_ticket.status_label
                    ? ` · ${bundle.change_ticket.status_label}`
                    : ''}
                  {bundle.change_ticket.url ? (
                    <a
                      href={bundle.change_ticket.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="ml-2 font-medium underline"
                    >
                      Open ticket
                    </a>
                  ) : null}
                </Notice>
              ) : null}

              <Card flush>
                <pre
                  className={cn(
                    'max-h-[46vh] overflow-auto px-4 py-3 font-mono text-[11px] leading-relaxed text-slate-700',
                    format === 'md' && 'whitespace-pre-wrap',
                  )}
                >
                  {body}
                </pre>
              </Card>

              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 px-1 text-[11px] text-slate-400">
                <span>
                  Generated {bundle.generated_at ? formatDateTime(bundle.generated_at) : '—'}
                  {bundle.generated_by ? ` by ${bundle.generated_by}` : ''}
                </span>
                {bundle.incident_console_url ? (
                  <a
                    href={bundle.incident_console_url}
                    className="font-medium text-blue-700 hover:underline"
                  >
                    Reopen this event
                  </a>
                ) : null}
                {bundle.monitoring?.grafana_annotation_url ? (
                  <a
                    href={bundle.monitoring.grafana_annotation_url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="font-medium text-blue-700 hover:underline"
                  >
                    Grafana annotation window
                  </a>
                ) : null}
              </p>
            </div>
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-slate-200 bg-slate-50/70 px-5 py-3">
          <span className="text-[11px] text-slate-400">
            Markdown pastes straight into Jira, Confluence, Notion or a GitHub issue.
          </span>
          <Button size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Triggers the download through an anchor rather than a fetch + blob.
 *
 * The filename then comes from the server's own Content-Disposition header,
 * which is the same file an operator gets by opening the URL directly — one
 * naming rule instead of two.
 */
function downloadBundle(
  eventId: string,
  format: ExportFormat,
  range: IncidentWindow,
  fallbackName: string,
) {
  const a = document.createElement('a')
  a.href = postMortemDownloadUrl(eventId, format, range)
  a.download = fallbackName
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
}

function slug(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, '-')
}

function Notice({
  tone,
  icon,
  children,
}: {
  tone: 'amber' | 'blue'
  icon: React.ReactNode
  children: React.ReactNode
}) {
  const styles =
    tone === 'amber'
      ? 'border-amber-200 bg-amber-50 text-amber-800'
      : 'border-blue-200 bg-blue-50/60 text-blue-800'
  return (
    <div className={cn('flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2 text-[11px]', styles)}>
      <span className="shrink-0">{icon}</span>
      <span className="min-w-0">{children}</span>
    </div>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">{label}</p>
      <p
        className={cn('mt-0.5 truncate text-xs text-slate-700', mono && 'font-mono')}
        title={value}
      >
        {value}
      </p>
    </div>
  )
}