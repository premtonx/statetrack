import { useMemo, useState } from 'react'
import { ChevronDown, Filter, ScrollText, Search, User as UserIcon, X } from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill from '../ui/StatusPill'
import RoleBadge from './RoleBadge'
import { Select, TextInput } from '../ui/controls'
import { useAuditLogs } from '../../api/hooks'
import type { AuditLogEntry } from '../../types'
import { cn, formatDateTime, timeAgo } from '../../lib/utils'

/** Human sentences for the dotted action vocabulary. */
const ACTION_LABELS: Record<string, string> = {
  'auth.login': 'Signed in',
  'auth.logout': 'Signed out',
  'auth.role_switched': 'Switched role',
  'auth.2fa_enabled': 'Enabled 2FA',
  'auth.2fa_disabled': 'Disabled 2FA',
  'rule.applied': 'Applied policy rule',
  'rule.dismissed': 'Dismissed recommendation',
  'rule.watch_created': 'Added watched target',
  'rule.watch_deleted': 'Removed watched target',
  'integration.updated': 'Updated integration',
  'apikey.created': 'Created API key',
  'apikey.revoked': 'Revoked API key',
  'token.created': 'Created enrollment token',
  'agent.revoked': 'Revoked enrollment token',
  'sso.updated': 'Updated SSO configuration',
  'settings.updated': 'Updated settings',
  'host.forensic_enabled': 'Started forensic capture',
  'itsm.settings_updated': 'Updated ITSM settings',
  'itsm.tickets_synced': 'Synced change tickets',
  'itsm.ticket_recorded': 'Recorded change ticket',
  'itsm.ticket_deleted': 'Deleted change ticket',
  'ai.settings_updated': 'Updated AI provider',
}

/** Tint per action family, so a scan by color answers "what kind of change?". */
function actionTone(action: string): 'blue' | 'green' | 'amber' | 'purple' | 'red' | 'slate' {
  if (action.startsWith('auth.')) return 'slate'
  if (action.startsWith('apikey.')) return 'purple'
  if (action.startsWith('token.') || action.startsWith('agent.')) return 'blue'
  if (action.startsWith('rule.')) return 'green'
  if (action.startsWith('sso.') || action.startsWith('settings.')) return 'amber'
  if (action.startsWith('itsm.') || action.startsWith('ai.')) return 'purple'
  if (action.startsWith('integration.')) return 'blue'
  if (action.startsWith('host.')) return 'red'
  return 'slate'
}

function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action
}

/**
 * The control-plane audit trail.
 *
 * High density on purpose: a CISO reviewing "who changed what?" wants every
 * administrative action on one screen with the actor, the role, the target and
 * the source address. The detail column is expandable rather than truncated
 * because the JSONB payload is where the actual before/after lives.
 */
export default function AuditLogCard() {
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)

  const { data, isLoading } = useAuditLogs({ action, actor, limit: 200 })
  const rows = data?.audit_logs ?? []
  const actions = data?.actions ?? []

  // The actor filter is a free-text field server-side, but the client narrows
  // the already-fetched page too so typing feels instant.
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) =>
      `${r.actor_email} ${actionLabel(r.action)} ${r.action} ${r.target}`.toLowerCase().includes(q),
    )
  }, [rows, query])

  const columns: DataTableColumn<AuditLogEntry>[] = [
    {
      key: 'time',
      header: 'Timestamp',
      cell: (r) => (
        <span
          className="whitespace-nowrap font-mono text-[11px] tabular-nums text-slate-500"
          title={formatDateTime(r.occurred_at)}
        >
          {formatDateTime(r.occurred_at)}
        </span>
      ),
    },
    {
      key: 'actor',
      header: 'Actor',
      cell: (r) => (
        <span className="whitespace-nowrap font-mono text-[11px] text-slate-700">{r.actor_email}</span>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      cell: (r) => <RoleBadge role={r.actor_role} short />,
    },
    {
      key: 'action',
      header: 'Action',
      cell: (r) => (
        <StatusPill tone={actionTone(r.action)} mono={false}>
          {actionLabel(r.action)}
        </StatusPill>
      ),
    },
    {
      key: 'target',
      header: 'Target',
      className: 'max-w-[18rem]',
      cell: (r) =>
        r.target ? (
          <span className="block truncate text-xs text-slate-600" title={r.target}>
            {r.target}
          </span>
        ) : null,
    },
    {
      key: 'source',
      header: 'Source IP',
      cell: (r) => (
        <span className="whitespace-nowrap font-mono text-[11px] text-slate-500">{r.source_ip || '—'}</span>
      ),
    },
    {
      key: 'details',
      header: '',
      align: 'right',
      cell: (r) => (
        <button
          onClick={() => setExpanded((id) => (id === r.id ? null : r.id))}
          aria-label={expanded === r.id ? 'Hide details' : 'Show details'}
          className={cn(
            'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors',
            expanded === r.id
              ? 'bg-slate-200 text-slate-700'
              : 'text-slate-400 hover:bg-slate-100 hover:text-slate-600',
          )}
        >
          <ChevronDown className={cn('h-3 w-3 transition-transform', expanded === r.id && 'rotate-180')} />
          {expanded === r.id ? 'Hide' : 'Details'}
        </button>
      ),
    },
  ]

  return (
    <Card flush>
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <CardHeader
          className="min-w-0 flex-1"
          title="Control-Plane Audit Log"
          subtitle="Every administrative change, appended in order and never rewritten"
          icon={<ScrollText className="h-4 w-4" />}
        />
        <div className="flex flex-wrap items-center gap-2">
          <TextInput
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter this page…"
            icon={<Search className="h-3.5 w-3.5" />}
            wrapperClassName="w-48"
            className="h-8 text-xs"
            aria-label="Filter audit entries"
          />
          <TextInput
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            placeholder="Actor email…"
            icon={<UserIcon className="h-3.5 w-3.5" />}
            wrapperClassName="w-44"
            className="h-8 text-xs"
            aria-label="Filter by actor"
          />
          <Select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="h-8 text-xs"
            wrapperClassName="w-44"
            aria-label="Filter by action"
          >
            <option value="">All actions</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {actionLabel(a)}
              </option>
            ))}
          </Select>
        </div>
      </div>

      {/* Active server-side filters, shown as removable chips so a narrowed view
          is never mistaken for a complete one. */}
      {action || actor ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 bg-slate-50/60 px-4 py-2">
          <Filter className="h-3 w-3 text-slate-400" />
          {action ? (
            <FilterChip label={`Action: ${actionLabel(action)}`} onClear={() => setAction('')} />
          ) : null}
          {actor ? (
            <FilterChip label={`Actor: ${actor}`} onClear={() => setActor('')} />
          ) : null}
          <span className="text-[11px] text-slate-400">{filtered.length} entries</span>
        </div>
      ) : (
        <div className="flex items-center gap-2 border-b border-slate-100 px-4 py-1.5">
          <span className="text-[11px] text-slate-400">
            Newest first · {filtered.length} of the last 200 control-plane actions
          </span>
        </div>
      )}

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(r) => String(r.id)}
        loading={isLoading}
        pageSize={25}
        empty="No audit entries match the current filter."
        rowClassName={(r) => (expanded === r.id ? 'bg-blue-50/40' : undefined)}
      />

      {expanded !== null ? (
        <DetailPanel
          entry={(filtered ?? []).find((r) => r.id === expanded) ?? null}
          onClose={() => setExpanded(null)}
        />
      ) : null}
    </Card>
  )
}

function FilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[11px] text-slate-600">
      {label}
      <button
        onClick={onClear}
        aria-label={`Clear ${label}`}
        className="flex h-3.5 w-3.5 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600"
      >
        <X className="h-2.5 w-2.5" />
      </button>
    </span>
  )
}

/** Expanded JSONB detail for one audited action. */
function DetailPanel({ entry, onClose }: { entry: AuditLogEntry | null; onClose: () => void }) {
  if (!entry) return null
  const details = entry.details ?? {}
  const keys = Object.keys(details)
  return (
    <div className="border-t border-slate-200 bg-slate-50/70 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="text-xs font-semibold text-slate-700">
          {actionLabel(entry.action)}{' '}
          <span className="font-mono text-[11px] font-normal text-slate-400">{entry.action}</span>
        </p>
        <button
          onClick={onClose}
          className="text-[11px] font-medium text-slate-500 hover:text-slate-700"
        >
          Close
        </button>
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
        <DetailRow label="Occurred" value={formatDateTime(entry.occurred_at)} />
        <DetailRow label="Relative" value={timeAgo(entry.occurred_at)} />
        <DetailRow label="Actor" value={entry.actor_email} mono />
        <DetailRow label="Actor role" value={entry.actor_role} mono />
        <DetailRow label="Target" value={entry.target || '—'} />
        <DetailRow label="Source IP" value={entry.source_ip || '—'} mono />
      </dl>
      {keys.length > 0 ? (
        <div className="mt-3">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-400">
            Details
          </p>
          <pre className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 font-mono text-[11px] leading-relaxed text-slate-200">
            {JSON.stringify(details, null, 2)}
          </pre>
        </div>
      ) : null}
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-24 shrink-0 text-[11px] text-slate-400">{label}</dt>
      <dd className={cn('min-w-0 truncate text-xs text-slate-700', mono && 'font-mono')}>{value}</dd>
    </div>
  )
}
