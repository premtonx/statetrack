import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  Clock,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Ticket,
  Trash2,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, SectionTitle } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill from '../ui/StatusPill'
import { Button, Field, Select, TextInput, Toggle } from '../ui/controls'
import { ComplianceBadge } from '../Compliance/ChangeControlBadge'
import { useITSMIntegration, useComplianceEvents } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import { cn, formatDateTime, timeUntil } from '../../lib/utils'
import type { ChangeTicket, Compliance, ComplianceEvent, EnforcementMode, ITSMConnection } from '../../types'

/**
 * The ITSM change-ticket bridge tab: connector configuration, the mirrored
 * ticket set, and the control's actual output.
 *
 * All three live on one screen on purpose. Configuring a control without
 * seeing what it flags is how an enforcement mode gets turned on prematurely,
 * and reviewing flagged changes without being able to see the ticket that
 * should have covered them is how a reviewer gives up and stops looking.
 *
 * Nothing on this page calls out to Jira or ServiceNow. That is the design:
 * the correlation runs against the local mirror, so a site whose ITSM is
 * unreachable — or has none at all — still gets correct verdicts.
 */
export default function ITSMTab() {
  const readOnly = useReadOnly()
  const itsm = useITSMIntegration()
  const { settings, tickets } = itsm

  return (
    <section className="space-y-5">
      <SectionTitle
        hint="Correlate Level 1 production changes against approved ITIL change requests, and flag the rest."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {itsm.isFallback ? (
              <StatusPill tone="amber" dot>
                Preview data
              </StatusPill>
            ) : null}
            <EnforcementPill mode={settings.enforcement} />
            <StatusPill tone={settings.unapproved_count > 0 ? 'red' : 'green'} dot>
              {settings.unapproved_count} unapproved / 24h
            </StatusPill>
          </div>
        }
      >
        Change Management (Jira & ServiceNow)
      </SectionTitle>

      {itsm.isError && !itsm.isFallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Could not load the saved bridge configuration. Showing defaults — saving will overwrite
            them.
          </span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ConnectorCard
          kind="jira"
          title="Jira"
          subtitle="Project key and service account for the change project"
          tokenSet={settings.jira_token_set}
          connection={settings.jira}
          placeholderURL="https://acme.atlassian.net"
          placeholderProject="OPS"
          placeholderUser="svc-statetrack@acme.example"
          disabled={readOnly || itsm.isSaving}
          onSave={(update) => itsm.save({ jira: update })}
          lastError={itsm.saveError}
        />
        <ConnectorCard
          kind="servicenow"
          title="ServiceNow"
          subtitle="Change table and integration user for the change_request API"
          tokenSet={settings.servicenow_token_set}
          connection={settings.servicenow}
          placeholderURL="https://acme.service-now.com"
          placeholderProject="change_request"
          placeholderUser="statetrack.integration"
          disabled={readOnly || itsm.isSaving}
          onSave={(update) => itsm.save({ servicenow: update })}
          lastError={itsm.saveError}
        />
      </div>

      <EnforcementCard
        mode={settings.enforcement}
        graceMinutes={settings.window_grace_minutes}
        minLevel={settings.min_level}
        exemptActors={settings.exempt_actors}
        modes={settings.modes}
        disabled={readOnly || itsm.isSaving}
        isSaving={itsm.isSaving}
        saveError={itsm.saveError}
        savedAt={itsm.savedAt}
        onSave={(update) => itsm.save(update)}
      />

      <TicketMirrorCard
        tickets={tickets}
        disabled={readOnly || itsm.isMutating}
        error={itsm.ticketError}
        onAdd={itsm.addTicket}
        onRemove={itsm.removeTicket}
      />

      <RecentVerdictsCard />
    </section>
  )
}

/* -------------------------------------------------------------------------- */
/* Connector                                                                   */
/* -------------------------------------------------------------------------- */

function ConnectorCard({
  kind,
  title,
  subtitle,
  connection,
  tokenSet,
  placeholderURL,
  placeholderProject,
  placeholderUser,
  disabled,
  onSave,
  lastError,
}: {
  kind: 'jira' | 'servicenow'
  title: string
  subtitle: string
  connection: ITSMConnection
  tokenSet: boolean
  placeholderURL: string
  placeholderProject: string
  placeholderUser: string
  disabled: boolean
  onSave: (update: {
    url: string
    project: string
    auth_token: string
    username: string
    enabled: boolean
  }) => void
  lastError: string | null
}) {
  const [url, setUrl] = useState(connection.url ?? '')
  const [project, setProject] = useState(connection.project ?? '')
  const [username, setUsername] = useState(connection.username ?? '')
  // Deliberately starts empty and stays empty unless the operator types: the
  // server never returns the stored token, and sending an empty string would
  // otherwise be indistinguishable from "clear the credential".
  const [token, setToken] = useState('')
  const [enabled, setEnabled] = useState(connection.enabled)

  const seeded = useRef('')
  useEffect(() => {
    const key = JSON.stringify(connection)
    if (key === seeded.current) return
    seeded.current = key
    setUrl(connection.url ?? '')
    setProject(connection.project ?? '')
    setUsername(connection.username ?? '')
    setEnabled(connection.enabled)
  }, [connection])

  const dirty =
    url !== (connection.url ?? '') ||
    project !== (connection.project ?? '') ||
    username !== (connection.username ?? '') ||
    token !== '' ||
    enabled !== connection.enabled

  const synced = connection.last_sync_at

  return (
    <Card>
      <CardHeader
        title={title}
        subtitle={subtitle}
        icon={<ArrowRightLeft className="h-4 w-4" />}
        actions={
          <div className="flex items-center gap-2">
            {tokenSet ? (
              <StatusPill tone="green" dot>
                Token stored
              </StatusPill>
            ) : (
              <StatusPill tone="slate" dot>
                No token
              </StatusPill>
            )}
            <StatusPill tone={connection.enabled ? 'blue' : 'slate'} dot>
              {connection.enabled ? 'Enabled' : 'Disabled'}
            </StatusPill>
          </div>
        }
      />

      <div className="mt-4 space-y-4">
        <Field label={`${title} URL`} htmlFor={`itsm-${kind}-url`}>
          <TextInput
            id={`itsm-${kind}-url`}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={placeholderURL}
          />
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field
            label={kind === 'jira' ? 'Project key' : 'Change table'}
            htmlFor={`itsm-${kind}-project`}
          >
            <TextInput
              id={`itsm-${kind}-project`}
              value={project}
              onChange={(e) => setProject(e.target.value)}
              placeholder={placeholderProject}
              className="font-mono text-xs"
            />
          </Field>
          <Field
            label="Service account"
            hint={kind === 'jira' ? 'Email for Jira Cloud; blank for bearer auth.' : undefined}
            htmlFor={`itsm-${kind}-user`}
          >
            <TextInput
              id={`itsm-${kind}-user`}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={placeholderUser}
              className="font-mono text-xs"
            />
          </Field>
        </div>

        <Field
          label="API token"
          hint={
            tokenSet
              ? 'A token is stored. Leaving this blank keeps it.'
              : 'Stored encrypted at rest and never returned by the API.'
          }
          htmlFor={`itsm-${kind}-token`}
        >
          <TextInput
            id={`itsm-${kind}-token`}
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={tokenSet ? '••••••••  (unchanged)' : 'Paste the API token'}
            className="font-mono text-xs"
          />
        </Field>

        <div className="border-t border-slate-100 pt-2">
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            disabled={disabled}
            label="Sync change requests from this system"
            description="Disabling stops future syncs. Already-mirrored tickets stay, so approved changes are not retroactively unapproved."
          />
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-3">
          <Button
            variant="primary"
            size="sm"
            icon={<Save className="h-3.5 w-3.5" />}
            disabled={disabled || !dirty}
            onClick={() => {
              onSave({
                url: url.trim(),
                project: project.trim(),
                auth_token: token,
                username: username.trim(),
                enabled,
              })
              setToken('')
            }}
          >
            Save {title}
          </Button>
          {lastError ? (
            <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
              <XCircle className="h-3.5 w-3.5" /> {lastError}
            </span>
          ) : synced ? (
            <span
              className={cn(
                'flex items-center gap-1.5 text-xs',
                connection.last_sync_ok ? 'text-slate-500' : 'text-amber-700',
              )}
            >
              <Clock className="h-3.5 w-3.5" />
              Last sync {formatDateTime(synced)} · {connection.last_sync_count} ticket
              {connection.last_sync_count === 1 ? '' : 's'}
              {connection.last_sync_ok ? '' : ' (failed)'}
            </span>
          ) : (
            <span className="text-xs text-slate-400">Never synced</span>
          )}
        </div>

        {connection.last_sync_error && !connection.last_sync_ok ? (
          <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-800">
            {connection.last_sync_error}
          </p>
        ) : null}

        <p className="text-[11px] leading-relaxed text-slate-400">
          StateTrack does not fetch tickets itself. A sync job (or an operator importing a CSV)
          writes into the mirror below via{' '}
          <span className="font-mono">POST /api/v1/integrations/itsm/sync</span>, which is what makes
          the bridge work in an air-gapped site.
        </p>
      </div>
    </Card>
  )
}

function EnforcementPill({ mode }: { mode: EnforcementMode }) {
  switch (mode) {
    case 'required':
      return (
        <StatusPill tone="red" dot>
          Enforcement: required
        </StatusPill>
      )
    case 'warn':
      return (
        <StatusPill tone="amber" dot>
          Enforcement: warn
        </StatusPill>
      )
    default:
      return (
        <StatusPill tone="slate" dot>
          Enforcement: off
        </StatusPill>
      )
  }
}

/* -------------------------------------------------------------------------- */
/* Enforcement                                                                 */
/* -------------------------------------------------------------------------- */

function EnforcementCard({
  mode,
  graceMinutes,
  minLevel,
  exemptActors,
  modes,
  disabled,
  isSaving,
  saveError,
  savedAt,
  onSave,
}: {
  mode: EnforcementMode
  graceMinutes: number
  minLevel: number
  exemptActors: string[]
  modes: { value: EnforcementMode; label: string; help: string }[]
  disabled: boolean
  isSaving: boolean
  saveError: string | null
  savedAt: number | null
  onSave: (update: {
    enforcement: EnforcementMode
    window_grace_minutes: number
    min_level: number
    exempt_actors: string[]
  }) => void
}) {
  const [next, setNext] = useState<EnforcementMode>(mode)
  const [grace, setGrace] = useState(String(graceMinutes))
  const [level, setLevel] = useState(String(minLevel))
  const [exempt, setExempt] = useState(exemptActors.join(', '))

  const seeded = useRef('')
  useEffect(() => {
    const key = JSON.stringify([mode, graceMinutes, minLevel, exemptActors])
    if (key === seeded.current) return
    seeded.current = key
    setNext(mode)
    setGrace(String(graceMinutes))
    setLevel(String(minLevel))
    setExempt(exemptActors.join(', '))
  }, [mode, graceMinutes, minLevel, exemptActors])

  const parsedGrace = Number(grace)
  const parsedLevel = Number(level)
  const graceValid = Number.isFinite(parsedGrace) && parsedGrace >= 0 && parsedGrace <= 1440
  const levelValid = Number.isInteger(parsedLevel) && parsedLevel >= 1 && parsedLevel <= 4

  const dirty =
    next !== mode ||
    parsedGrace !== graceMinutes ||
    parsedLevel !== minLevel ||
    exempt !== exemptActors.join(', ')

  const activeHelp = modes.find((m) => m.value === next)?.help ?? ''

  return (
    <Card>
      <CardHeader
        title="Enforcement & Matching"
        subtitle="When a change needs a ticket, and how the ticket's window is matched"
        icon={<ShieldCheck className="h-4 w-4" />}
        actions={<EnforcementPill mode={mode} />}
      />

      <div className="mt-4 grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="space-y-4">
          {/* Posture */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-slate-700">Enforcement posture</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {modes.map((m) => {
                const active = m.value === next
                return (
                  <button
                    key={m.value}
                    type="button"
                    onClick={() => setNext(m.value)}
                    disabled={disabled}
                    aria-pressed={active}
                    className={cn(
                      'rounded-lg border px-3 py-2.5 text-left transition-colors disabled:opacity-60',
                      active
                        ? 'border-blue-300 bg-blue-50/70 ring-1 ring-blue-200'
                        : 'border-slate-200 hover:bg-slate-50',
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className={cn(
                          'h-3 w-3 shrink-0 rounded-full border-2',
                          active ? 'border-blue-600 bg-blue-600' : 'border-slate-300',
                        )}
                      />
                      <span className="text-xs font-semibold text-slate-800">{m.label}</span>
                    </span>
                  </button>
                )
              })}
            </div>
            {activeHelp ? (
              <p className="text-[11px] leading-relaxed text-slate-500">{activeHelp}</p>
            ) : null}
          </div>

          <div className="grid grid-cols-1 gap-3 border-t border-slate-100 pt-4 sm:grid-cols-2">
            <Field
              label="Ticket window grace (minutes)"
              hint="Applied to both ends. A change executed a few minutes early is not a violation."
              htmlFor="itsm-grace"
            >
              <TextInput
                id="itsm-grace"
                value={grace}
                onChange={(e) => setGrace(e.target.value)}
                inputMode="numeric"
                className={cn('font-mono text-xs', !graceValid && 'border-red-300')}
              />
            </Field>
            <Field
              label="Minimum impact level needing a ticket"
              hint="Level 1 by default — flagging staging drift would make the audit queue useless."
              htmlFor="itsm-min-level"
            >
              <Select
                id="itsm-min-level"
                value={level}
                onChange={(e) => setLevel(e.target.value)}
                className="font-mono text-xs"
              >
                <option value="1">Level 1 · Critical</option>
                <option value="2">Level 2 · Grouped</option>
                <option value="3">Level 3 · Drift</option>
                <option value="4">Level 4 · Forensic</option>
              </Select>
            </Field>
          </div>

          <Field
            label="Exempt actors"
            hint="Comma-separated usernames that never need a ticket — the configuration-management account is the usual case, since it is itself the system of record."
            htmlFor="itsm-exempt"
          >
            <TextInput
              id="itsm-exempt"
              value={exempt}
              onChange={(e) => setExempt(e.target.value)}
              placeholder="config-management, terraform, state-sync"
              className="font-mono text-xs"
            />
          </Field>

          <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
            <Button
              variant="primary"
              size="sm"
              icon={
                isSaving ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Save className="h-3.5 w-3.5" />
                )
              }
              disabled={disabled || !dirty || !graceValid || !levelValid}
              onClick={() =>
                onSave({
                  enforcement: next,
                  window_grace_minutes: parsedGrace,
                  min_level: parsedLevel,
                  exempt_actors: splitList(exempt),
                })
              }
            >
              {isSaving ? 'Saving…' : 'Save enforcement'}
            </Button>
            {saveError ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
                <XCircle className="h-3.5 w-3.5" /> {saveError}
              </span>
            ) : savedAt ? (
              <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" /> Saved
              </span>
            ) : (
              <span className="text-xs text-slate-400">
                {dirty ? 'Unsaved changes' : 'No changes'}
              </span>
            )}
          </div>
        </div>

        {/* The decision table, stated plainly: the control's rule is the one
            thing an auditor will ask about, and a reviewer who does not know
            the order of the checks cannot predict what it will flag. */}
        <aside className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
            How a verdict is reached
          </p>
          <ol className="mt-2 space-y-2 text-[11px] leading-relaxed text-slate-600">
            {[
              'Enforcement off, a non-exempt-actor change below the minimum level, or an exempt actor → not required.',
              'The change cites a ticket that exists and is approved → approved.',
              'The change cites a ticket that exists but is not approved → unapproved. This is the finding that matters most.',
              'No citation, but an approved in-scope ticket’s window covers the change → approved.',
              'Only an approved ticket whose window has closed matches → expired.',
              'Otherwise → unapproved.',
            ].map((step, i) => (
              <li key={i} className="flex gap-2">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-slate-200 text-[9px] font-bold text-slate-600">
                  {i + 1}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
          <p className="mt-3 border-t border-slate-200 pt-2 text-[10px] leading-relaxed text-slate-400">
            Scope is matched on the ticket&apos;s hosts, environments and path globs. Everything
            runs against the local mirror, so verdicts are produced even when the ITSM system is
            unreachable.
          </p>
        </aside>
      </div>
    </Card>
  )
}

/* -------------------------------------------------------------------------- */
/* Ticket mirror                                                               */
/* -------------------------------------------------------------------------- */

type TicketDraft = {
  ref: string
  status: string
  summary: string
  url: string
  hosts: string
  paths: string
  windowStart: string
  windowEnd: string
}

const EMPTY_DRAFT: TicketDraft = {
  ref: '',
  status: 'approved',
  summary: '',
  url: '',
  hosts: '',
  paths: '',
  windowStart: '',
  windowEnd: '',
}

const STATUS_OPTIONS = [
  { value: 'approved', label: 'Approved' },
  { value: 'scheduled', label: 'Scheduled' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'requested', label: 'Pending Approval' },
  { value: 'draft', label: 'Draft' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'cancelled', label: 'Cancelled' },
]

function TicketMirrorCard({
  tickets,
  disabled,
  error,
  onAdd,
  onRemove,
}: {
  tickets: ChangeTicket[]
  disabled: boolean
  error: string | null
  onAdd: (ticket: {
    ref: string
    kind?: string
    status?: string
    summary?: string
    url?: string
    hosts?: string[]
    environments?: string[]
    paths?: string[]
    window_start?: string
    window_end?: string
  }) => void
  onRemove: (ref: string) => void
}) {
  const [draft, setDraft] = useState<TicketDraft>(EMPTY_DRAFT)
  const [showForm, setShowForm] = useState(false)

  const columns: DataTableColumn<ChangeTicket>[] = useMemo(
    () => [
      {
        key: 'ref',
        header: 'Ticket',
        cell: (t) => (
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="flex items-center gap-1.5">
              <Ticket className="h-3 w-3 shrink-0 text-slate-400" />
              {t.url ? (
                <a
                  href={t.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  onClick={(e) => e.stopPropagation()}
                  className="font-mono text-xs font-semibold text-blue-700 hover:underline"
                >
                  {t.ref}
                </a>
              ) : (
                <span className="font-mono text-xs font-semibold text-slate-800">{t.ref}</span>
              )}
            </span>
            <span className="truncate text-[11px] text-slate-400">{t.kind}</span>
          </div>
        ),
      },
      {
        key: 'status',
        header: 'Status',
        cell: (t) => (
          <StatusPill tone={t.authorized ? 'green' : t.expired ? 'amber' : 'red'} dot>
            {t.expired && t.authorized ? 'Window closed' : t.status_label}
          </StatusPill>
        ),
      },
      {
        key: 'summary',
        header: 'Summary',
        className: 'max-w-[22rem]',
        cell: (t) => (
          <span className="block truncate text-xs text-slate-700" title={t.summary}>
            {t.summary}
          </span>
        ),
      },
      {
        key: 'scope',
        header: 'Scope',
        className: 'max-w-[16rem]',
        cell: (t) => {
          const bits = [
            ...(t.hosts ?? []).map((h) => `host:${h}`),
            ...(t.environments ?? []).map((e) => e),
            ...(t.paths ?? []).map((p) => p),
          ]
          if (bits.length === 0) {
            return <span className="text-[11px] italic text-slate-400">Any host</span>
          }
          const shown = bits.slice(0, 2).join(' · ')
          const extra = bits.length - 2
          return (
            <span className="block truncate font-mono text-[11px] text-slate-600" title={bits.join('\n')}>
              {shown}
              {extra > 0 ? ` +${extra}` : ''}
            </span>
          )
        },
      },
      {
        key: 'window',
        header: 'Window',
        cell: (t) => {
          if (!t.window_end) {
            return <span className="text-[11px] text-slate-400">Open-ended</span>
          }
          return (
            <span
              className={cn(
                'whitespace-nowrap text-[11px]',
                t.expired ? 'text-amber-700' : 'text-slate-500',
              )}
            >
              {t.expired ? 'closed ' : 'ends '}
              {timeUntil(t.window_end)}
            </span>
          )
        },
      },
      {
        key: 'actions',
        header: '',
        align: 'right',
        cell: (t) => (
          <button
            onClick={() => onRemove(t.ref)}
            disabled={disabled}
            aria-label={`Delete ${t.ref}`}
            title={`Delete ${t.ref}`}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-200 text-slate-400 transition-colors hover:border-red-200 hover:bg-red-50 hover:text-red-600 disabled:opacity-40"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        ),
      },
    ],
    [onRemove, disabled],
  )

  const submit = () => {
    const ref = draft.ref.trim().toUpperCase()
    if (!ref) return
    onAdd({
      ref,
      kind: 'manual',
      status: draft.status,
      summary: draft.summary.trim(),
      url: draft.url.trim(),
      hosts: splitList(draft.hosts),
      paths: splitList(draft.paths),
      window_start: draft.windowStart,
      window_end: draft.windowEnd,
    })
    setDraft(EMPTY_DRAFT)
    setShowForm(false)
  }

  return (
    <Card flush>
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <CardHeader
          className="min-w-0 flex-1"
          title="Ticket Mirror"
          subtitle="The local change calendar the correlation reads — synced from ITSM or entered by hand"
          icon={<Ticket className="h-4 w-4" />}
        />
        <StatusPill tone="slate">{tickets.length} tickets</StatusPill>
        <Button
          size="sm"
          icon={<Plus className="h-3.5 w-3.5" />}
          disabled={disabled}
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? 'Cancel' : 'Add ticket'}
        </Button>
      </div>

      {error ? (
        <div className="flex items-start gap-2 border-b border-red-100 bg-red-50 px-4 py-2 text-xs text-red-800">
          <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      {showForm ? (
        <div className="grid grid-cols-1 gap-3 border-b border-slate-200 bg-slate-50/60 px-4 py-4 sm:grid-cols-2 xl:grid-cols-4">
          <Field label="Reference" htmlFor="ticket-ref">
            <TextInput
              id="ticket-ref"
              value={draft.ref}
              onChange={(e) => setDraft({ ...draft, ref: e.target.value })}
              placeholder="CHG-1042"
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Status" htmlFor="ticket-status">
            <Select
              id="ticket-status"
              value={draft.status}
              onChange={(e) => setDraft({ ...draft, status: e.target.value })}
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Valid from" hint="Optional — blank means open-ended." htmlFor="ticket-from">
            <TextInput
              id="ticket-from"
              type="datetime-local"
              value={draft.windowStart}
              onChange={(e) => setDraft({ ...draft, windowStart: e.target.value })}
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Valid until" hint="Optional — blank means open-ended." htmlFor="ticket-to">
            <TextInput
              id="ticket-to"
              type="datetime-local"
              value={draft.windowEnd}
              onChange={(e) => setDraft({ ...draft, windowEnd: e.target.value })}
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Summary" className="sm:col-span-2" htmlFor="ticket-summary">
            <TextInput
              id="ticket-summary"
              value={draft.summary}
              onChange={(e) => setDraft({ ...draft, summary: e.target.value })}
              placeholder="Raise nginx upstream timeout"
            />
          </Field>
          <Field label="Hosts" hint="Comma-separated." htmlFor="ticket-hosts">
            <TextInput
              id="ticket-hosts"
              value={draft.hosts}
              onChange={(e) => setDraft({ ...draft, hosts: e.target.value })}
              placeholder="prod-web-01, prod-k8s-01"
              className="font-mono text-xs"
            />
          </Field>
          <Field
            label="Path globs"
            hint="POSIX paths or registry keys. ** spans segments."
            htmlFor="ticket-paths"
          >
            <TextInput
              id="ticket-paths"
              value={draft.paths}
              onChange={(e) => setDraft({ ...draft, paths: e.target.value })}
              placeholder="/etc/nginx/**, HKLM\Software\Company\**"
              className="font-mono text-xs"
            />
          </Field>
          <div className="flex items-end sm:col-span-2 xl:col-span-4">
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="h-3.5 w-3.5" />}
              disabled={disabled || !draft.ref.trim()}
              onClick={submit}
            >
              Add to mirror
            </Button>
          </div>
        </div>
      ) : null}

      <DataTable
        columns={columns}
        rows={tickets}
        rowKey={(t) => t.id || t.ref}
        pageSize={8}
        empty="No change tickets mirrored yet. Tickets arrive from a sync job, or can be added by hand above."
      />
    </Card>
  )
}

/* -------------------------------------------------------------------------- */
/* Recent verdicts                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The control's own output: the most recent changes with their verdict.
 *
 * This is the half that makes the tab honest. A configuration screen that only
 * shows what could be configured lets an operator enable `required` and walk
 * away without ever seeing that it is flagging every deploy; here, the
 * consequence of the settings above is visible on the same page.
 */
function RecentVerdictsCard() {
  const feed = useComplianceEvents({ limit: 25, impact_level: 1 })

  const columns: DataTableColumn<VerdictRow>[] = useMemo(
    () => [
      {
        key: 'time',
        header: 'Time',
        cell: (r) => (
          <span className="whitespace-nowrap font-mono text-xs tabular-nums text-slate-500">
            {formatDateTime(r.time)}
          </span>
        ),
      },
      {
        key: 'host',
        header: 'Host',
        cell: (r) => <span className="font-mono text-xs text-slate-600">{r.host}</span>,
      },
      {
        key: 'target',
        header: 'Target',
        className: 'max-w-[20rem]',
        cell: (r) => (
          <span className="block truncate font-mono text-xs text-slate-700" title={r.target}>
            {r.target}
          </span>
        ),
      },
      {
        key: 'verdict',
        header: 'Verdict',
        cell: (r) => (
          <div className="flex flex-col gap-1">
            <ComplianceBadge compliance={r.compliance} reason={r.reason} />
            {r.ticketRef ? (
              <span className="font-mono text-[10px] text-slate-500">
                {r.ticketRef}
                {r.ticketStatus ? ` · ${r.ticketStatus}` : ''}
              </span>
            ) : null}
          </div>
        ),
      },
      {
        key: 'reason',
        header: 'Why',
        className: 'max-w-[24rem]',
        cell: (r) => (
          <span className="block truncate text-[11px] text-slate-500" title={r.reason}>
            {r.reason}
          </span>
        ),
      },
    ],
    [],
  )

  const rows = (feed.events ?? []).map(toRow)

  return (
    <Card flush>
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
        <CardHeader
          className="min-w-0 flex-1"
          title="Recent Level 1 Verdicts"
          subtitle="What the current settings flag across the fleet, newest first"
          icon={<ShieldCheck className="h-4 w-4" />}
        />
        <div className="flex flex-wrap items-center gap-2">
          {feed.isFallback ? (
            <StatusPill tone="amber" dot>
              Preview data
            </StatusPill>
          ) : null}
          {!feed.enforced && !feed.isFallback ? (
            <StatusPill tone="slate" dot>
              Advisory only
            </StatusPill>
          ) : null}
          <StatusPill tone={feed.counts.unapproved > 0 ? 'red' : 'green'} dot>
            {feed.counts.unapproved} unauthorised
          </StatusPill>
          <StatusPill tone="green" dot>
            {feed.counts.approved} approved
          </StatusPill>
          {feed.counts.expired > 0 ? (
            <StatusPill tone="amber" dot>
              {feed.counts.expired} expired
            </StatusPill>
          ) : null}
        </div>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        pageSize={8}
        empty="No Level 1 changes in the current window."
      />
    </Card>
  )
}

/** One row of the verdict table: the event projected onto what the table shows. */
interface VerdictRow {
  id: string
  time: string
  host: string
  target: string
  compliance: Compliance
  reason: string
  ticketRef?: string
  ticketStatus?: string
}

function toRow(e: ComplianceEvent): VerdictRow {
  return {
    id: e.id,
    time: e.occurred_at,
    host: e.hostname || e.host_id,
    target: e.path_or_key || e.summary,
    compliance: e.compliance,
    reason: e.compliance_reason ?? '',
    ticketRef: e.ticket_ref,
    ticketStatus: e.ticket_status,
  }
}

/** Splits a comma-separated form field into a trimmed, de-duplicated list. */
function splitList(raw: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const part of raw.split(',')) {
    const v = part.trim()
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}
