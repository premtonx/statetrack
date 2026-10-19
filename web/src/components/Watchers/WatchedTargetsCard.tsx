import { useMemo, useState } from 'react'
import {
  Crosshair,
  Info,
  Loader2,
  Plus,
  Radar,
  ShieldAlert,
  Trash2,
  TriangleAlert,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import Modal from '../ui/Modal'
import StatusPill, { LevelPill, PreviewBadge } from '../ui/StatusPill'
import { Button, Field, IconButton, Select, TextInput } from '../ui/controls'
import { useWatchRules } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import { useConsole } from '../../lib/consoleContext'
import { cn, formatDateTime, timeAgo } from '../../lib/utils'
import { FLEET_SCOPE, type WatchRule, type WatchTargetType } from '../../types'

/** The platform token a target type is restricted to, if any. */
function typePlatform(t: WatchTargetType): string | undefined {
  return t.platforms && t.platforms.length > 0 ? t.platforms[0] : undefined
}

function hostPlatform(osFamily?: string): string {
  return (osFamily ?? '').toLowerCase().includes('win') ? 'windows' : 'linux'
}

/** The label the server will derive when the operator leaves the name blank. */
function derivedName(pattern: string): string {
  const trimmed = pattern.trim()
  if (!trimmed) return ''
  const cut = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'))
  return cut >= 0 && cut + 1 < trimmed.length ? trimmed.slice(cut + 1) : trimmed
}

/**
 * Custom watched targets, authored here rather than in `agent.yaml`.
 *
 * The card is the operator-facing half of the surgical watchers: a row here is
 * a `host_policy_rules` entry that the classifier and the IIS/database
 * collectors read, so adding one starts tracking a specific pool, table or file
 * on the next heartbeat without an agent restart.
 */
export default function WatchedTargetsCard() {
  const { hosts } = useConsole()
  const readOnly = useReadOnly()
  const feed = useWatchRules()

  const [open, setOpen] = useState(false)
  const [hostScope, setHostScope] = useState(FLEET_SCOPE)
  const [targetType, setTargetType] = useState('')
  const [pattern, setPattern] = useState('')
  const [level, setLevel] = useState(feed.defaultLevel)
  const [name, setName] = useState('')
  const [removing, setRemoving] = useState<WatchRule | null>(null)

  const selectedHost = (hosts ?? []).find(
    (h) => h.hostname === hostScope || h.id === hostScope,
  )
  const platform = hostScope === FLEET_SCOPE ? '' : hostPlatform(selectedHost?.os_family)

  // A Windows-only type (an IIS pool, a registry key) is unreachable on a Linux
  // host, so the option is disabled rather than removed: seeing it greyed out
  // with a reason is how an operator learns the rule would never fire.
  const options = useMemo(
    () =>
      (feed.targetTypes ?? []).filter(
        (t) => !platform || !typePlatform(t) || typePlatform(t) === platform,
      ),
    [feed.targetTypes, platform],
  )

  const activeType =
    options.find((t) => t.value === targetType) ??
    options.find((t) => t.value === 'file') ??
    options[0]

  const reset = () => {
    setHostScope(FLEET_SCOPE)
    setTargetType('')
    setPattern('')
    setLevel(feed.defaultLevel)
    setName('')
    feed.clearError()
  }

  const openBuilder = () => {
    reset()
    setOpen(true)
  }

  const submit = () => {
    if (!activeType || !pattern.trim()) return
    feed.create(
      {
        host_scope: hostScope,
        target_type: activeType.value,
        pattern: pattern.trim(),
        level,
        diff: level === 1,
        name: name.trim() || undefined,
      },
      // Closing on the accepted response (not on "submitted") keeps a
      // validation failure visible: the server's message names the fix.
      () => {
        setOpen(false)
        reset()
      },
    )
  }

  const columns: DataTableColumn<WatchRule>[] = [
    {
      key: 'target',
      header: 'Watched Target',
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <p className="truncate font-mono text-xs font-medium text-slate-800">{r.pattern}</p>
          </div>
          <p className="mt-0.5 truncate text-[11px] text-slate-400">
            {r.name}
            {r.created_by ? ` · added by ${r.created_by}` : ''}
          </p>
        </div>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      cell: (r) => (
        <StatusPill tone={typeTone(r.target_type)}>{r.target_label || r.target_type}</StatusPill>
      ),
    },
    {
      key: 'host',
      header: 'Host',
      cell: (r) =>
        r.host_scope === FLEET_SCOPE || !r.host_scope ? (
          <StatusPill tone="slate">All Hosts</StatusPill>
        ) : (
          <span className="whitespace-nowrap font-mono text-xs text-slate-700">
            {r.hostname || r.host_scope}
          </span>
        ),
    },
    {
      key: 'impact',
      header: 'Impact',
      cell: (r) => <LevelPill level={r.level} short />,
    },
    {
      key: 'capture',
      header: 'Capture',
      cell: (r) => (
        <span
          className={cn(
            'whitespace-nowrap text-[11px]',
            r.diff ? 'font-medium text-slate-700' : 'text-slate-500',
          )}
        >
          {r.diff_mode || (r.diff ? 'Full diff' : 'Hash only')}
        </span>
      ),
    },
    {
      key: 'created',
      header: 'Added',
      cell: (r) => (
        <span className="whitespace-nowrap text-[11px] text-slate-500" title={formatDateTime(r.created_at)}>
          {timeAgo(r.created_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      cell: (r) => (
        <IconButton
          label={readOnly ? 'Read-only session — cannot remove watched targets' : `Stop watching ${r.pattern}`}
          disabled={readOnly}
          onClick={() => setRemoving(r)}
          className="hover:border-red-200 hover:bg-red-50 hover:text-red-600"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </IconButton>
      ),
    },
  ]

  return (
    <>
      <Card flush>
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <CardHeader
            className="min-w-0 flex-1"
            title={
              <span className="flex items-center gap-2">
                Watched Targets
                {feed.isFallback ? <PreviewBadge /> : null}
              </span>
            }
            subtitle={
              feed.isFallback
                ? 'Seeded preview — start the server to provision targets on your agents'
                : `${feed.count} custom target${feed.count === 1 ? '' : 's'} · ${feed.critical} Level 1 · pushed on the next heartbeat`
            }
            icon={<Radar className="h-4 w-4" />}
          />
          <Button
            variant="primary"
            size="sm"
            disabled={readOnly}
            onClick={openBuilder}
            icon={<Plus className="h-3.5 w-3.5" />}
          >
            Add Watched Target
          </Button>
        </div>

        {feed.isError ? (
          <div className="flex items-start gap-2 border-b border-red-200 bg-red-50 px-4 py-2 text-xs text-red-800">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>Could not load watched targets.</span>
          </div>
        ) : null}

        <DataTable
          columns={columns}
          rows={feed.rules}
          rowKey={(r) => r.id}
          loading={feed.isLoading}
          empty="No custom watched targets yet. Add one to track a specific file, IIS app pool or database table."
        />
      </Card>

      {/* Builder */}
      <Modal
        open={open}
        onClose={() => {
          setOpen(false)
          reset()
        }}
        size="lg"
        title="Add watched target"
        description="Track one specific surface — a file, an IIS app pool, a database table — with its own impact level."
        footer={
          <>
            <Button
              onClick={() => {
                setOpen(false)
                reset()
              }}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={!activeType || !pattern.trim() || feed.isCreating}
              onClick={submit}
              icon={
                feed.isCreating ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Crosshair className="h-4 w-4" />
                )
              }
            >
              {feed.isCreating ? 'Adding…' : 'Add target'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field
              label="Host"
              htmlFor="watch-host"
              hint={hostScope === FLEET_SCOPE ? 'Applies to every host, including ones that enroll later.' : undefined}
            >
              <Select
                id="watch-host"
                value={hostScope}
                onChange={(e) => {
                  setHostScope(e.target.value)
                  // The selected host can make the current type unreachable
                  // (an IIS pool on Linux); fall back to the first valid one.
                  const nextPlatform =
                    e.target.value === FLEET_SCOPE
                      ? ''
                      : hostPlatform(
                          (hosts ?? []).find(
                            (h) => h.hostname === e.target.value || h.id === e.target.value,
                          )?.os_family,
                        )
                  const ok = (feed.targetTypes ?? []).filter(
                    (t) => !nextPlatform || !typePlatform(t) || typePlatform(t) === nextPlatform,
                  )
                  if (!ok.some((t) => t.value === targetType)) setTargetType(ok[0]?.value ?? '')
                }}
              >
                <option value={FLEET_SCOPE}>All Hosts</option>
                {(hosts ?? []).map((h) => (
                  <option key={h.id} value={h.hostname}>
                    {h.hostname} · {hostPlatform(h.os_family)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Target Type" htmlFor="watch-type">
              <Select
                id="watch-type"
                value={activeType?.value ?? ''}
                onChange={(e) => {
                  setTargetType(e.target.value)
                  setPattern('')
                }}
              >
                {options.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>

          <Field
            label="Path / Identifier"
            htmlFor="watch-pattern"
            hint={activeType?.help}
          >
            <TextInput
              id="watch-pattern"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder={activeType?.placeholder}
              spellCheck={false}
              className="font-mono text-xs"
            />
          </Field>

          <Field
            label="Name"
            htmlFor="watch-name"
            hint={
              name.trim()
                ? 'Shown in the timeline and the audit trail.'
                : `Optional — defaults to “${derivedName(pattern) || 'the last path segment'}”.`
            }
          >
            <TextInput
              id="watch-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={derivedName(pattern) || 'CheckoutAppPool'}
            />
          </Field>

          <div>
            <p className="text-xs font-medium text-slate-700">Impact level</p>
            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {(feed.impactLevels ?? []).map((l) => {
                const on = level === l.value
                return (
                  <button
                    key={l.value}
                    type="button"
                    onClick={() => setLevel(l.value)}
                    className={cn(
                      'rounded-lg border px-3 py-2.5 text-left transition-colors',
                      on
                        ? l.value === 1
                          ? 'border-red-300 bg-red-50/70'
                          : 'border-amber-300 bg-amber-50/70'
                        : 'border-slate-200 hover:bg-slate-50',
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className={cn(
                          'flex h-3.5 w-3.5 items-center justify-center rounded-full border',
                          on ? 'border-blue-600' : 'border-slate-300',
                        )}
                      >
                        {on ? <span className="h-1.5 w-1.5 rounded-full bg-blue-600" /> : null}
                      </span>
                      <span className="text-xs font-medium text-slate-800">{l.label}</span>
                    </span>
                    <span className="mt-1 block pl-5 text-[11px] leading-snug text-slate-500">
                      {l.help}
                    </span>
                  </button>
                )
              })}
            </div>
          </div>

          {pattern.trim() ? (
            <div className="rounded-lg border border-slate-200 bg-slate-50/70 px-3 py-2">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                Agent will track
              </p>
              <p className="mt-1 break-all font-mono text-xs text-slate-700">
                {activeType?.value === 'iis_apppool' && !pattern.startsWith('iis://')
                  ? `iis://apppool/${pattern.trim()}`
                  : pattern.trim()}
              </p>
              <p className="mt-1 text-[11px] text-slate-500">
                on {hostScope === FLEET_SCOPE ? 'every host' : hostScope} ·{' '}
                {level === 1 ? 'full diff, instant alert' : 'hash only, drift'}
              </p>
            </div>
          ) : null}

          {feed.mutationError ? (
            <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{feed.mutationError}</span>
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-[11px] text-slate-500">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                Rules reach the agent on its next heartbeat — no restart. A database target is
                read-only (SELECT only), and credentials are scrubbed at the edge before hashing.
              </span>
            </div>
          )}
        </div>
      </Modal>

      {/* Removal confirmation */}
      <Modal
        open={Boolean(removing)}
        onClose={() => setRemoving(null)}
        size="sm"
        title={`Stop watching ${removing?.name ?? ''}?`}
        description="The target stops being polled and no longer classifies changes. Its history is kept."
        footer={
          <>
            <Button onClick={() => setRemoving(null)}>Cancel</Button>
            <Button
              variant="danger"
              disabled={feed.isDeleting}
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => {
                if (removing) feed.remove(removing.id)
                setRemoving(null)
              }}
            >
              Remove target
            </Button>
          </>
        }
      >
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span className="break-all font-mono">{removing?.pattern}</span>
        </div>
      </Modal>
    </>
  )
}

/** Target-type colour: the Windows surfaces read blue, data reads purple. */
function typeTone(type: string): 'blue' | 'purple' | 'amber' | 'slate' | 'cyan' {
  switch (type) {
    case 'iis_apppool':
    case 'iis_site':
      return 'blue'
    case 'database_table':
    case 'database_schema':
    case 'database_params':
      return 'purple'
    case 'registry':
      return 'amber'
    case 'k8s_object':
      return 'cyan'
    default:
      return 'slate'
  }
}
