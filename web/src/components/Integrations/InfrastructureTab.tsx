import { useMemo, useState } from 'react'
import {
  CheckCircle2,
  Eye,
  Radio,
  RefreshCw,
  Server,
  TerminalSquare,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, SectionTitle } from '../ui/Card'
import StatusPill from '../ui/StatusPill'
import { Button, Field, Select, TextInput } from '../ui/controls'
import { AssetActions, BlockSkeleton, CodeBlock } from './AssetActions'
import { useHostList, useHostSummary } from '../../api/hooks'
import { INTEGRATION_ASSETS } from '../../lib/integrationAssets'
import type { HostSummary } from '../../types'
import { formatDateTime, timeAgo, cn } from '../../lib/utils'

const DEFAULT_PREVIEW_HOST = 'prod-web-01'

/** Checkmk's local-check state numbers. */
const OK = 0
const WARNING = 1
const CRITICAL = 2
const UNKNOWN = 3

const STATE_NAMES: Record<number, string> = {
  [OK]: 'OK',
  [WARNING]: 'WARNING',
  [CRITICAL]: 'CRITICAL',
  [UNKNOWN]: 'UNKNOWN',
}

/**
 * The check plugin's default thresholds (integrations/checkmk/check_statetrack.py).
 * All five are exposed as CLI flags there; these are the defaults the hub shows,
 * and they also ride along in the perfdata so Checkmk draws them on the graph.
 */
const WARN_CRITICAL = 1
const CRIT_CRITICAL = 1
const WARN_DRIFT = 5
const CRIT_DRIFT = 10
/** 0 disables the targets check — a healthy host legitimately tracks dozens. */
const WARN_TARGETS = 0

/**
 * Infrastructure Monitors tab: Checkmk and Zabbix.
 *
 * Both are pollers that consume the same `hosts/{host}/summary` rollup, so the
 * tab shows that document once and then renders the two integrations that
 * consume it — including the literal output each one would produce, computed
 * from the live response rather than from a mocked-up string.
 */
export default function InfrastructureTab() {
  const { hosts } = useHostList()
  const [host, setHost] = useState(DEFAULT_PREVIEW_HOST)
  const [window, setWindow] = useState('7d')

  // Prefer a host that actually exists, so a fresh install with a different
  // fleet does not preview a 404.
  const effectiveHost = useMemo(() => {
    if ((hosts ?? []).some((h) => h.hostname === host)) return host
    return hosts?.[0]?.hostname ?? host
  }, [hosts, host])

  const summary = useHostSummary(effectiveHost, window)

  return (
    <div className="space-y-6">
      {/* Shared poller document */}
      <Card flush>
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <CardHeader
            className="min-w-0 flex-1"
            title="Poller Rollup"
            subtitle="The single document Checkmk, Zabbix, Icinga and Datadog all consume"
            icon={<Radio className="h-4 w-4" />}
          />
          <div className="flex flex-wrap items-center gap-2">
            <div className="w-52">
              <Select
                aria-label="Host to preview"
                value={effectiveHost}
                onChange={(e) => setHost(e.target.value)}
              >
                {(hosts ?? []).map((h) => (
                  <option key={h.id} value={h.hostname}>
                    {h.hostname} ({h.os_family})
                  </option>
                ))}
                {(hosts ?? []).length === 0 ? (
                  <option value={DEFAULT_PREVIEW_HOST}>{DEFAULT_PREVIEW_HOST}</option>
                ) : null}
              </Select>
            </div>
            <div className="w-28">
              <Select
                aria-label="Lookback window"
                value={window}
                onChange={(e) => setWindow(e.target.value)}
              >
                {['15m', '1h', '24h', '7d'].map((w) => (
                  <option key={w} value={w}>
                    {w}
                  </option>
                ))}
              </Select>
            </div>
            <Button
              icon={<RefreshCw className={cn('h-4 w-4', summary.isFetching && 'animate-spin')} />}
              onClick={() => void summary.refetch()}
              disabled={summary.isFetching}
            >
              Refresh
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 p-4 lg:grid-cols-3">
          <div className="space-y-3 lg:col-span-1">
            <div className="flex items-center gap-2">
              {summary.data ? (
                summary.data.online ? (
                  <StatusPill tone="green" dot>
                    Agent online
                  </StatusPill>
                ) : (
                  <StatusPill tone="red" dot>
                    Agent offline
                  </StatusPill>
                )
              ) : (
                <StatusPill tone="slate" dot>
                  {summary.isLoading ? 'Loading…' : 'No data'}
                </StatusPill>
              )}
              <span className="font-mono text-xs text-slate-500">{effectiveHost}</span>
            </div>
            {summary.isError ? (
              <div className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
                <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  GET /api/v1/hosts/{effectiveHost}/summary failed. The endpoint is served by the
                  Go backend on :8080.
                </span>
              </div>
            ) : summary.data ? (
              <dl className="divide-y divide-slate-100 rounded-lg border border-slate-200">
                {[
                  ['Total changes', summary.data.counts?.total],
                  ['L1 critical', summary.data.counts?.l1_critical],
                  ['L2 grouped', summary.data.counts?.l2_grouped],
                  ['L3 drift', summary.data.counts?.l3_drift],
                  ['Tracked targets', summary.data.drift_targets_count],
                ].map(([label, value]) => (
                  <div key={String(label)} className="flex items-center justify-between gap-3 px-3 py-2">
                    <dt className="text-xs text-slate-500">{label}</dt>
                    <dd className="font-mono text-sm tabular-nums text-slate-800">
                      {typeof value === 'number' ? value.toLocaleString() : '—'}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <BlockSkeleton rows={4} />
            )}
            {summary.data?.latest_critical ? (
              <div className="rounded-lg border border-red-200 bg-red-50/60 px-3 py-2">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-red-700">
                  Latest critical change
                </p>
                <p className="mt-1 text-xs text-slate-700">{summary.data.latest_critical.summary}</p>
                <p className="mt-0.5 font-mono text-[11px] text-slate-500">
                  {summary.data.latest_critical.target}
                  {summary.data.latest_critical.actor
                    ? ` · ${summary.data.latest_critical.actor}`
                    : ''}
                  {summary.data.latest_critical.tool
                    ? ` via ${summary.data.latest_critical.tool}`
                    : ''}
                </p>
                <p className="mt-1 text-[10px] text-slate-400">
                  {formatDateTime(summary.data.latest_critical.occurred_at)}
                </p>
              </div>
            ) : null}
          </div>

          <div className="lg:col-span-2">
            <p className="mb-2 text-xs font-medium text-slate-700">
              Live JSON — exactly what a poller receives
            </p>
            {summary.data ? (
              <CodeBlock
                label={`GET /api/v1/hosts/${effectiveHost}/summary?window=${window}`}
                language="json"
                code={JSON.stringify(summary.data, null, 2)}
                maxHeight="max-h-72"
              />
            ) : (
              <BlockSkeleton rows={8} />
            )}
          </div>
        </div>
      </Card>

      <CheckmkSection summary={summary.data ?? null} host={effectiveHost} window={window} />
      <ZabbixSection summary={summary.data ?? null} host={effectiveHost} window={window} />
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Checkmk                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Reproduces the check plugin's evaluate()/render_* logic so the preview is the
 * plugin's own output, not an approximation of it.
 *
 * The thresholds mirror the plugin's defaults (warn-critical=1, crit-critical=1,
 * warn-drift=5, crit-drift=10, warn-targets=0/disabled). If those defaults
 * change in integrations/checkmk/check_statetrack.py this must change with
 * them; the alternative — shelling out to the Python plugin from the server —
 * would put a Python dependency in the Go backend's runtime path for a
 * convenience preview, which is not a trade worth making.
 */
function evaluate(s: HostSummary) {
  const l1 = s.counts?.l1_critical ?? 0
  const l3 = s.counts?.l3_drift ?? 0
  const targets = s.drift_targets_count ?? 0
  const window = s.window || '7d'
  let state = OK
  const reasons: string[] = []

  if (!s.online) {
    state = CRITICAL
    reasons.push(`agent offline (last seen ${s.last_seen_seconds}s ago)`)
  }
  // Thresholds mirror the plugin's defaults: warn-critical=1, crit-critical=1,
  // warn-drift=5, crit-drift=10, and --warn-targets disabled (0).
  if (l1 >= CRIT_CRITICAL) {
    state = Math.max(state, CRITICAL)
    reasons.push(`${l1} critical change${l1 === 1 ? '' : 's'} in last ${window}`)
  } else if (l1 >= WARN_CRITICAL) {
    state = Math.max(state, WARNING)
    reasons.push(`${l1} critical change(s) in last ${window}`)
  }
  if (l3 >= CRIT_DRIFT) {
    state = Math.max(state, CRITICAL)
    reasons.push(`${l3} drift changes (>= ${CRIT_DRIFT})`)
  } else if (l3 >= WARN_DRIFT) {
    state = Math.max(state, WARNING)
    reasons.push(`${l3} drift changes`)
  }
  if (WARN_TARGETS && targets >= WARN_TARGETS) {
    state = Math.max(state, WARNING)
    reasons.push(`${targets} tracked targets`)
  }

  let message: string
  if (reasons.length > 0) message = reasons.join('; ')
  else if (s.online) message = `Agent online, 0 critical changes in last ${window}`
  else message = 'Agent offline'

  // The plugin appends the detail whenever there is one, regardless of state.
  const detail = criticalDetail(s)
  if (detail) message = `${message} - ${detail}`
  return { state, message, l1, l3, targets }
}

/**
 * Mirrors the plugin's critical_detail(): the newest critical change rendered as
 * "latest: <actor> via <tool> <target> <summary> [<id>] <deep_link>".
 *
 * Every part matters operationally — the id lets an operator grep raw agent
 * output even when the link is truncated downstream, and the link is what makes
 * the check actionable from Checkmk's UI.
 */
function criticalDetail(s: HostSummary): string {
  const latest = s.latest_critical
  if (!latest) return ''
  const parts: string[] = []
  const actor = (latest.actor ?? '').trim()
  const tool = (latest.tool ?? '').trim()
  if (actor && tool) parts.push(`${actor} via ${tool}`)
  else if (actor) parts.push(actor)
  const target = (latest.target ?? '').trim()
  if (target) parts.push(target)
  const text = parts.length > 0 ? parts.join(' ') : (latest.summary ?? '').trim()

  const summaryText = (latest.summary ?? '').trim()
  let detail = text ? `latest: ${text} ${summaryText}`.trim() : summaryText
  const alt = (latest.id ?? '').trim()
  if (alt) detail = detail ? `${detail} [${alt}]` : `[${alt}]`
  const link = (latest.deep_link ?? '').trim()
  if (link) detail = detail ? `${detail} ${link}` : link
  return detail.trim()
}

/** Checkmk sanitizes its single output line: collapse whitespace, no pipes. */
function sanitize(text: string): string {
  return text.replace(/\s+/g, ' ').trim().replace(/\|/g, '/')
}

function truncate(text: string, limit = 480): string {
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`
}

function renderLocal(s: HostSummary, service = 'StateTrack_Changes'): string {
  const { state, message } = evaluate(s)
  const perf = [
    `total=${s.counts?.total ?? 0}`,
    `l1_critical=${s.counts?.l1_critical ?? 0};${WARN_CRITICAL};${CRIT_CRITICAL}`,
    `l2_grouped=${s.counts?.l2_grouped ?? 0}`,
    `l3_drift=${s.counts?.l3_drift ?? 0};${WARN_DRIFT};${CRIT_DRIFT}`,
    `drift_targets=${s.drift_targets_count}`,
  ]
  return `${state} "${service}" ${perf.join('|')} ${truncate(sanitize(message))}`
}

function renderNagios(s: HostSummary): string {
  const { state, message } = evaluate(s)
  const perf = [
    `total=${s.counts?.total ?? 0}`,
    `l1_critical=${s.counts?.l1_critical ?? 0};${WARN_CRITICAL};${CRIT_CRITICAL}`,
    `l2_grouped=${s.counts?.l2_grouped ?? 0}`,
    `l3_drift=${s.counts?.l3_drift ?? 0};${WARN_DRIFT};${CRIT_DRIFT}`,
    `drift_targets=${s.drift_targets_count}`,
  ]
  return `STATETRACK ${STATE_NAMES[state]} - ${truncate(sanitize(message))} | ${perf.join(' ')}`
}

function CheckmkSection({
  summary,
  host,
  window: lookback,
}: {
  summary: HostSummary | null
  host: string
  window: string
}) {
  const [mode, setMode] = useState<'local' | 'nagios'>('local')
  const [showPreview, setShowPreview] = useState(false)

  const evalResult = summary ? evaluate(summary) : null

  // Host names come from the console's own data and could contain a space or a
  // quote; quoting them keeps every generated command paste-safe.
  const q = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`
  const url = `${globalThis.location.origin.replace(/:5173$/, ':8080')}`

  const commands = {
    local: `# /usr/lib/check_mk_agent/local/60/check_statetrack
python3 check_statetrack.py \\
  --mode local \\
  --url ${q(url)} \\
  --host ${q(host)} \\
  --window ${q(lookback)} \\
  --service StateTrack_Changes`,
    nagios: `# MRPE entry in check_mk.user.yml (or an Icinga/Nagios command)
MRPE:
  - StateTrack_Changes python3 /usr/lib/check_mk_agent/local/check_statetrack.py \\
      --mode nagios --url ${q(url)} --host ${q(host)} --window ${q(lookback)}`,
  }

  return (
    <section className="space-y-4">
      <SectionTitle
        hint="Zero-dependency Python check — local check for the agent, or MRPE/active check."
        actions={
          <StatusPill tone="blue" mono>
            --mode local | --mode nagios
          </StatusPill>
        }
      >
        Checkmk
      </SectionTitle>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader
            title="Deployment Mode"
            subtitle="Where the script runs determines which protocol to use"
            icon={<TerminalSquare className="h-4 w-4" />}
          />
          <div className="mt-4 space-y-3">
            <ModeNote
              active={mode === 'local'}
              onClick={() => setMode('local')}
              title="--mode local"
              where="/usr/lib/check_mk_agent/local/"
              body="The plugin runs on the monitored host inside the Checkmk agent's local-check directory. It prints one line per service, which the agent forwards on its normal poll — no extra network access or Checkmk-side configuration."
            />
            <ModeNote
              active={mode === 'nagios'}
              onClick={() => setMode('nagios')}
              title="--mode nagios"
              where="MRPE / active check"
              body="The plugin prints the Nagios plugin protocol (OK/WARNING/CRITICAL with exit codes and perfdata). Use this when Checkmk is not installed on the host, or when the check runs centrally against the API from a monitoring server."
            />
          </div>
          <div className="mt-4">
            <CodeBlock label={`CLI · ${mode}`} language="bash" code={commands[mode]} />
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Live Check Output"
            subtitle="The plugin's exact output for the selected host and window"
            icon={<Eye className="h-4 w-4" />}
            actions={
              evalResult ? (
                <StatusPill tone={evalResult.state === OK ? 'green' : evalResult.state === WARNING ? 'amber' : 'red'} dot>
                  {STATE_NAMES[evalResult.state]}
                </StatusPill>
              ) : undefined
            }
          />
          <div className="mt-4 space-y-3">
            <Button
              variant="primary"
              icon={<Eye className="h-4 w-4" />}
              disabled={!summary}
              onClick={() => setShowPreview(true)}
            >
              Live Preview Check Output
            </Button>
            {showPreview && summary ? (
              <>
                <div>
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                    Checkmk local check line
                  </p>
                  <CodeBlock
                    label="60/check_statetrack"
                    language="text"
                    code={renderLocal(summary)}
                    maxHeight="max-h-40"
                  />
                </div>
                <div>
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                    Nagios / MRPE output
                  </p>
                  <CodeBlock
                    label="MRPE"
                    language="text"
                    code={renderNagios(summary)}
                    maxHeight="max-h-40"
                  />
                </div>
                <p className="text-[11px] text-slate-400">
                  Precedence: an offline agent reports CRITICAL first, then Level 1 critical
                  changes, then drift.
                </p>
              </>
            ) : (
              <p className="text-xs text-slate-500">
                Runs the check logic against the live summary document above — no request leaves
                your browser.
              </p>
            )}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Check Plugin"
          subtitle={INTEGRATION_ASSETS.checkmkPlugin.description}
          icon={<CheckCircle2 className="h-4 w-4" />}
        />
        <p className="mt-3 text-xs text-slate-500">
          Thresholds are flags, not code: <span className="font-mono">--warn-critical</span>,{' '}
          <span className="font-mono">--crit-critical</span>,{' '}
          <span className="font-mono">--warn-drift</span>,{' '}
          <span className="font-mono">--crit-drift</span>. All thresholds also ride along in the
          perfdata, so Checkmk draws the levels on the graph.
        </p>
        <AssetActions asset={INTEGRATION_ASSETS.checkmkPlugin} className="mt-4" />
      </Card>
    </section>
  )
}

function ModeNote({
  active,
  onClick,
  title,
  where,
  body,
}: {
  active: boolean
  onClick: () => void
  title: string
  where: string
  body: string
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full rounded-lg border px-3 py-2.5 text-left transition-colors',
        active ? 'border-blue-300 bg-blue-50/60' : 'border-slate-200 hover:bg-slate-50',
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cn(
            'h-3 w-3 shrink-0 rounded-full border-2',
            active ? 'border-blue-600 bg-blue-600' : 'border-slate-300',
          )}
        />
        <span className="font-mono text-xs font-semibold text-slate-800">{title}</span>
        <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-400">{where}</span>
      </div>
      <p className="mt-1.5 pl-5 text-xs leading-relaxed text-slate-500">{body}</p>
    </button>
  )
}

/* -------------------------------------------------------------------------- */
/* Zabbix                                                                     */
/* -------------------------------------------------------------------------- */

const ZABBIX_MACROS = [
  {
    macro: '{$STATETRACK.URL}',
    value: 'http://statetrack-server:8080',
    hint: 'Base URL, no trailing slash (the item appends the path).',
  },
  {
    macro: '{$STATETRACK.TOKEN}',
    value: '(empty)',
    hint: 'API bearer token. Declared SECRET_TEXT, so it is masked in the UI and in exports.',
  },
  {
    macro: '{$STATETRACK.WINDOW}',
    value: '15m',
    hint: 'Lookback window: 15m, 1h, 24h or 7d.',
  },
]

function ZabbixSection({
  summary,
  host,
  window,
}: {
  summary: HostSummary | null
  host: string
  window: string
}) {
  const [macroHost, setMacroHost] = useState('')
  const [macroWindow, setMacroWindow] = useState('15m')

  // Zabbix interpolates the item URL per host, so the preview shows that same
  // substitution rather than a raw template string.
  const effectiveHost = macroHost.trim() || host

  return (
    <section className="space-y-4">
      <SectionTitle
        hint="One HTTP Agent master item per host, with dependent items and a JSONPath preprocessing step."
        actions={
          <StatusPill tone="purple" mono>
            Zabbix 6.4 / 7.0
          </StatusPill>
        }
      >
        Zabbix
      </SectionTitle>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader
            title="Template Macros"
            subtitle="Configure these once at the host, template or global level"
            icon={<Server className="h-4 w-4" />}
          />
          <div className="mt-4">
            <div className="overflow-hidden rounded-lg border border-slate-200">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70">
                    <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                      Macro
                    </th>
                    <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                      Example
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {ZABBIX_MACROS.map((m) => (
                    <tr key={m.macro} className="border-b border-slate-100 last:border-0">
                      <td className="px-3 py-2 align-top">
                        <p className="font-mono text-xs text-slate-800">{m.macro}</p>
                        <p className="mt-0.5 text-[11px] text-slate-500">{m.hint}</p>
                      </td>
                      <td className="px-3 py-2 align-top">
                        <span className="rounded bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
                          {m.value}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <AssetActions asset={INTEGRATION_ASSETS.zabbixTemplate} className="mt-4" />
        </Card>

        <Card>
          <CardHeader
            title="HTTP Agent Master Item"
            subtitle="Resolve {HOST.HOST} and {$STATETRACK.WINDOW} to see the request"
            icon={<Radio className="h-4 w-4" />}
          />
          <div className="mt-4 space-y-3">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Host ({HOST.HOST})" htmlFor="zabbix-host">
                <TextInput
                  id="zabbix-host"
                  value={macroHost}
                  onChange={(e) => setMacroHost(e.target.value)}
                  placeholder={host}
                  className="font-mono text-xs"
                />
              </Field>
              <Field label="{$STATETRACK.WINDOW}" htmlFor="zabbix-window">
                <Select
                  id="zabbix-window"
                  value={macroWindow}
                  onChange={(e) => setMacroWindow(e.target.value)}
                >
                  {['15m', '1h', '24h', '7d'].map((w) => (
                    <option key={w} value={w}>
                      {w}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <CodeBlock
              label="Item URL"
              language="text"
              code={`GET {$STATETRACK.URL}/api/v1/hosts/${effectiveHost}/summary?window=${macroWindow}
Authorization: Bearer {$STATETRACK.TOKEN}
Accept: application/json`}
            />
            <p className="text-[11px] text-slate-400">
              Preprocessing: <span className="font-mono">JSONPath $.counts.l1_critical</span> and
              friends, one dependent item per field. The master item is what fails and shows
              <span className="font-mono"> Unsupported</span> when the API is unreachable.
            </p>
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Master Item Payload"
          subtitle={`Live response for ${host} (${window}) — the body Zabbix parses`}
          icon={<Eye className="h-4 w-4" />}
          actions={
            summary ? (
              <span className="text-[11px] text-slate-400">
                seen {timeAgo(new Date(Date.now() - summary.last_seen_seconds * 1000).toISOString())}
              </span>
            ) : undefined
          }
        />
        <div className="mt-4">
          {summary ? (
            <CodeBlock
              label={`GET /api/v1/hosts/${host}/summary?window=${window}`}
              language="json"
              code={JSON.stringify(summary, null, 2)}
              maxHeight="max-h-80"
            />
          ) : (
            <BlockSkeleton rows={8} />
          )}
        </div>
      </Card>
    </section>
  )
}
