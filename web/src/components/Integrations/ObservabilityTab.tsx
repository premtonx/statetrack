import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Plug,
  RefreshCw,
  Save,
  Send,
  ShieldCheck,
  Wifi,
  XCircle,
} from 'lucide-react'
import Card, { CardHeader, SectionTitle } from '../ui/Card'
import DataTable, { type DataTableColumn } from '../ui/DataTable'
import StatusPill, { LevelPill } from '../ui/StatusPill'
import { Button, Field, TextInput, Toggle } from '../ui/controls'
import { AssetActions, BlockSkeleton, CodeBlock } from './AssetActions'
import { GRAFANA_DASHBOARDS } from '../../api/mockData'
import { useGrafanaIntegration } from '../../api/hooks'
import { useReadOnly } from '../../lib/authContext'
import { useConsole } from '../../lib/consoleContext'
import { INTEGRATION_ASSETS, copyText } from '../../lib/integrationAssets'
import type { GrafanaAnnotation } from '../../types'
import { formatDateTime, cn } from '../../lib/utils'

/** Mirrors the server's own default so a first save sends a sane template. */
const DEFAULT_TEMPLATE =
  '[StateTrack] {{summary}} · actor {{actor}} on {{hostname}} · {{level}}'

const TEMPLATE_VARS = [
  '{{summary}}',
  '{{actor}}',
  '{{hostname}}',
  '{{level}}',
  '{{category}}',
  '{{path}}',
]

/**
 * The scrape job an operator pastes into prometheus.yml.
 *
 * metrics_path is /metrics and the target is the server's HTTP port: the
 * exporter is registered on the main API listener rather than a separate one,
 * so there is no second port to open in a firewall.
 */
function prometheusScrapeConfig(baseURL: string): string {
  return `# prometheus.yml — StateTrack change-intelligence exporter
scrape_configs:
  - job_name: statetrack
    metrics_path: /metrics
    scrape_interval: 30s
    static_configs:
      - targets: ['${baseURL.replace(/^https?:\/\//, '')}']
        labels:
          environment: production
          component: statetrack`
}

/** The key series the hub surfaces, with the reason each one matters. */
const KEY_SERIES = [
  { name: 'statetrack_active_agents', hint: 'Agents reporting, by host, OS and status' },
  { name: 'statetrack_mutations_total', hint: 'Changes by host, level, category and action' },
  { name: 'statetrack_drift_targets', hint: 'Config targets tracked per host' },
  { name: 'statetrack_storm_throttles_total', hint: 'Circuit-breaker activations per host' },
  { name: 'statetrack_webhook_deliveries_total', hint: 'Outbound delivery outcomes by provider' },
  { name: 'statetrack_ingest_events_received_total', hint: 'Lifetime events ingested' },
]

/**
 * Observability tab: the Grafana annotation integration and the Prometheus
 * exporter.
 *
 * Grouped because they answer the same question — "is StateTrack's data
 * reaching my Grafana/Prometheus stack?" — from the two directions an operator
 * cares about: push (annotations) and pull (scrape).
 */
export default function ObservabilityTab() {
  const [prom, setProm] = useState<PromMetrics | null>(null)
  const [promError, setPromError] = useState<string | null>(null)
  const [promLoading, setPromLoading] = useState(true)

  const loadMetrics = useMemo(
    () => async () => {
      setPromLoading(true)
      try {
        const res = await fetch('/metrics')
        if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`)
        setProm(parseExposition(await res.text()))
        setPromError(null)
      } catch (err) {
        setProm(null)
        setPromError(err instanceof Error ? err.message : 'Could not reach /metrics')
      } finally {
        setPromLoading(false)
      }
    },
    [],
  )

  useEffect(() => {
    void loadMetrics()
  }, [loadMetrics])

  // The scrape target is the console's own origin minus the dev-server port, so
  // the snippet is correct whether the operator is on :5173 or behind a proxy.
  const scrapeTarget = typeof window === 'undefined' ? 'localhost:8080' : window.location.host

  return (
    <div className="space-y-6">
      <GrafanaSection />
      <PrometheusSection
        metrics={prom}
        error={promError}
        loading={promLoading}
        onRefresh={loadMetrics}
        scrapeConfig={prometheusScrapeConfig(scrapeTarget)}
      />
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Grafana                                                                    */
/* -------------------------------------------------------------------------- */

function GrafanaSection() {
  const { openEvent } = useConsole()
  const readOnly = useReadOnly()
  const grafana = useGrafanaIntegration()
  const { settings } = grafana

  // Local form state, reseeded whenever the server's copy changes (initial
  // load, or after a save round-trips). Without this a save would leave the
  // form holding stale values and the next partial PUT would write them back.
  const [url, setUrl] = useState(settings.url)
  const [apiKey, setApiKey] = useState(settings.api_token)
  const [org, setOrg] = useState(settings.org)
  const [push1, setPush1] = useState(settings.push_l1)
  const [push2, setPush2] = useState(settings.push_l2)
  const [push3, setPush3] = useState(settings.push_l3)
  const [template, setTemplate] = useState(settings.template || DEFAULT_TEMPLATE)
  const [dashboards, setDashboards] = useState<string[]>(settings.dashboards ?? [])

  const [revealKey, setRevealKey] = useState(false)
  const [copied, setCopied] = useState(false)
  const [savedAt, setSavedAt] = useState<number | null>(null)

  const seededRef = useRef<string>('')
  useEffect(() => {
    const key = JSON.stringify(settings)
    if (key === seededRef.current) return
    seededRef.current = key
    setUrl(settings.url)
    setApiKey(settings.api_token)
    setOrg(settings.org)
    setPush1(settings.push_l1)
    setPush2(settings.push_l2)
    setPush3(settings.push_l3)
    setTemplate(settings.template || DEFAULT_TEMPLATE)
    setDashboards(settings.dashboards ?? [])
  }, [settings])

  useEffect(() => {
    if (!savedAt) return
    const timer = window.setTimeout(() => setSavedAt(null), 2500)
    return () => window.clearTimeout(timer)
  }, [savedAt])

  const dirty =
    url !== settings.url ||
    apiKey !== settings.api_token ||
    org !== settings.org ||
    push1 !== settings.push_l1 ||
    push2 !== settings.push_l2 ||
    push3 !== settings.push_l3 ||
    template !== settings.template ||
    JSON.stringify(dashboards) !== JSON.stringify(settings.dashboards ?? [])

  const toggleDashboard = (name: string) => {
    setDashboards((prev) =>
      prev.includes(name) ? prev.filter((d) => d !== name) : [...prev, name],
    )
  }

  const handleSave = () => {
    grafana.save({
      url: url.trim(),
      api_token: apiKey,
      org,
      push_l1: push1,
      push_l2: push2,
      push_l3: push3,
      template,
      dashboards,
      enabled: true,
    })
    setSavedAt(Date.now())
  }

  // The status pill reflects the *last recorded* test on the server unless a
  // fresher in-memory result exists. A live probe on every render would hammer
  // Grafana; a cheap read is what this pane should do.
  const reachable = grafana.testResult?.ok ?? settings.last_test_ok
  const testDetail = grafana.testResult?.detail || settings.last_test_error || ''

  const columns: DataTableColumn<GrafanaAnnotation>[] = useMemo(
    () => [
      {
        key: 'time',
        header: 'Time',
        cell: (a) => (
          <span className="whitespace-nowrap font-mono text-xs tabular-nums text-slate-500">
            {formatDateTime(a.time)}
          </span>
        ),
      },
      {
        key: 'level',
        header: 'Level',
        cell: (a) => <LevelPill level={Number(a.impact_number) || 1} short />,
      },
      {
        key: 'event',
        header: 'Event',
        className: 'max-w-[24rem]',
        cell: (a) => <span className="block truncate text-xs text-slate-700">{a.summary}</span>,
      },
      {
        key: 'server',
        header: 'Server',
        cell: (a) => <span className="font-mono text-xs text-slate-600">{a.hostname}</span>,
      },
      {
        key: 'status',
        header: 'Delivery',
        cell: (a) =>
          a.status === 'delivered' ? (
            <StatusPill tone="green" dot>
              Delivered
            </StatusPill>
          ) : (
            <StatusPill tone="red" dot>
              {a.status === 'skipped' ? 'Skipped' : 'Failed'}
            </StatusPill>
          ),
      },
      {
        key: 'view',
        header: 'Actions',
        align: 'right',
        cell: (a) => (
          <Button
            size="sm"
            icon={<ExternalLink className="h-3.5 w-3.5" />}
            disabled={!a.event_id}
            onClick={() => a.event_id && openEvent(a.event_id, 'integrations')}
          >
            View
          </Button>
        ),
      },
    ],
    [openEvent],
  )

  // Annotation preview: the template with realistic values substituted, so the
  // operator sees the rendered text rather than the raw placeholders.
  const previewText = useMemo(
    () =>
      template
        .replaceAll('{{summary}}', 'Modified /etc/nginx/nginx.conf')
        .replaceAll('{{actor}}', 'alice')
        .replaceAll('{{hostname}}', 'prod-web-01')
        .replaceAll('{{level}}', 'L1')
        .replaceAll('{{category}}', 'config')
        .replaceAll('{{path}}', '/etc/nginx/nginx.conf'),
    [template],
  )

  return (
    <section className="space-y-4">
      <SectionTitle
        hint="Push changes to Grafana as annotation markers and query them from your dashboards."
        actions={
          <div className="flex items-center gap-2">
            {grafana.isFallback ? (
              <StatusPill tone="amber" dot>
                Preview data
              </StatusPill>
            ) : null}
            <StatusPill tone={reachable ? 'green' : 'slate'} dot>
              {reachable ? 'Connected' : 'Not verified'}
            </StatusPill>
          </div>
        }
      >
        Grafana
      </SectionTitle>

      {grafana.isError && !grafana.isFallback ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Could not load the saved integration. Showing defaults — saving will overwrite them.
          </span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Connection */}
        <Card>
          <CardHeader
            title="Grafana Connection"
            subtitle="Service account the server uses to POST annotations"
            icon={<Plug className="h-4 w-4" />}
            actions={
              <StatusPill tone={reachable ? 'green' : 'amber'} dot>
                {reachable ? 'Reachable' : 'Unverified'}
              </StatusPill>
            }
          />
          <div className="mt-4 space-y-4">
            <Field label="Grafana URL" htmlFor="grafana-url">
              <TextInput
                id="grafana-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://grafana.example.com"
              />
            </Field>

            <Field
              label="API Key"
              hint="Service account token with the annotations:write scope."
              htmlFor="grafana-key"
            >
              <div className="flex items-center gap-2">
                <TextInput
                  id="grafana-key"
                  type={revealKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="font-mono text-xs"
                  wrapperClassName="flex-1"
                  placeholder="glsa_…"
                />
                <Button
                  icon={revealKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  onClick={() => setRevealKey((v) => !v)}
                  aria-label={revealKey ? 'Hide API key' : 'Reveal API key'}
                >
                  {revealKey ? 'Hide' : 'Reveal'}
                </Button>
              </div>
            </Field>

            <Field label="Organization" htmlFor="grafana-org">
              <TextInput
                id="grafana-org"
                value={org}
                onChange={(e) => setOrg(e.target.value)}
                placeholder="Acme Corporation"
              />
            </Field>

            <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
              <Button
                variant="primary"
                disabled={readOnly || grafana.isTesting || !url.trim()}
                icon={
                  grafana.isTesting ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Wifi className="h-4 w-4" />
                  )
                }
                onClick={() => grafana.test()}
                title={readOnly ? 'Read-only session — testing is disabled' : undefined}
              >
                {grafana.isTesting ? 'Testing…' : 'Test Connection'}
              </Button>
              {testDetail ? (
                reachable ? (
                  <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                    <CheckCircle2 className="h-4 w-4" /> {testDetail}
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
                    <XCircle className="h-4 w-4" /> {testDetail}
                  </span>
                )
              ) : (
                <span className="text-xs text-slate-400">
                  {settings.last_test_at
                    ? `Last checked ${formatDateTime(settings.last_test_at)}`
                    : 'Not tested yet'}
                </span>
              )}
            </div>
          </div>
        </Card>

        {/* Annotation settings */}
        <Card>
          <CardHeader
            title="Annotation Settings"
            subtitle="Choose which impact levels become Grafana markers"
            icon={<Send className="h-4 w-4" />}
          />
          <div className="mt-2 divide-y divide-slate-100">
            <Toggle
              checked={push1}
              onChange={setPush1}
              label={
                <span className="flex items-center gap-2">
                  Push Level 1 (Critical)
                  <LevelPill level={1} short />
                </span>
              }
              description="Always pushed — config, identity and service changes."
            />
            <Toggle
              checked={push2}
              onChange={setPush2}
              label={
                <span className="flex items-center gap-2">
                  Push Level 2 (Grouped)
                  <LevelPill level={2} short />
                </span>
              }
              description="One annotation per package/CM transaction."
            />
            <Toggle
              checked={push3}
              onChange={setPush3}
              label={
                <span className="flex items-center gap-2">
                  Push Level 3 (Drift)
                  <LevelPill level={3} short />
                </span>
              }
              description="Hash-only changes — noisy, off by default."
            />
          </div>

          <div className="mt-4 space-y-4">
            <Field
              label="Annotation text template"
              hint="Available variables: {{summary}}, {{actor}}, {{hostname}}, {{level}}, {{category}}, {{path}}."
              htmlFor="annotation-template"
            >
              <TextInput
                id="annotation-template"
                value={template}
                onChange={(e) => setTemplate(e.target.value)}
                className="font-mono text-xs"
              />
            </Field>

            <div>
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-medium text-slate-700">Available dashboards</span>
                <button
                  onClick={async () => {
                    await copyText(template)
                    setCopied(true)
                    window.setTimeout(() => setCopied(false), 1200)
                  }}
                  className="flex items-center gap-1 text-[11px] font-medium text-blue-700 hover:text-blue-800"
                >
                  <Copy className="h-3 w-3" /> {copied ? 'Copied' : 'Copy template'}
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {GRAFANA_DASHBOARDS.map((d) => {
                  const on = dashboards.includes(d)
                  return (
                    <button
                      key={d}
                      onClick={() => toggleDashboard(d)}
                      className={cn(
                        'rounded-full border px-2.5 py-1 text-xs font-medium transition-colors',
                        on
                          ? 'border-blue-200 bg-blue-50 text-blue-700'
                          : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50',
                      )}
                    >
                      {d}
                    </button>
                  )
                })}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
              <Button
                variant="primary"
                icon={
                  grafana.isSaving ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="h-4 w-4" />
                  )
                }
                disabled={readOnly || grafana.isSaving || !dirty}
                onClick={handleSave}
              >
                {grafana.isSaving ? 'Saving…' : 'Save integration'}
              </Button>
              {grafana.saveError ? (
                <span className="flex items-center gap-1.5 text-xs font-medium text-red-700">
                  <XCircle className="h-3.5 w-3.5" /> {grafana.saveError}
                </span>
              ) : savedAt ? (
                <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Saved
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-xs text-slate-500">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
                  Token stored encrypted at rest
                </span>
              )}
            </div>
          </div>
        </Card>
      </div>

      {/* Dashboard asset */}
      <Card>
        <CardHeader
          title="Provisioned Dashboard"
          subtitle={INTEGRATION_ASSETS.grafanaDashboard.description}
          icon={<ExternalLink className="h-4 w-4" />}
        />
        <p className="mt-3 text-xs text-slate-500">
          Import this file into Grafana (Dashboards → New → Import), or drop it in a provisioning
          directory. It binds a Prometheus datasource for scrape-side metrics and a Postgres
          datasource pointed at the StateTrack database for the exact counts, tables and telemetry
          line, so both are requested on import.
        </p>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {[
            { method: 'GET', path: '/api/v1/grafana/annotations' },
            { method: 'GET', path: '/api/v1/grafana/events' },
          ].map((e) => (
            <span
              key={e.path}
              className="inline-flex items-center gap-1.5 rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[10px] text-slate-600"
            >
              <span className="font-semibold text-emerald-700">{e.method}</span>
              {e.path}
            </span>
          ))}
        </div>
        <AssetActions asset={INTEGRATION_ASSETS.grafanaDashboard} className="mt-4" />
      </Card>

      {/* Recent annotations */}
      <Card flush>
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
          <CardHeader
            className="min-w-0 flex-1"
            title="Recent Annotations Dispatched"
            subtitle="Last successful POSTs to the Grafana annotation API"
            icon={<Send className="h-4 w-4" />}
          />
          <StatusPill tone="green" dot>
            {grafana.annotations.length} dispatched
          </StatusPill>
        </div>
        <DataTable
          columns={columns}
          rows={grafana.annotations}
          rowKey={(a) => a.id}
          pageSize={6}
          empty="No annotations dispatched yet."
        />
      </Card>

      {/* Annotation preview */}
      <Card>
        <CardHeader
          title="Annotation Preview"
          subtitle="How markers render on your Grafana panels"
          icon={<ExternalLink className="h-4 w-4" />}
        />
        <div className="mt-4">
          <CodeBlock
            label="POST /api/annotations"
            language="json"
            copyable={false}
            code={`POST ${url || 'https://grafana.example.com'}/api/annotations
{
  "time": ${Date.now()},
  "text": "${previewText}",
  "tags": ["statetrack", "host:prod-web-01", "level:L1"]
}`}
          />
        </div>
        <p className="mt-2 text-xs text-slate-500">
          <code className="font-mono text-[11px] text-slate-700">time</code> only — never{' '}
          <code className="font-mono text-[11px] text-slate-700">timeEnd</code> or{' '}
          <code className="font-mono text-[11px] text-slate-700">isRegion</code>. An end time makes
          Grafana draw a translucent region curtain across the panel, which hides the data it is
          meant to explain; a single timestamp draws one vertical line.
        </p>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {TEMPLATE_VARS.map((v) => (
            <button
              key={v}
              onClick={() => setTemplate((prev) => `${prev} ${v}`.trim())}
              className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 hover:bg-slate-100"
            >
              {v}
            </button>
          ))}
        </div>
      </Card>
    </section>
  )
}

/* -------------------------------------------------------------------------- */
/* Prometheus                                                                 */
/* -------------------------------------------------------------------------- */

interface PromMetrics {
  /** Total series in the exposition. */
  series: number
  /** Family names present, for the key-series checklist. */
  families: string[]
  /** Sample values for the key series, summed across label combinations. */
  totals: Record<string, number>
  /** Raw content length, as a rough "is the exporter alive" signal. */
  bytes: number
}

function PrometheusSection({
  metrics,
  error,
  loading,
  onRefresh,
  scrapeConfig,
}: {
  metrics: PromMetrics | null
  error: string | null
  loading: boolean
  onRefresh: () => Promise<void>
  scrapeConfig: string
}) {
  const present = new Set(metrics?.families ?? [])

  return (
    <section className="space-y-4">
      <SectionTitle
        hint="Scrape StateTrack's Prometheus exporter and alert on change, drift and delivery health."
        actions={
          <div className="flex items-center gap-2">
            {error ? (
              <StatusPill tone="red" dot>
                Unreachable
              </StatusPill>
            ) : loading ? (
              <StatusPill tone="slate" dot>
                Checking…
              </StatusPill>
            ) : (
              <StatusPill tone="green" dot>
                Serving {metrics?.series ?? 0} series
              </StatusPill>
            )}
            <Button
              size="sm"
              icon={<RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />}
              onClick={() => void onRefresh()}
              disabled={loading}
            >
              Refresh
            </Button>
          </div>
        }
      >
        Prometheus
      </SectionTitle>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader
            title="Exporter Status"
            subtitle="GET /metrics — same listener as the API, no second port to open"
            icon={<Plug className="h-4 w-4" />}
          />
          {error ? (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                <div className="font-medium">Could not reach /metrics</div>
                <div className="break-words">{error}</div>
              </div>
            </div>
          ) : loading && !metrics ? (
            <div className="mt-4">
              <BlockSkeleton rows={3} />
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <Stat label="Series" value={String(metrics?.series ?? 0)} />
                <Stat label="Families" value={String(metrics?.families.length ?? 0)} />
              </div>
              <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200">
                {KEY_SERIES.map((s) => {
                  const ok = present.has(s.name)
                  return (
                    <li key={s.name} className="flex items-start gap-3 px-3 py-2">
                      <span
                        className={cn(
                          'mt-1 h-1.5 w-1.5 shrink-0 rounded-full',
                          ok ? 'bg-emerald-600' : 'bg-slate-300',
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-[11px] text-slate-700">{s.name}</p>
                        <p className="mt-0.5 text-[11px] text-slate-500">{s.hint}</p>
                      </div>
                      <span className="shrink-0 font-mono text-xs tabular-nums text-slate-600">
                        {ok && metrics ? formatMetric(metrics.totals[s.name]) : '—'}
                      </span>
                    </li>
                  )
                })}
              </ul>
              <p className="text-[11px] text-slate-400">
                Counter series are pre-seeded with a zero baseline at startup, so a fresh install
                reports <span className="font-mono">0</span> rather than no data.
              </p>
            </div>
          )}
        </Card>

        <Card>
          <CardHeader
            title="Scrape Configuration"
            subtitle="Paste into prometheus.yml and reload"
            icon={<Copy className="h-4 w-4" />}
          />
          <div className="mt-4">
            <CodeBlock label="prometheus.yml" language="yaml" code={scrapeConfig} maxHeight="max-h-52" />
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Reload with <span className="font-mono">POST /-/reload</span> (or send SIGHUP) once the
            file is in place.
          </p>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Alerting Rules"
          subtitle={INTEGRATION_ASSETS.prometheusAlerts.description}
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <ul className="mt-3 space-y-1.5 text-xs text-slate-500">
          {[
            'StateTrackAgentOffline — no heartbeat within the online window',
            'StateTrackCriticalChangeSpike — burst of Level 1 changes on one host',
            'StateTrackChangeStorm — the agent circuit breaker is throttling',
            'StateTrackWebhookDeliveryFailures — outbound delivery is erroring',
          ].map((r) => (
            <li key={r} className="flex items-start gap-2">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-400" />
              <span>{r}</span>
            </li>
          ))}
        </ul>
        <AssetActions asset={INTEGRATION_ASSETS.prometheusAlerts} className="mt-4" />
      </Card>
    </section>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2">
      <p className="text-[10px] font-medium uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-0.5 font-mono text-sm tabular-nums text-slate-800">{value}</p>
    </div>
  )
}

function formatMetric(value: number | undefined): string {
  if (value === undefined) return '—'
  return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(2)
}

/**
 * Minimal Prometheus text-format reader.
 *
 * Deliberately not a full parser: the hub needs the number of series, the set
 * of family names, and the summed value of a handful of known counters. Pulling
 * in a Prometheus parsing library to answer three questions would be far more
 * code than this, and this cannot mis-render anything because it only ever
 * displays what it read.
 */
function parseExposition(text: string): PromMetrics {
  const families = new Set<string>()
  const totals: Record<string, number> = {}
  let series = 0

  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    // Split on the last space so a label value containing spaces on a malformed
    // line cannot produce a NaN value silently.
    const idx = line.lastIndexOf(' ')
    if (idx <= 0) continue
    const namePart = line.slice(0, idx)
    const value = Number(line.slice(idx + 1))
    if (!Number.isFinite(value)) continue

    series++
    // Strip the label set: statetrack_mutations_total{a="b"} -> statetrack_mutations_total
    const brace = namePart.indexOf('{')
    const name = brace < 0 ? namePart : namePart.slice(0, brace)
    // A histogram/summary emits _bucket/_sum/_count; count the base family once.
    const base = name.replace(/_(bucket|sum|count)$/, '')
    families.add(base)
    families.add(name)
    totals[name] = (totals[name] ?? 0) + value
    if (base !== name) totals[base] = (totals[base] ?? 0) + value
  }

  return { series, families: [...families], totals, bytes: text.length }
}
